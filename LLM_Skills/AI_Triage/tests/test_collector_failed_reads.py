"""Property: a read that failed is never reported as an absence.

For every registered collector, each AWS operation it makes is answered with AccessDenied in turn, and no
fact built from that failed call may say that nothing was found ("no ", "none", "not found", "were found",
"0 "). Facts are matched to the failed call by the command they carry.
"""
import copy
import importlib
import re
import tempfile
from pathlib import Path

import pytest
import yaml

from conftest import EXAMPLE_CONFIG
from fakes import access_denied
from helpers import make_context
from triage.collectors import all_collectors

ACCOUNT = "111111111111"
ABSENCE = re.compile(r"(?<![\w.])no\s|\bnone\b|not found|were found|(?<![\d.])0\s", re.IGNORECASE)

TARGETS = {
    "access": {"role": "checkout-task", "action": "s3:GetObject", "kms_key": "k1", "secret": "orders/db"},
    "alarms": {"name_prefix": "checkout"},
    "apigateway": {"api_id": "abc123"},
    "autoscaling": {"group": "checkout-asg", "ecs_cluster": "checkout", "ecs_service": "checkout-api"},
    "changes": {"resource_names": "checkout-api", "event_sources": "ecs.amazonaws.com",
                "stack": "web-stack", "pipeline": "web", "config_resource": "AWS::EC2::SecurityGroup/sg-0abc"},
    "cloudfront_waf": {"distribution_id": "E123"},
    "dynamodb": {"table": "orders"},
    "ec2": {"instance_ids": "i-0abc"},
    "ecr": {"repository": "checkout"},
    "ecs": {"cluster": "checkout", "service": "checkout-api"},
    "edge": {"load_balancer": "web-alb"},
    "efs": {"file_system": "fs-0abc"},
    "eks": {"cluster": "platform-prod"},
    "elasticache": {"replication_group": "sessions"},
    "lambda": {"function": "checkout-fn"},
    "logs": {"log_groups": "/ecs/checkout"},
    "messaging": {"queues": "orders-queue", "topics": "orders-topic"},
    "opensearch_domain": {"domain": "search"},
    "platform": {"service_codes": "ecs"},
    "rds": {"db": "orders-db"},
    "vpc": {"vpc_id": "vpc-0abc"},
}

# Further target sets for a collector whose targets take different paths (name, then the variant label).
VARIANTS: dict[str, tuple[str, dict]] = {
    "alarms[in_alarm]": ("alarms", {"in_alarm": "true"}),
}

# Operations known to word an absence about a failed read. Each is a gap for the collector's owner to fix.
KNOWN_GAPS: dict[tuple[str, str], str] = {}


def _module(name: str):
    return importlib.import_module(f"test_collector_{name}")


def _seed(name: str) -> tuple[dict, dict, dict | None]:
    """Targets, AWS answers and kubectl answers for a run that gets deep into the collector.

    Built from the collector's own test fixtures where it has a zero-argument builder; the rest
    run on empty answers, which reaches only their first calls.
    """
    targets = dict(TARGETS[name])
    answers: dict = {}
    kube = None
    if name == "access":
        m = _module("access")
        answers = {**m.role_answers(), "kms describe-key": m.key_reply(),
                   "secretsmanager describe-secret": m.secret_reply(),
                   "iam simulate-principal-policy": m.simulation("explicitDeny", [{"SourcePolicyId": "p", "SourcePolicyType": "t"}])}
    elif name == "apigateway":
        m = _module("apigateway")
        targets, answers = dict(m.REST), m.rest_answers()
    elif name == "autoscaling":
        answers, targets = _module("autoscaling").answers(), {"group": "web-asg"}
    elif name == "cloudfront_waf":
        answers = _module("cloudfront_waf").answers_for()
    elif name == "dynamodb":
        answers = _module("dynamodb").healthy_answers()
    elif name == "ec2":
        answers, targets = _module("ec2").answers(), {"instance_ids": "i-0aaa"}
    elif name == "ecs":
        answers = _module("ecs").failed_answers()
    elif name == "edge":
        answers = _module("edge").healthy_answers()
    elif name == "efs":
        m = _module("efs")
        answers, targets = m.healthy_answers(), dict(m.TARGETS)
    elif name == "eks":
        m = _module("eks")
        answers, kube, targets = m.aws_answers(), m.kube_answers(), {"cluster": m.CLUSTER}
    elif name == "elasticache":
        m = _module("elasticache")
        answers, targets = m.healthy_answers(), dict(m.TARGETS)
    elif name == "lambda":
        answers, targets = _module("lambda").answers(), {"function": "orders-worker"}
    elif name == "messaging":
        answers = _module("messaging").base_answers()
    elif name == "opensearch_domain":
        m = _module("opensearch_domain")
        answers, targets = m.healthy_answers(), dict(m.TARGETS)
    elif name == "rds":
        m = _module("rds")
        answers, targets = m.healthy_answers(), dict(m.TARGETS)
    elif name == "vpc":
        m = _module("vpc")
        answers, targets = m.healthy_answers(), dict(m.TARGETS)
    elif name == "changes":
        m = _module("changes")
        answers = {
            "cloudtrail lookup-events": {"Events": [m.event("UpdateService")]},
            "cloudformation describe-stack-events": {"StackEvents": [m.stack_event("UPDATE_FAILED", logical="Db")]},
        }
    elif name == "platform":
        m = _module("platform")
        answers = m.quota_answers([m.quota("Tasks", 100)], m.usage_reply(50))
    return targets, answers, kube


def _config() -> dict:
    return copy.deepcopy(yaml.safe_load(Path(EXAMPLE_CONFIG).read_text()))


def _run(tmp_path, name, overrides, variant=None):
    targets, answers, kube = _seed(name)
    if variant:
        name, targets = VARIANTS[variant][0], dict(VARIANTS[variant][1])
    answers = {**answers, **overrides}
    collector = all_collectors()[name]
    ctx, aws, _ = make_context(_config(), tmp_path, answers, collector=name, kube_answers=kube)
    try:
        collector.run(ctx, targets)
    except Exception:  # collect.py records a raising collector as CollectorError; not this property
        pass
    return ctx, aws


def _operations(name: str, variant=None) -> list[tuple[str, str]]:
    with tempfile.TemporaryDirectory() as tmp:
        _, aws = _run(Path(tmp), name, {}, variant)
    return sorted({(call[1], call[2]) for call in aws.calls})


RUNS = [(name, None) for name in sorted(TARGETS)] + [(VARIANTS[v][0], v) for v in sorted(VARIANTS)]
CASES = [(name, variant, service, operation) for name, variant in RUNS for service, operation in _operations(name, variant)]


def test_every_registered_collector_has_a_target():
    assert set(all_collectors()) == set(TARGETS)


def _absence_claims(ctx, service: str, operation: str) -> list[str]:
    """Absence facts built from the failed call, and absence facts that carry no command at all
    (those cannot be told apart from one built on the failed call)."""
    marker = f" {service} {operation} "
    return [f.summary for f in ctx.evidence.facts
            if (marker in f" {f.command} " or not f.command.strip()) and ABSENCE.search(f.summary)]


def test_the_check_catches_an_absence_claim_about_a_failed_read(tmp_path):
    ctx, _, _ = make_context(_config(), tmp_path, {}, collector="ecs")
    ctx.evidence.add(kind="current", resource="r", summary="No stopped tasks were found",
                     command="aws ecs list-tasks --cluster c --profile p --region r")
    ctx.evidence.add(kind="current", resource="r", summary="Service has 3 tasks",
                     command="aws ecs list-tasks --cluster c --profile p --region r")
    ctx.evidence.add(kind="current", resource="r", summary="No stopped tasks were found",
                     command="aws ecs describe-tasks --cluster c --profile p --region r")
    assert _absence_claims(ctx, "ecs", "list-tasks") == ["No stopped tasks were found"]


def test_the_seeds_reach_past_the_first_call():
    deep = {name for name in TARGETS if len(_operations(name)) > 1}
    assert {"ecs", "access", "rds", "vpc", "eks", "edge", "lambda", "changes"} <= deep


def test_the_check_catches_an_absence_claim_with_no_command(tmp_path):
    ctx, _, _ = make_context(_config(), tmp_path, {}, collector="alarms")
    ctx.evidence.add(kind="current", resource="alarms", summary="No alarms were found")
    assert _absence_claims(ctx, "cloudwatch", "describe-alarms") == ["No alarms were found"]


def test_the_in_alarm_variant_is_covered():
    assert ("alarms", "alarms[in_alarm]", "cloudwatch", "describe-alarms") in CASES


@pytest.mark.parametrize("name,variant,service,operation", CASES,
                         ids=[f"{v or n}:{s}.{o}" for n, v, s, o in CASES])
def test_failed_read_is_not_reported_as_absence(tmp_path, name, variant, service, operation):
    ctx, _ = _run(tmp_path, name, {f"{service} {operation}": access_denied(operation)}, variant)
    assert ctx.evidence.errors, "the failed call must be recorded as an error"
    claims = _absence_claims(ctx, service, operation)
    if claims and (name, f"{service}.{operation}") in KNOWN_GAPS:
        pytest.xfail(f"{KNOWN_GAPS[(name, f'{service}.{operation}')]}: {claims[0]}")
    assert claims == []
