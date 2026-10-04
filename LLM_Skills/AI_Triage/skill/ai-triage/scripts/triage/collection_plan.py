"""Turn a case's target into the exact collector commands, so a run never relies on remembered option names."""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from triage.case import CaseError
from triage.config import TriageConfig

DOMAINS = ("changes", "compute", "data", "edge", "logs")
COLLECTOR_DOMAIN = {
    "changes": "changes", "platform": "changes", "access": "changes",
    "ecs": "compute", "ec2": "compute", "ecr": "compute", "lambda": "compute", "autoscaling": "compute", "eks": "compute",
    "rds": "data", "elasticache": "data", "opensearch_domain": "data", "dynamodb": "data", "efs": "data", "messaging": "data",
    "edge": "edge", "vpc": "edge", "apigateway": "edge", "cloudfront_waf": "edge",
    "logs": "logs", "alarms": "logs", "opensearch": "logs",
}
# The collector that a resource key feeds, used to name a skipped resource.
RESOURCE_COLLECTOR = {
    "ecs_service": "ecs", "ec2_instances": "ec2", "auto_scaling_group": "autoscaling", "lambda_functions": "lambda",
    "eks": "eks", "load_balancer": "edge", "api_gateway": "apigateway", "cloudfront_distribution": "cloudfront_waf",
    "rds": "rds", "elasticache": "elasticache", "dynamodb_tables": "dynamodb", "efs": "efs",
    "sqs_queues": "messaging", "sns_topics": "messaging", "log_groups": "logs", "opensearch": "opensearch",
}
MAX_RESOURCE_NAMES = 10
OPENSEARCH_QUERIES = ("histogram", "top-messages", "search")
SKIPPED = "skipped"


@dataclass(frozen=True)
class PlannedCommand:
    domain: str
    tool: str
    name: str
    argv: list[str]
    reason: str

    def shell(self) -> str:
        return shlex.join(self.argv)


class _Planner:
    def __init__(self, case: dict, config: TriageConfig, skill_dir: Path):
        self.case, self.config = case, config
        target = case["target"]
        self.account, self.region, self.resources = target["account"], target["region"], target["resources"]
        self.python = str(skill_dir / ".venv" / "bin" / "python")
        self.collect_script = str(skill_dir / "scripts" / "collect.py")
        self.opensearch_script = str(skill_dir / "scripts" / "opensearch_query.py")
        self.hostnames = list(case["incident"].get("hostnames", []))
        self.commands: list[PlannedCommand] = []

    def collect(self, name: str, targets: dict[str, str], reason: str, suffix: str = "") -> None:
        argv = [self.python, self.collect_script, name, "--account", self.account, "--region", self.region,
                "--start", self.case["window"]["start"], "--end", self.case["window"]["end"],
                "--case-dir", self.case["case_dir"]]
        for key, value in targets.items():
            argv += ["--target", f"{key}={value}"]
        if suffix:
            argv.append(f"--suffix={suffix}")
        self.commands.append(PlannedCommand(COLLECTOR_DOMAIN[name], "collect.py", name, argv, reason))

    def opensearch(self, subcommand: str, spec: dict, reason: str) -> None:
        argv = [self.python, self.opensearch_script, subcommand, "--cluster", spec["cluster"],
                "--index", spec["index_pattern"], "--start", self.case["window"]["start"],
                "--end", self.case["window"]["end"], "--case-dir", self.case["case_dir"]]
        for key, value in (spec.get("filter") or {}).items():
            text = value if isinstance(value, str) else json.dumps(value)
            argv += ["--filter", f"{key}={text}"]
        argv.append(f"--suffix={subcommand}")
        self.commands.append(PlannedCommand(COLLECTOR_DOMAIN["opensearch"], "opensearch_query.py", "opensearch", argv, reason))

    def skip(self, key: str, why: str) -> None:
        name = RESOURCE_COLLECTOR.get(key, key)
        domain = COLLECTOR_DOMAIN.get(name, "changes")
        self.commands.append(PlannedCommand(domain, SKIPPED, name, [], f"{key}: {why}"))


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _text_list(value: Any) -> list[str] | None:
    """The list when every item is text, else None. An empty list is a valid list."""
    if isinstance(value, list) and all(_is_text(item) for item in value):
        return list(value)
    return None


def _split_ecs(value: Any) -> tuple[str, str] | None:
    if not _is_text(value):
        return None
    cluster, _, service = (part.strip() for part in value.partition("/"))
    return (cluster, service) if cluster and service and "/" not in service else None


def _plan_ecs(p: _Planner, value: Any) -> None:
    parts = _split_ecs(value)
    if parts is None:
        p.skip("ecs_service", "must look like cluster/service")
        return
    p.collect("ecs", {"cluster": parts[0], "service": parts[1]}, "ECS service events, tasks, and deployments")


def _plan_ec2(p: _Planner, value: Any) -> None:
    ids = _text_list(value)
    if ids is None:
        p.skip("ec2_instances", "must be a list of instance ids")
    elif ids:
        p.collect("ec2", {"instance_ids": ",".join(ids)}, "instance state and status checks")


def _plan_asg(p: _Planner, value: Any) -> None:
    if not _is_text(value):
        p.skip("auto_scaling_group", "must be a group name")
        return
    targets = {"group": value}
    parts = _split_ecs(p.resources.get("ecs_service"))
    if parts:
        targets.update({"ecs_cluster": parts[0], "ecs_service": parts[1]})
    p.collect("autoscaling", targets, "scaling activities and capacity")


def _plan_each(p: _Planner, key: str, collector: str, target_key: str, reason: str, value: Any) -> None:
    items = _text_list(value)
    if items is None:
        p.skip(key, "must be a list of names")
        return
    for item in items:
        p.collect(collector, {target_key: item}, reason, suffix=item)


def _plan_eks(p: _Planner, value: Any) -> None:
    if not isinstance(value, dict) or not _is_text(value.get("cluster")) or not _is_text(value.get("namespace")):
        p.skip("eks", "must be a mapping with cluster and namespace")
        return
    workloads = _text_list(value.get("workloads", []))
    if workloads is None:
        p.skip("eks", "workloads must be a list of names")
        return
    if value["cluster"] not in p.config.eks_clusters:
        p.skip("eks", f"cluster '{value['cluster']}' is not in the config")
        return
    targets = {"cluster": value["cluster"], "namespace": value["namespace"]}
    if workloads:
        targets["workloads"] = ",".join(workloads)
    p.collect("eks", targets, "pods, events, and rollouts in the namespace")


def _plan_load_balancer(p: _Planner, value: Any) -> None:
    if not _is_text(value):
        p.skip("load_balancer", "must be a load balancer name")
        return
    targets = {"load_balancer": value}
    if len(p.hostnames) == 1:
        targets["hostname"] = p.hostnames[0]
    p.collect("edge", targets, "target health, listeners, and error rates")


def _plan_single(collector: str, key: str, target_key: str, reason: str):
    def plan(p: _Planner, value: Any) -> None:
        if not _is_text(value):
            p.skip(key, "must be a single name")
            return
        p.collect(collector, {target_key: value}, reason)
    return plan


def _plan_log_groups(p: _Planner, value: Any) -> None:
    groups = _text_list(value)
    if groups is None:
        p.skip("log_groups", "must be a list of log group names")
    elif groups:
        p.collect("logs", {"log_groups": ",".join(groups)}, "error and volume patterns in the logs")


def _plan_opensearch(p: _Planner, value: Any) -> None:
    if (not isinstance(value, dict) or not _is_text(value.get("cluster")) or not _is_text(value.get("index_pattern"))
            or not isinstance(value.get("filter") or {}, dict)):
        p.skip("opensearch", "must be a mapping with cluster, index_pattern, and an optional filter mapping")
        return
    if value["cluster"] not in p.config.opensearch_clusters:
        p.skip("opensearch", f"cluster '{value['cluster']}' is not in the config")
        return
    reasons = {
        "histogram": "log volume over time",
        "top-messages": "most frequent log messages",
        "search": "matching log lines",
    }
    for subcommand in OPENSEARCH_QUERIES:
        p.opensearch(subcommand, value, reasons[subcommand])


def _plan_messaging(p: _Planner) -> None:
    targets: dict[str, str] = {}
    for key, target_key in (("sqs_queues", "queues"), ("sns_topics", "topics")):
        if key not in p.resources:
            continue
        names = _text_list(p.resources[key])
        if names is None:
            p.skip(key, "must be a list of names")
        elif names:
            targets[target_key] = ",".join(names)
    if targets:
        p.collect("messaging", targets, "queue depth, age, and topic delivery")


def _resource_names(resources: dict) -> list[str]:
    names: list[str] = []
    parts = _split_ecs(resources.get("ecs_service"))
    if parts:
        names.append(parts[1])
    for key in ("load_balancer", "rds", "elasticache"):
        if _is_text(resources.get(key)):
            names.append(resources[key])
    for key in ("lambda_functions", "dynamodb_tables", "sqs_queues"):
        names += _text_list(resources.get(key)) or []
    return list(dict.fromkeys(names))[:MAX_RESOURCE_NAMES]


def plan_collection(case: dict, config: TriageConfig, skill_dir: Path) -> list[PlannedCommand]:
    """The commands to run for the case's target, in a fixed order."""
    if not case.get("target"):
        raise CaseError(["the case has no target; run case.py target first"])
    p = _Planner(case, config, skill_dir)
    handlers = {
        "ecs_service": _plan_ecs,
        "ec2_instances": _plan_ec2,
        "auto_scaling_group": _plan_asg,
        "lambda_functions": lambda pl, v: _plan_each(pl, "lambda_functions", "lambda", "function", "configuration, errors, and throttles", v),
        "eks": _plan_eks,
        "load_balancer": _plan_load_balancer,
        "api_gateway": _plan_single("apigateway", "api_gateway", "api_id", "API stages, errors, and latency"),
        "cloudfront_distribution": _plan_single("cloudfront_waf", "cloudfront_distribution", "distribution_id", "distribution status, errors, and WAF blocks"),
        "rds": _plan_single("rds", "rds", "db", "instance state, events, and connections"),
        "elasticache": _plan_single("elasticache", "elasticache", "replication_group", "cache state, events, and memory"),
        "dynamodb_tables": lambda pl, v: _plan_each(pl, "dynamodb_tables", "dynamodb", "table", "table status and throttling", v),
        "efs": _plan_single("efs", "efs", "file_system", "file system state and burst credits"),
        "log_groups": _plan_log_groups,
        "opensearch": _plan_opensearch,
    }
    for key, handler in handlers.items():
        if key in p.resources:
            handler(p, p.resources[key])
    if "sqs_queues" in p.resources or "sns_topics" in p.resources:
        _plan_messaging(p)
    for key in p.resources:
        if key not in handlers and key not in ("sqs_queues", "sns_topics"):
            p.skip(key, "unknown resource key")
    changes = {"incident_start": case["incident_start"]}
    names = _resource_names(p.resources)
    if names:
        changes = {"resource_names": ",".join(names), **changes}
    p.collect("changes", changes, "deployments and configuration changes before the incident")
    p.collect("platform", {}, "known AWS service events")
    return p.commands
