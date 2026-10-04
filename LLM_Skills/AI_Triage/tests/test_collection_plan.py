from pathlib import Path

import pytest

from triage.case import CaseError
from triage.collection_plan import COLLECTOR_DOMAIN, DOMAINS, PlannedCommand, plan_collection
from triage.collectors import all_collectors
from triage.config import parse_config

SKILL_DIR = Path("/opt/skill")
PYTHON = str(SKILL_DIR / ".venv" / "bin" / "python")
START, END = "2026-10-04T09:42:00Z", "2026-10-04T11:00:00Z"


@pytest.fixture
def config(config_data):
    return parse_config(config_data)


def make_case(resources, hostnames=("checkout.example.com",)):
    return {
        "case_dir": "/cases/INC-1/run",
        "incident": {"number": "INC-1", "hostnames": list(hostnames)},
        "incident_start": "2026-10-04T10:42:00Z",
        "window": {"start": START, "end": END},
        "target": {"source": "map", "service": "s", "environment": "prod", "account": "prod-main",
                   "region": "eu-west-1", "resources": resources, "depends_on": []},
    }


def plan(resources, config, **kwargs):
    return plan_collection(make_case(resources, **kwargs), config, SKILL_DIR)


def targets_of(command):
    argv = command.argv
    return {pair.partition("=")[0]: pair.partition("=")[2]
            for flag, pair in zip(argv, argv[1:]) if flag == "--target"}


def option(command, name):
    argv = command.argv
    return argv[argv.index(name) + 1]


def named(commands, name):
    return [c for c in commands if c.name == name]


def one(commands, name):
    found = named(commands, name)
    assert len(found) == 1, [c.name for c in commands]
    return found[0]


# shape

def test_collect_commands_carry_the_case_options(config):
    command = one(plan({"rds": "checkout-prod-db"}, config), "rds")
    assert command.argv[:3] == [PYTHON, str(SKILL_DIR / "scripts" / "collect.py"), "rds"]
    assert command.tool == "collect.py"
    assert option(command, "--account") == "prod-main"
    assert option(command, "--region") == "eu-west-1"
    assert option(command, "--start") == START and option(command, "--end") == END
    assert option(command, "--case-dir") == "/cases/INC-1/run"
    assert targets_of(command) == {"db": "checkout-prod-db"}
    assert command.reason


def test_domains_are_the_five_known_ones():
    assert DOMAINS == ("changes", "compute", "data", "edge", "logs")
    assert set(COLLECTOR_DOMAIN.values()) <= set(DOMAINS)


# one test per resource row

def test_ecs_service(config):
    command = one(plan({"ecs_service": "checkout/checkout-api"}, config), "ecs")
    assert targets_of(command) == {"cluster": "checkout", "service": "checkout-api"}
    assert command.domain == "compute"


def test_ec2_instances(config):
    command = one(plan({"ec2_instances": ["i-0aaa", "i-0bbb"]}, config), "ec2")
    assert targets_of(command) == {"instance_ids": "i-0aaa,i-0bbb"}


def test_auto_scaling_group_alone(config):
    command = one(plan({"auto_scaling_group": "checkout-asg"}, config), "autoscaling")
    assert targets_of(command) == {"group": "checkout-asg"}


def test_auto_scaling_group_with_ecs_service(config):
    commands = plan({"auto_scaling_group": "checkout-asg", "ecs_service": "checkout/checkout-api"}, config)
    assert targets_of(one(commands, "autoscaling")) == {
        "group": "checkout-asg", "ecs_cluster": "checkout", "ecs_service": "checkout-api"}


def test_lambda_functions_one_command_each(config):
    commands = named(plan({"lambda_functions": ["fn-a", "fn-b"]}, config), "lambda")
    assert [targets_of(c) for c in commands] == [{"function": "fn-a"}, {"function": "fn-b"}]
    assert [option(c, "--suffix") for c in commands] == ["fn-a", "fn-b"]


def test_eks(config):
    resources = {"eks": {"cluster": "platform-prod", "namespace": "payments",
                         "workloads": ["deployment/a", "deployment/b"]}}
    command = one(plan(resources, config), "eks")
    assert targets_of(command) == {"cluster": "platform-prod", "namespace": "payments",
                                   "workloads": "deployment/a,deployment/b"}


def test_eks_without_workloads(config):
    command = one(plan({"eks": {"cluster": "platform-prod", "namespace": "payments"}}, config), "eks")
    assert targets_of(command) == {"cluster": "platform-prod", "namespace": "payments"}


def test_load_balancer_with_one_hostname(config):
    command = one(plan({"load_balancer": "checkout-prod"}, config), "edge")
    assert targets_of(command) == {"load_balancer": "checkout-prod", "hostname": "checkout.example.com"}
    assert command.domain == "edge"


@pytest.mark.parametrize("hostnames", [(), ("a.example.com", "b.example.com")])
def test_load_balancer_without_exactly_one_hostname(config, hostnames):
    command = one(plan({"load_balancer": "checkout-prod"}, config, hostnames=hostnames), "edge")
    assert targets_of(command) == {"load_balancer": "checkout-prod"}


def test_api_gateway(config):
    assert targets_of(one(plan({"api_gateway": "abc123"}, config), "apigateway")) == {"api_id": "abc123"}


def test_cloudfront_distribution(config):
    command = one(plan({"cloudfront_distribution": "E1ABC"}, config), "cloudfront_waf")
    assert targets_of(command) == {"distribution_id": "E1ABC"}


def test_rds(config):
    assert targets_of(one(plan({"rds": "db-1"}, config), "rds")) == {"db": "db-1"}


def test_elasticache(config):
    command = one(plan({"elasticache": "cache-1"}, config), "elasticache")
    assert targets_of(command) == {"replication_group": "cache-1"}


def test_dynamodb_tables_one_command_each(config):
    commands = named(plan({"dynamodb_tables": ["t1", "t2"]}, config), "dynamodb")
    assert [targets_of(c) for c in commands] == [{"table": "t1"}, {"table": "t2"}]
    assert [option(c, "--suffix") for c in commands] == ["t1", "t2"]


def test_efs(config):
    assert targets_of(one(plan({"efs": "fs-0123"}, config), "efs")) == {"file_system": "fs-0123"}


def test_messaging_is_one_command_for_queues_and_topics(config):
    command = one(plan({"sqs_queues": ["q1", "q2"], "sns_topics": ["t1"]}, config), "messaging")
    assert targets_of(command) == {"queues": "q1,q2", "topics": "t1"}


def test_messaging_with_only_topics(config):
    command = one(plan({"sns_topics": ["t1"]}, config), "messaging")
    assert targets_of(command) == {"topics": "t1"}


def test_no_messaging_without_queues_or_topics(config):
    assert named(plan({"sqs_queues": []}, config), "messaging") == []


def test_log_groups(config):
    command = one(plan({"log_groups": ["/ecs/a", "/ecs/b"]}, config), "logs")
    assert targets_of(command) == {"log_groups": "/ecs/a,/ecs/b"}
    assert command.domain == "logs"


def test_opensearch_plans_three_queries(config):
    resources = {"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*",
                                "filter": {"service": "checkout-api", "env": "prod"}}}
    commands = named(plan(resources, config), "opensearch")
    assert [c.argv[2] for c in commands] == ["histogram", "top-messages", "search"]
    assert [option(c, "--suffix") for c in commands] == ["histogram", "top-messages", "search"]
    for command in commands:
        assert command.tool == "opensearch_query.py"
        assert command.argv[:2] == [PYTHON, str(SKILL_DIR / "scripts" / "opensearch_query.py")]
        assert option(command, "--cluster") == "logs-prod"
        assert option(command, "--index") == "app-logs-checkout-*"
        assert option(command, "--start") == START and option(command, "--end") == END
        assert option(command, "--case-dir") == "/cases/INC-1/run"
        filters = [v for f, v in zip(command.argv, command.argv[1:]) if f == "--filter"]
        assert filters == ["service=checkout-api", "env=prod"]
        assert command.domain == "logs"
        assert "--account" not in command.argv and "--region" not in command.argv


def test_opensearch_without_filter(config):
    resources = {"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*"}}
    assert "--filter" not in named(plan(resources, config), "opensearch")[0].argv


def test_unknown_opensearch_cluster_is_skipped(config):
    resources = {"opensearch": {"cluster": "nope", "index_pattern": "app-logs-*"}}
    commands = plan(resources, config)
    assert [c for c in named(commands, "opensearch") if c.tool != "skipped"] == []
    assert any(c.tool == "skipped" and "nope" in c.reason for c in commands)


# always planned

def test_changes_and_platform_are_always_planned(config):
    commands = plan({}, config)
    changes = one(commands, "changes")
    assert targets_of(changes) == {"incident_start": "2026-10-04T10:42:00Z"}
    assert changes.domain == "changes"
    platform = one(commands, "platform")
    assert targets_of(platform) == {} and platform.domain == "changes"


def test_changes_resource_names(config):
    resources = {"ecs_service": "checkout/checkout-api", "load_balancer": "lb-1", "rds": "db-1",
                 "elasticache": "cache-1", "lambda_functions": ["fn-1"], "dynamodb_tables": ["tbl-1"],
                 "sqs_queues": ["q-1"]}
    names = targets_of(one(plan(resources, config), "changes"))["resource_names"].split(",")
    assert names == ["checkout-api", "lb-1", "db-1", "cache-1", "fn-1", "tbl-1", "q-1"]


def test_changes_resource_names_are_capped_at_ten(config):
    resources = {"lambda_functions": [f"fn-{n}" for n in range(15)]}
    names = targets_of(one(plan(resources, config), "changes"))["resource_names"].split(",")
    assert names == [f"fn-{n}" for n in range(10)]


# problems

def test_a_malformed_resource_is_skipped_with_a_reason(config):
    commands = plan({"ecs_service": "no-slash", "rds": ["not", "a", "string"], "ec2_instances": "i-1"}, config)
    skipped = [c for c in commands if c.tool == "skipped"]
    assert {c.name for c in skipped} == {"ecs", "rds", "ec2"}
    assert all(c.reason and c.argv == [] for c in skipped)
    assert {c.name for c in commands if c.tool != "skipped"} == {"changes", "platform"}
    assert "ecs_service" in next(c for c in skipped if c.name == "ecs").reason


def test_an_empty_list_plans_nothing_and_is_not_an_error(config):
    commands = plan({"ec2_instances": [], "log_groups": [], "lambda_functions": []}, config)
    assert {c.name for c in commands} == {"changes", "platform"}


def test_an_unknown_resource_key_is_skipped(config):
    commands = plan({"mystery": "x"}, config)
    assert any(c.tool == "skipped" and "mystery" in c.reason for c in commands)


def test_no_target_is_an_error(config):
    case = make_case({})
    case["target"] = None
    with pytest.raises(CaseError):
        plan_collection(case, config, SKILL_DIR)


# against the real registry

FULL_RESOURCES = {
    "ecs_service": "c/s", "ec2_instances": ["i-1"], "auto_scaling_group": "g", "lambda_functions": ["f"],
    "eks": {"cluster": "platform-prod", "namespace": "n", "workloads": ["deployment/w"]},
    "load_balancer": "lb", "api_gateway": "a", "cloudfront_distribution": "E1", "rds": "d",
    "elasticache": "e", "dynamodb_tables": ["t"], "efs": "fs", "sqs_queues": ["q"], "sns_topics": ["n"],
    "log_groups": ["/g"],
}


def test_every_collector_has_a_domain():
    assert set(all_collectors()) <= set(COLLECTOR_DOMAIN)


def test_planned_collectors_exist_and_targets_are_declared(config):
    registry = all_collectors()
    commands = [c for c in plan(FULL_RESOURCES, config) if c.tool == "collect.py"]
    assert len(commands) >= 15
    for command in commands:
        collector = registry[command.argv[2]]
        assert command.name == collector.name
        targets = targets_of(command)
        assert set(targets) <= set(collector.required) | set(collector.optional)
        assert set(collector.required) <= set(targets)
        assert command.domain == COLLECTOR_DOMAIN[collector.name]


def test_every_command_has_a_known_domain(config):
    resources = {**FULL_RESOURCES,
                 "opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*"}}
    for command in plan(resources, config):
        assert command.domain in DOMAINS
        assert isinstance(command, PlannedCommand)


def test_collect_options_are_accepted_by_the_command(config):
    import collect
    parser = collect._build_parser()
    for command in plan(FULL_RESOURCES, config):
        if command.tool == "collect.py":
            parser.parse_args(command.argv[2:])


def test_opensearch_options_are_accepted_by_the_command(config):
    import opensearch_query
    parser = opensearch_query._build_parser()
    resources = {"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*", "filter": {"a": "b"}}}
    for command in plan(resources, config):
        if command.tool == "opensearch_query.py":
            parser.parse_args(command.argv[2:])
