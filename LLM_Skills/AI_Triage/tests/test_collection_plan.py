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
    for index, word in enumerate(argv):
        if word.startswith(name + "="):
            return word[len(name) + 1:]
        if word == name:
            return argv[index + 1]
    raise AssertionError(f"{name} not in {argv}")


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
    assert targets_of(command) == {"db": "checkout-prod-db", "incident_start": "2026-10-04T10:42:00Z"}
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
    assert targets_of(one(plan({"rds": "db-1"}, config), "rds")) == {"db": "db-1", "incident_start": "2026-10-04T10:42:00Z"}


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
    assert {c.name for c in commands if c.tool != "skipped"} == {"changes", "platform", "alarms"}
    assert "ecs_service" in next(c for c in skipped if c.name == "ecs").reason


def test_an_empty_list_plans_nothing_and_is_not_an_error(config):
    commands = plan({"ec2_instances": [], "log_groups": [], "lambda_functions": []}, config)
    assert {c.name for c in commands if c.tool != "skipped"} == {"changes", "platform", "alarms"}


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


# fix round 1

def test_a_suffix_that_starts_with_a_dash_is_planned_as_one_word(config):
    import collect
    command = one(plan({"dynamodb_tables": ["-ledger"]}, config), "dynamodb")
    assert "--suffix=-ledger" in command.argv
    assert collect._build_parser().parse_args(command.argv[2:]).suffix == "-ledger"


def test_opensearch_suffix_is_one_word(config):
    resources = {"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*"}}
    assert [c.argv[-1] for c in named(plan(resources, config), "opensearch")] == [
        "--suffix=histogram", "--suffix=top-messages", "--suffix=search"]


def test_non_string_filter_values_are_planned_as_json(config):
    import opensearch_query
    filter_ = {"ok": True, "no": False, "n": 5, "x": None, "s": "text", "f": 1.5}
    resources = {"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*", "filter": filter_}}
    command = named(plan(resources, config), "opensearch")[0]
    filters = [v for f, v in zip(command.argv, command.argv[1:]) if f == "--filter"]
    assert filters == ["ok=true", "no=false", "n=5", "x=null", "s=text", "f=1.5"]
    opensearch_query._build_parser().parse_args(command.argv[2:])


@pytest.mark.parametrize("value", [" /svc", "cluster/ ", "/", "  /  ", "a/b/c"])
def test_an_ecs_service_with_an_empty_part_is_refused(config, value):
    commands = plan({"ecs_service": value}, config)
    assert [c.tool for c in named(commands, "ecs")] == ["skipped"]


def test_ecs_service_parts_are_stripped(config):
    command = one(plan({"ecs_service": " c / s "}, config), "ecs")
    assert targets_of(command) == {"cluster": "c", "service": "s"}


# fix round 2

def evidence_stem(command):
    suffix = option(command, "--suffix")
    cleaned = "".join(ch for ch in suffix if ch.isalnum() and ch.isascii() or ch == "-")
    return (command.name, command.argv[command.argv.index("--account") + 1] if "--account" in command.argv else "os",
            cleaned)


@pytest.mark.parametrize("key, names", [
    ("dynamodb_tables", ["orders.v1", "orders_v1"]),
    ("lambda_functions", ["a_b", "ab"]),
    ("lambda_functions", ["a_b", "a.b", "a-b"]),
])
def test_names_that_clean_to_the_same_text_get_distinct_files(config, key, names):
    commands = [c for c in plan({key: names}, config) if c.tool == "collect.py" and c.name not in ("changes", "platform", "alarms")]
    assert len(commands) == len(names)
    assert len({evidence_stem(c) for c in commands}) == len(names)


def test_a_cleaned_name_gets_a_dash_and_six_hex_characters_of_its_hash(config):
    import hashlib
    commands = named(plan({"dynamodb_tables": ["orders.v1", "plain-name"]}, config), "dynamodb")
    digest = hashlib.sha256(b"orders.v1").hexdigest()[:6]
    assert option(commands[0], "--suffix") == f"ordersv1-{digest}"
    assert option(commands[1], "--suffix") == "plain-name"


def test_a_name_with_nothing_left_after_cleaning_still_gets_a_suffix(config):
    command = one(plan({"dynamodb_tables": ["___"]}, config), "dynamodb")
    assert len(option(command, "--suffix").lstrip("-")) >= 6


def test_a_repeated_name_is_planned_once(config):
    assert len(named(plan({"lambda_functions": ["f", "f"]}, config), "lambda")) == 1


def test_a_duplicate_evidence_file_name_is_an_error(config, monkeypatch):
    import triage.collection_plan as module
    monkeypatch.setattr(module, "_suffix_for", lambda *args: "same")
    with pytest.raises(CaseError) as caught:
        plan({"lambda_functions": ["a", "b"]}, config)
    assert "same evidence file" in str(caught.value)


@pytest.mark.parametrize("key", ["-dash", "", "k=x", "1abc", "a b", "a$b", "é"])
def test_a_bad_opensearch_filter_key_is_refused(config, key):
    resources = {"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*", "filter": {key: "v"}}}
    with pytest.raises(CaseError) as caught:
        plan(resources, config)
    assert "filter" in str(caught.value)


@pytest.mark.parametrize("key", ["service", "_x", "@timestamp", "kubernetes.labels.app-name", "a1_b.c@d-e"])
def test_good_opensearch_filter_keys_are_planned(config, key):
    resources = {"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*", "filter": {key: "v"}}}
    assert f"{key}=v" in named(plan(resources, config), "opensearch")[0].argv


def test_every_planned_command_is_accepted_by_the_guard_and_the_parsers(config):
    import collect
    import opensearch_query
    from triage.guard import context_from_config, decide
    from triage.verdict import ALLOW
    resources = {
        **FULL_RESOURCES,
        "lambda_functions": ["a_b", "ab", "-lead", "x.y"],
        "dynamodb_tables": ["orders.v1", "orders_v1", "--help"],
        "opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*",
                       "filter": {"service": "it's $(id)", "n": 5}},
    }
    context = context_from_config(config, SKILL_DIR)
    for command in plan(resources, config):
        if command.tool == "skipped":
            continue
        assert decide(command.shell(), context).kind == ALLOW, command.shell()
        if command.tool == "collect.py":
            collect._build_parser().parse_args(command.argv[2:])
        else:
            opensearch_query._build_parser().parse_args(command.argv[2:])


# fix round 3

def stems(commands):
    return [c.argv[2] + "|" + option(c, "--suffix").lower() for c in commands if c.tool == "collect.py" and "--suffix=" in " ".join(c.argv)]


@pytest.mark.parametrize("names", [["Orders", "orders"], ["orders", "Orders"], ["ORDERS", "Orders", "orders"]])
def test_names_that_differ_only_in_case_get_distinct_files_ignoring_case(config, names):
    import hashlib
    commands = named(plan({"dynamodb_tables": names}, config), "dynamodb")
    assert len(commands) == len(names)
    assert len(set(stems(commands))) == len(names)
    upper = next(c for c, n in zip(commands, names) if n == "Orders")
    assert option(upper, "--suffix") == "Orders-" + hashlib.sha256(b"Orders").hexdigest()[:6]


def test_a_lower_case_name_keeps_its_plain_suffix(config):
    assert option(one(plan({"dynamodb_tables": ["orders"]}, config), "dynamodb"), "--suffix") == "orders"


def test_a_case_insensitive_duplicate_is_an_error(config, monkeypatch):
    import triage.collection_plan as module
    monkeypatch.setattr(module, "_suffix_for", lambda *args: "Same" if args[0] == "a" else "same")
    with pytest.raises(CaseError):
        plan({"lambda_functions": ["a", "b"]}, config)


@pytest.mark.parametrize("length", [190, 200, 254, 300])
def test_a_long_name_is_cut_so_the_evidence_file_name_fits(config, length):
    import hashlib
    name = "a" * (length - 1) + "."
    command = one(plan({"dynamodb_tables": [name]}, config), "dynamodb")
    suffix = option(command, "--suffix")
    stem = "-".join(["dynamodb", "prod-main", "eu-west-1", suffix]) + ".json"
    assert len(stem.encode()) <= 200
    if length > 150:
        assert suffix.endswith("-" + hashlib.sha256(name.encode()).hexdigest()[:6])


def test_two_long_names_with_the_same_start_stay_distinct(config):
    names = ["a" * 300 + "x", "a" * 300 + "y"]
    commands = named(plan({"lambda_functions": names}, config), "lambda")
    assert len({option(c, "--suffix") for c in commands}) == 2


def test_long_names_are_still_accepted_by_the_guard_and_parser(config):
    import collect
    from triage.guard import context_from_config, decide
    from triage.verdict import ALLOW
    context = context_from_config(config, SKILL_DIR)
    for command in named(plan({"dynamodb_tables": ["A" * 400, "b" * 400]}, config), "dynamodb"):
        assert decide(command.shell(), context).kind == ALLOW
        collect._build_parser().parse_args(command.argv[2:])


# follow-up: incident start for every collector that declares it

def test_every_planned_collector_that_declares_incident_start_gets_it(config):
    registry = all_collectors()
    wanting = {name for name, collector in registry.items() if "incident_start" in collector.optional}
    assert {"changes", "rds"} <= wanting
    planned = [c for c in plan(FULL_RESOURCES, config) if c.tool == "collect.py" and c.name in wanting]
    assert {c.name for c in planned} >= {"changes", "rds"}
    for command in planned:
        assert targets_of(command)["incident_start"] == "2026-10-04T10:42:00Z", command.name


def test_collectors_that_do_not_declare_incident_start_do_not_get_it(config):
    registry = all_collectors()
    for command in plan(FULL_RESOURCES, config):
        if command.tool == "collect.py" and "incident_start" not in registry[command.name].optional:
            assert "incident_start" not in targets_of(command), command.name


def test_rds_gets_the_incident_start_next_to_its_db(config):
    command = one(plan({"rds": "db-1"}, config), "rds")
    assert targets_of(command) == {"db": "db-1", "incident_start": "2026-10-04T10:42:00Z"}


# collect: run the plan

import json
import subprocess
import threading
import time

from triage.collection_plan import run_collection


def runnable(commands):
    """The plan without its skipped lines (a plan without mapped alarms always has one)."""
    return [c for c in commands if c.tool != "skipped"]


def test_each_planned_command_names_its_evidence_file_and_suffix(config):
    registry_names = {"ecs": "ecs-prod-main-eu-west-1.json", "rds": "rds-prod-main-eu-west-1.json"}
    commands = plan({"ecs_service": "c/s", "rds": "d", "lambda_functions": ["a_b"],
                     "opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*"}}, config)
    by_name = {c.name: c for c in commands if c.name in registry_names}
    for name, file_name in registry_names.items():
        assert by_name[name].evidence == "evidence/" + file_name
        assert by_name[name].suffix == ""
    lam = one(commands, "lambda")
    assert lam.suffix.startswith("ab-") and lam.evidence == f"evidence/lambda-prod-main-eu-west-1-{lam.suffix}.json"
    searches = named(commands, "opensearch")
    assert [c.suffix for c in searches] == ["histogram", "top-messages", "search"]
    assert searches[0].evidence == "evidence/opensearch-prod-main-logs-prod-histogram.json"
    assert all(c.evidence == "" for c in commands if c.tool == "skipped")


def test_the_evidence_names_match_what_the_evidence_writer_makes(config, tmp_path):
    from triage.evidence import Evidence
    from triage.window import make_window
    window = make_window(START, END, 6)
    for command in plan({"lambda_functions": ["a_b", "Orders", "x.y"], "dynamodb_tables": ["-t"]}, config):
        if command.tool == "collect.py":
            account, region = option(command, "--account"), option(command, "--region")
            suffix = option(command, "--suffix") if "--suffix=" in " ".join(command.argv) else ""
            written = Evidence(command.name, account, region, window).write(tmp_path, suffix)
            assert command.evidence == f"evidence/{written.name}"


def fake_launch(log=None, fail=None):
    def launch(argv, timeout):
        if log is not None:
            log.append((argv, timeout))
        if fail and fail(argv):
            return fail(argv)
        return 0, ""
    return launch


def write_evidence(case_dir, command, facts=2, errors=1):
    path = case_dir / command.evidence
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"facts": [{}] * facts, "errors": ["e"] * errors}))


def test_run_collection_runs_every_command_and_reports_counts(config, tmp_path):
    commands = runnable(plan({"rds": "d", "lambda_functions": ["f"]}, config))
    log = []

    def launch(argv, timeout):
        log.append((argv, timeout))
        command = next(c for c in commands if c.argv == argv)
        write_evidence(tmp_path, command, facts=3, errors=0)
        return 0, ""

    results = run_collection(commands, tmp_path, launch=launch)
    assert [r["name"] for r in results] == [c.name for c in commands]
    assert len(log) == len(commands) and all(timeout == 300 for _, timeout in log)
    rds = next(r for r in results if r["name"] == "rds")
    assert rds == {"name": "rds", "tool": "collect.py", "suffix": "", "status": "collected", "exit_code": 0,
                   "evidence": "evidence/rds-prod-main-eu-west-1.json", "facts": 3, "errors": 0, "stderr": ""}


def test_an_existing_evidence_file_is_not_collected_again(config, tmp_path):
    commands = runnable(plan({"rds": "d"}, config))
    for command in commands:
        write_evidence(tmp_path, command, facts=4, errors=2)
    log = []
    results = run_collection(commands, tmp_path, launch=fake_launch(log))
    assert log == []
    assert {r["status"] for r in results} == {"already collected"}
    assert all(r["facts"] == 4 and r["errors"] == 2 and r["exit_code"] is None for r in results)


def test_a_command_that_fails_is_reported_with_the_last_stderr_line(config, tmp_path):
    commands = runnable(plan({"rds": "d"}, config))
    results = run_collection(commands, tmp_path, launch=fake_launch(fail=lambda argv: (3, "first\n\nSign-in expired\n\n")))
    assert all(r["status"] == "failed" and r["exit_code"] == 3 and r["stderr"] == "Sign-in expired" and r["evidence"] is None
               for r in results)


def test_a_command_that_cannot_start_or_times_out_does_not_stop_the_others(config, tmp_path):
    commands = plan({"rds": "d", "efs": "fs", "ecs_service": "c/s"}, config)

    def launch(argv, timeout):
        if argv[2] == "rds":
            raise FileNotFoundError(2, "No such file or directory")
        if argv[2] == "efs":
            raise subprocess.TimeoutExpired(argv, timeout)
        write_evidence(tmp_path, next(c for c in commands if c.argv == argv))
        return 0, ""

    status = {r["name"]: r["status"] for r in run_collection(commands, tmp_path, launch=launch)}
    assert status["rds"] == "not started" and status["efs"] == "timed out" and status["ecs"] == "collected"
    assert status["changes"] == "collected" and status["platform"] == "collected"


def test_at_most_four_commands_run_at_once(config, tmp_path):
    commands = plan(FULL_RESOURCES, config)
    assert len(commands) >= 8
    lock, state = threading.Lock(), {"now": 0, "peak": 0}

    def launch(argv, timeout):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1
        return 0, ""

    run_collection(commands, tmp_path, launch=launch)
    assert state["peak"] == 4


def test_skipped_commands_are_reported_and_not_run(config, tmp_path):
    commands = plan({"rds": ["bad"]}, config)
    log = []
    results = run_collection(commands, tmp_path, launch=fake_launch(log))
    skipped = next(r for r in results if r["status"] == "skipped")
    assert skipped["tool"] == "skipped" and skipped["stderr"] and skipped["evidence"] is None
    assert all(argv[2] != "rds" for argv, _ in log)


def test_the_default_launch_uses_the_same_interpreter(monkeypatch):
    import sys
    import triage.collection_plan as module
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module._launch(["/skill/.venv/bin/python", "/skill/scripts/collect.py", "rds"], 300)
    assert seen["argv"] == [sys.executable, "/skill/scripts/collect.py", "rds"]
    assert seen["timeout"] == 300 and "env" not in seen


# change lookups for every resource type

def changes_names(commands):
    return targets_of(one(commands, "changes"))["resource_names"].split(",")


def test_an_eks_cluster_is_looked_up_by_name_and_the_namespace_is_not(config):
    resources = {"eks": {"cluster": "platform-prod", "namespace": "payments", "workloads": ["deployment/payments-api"]}}
    names = changes_names(plan(resources, config))
    assert names == ["platform-prod"]


@pytest.mark.parametrize("resources, expected", [
    ({"auto_scaling_group": "asg-1"}, ["asg-1"]),
    ({"ec2_instances": ["i-1", "i-2"]}, ["i-1", "i-2"]),
    ({"api_gateway": "api123"}, ["api123"]),
    ({"cloudfront_distribution": "E1ABC"}, ["E1ABC"]),
    ({"efs": "fs-0123"}, ["fs-0123"]),
    ({"sns_topics": ["t1"]}, ["t1"]),
    ({"sqs_queues": ["q1"]}, ["q1"]),
    ({"lambda_functions": ["f1"]}, ["f1"]),
    ({"dynamodb_tables": ["tbl"]}, ["tbl"]),
    ({"load_balancer": "lb"}, ["lb"]),
    ({"rds": "db"}, ["db"]),
    ({"elasticache": "cache"}, ["cache"]),
    ({"ecs_service": "c/svc"}, ["svc"]),
    ({"log_groups": ["/g"]}, []),
    ({"opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-x-*"}}, []),
])
def test_every_resource_type_contributes_its_name(config, resources, expected):
    commands = plan(resources, config)
    if expected:
        assert changes_names(commands) == expected
    else:
        assert "resource_names" not in targets_of(one(commands, "changes"))


def test_with_every_resource_type_the_names_stay_within_the_cap_and_the_note_lists_what_was_left_out(config):
    commands = plan(FULL_RESOURCES, config)
    changes = one(commands, "changes")
    names = changes_names(commands)
    assert len(names) == 10 and "platform-prod" in names and "s" in names
    left_out = changes.reason.split("left out: ")[1].split(", ")
    assert left_out and not set(left_out) & set(names)
    assert len(names) + len(left_out) == len(set(_all_names(FULL_RESOURCES)))


def _all_names(resources):
    names = [resources["ecs_service"].split("/")[1], resources["eks"]["cluster"], resources["load_balancer"],
             resources["rds"], resources["elasticache"], resources["auto_scaling_group"]]
    for key in ("lambda_functions", "dynamodb_tables", "sqs_queues", "sns_topics", "ec2_instances"):
        names += resources[key]
    names += [resources["api_gateway"], resources["cloudfront_distribution"], resources["efs"]]
    return names


def test_the_note_says_nothing_about_left_out_names_when_all_fit(config):
    assert "left out" not in one(plan({"rds": "db"}, config), "changes").reason


# new resource keys, event sources, alarms, dependencies

def test_alarms_ecr_and_the_opensearch_domain_are_planned_with_their_targets(config):
    resources = {"alarms": ["checkout-5xx", "checkout-cpu"], "ecr_repository": "checkout-api",
                 "opensearch_domain": "logs-domain"}
    commands = plan(resources, config)
    assert targets_of(one(commands, "alarms")) == {"alarm_names": "checkout-5xx,checkout-cpu"}
    assert targets_of(one(commands, "ecr")) == {"repository": "checkout-api"}
    assert targets_of(one(commands, "opensearch_domain")) == {"domain": "logs-domain"}
    assert one(commands, "alarms").domain == "logs"
    assert one(commands, "ecr").domain == "compute" and one(commands, "opensearch_domain").domain == "data"


def test_the_new_keys_are_known_to_the_service_map():
    from triage.service_map import RESOURCE_KEYS
    assert {"alarms", "ecr_repository", "opensearch_domain"} <= RESOURCE_KEYS


def test_alarm_names_are_capped_at_the_collectors_limit(config):
    command = one(plan({"alarms": [f"a{n}" for n in range(80)]}, config), "alarms")
    assert len(targets_of(command)["alarm_names"].split(",")) == 50


def test_without_mapped_alarms_the_alarms_in_alarm_now_are_planned(config):
    for resources in ({"rds": "db"}, {"alarms": []}):
        alarms = one(plan(resources, config), "alarms")
        assert alarms.tool == "collect.py" and alarms.domain == "logs"
        assert targets_of(alarms) == {"in_alarm": "true"}
        assert alarms.reason == "alarms in ALARM now; alarms that fired and cleared need names in the service map"
        assert alarms.evidence == "evidence/alarms-prod-main-eu-west-1.json"


def test_mapped_alarms_are_not_replaced_by_the_in_alarm_listing(config):
    commands = named(plan({"alarms": ["a1"]}, config), "alarms")
    assert [targets_of(c) for c in commands] == [{"alarm_names": "a1"}]


def test_a_dependency_without_mapped_alarms_gets_no_in_alarm_run(config):
    dependency = {**PAYMENTS, "resources": {"rds": "payments-db"}}
    commands = plan_collection(with_dependencies({"rds": "db"}, [dependency]), config, SKILL_DIR)
    assert len(named(commands, "alarms")) == 1


@pytest.mark.parametrize("resources", [{"alarms": "one"}, {"ecr_repository": ["x"]}, {"opensearch_domain": 5}])
def test_a_malformed_new_key_is_skipped_with_a_reason(config, resources):
    commands = plan(resources, config)
    key = next(iter(resources))
    assert any(c.tool == "skipped" and c.reason.startswith(key) for c in commands)


EVENT_SOURCES = {
    "ecs_service": ("c/s", ["ecs.amazonaws.com", "application-autoscaling.amazonaws.com"]),
    "load_balancer": ("lb", ["elasticloadbalancing.amazonaws.com"]),
    "rds": ("d", ["rds.amazonaws.com"]),
    "elasticache": ("e", ["elasticache.amazonaws.com"]),
    "lambda_functions": (["f"], ["lambda.amazonaws.com"]),
    "eks": ({"cluster": "platform-prod", "namespace": "n"}, ["eks.amazonaws.com"]),
    "auto_scaling_group": ("g", ["autoscaling.amazonaws.com"]),
    "ec2_instances": (["i-1"], ["ec2.amazonaws.com"]),
    "dynamodb_tables": (["t"], ["dynamodb.amazonaws.com"]),
    "sqs_queues": (["q"], ["sqs.amazonaws.com"]),
    "sns_topics": (["n"], ["sns.amazonaws.com"]),
    "api_gateway": ("a", ["apigateway.amazonaws.com"]),
    "cloudfront_distribution": ("E1", ["cloudfront.amazonaws.com"]),
    "efs": ("fs", ["elasticfilesystem.amazonaws.com"]),
}


@pytest.mark.parametrize("key", sorted(EVENT_SOURCES))
def test_changes_gets_the_event_sources_of_each_mapped_resource_kind(config, key):
    value, sources = EVENT_SOURCES[key]
    targets = targets_of(one(plan({key: value}, config), "changes"))
    assert targets["event_sources"].split(",") == sources


def test_event_sources_are_listed_once_in_a_fixed_order(config):
    targets = targets_of(one(plan({"rds": "d", "ecs_service": "c/s", "lambda_functions": ["a", "b"]}, config), "changes"))
    assert targets["event_sources"].split(",") == [
        "ecs.amazonaws.com", "application-autoscaling.amazonaws.com", "rds.amazonaws.com", "lambda.amazonaws.com"]
    assert list(targets) == ["resource_names", "event_sources", "incident_start"]


def test_no_event_sources_without_resource_names(config):
    assert "event_sources" not in targets_of(one(plan({"log_groups": ["/g"]}, config), "changes"))


def with_dependencies(resources, dependencies):
    case = make_case(resources)
    case["target"]["depends_on"] = [d["service"] for d in dependencies]
    case["target"]["dependencies"] = dependencies
    return case


PAYMENTS = {"service": "payments-api", "environment": "prod", "account": "staging", "region": "eu-west-1",
            "resources": {"rds": "payments-db", "alarms": ["payments-5xx"], "ecs_service": "pay/payments-api"}}


def test_a_dependency_gets_a_changes_run_and_an_alarms_run_with_its_own_stems(config):
    commands = plan_collection(with_dependencies({"rds": "db"}, [PAYMENTS]), config, SKILL_DIR)
    changes = [c for c in named(commands, "changes") if "payments-api" in c.evidence]
    alarms = [c for c in named(commands, "alarms") if c.tool != "skipped" and "payments-api" in c.evidence]
    assert len(changes) == 1 and len(alarms) == 1
    assert option(changes[0], "--account") == "staging" and option(changes[0], "--region") == "eu-west-1"
    assert targets_of(changes[0]) == {"resource_names": "payments-api,payments-db",
                                      "event_sources": "ecs.amazonaws.com,application-autoscaling.amazonaws.com,rds.amazonaws.com",
                                      "incident_start": "2026-10-04T10:42:00Z"}
    assert targets_of(alarms[0]) == {"alarm_names": "payments-5xx"}
    assert changes[0].suffix == "dep-payments-api" and changes[0].evidence.endswith("-dep-payments-api.json")
    assert "dependency payments-api" in changes[0].reason
    assert len(named(commands, "changes")) == 2  # the target's own and the dependency's


def test_a_dependency_without_alarms_gets_only_changes(config):
    dependency = {**PAYMENTS, "resources": {"rds": "payments-db"}}
    commands = plan_collection(with_dependencies({"rds": "db"}, [dependency]), config, SKILL_DIR)
    assert not [c for c in named(commands, "alarms") if c.tool != "skipped" and "payments-api" in c.evidence]


def test_a_dependency_is_followed_one_level_only(config):
    inner = {**PAYMENTS, "service": "ledger", "resources": {"rds": "ledger-db"}}
    outer = {**PAYMENTS, "depends_on": ["ledger"], "dependencies": [inner]}
    commands = plan_collection(with_dependencies({"rds": "db"}, [outer]), config, SKILL_DIR)
    assert not [c for c in commands if "ledger" in c.evidence]


def test_a_dependency_with_no_environment_or_no_resources_is_a_skipped_line(config):
    missing = {"service": "gone", "environment": None, "account": None, "region": None, "resources": {}}
    empty = {**PAYMENTS, "service": "empty", "resources": {"log_groups": ["/g"]}}
    commands = plan_collection(with_dependencies({"rds": "db"}, [missing, empty]), config, SKILL_DIR)
    skipped = [c.reason for c in commands if c.tool == "skipped"]
    assert any("dependency gone" in r for r in skipped) and any("dependency empty" in r for r in skipped)


def test_dependency_commands_pass_the_guard_and_the_parser(config):
    import collect
    from triage.guard import context_from_config, decide
    from triage.verdict import ALLOW
    context = context_from_config(config, SKILL_DIR)
    for command in plan_collection(with_dependencies(FULL_RESOURCES, [PAYMENTS]), config, SKILL_DIR):
        if command.tool == "collect.py":
            assert decide(command.shell(), context).kind == ALLOW
            collect._build_parser().parse_args(command.argv[2:])
