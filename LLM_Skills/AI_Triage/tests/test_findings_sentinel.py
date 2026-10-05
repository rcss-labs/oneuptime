"""End to end: what an agent typed into a tool can never become an accepted finding's quote.

Each case runs the real OpenSearch tool or the real collect command with fakes, puts a sentinel built at
runtime into every free-text input and target, answers without the sentinel, writes the evidence file the
real way, and then runs the real findings check against every fact of that file.
"""
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pytest
import yaml

import collect
import opensearch_query
from fakes import FakeAws
from helpers import WINDOW_END, WINDOW_START, FakeKubectl
from triage.findings import check_findings, load_facts

SENTINEL = "zz" + "sentinel" + "qq"
REPEATS = "only repeats what was asked"
OS_START = "2026-10-04T10:00:00Z"
OS_END = "2026-10-04T11:00:00Z"


@pytest.fixture
def skill_dir(tmp_path, config_data):
    directory = tmp_path / "skill"
    (directory / "config").mkdir(parents=True)
    (directory / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return directory


@pytest.fixture
def case_dir(tmp_path):
    directory = tmp_path / "case"
    directory.mkdir()
    return directory


def write_probe(case_dir, findings):
    directory = case_dir / "findings"
    directory.mkdir(exist_ok=True)
    (directory / "probe.json").write_text(json.dumps({"analyst": "probe", "findings": findings}))
    return check_findings(case_dir)


def probe(number, fact_id, excerpt):
    return {"id": f"probe-{number}", "claim": "probe", "fact_ids": [fact_id], "excerpt": excerpt,
            "provenance": "inferred", "confidence": "low"}


def assert_refused_for_every_fact(case_dir, quotes):
    facts = load_facts(case_dir)
    assert facts, "the run wrote no facts"
    findings = [probe(n, fact_id, quote) for n, (fact_id, quote) in enumerate(
        ((fact_id, quote) for fact_id in facts for quote in quotes), start=1)]
    result = write_probe(case_dir, findings)
    assert result["valid"] == [], [item["excerpt"] for item in result["valid"]]
    assert len(result["rejected"]) == len(findings)
    return result


def fact_holding(case_dir, text):
    for fact_id, fact in load_facts(case_dir).items():
        if text in json.dumps([fact.get("summary"), fact.get("excerpt"), fact.get("data")]):
            return fact_id
    raise AssertionError(f"no fact holds {text!r}")


def assert_found_text_accepted(case_dir, found):
    result = write_probe(case_dir, [probe(1, fact_holding(case_dir, found), found)])
    assert result["rejected"] == [], result["rejected"]
    assert len(result["valid"]) == 1


def reasons_for(case_dir, fact_id, excerpt):
    result = write_probe(case_dir, [probe(1, fact_id, excerpt)])
    assert result["valid"] == []
    return result["rejected"][0]["reasons"]


# OpenSearch tool

def _epoch_ms(text):
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp() * 1000)


class PathTransport:
    def __init__(self, answers):
        self.answers = answers

    def __call__(self, method, url, body, timeout_seconds, verify_tls, ca_bundle):
        answer = self.answers[urlsplit(url).path.strip("/")]
        status, payload = answer if isinstance(answer, tuple) else (200, answer)
        return status, json.dumps(payload)


def opensearch_answers(index, count=3):
    search = {
        "hits": {"total": {"value": 1}, "hits": [{"_index": "app-logs-1", "_source": {
            "@timestamp": "2026-10-04T10:12:00Z", "message": "java heap space exhausted in worker", "level": "ERROR"}}]},
        "aggregations": {
            "by_time": {"buckets": [{"key": _epoch_ms("2026-10-04T10:05:00Z"), "doc_count": 4}]},
            "top_messages": {"buckets": [{"key": "connection reset by peer upstream", "doc_count": 4}]},
        },
    }
    return {
        "_cluster/health": {"status": "yellow", "number_of_nodes": 3, "active_shards": 9, "unassigned_shards": 1,
                            "number_of_pending_tasks": 0},
        "_nodes/stats/jvm,fs,os,thread_pool": {"nodes": {"n1": {"name": "data-1", "jvm": {"mem": {"heap_used_percent": 71}}}}},
        f"_cat/indices/{index}": [{"health": "yellow", "index": "app-logs-1", "status": "open", "pri": "1", "rep": "1",
                                   "docs.count": "42"}],
        "_cat/shards": [{"index": "app-logs-1", "shard": "0", "prirep": "p", "state": "UNASSIGNED",
                         "unassigned.reason": "NODE_LEFT"}],
        "_cluster/allocation/explain": {"index": "app-logs-1", "shard": 0, "primary": True, "current_state": "unassigned",
                                        "allocate_explanation": "cannot allocate because all found copies are stale"},
        f"{index}/_mapping": {"app-logs-1": {"mappings": {"properties": {"message": {"type": "text"},
                                                                          "level": {"type": "keyword"}}}}},
        f"{index}/_count": {"count": count},
        f"{index}/_search": search,
    }


SENTINEL_INDEX = f"app-logs-{SENTINEL}"
SENTINEL_QUERY = f"message:{SENTINEL} AND OutOfMemoryError"
SENTINEL_FILTER = (f"field_{SENTINEL}", f"value {SENTINEL} checkout")
WINDOWED = ["--index", SENTINEL_INDEX, "--start", OS_START, "--end", OS_END, "--query", SENTINEL_QUERY,
            "--filter", "=".join(SENTINEL_FILTER)]

OPENSEARCH_CASES = {
    "health": ([], "3 nodes, 9 active shards"),
    "nodes": ([], "Node data-1: heap 71% used"),
    "indices": (["--index", SENTINEL_INDEX], "Index app-logs-1 is yellow"),
    "shards": ([], "of app-logs-1 is UNASSIGNED"),
    "allocation-explain": ([], "cannot allocate because all found copies are stale"),
    "mapping": (["--index", SENTINEL_INDEX], "message:text, level:keyword"),
    "count": (WINDOWED, "3 documents matched in the window"),
    "histogram": ([*WINDOWED, "--interval", "15m"], "4 documents in the 15m bucket"),
    "top-messages": ([*WINDOWED, "--field", f"field_{SENTINEL}"], "connection reset by peer upstream"),
    "search": ([*WINDOWED, "--size", "5", "--order", "desc"], "java heap space exhausted in worker"),
}


def run_opensearch(skill_dir, case_dir, subcommand, extra, answers):
    argv = [subcommand, "--cluster", "logs-prod", *extra, "--case-dir", str(case_dir), "--skill-dir", str(skill_dir)]
    assert opensearch_query.main(argv, transport=PathTransport(answers)) == 0


@pytest.mark.parametrize("subcommand", sorted(OPENSEARCH_CASES))
def test_opensearch_sentinel_is_refused_for_every_fact_and_found_text_accepted(skill_dir, case_dir, subcommand):
    extra, found = OPENSEARCH_CASES[subcommand]
    answers = opensearch_answers(SENTINEL_INDEX)
    assert SENTINEL not in json.dumps(list(answers.values()))
    run_opensearch(skill_dir, case_dir, subcommand, extra, answers)
    assert_refused_for_every_fact(case_dir, [SENTINEL, SENTINEL_INDEX, SENTINEL_QUERY, *SENTINEL_FILTER])
    assert_found_text_accepted(case_dir, found)


@pytest.mark.parametrize("subcommand", ["histogram", "search", "top-messages"])
def test_opensearch_empty_answer_sentinel_is_refused(skill_dir, case_dir, subcommand):
    answers = opensearch_answers(SENTINEL_INDEX)
    answers[f"{SENTINEL_INDEX}/_search"] = {"hits": {"total": {"value": 0}, "hits": []},
                                            "aggregations": {"by_time": {"buckets": []}, "top_messages": {"buckets": []}}}
    run_opensearch(skill_dir, case_dir, subcommand, WINDOWED, answers)
    assert_refused_for_every_fact(case_dir, [SENTINEL, SENTINEL_INDEX, SENTINEL_QUERY, *SENTINEL_FILTER])


def test_reproduction_count_summary_cannot_carry_the_query(skill_dir, case_dir):
    answers = opensearch_answers("app-logs-*", count=0)
    extra = ["--index", "app-logs-*", "--start", OS_START, "--end", OS_END,
             "--query", "OutOfMemoryError checkout", "--filter", "service=checkout"]
    run_opensearch(skill_dir, case_dir, "count", extra, answers)
    (fact_id,) = load_facts(case_dir)
    for excerpt in ("OutOfMemoryError checkout", "matching OutOfMemoryError", "with service=checkout"):
        assert reasons_for(case_dir, fact_id, excerpt), excerpt


# Collectors, through the real collect command

def run_collector(skill_dir, case_dir, name, targets, runner):
    argv = [name, "--account", "prod-main", "--start", WINDOW_START, "--end", WINDOW_END,
            "--case-dir", str(case_dir), "--skill-dir", str(skill_dir)]
    for key, value in targets.items():
        argv += ["--target", f"{key}={value}"]
    assert collect.main(argv, runner=runner, kube_runner=FakeKubectl({})) == 0
    (path,) = (case_dir / "evidence").glob("*.json")
    document = json.loads(path.read_text())
    assert "asked" in document, "collect.py no longer records what was asked"
    return document


def row(**fields):
    return [{"field": name, "value": value} for name, value in fields.items()]


LOG_ROW = row(**{"bin(5m)": "2026-10-04 10:40:00.000", "matches": "40", "@pattern": "connection to <*> refused",
                 "@sampleCount": "37", "@timestamp": "2026-10-04 10:41:02.500", "@logStream": "app/1",
                 "@message": "ERROR connection refused by upstream"})
LOG_GROUPS = [f"/aws/{SENTINEL}/group-{n}" for n in range(6)]
LOG_PATTERN = f"{SENTINEL} OutOfMemoryError"

LOGS_CASES = {
    "standard": ({"log_groups": ",".join(LOG_GROUPS), "pattern": LOG_PATTERN}, [LOG_ROW], "ERROR connection refused by upstream"),
    "no_match": ({"log_groups": ",".join(LOG_GROUPS), "pattern": LOG_PATTERN}, [], None),
    "bad_pattern": ({"log_groups": ",".join(LOG_GROUPS), "pattern": LOG_PATTERN + "\\"}, [LOG_ROW], None),
}


def logs_runner(rows):
    return FakeAws({"logs start-query": {"queryId": "q1"},
                    "logs get-query-results": {"status": "Complete", "results": rows}})


@pytest.mark.parametrize("variant", sorted(LOGS_CASES))
def test_logs_sentinel_is_refused_for_every_fact(skill_dir, case_dir, variant):
    targets, rows, found = LOGS_CASES[variant]
    run_collector(skill_dir, case_dir, "logs", targets, logs_runner(rows))
    assert_refused_for_every_fact(case_dir, [SENTINEL, LOG_PATTERN, *LOG_GROUPS])
    if found:
        assert_found_text_accepted(case_dir, found)


def test_reproduction_logs_skipped_group_cannot_be_quoted(skill_dir, case_dir):
    groups = [f"/aws/ecs/group-{n}" for n in range(5)] + ["/aws/checkout/OutOfMemoryError-killed"]
    run_collector(skill_dir, case_dir, "logs", {"log_groups": ",".join(groups)}, logs_runner([LOG_ROW]))
    fact_id = fact_holding(case_dir, "skipped:")
    assert any(REPEATS in reason for reason in reasons_for(case_dir, fact_id, "OutOfMemoryError"))
    excerpt = "skipped: /aws/checkout/OutOfMemoryError-killed"
    assert any(REPEATS in reason for reason in reasons_for(case_dir, fact_id, excerpt))


CHANGE_TARGETS = {
    "resource_names": f"{SENTINEL}-api,OutOfMemoryError {SENTINEL}",
    "stack": f"stack-{SENTINEL}",
    "pipeline": f"pipe-{SENTINEL}",
    "config_resource": f"AWS::ECS::Service/{SENTINEL}",
    "incident_start": "2026-10-04T10:50:00Z",
}
WRITE_EVENT = {"EventId": "e1", "EventName": "UpdateService", "ReadOnly": "false", "EventTime": "2026-10-04T10:46:00+00:00",
               "EventSource": "ecs.amazonaws.com", "Username": "deploy-bot",
               "Resources": [{"ResourceType": "AWS::ECS::Service", "ResourceName": "checkout-api"}]}
STACK_ANSWER = {"StackEvents": [{"Timestamp": "2026-10-04T10:44:00+00:00", "LogicalResourceId": "Service",
                                 "ResourceType": "AWS::ECS::Service", "ResourceStatus": "UPDATE_FAILED",
                                 "ResourceStatusReason": "Resource handler returned message: service unstable"}]}
PIPELINE_ANSWERS = {
    "codepipeline list-pipeline-executions": {"pipelineExecutionSummaries": [
        {"pipelineExecutionId": "exec-1", "status": "Failed", "startTime": "2026-10-04T10:30:00+00:00",
         "trigger": {"triggerType": "Webhook", "triggerDetail": "push"}}]},
    "codepipeline get-pipeline-state": {"stageStates": [{"stageName": "Deploy", "latestExecution": {"status": "Failed"}}]},
}
CONFIG_ANSWER = {"configurationItems": [{"configurationItemCaptureTime": "2026-10-04T10:45:00+00:00",
                                         "configurationItemStatus": "OK", "relatedEvents": ["evt-1"]}]}
NOT_DISCOVERED = (254, "An error occurred (ResourceNotDiscoveredException) when calling the "
                       "GetResourceConfigHistory operation: not discovered")

CHANGES_CASES = {
    "events": ({"cloudtrail lookup-events": {"Events": [WRITE_EVENT]}, "configservice get-resource-config-history": CONFIG_ANSWER},
               "UpdateService (ecs.amazonaws.com)"),
    "no_events": ({"cloudtrail lookup-events": {"Events": []}, "configservice get-resource-config-history": NOT_DISCOVERED},
                  "Resource handler returned message: service unstable"),
    "more_events": ({"cloudtrail lookup-events": {"Events": [], "NextToken": "t"},
                     "configservice get-resource-config-history": CONFIG_ANSWER}, "related CloudTrail events: evt-1"),
}


@pytest.mark.parametrize("variant", sorted(CHANGES_CASES))
def test_changes_sentinel_is_refused_for_every_fact(skill_dir, case_dir, variant):
    answers, found = CHANGES_CASES[variant]
    runner = FakeAws({**answers, "cloudformation describe-stack-events": STACK_ANSWER, **PIPELINE_ANSWERS})
    run_collector(skill_dir, case_dir, "changes", CHANGE_TARGETS, runner)
    quotes = [SENTINEL, *CHANGE_TARGETS["resource_names"].split(","), CHANGE_TARGETS["stack"],
              CHANGE_TARGETS["pipeline"], CHANGE_TARGETS["config_resource"]]
    assert_refused_for_every_fact(case_dir, quotes)
    assert_found_text_accepted(case_dir, found)


def test_reproduction_changes_resource_name_cannot_be_quoted(skill_dir, case_dir):
    run_collector(skill_dir, case_dir, "changes", {"resource_names": "OutOfMemoryError in checkout"},
                  FakeAws({"cloudtrail lookup-events": {"Events": []}}))
    fact_id = fact_holding(case_dir, "No change was recorded for OutOfMemoryError in checkout")
    assert any(REPEATS in reason for reason in reasons_for(case_dir, fact_id, "OutOfMemoryError in checkout"))


def alarm(name):
    return {"AlarmName": name, "StateValue": "ALARM", "StateReason": "Threshold Crossed: 3 datapoints were greater than 80",
            "MetricName": "CPUUtilization", "Threshold": 80.0, "ComparisonOperator": "GreaterThanThreshold"}


ALARM_HISTORY = {"AlarmHistoryItems": [{"Timestamp": "2026-10-04T10:42:10+00:00", "HistorySummary": "Alarm updated from OK to ALARM",
                                        "HistoryData": json.dumps({"oldState": {"stateValue": "OK"},
                                                                   "newState": {"stateValue": "ALARM"}})}]}
ALARM_TARGETS = {"alarm_names": f"{SENTINEL}-cpu,{SENTINEL}-mem", "name_prefix": f"{SENTINEL}-"}
ALARMS_CASES = {
    "found": ({"cloudwatch describe-alarms": {"MetricAlarms": [alarm("cpu-high")]},
               "cloudwatch describe-alarm-history": ALARM_HISTORY}, "Threshold Crossed: 3 datapoints"),
    "none_found": ({"cloudwatch describe-alarms": {}}, None),
}


@pytest.mark.parametrize("variant", sorted(ALARMS_CASES))
def test_alarms_sentinel_is_refused_for_every_fact(skill_dir, case_dir, variant):
    answers, found = ALARMS_CASES[variant]
    run_collector(skill_dir, case_dir, "alarms", ALARM_TARGETS, FakeAws(answers))
    assert_refused_for_every_fact(case_dir, [SENTINEL, *ALARM_TARGETS["alarm_names"].split(","), ALARM_TARGETS["name_prefix"]])
    if found:
        assert_found_text_accepted(case_dir, found)


# Every registered collector: a sentinel in every declared target, fake answers that are empty or errors

from fakes import access_denied  # noqa: E402
from triage.collectors import all_collectors  # noqa: E402

# Collectors whose own target checks refuse a sentinel value, with the reason. Listed, never skipped silently.
CANNOT_RUN_WITH_SENTINEL: dict[str, str] = {}
EXTRA_QUOTE = 11


def sentinel_value(key):
    """A sentinel value in the form the target takes: list targets (plural names) get a comma list."""
    if key.endswith("s"):
        return f"{SENTINEL}-{key}-a,{SENTINEL}-{key}-b"
    return f"{SENTINEL}-{key}"


def sentinel_quotes(summary):
    """The sentinel alone, and the sentinel with up to 11 other characters of the summary on either side."""
    quotes = [SENTINEL]
    position = summary.find(SENTINEL)
    if position < 0:
        return quotes + [SENTINEL + summary[:EXTRA_QUOTE]]
    end = position + len(SENTINEL)
    quotes.append(summary[position:end + EXTRA_QUOTE])
    quotes.append(summary[max(position - EXTRA_QUOTE, 0):end])
    return quotes


def test_every_collector_is_in_the_sweep_or_listed_with_a_reason():
    assert set(CANNOT_RUN_WITH_SENTINEL) <= set(all_collectors())


@pytest.mark.parametrize("answers", ["empty", "errors"])
@pytest.mark.parametrize("name", sorted(all_collectors()))
def test_registry_sentinel_is_refused_for_every_fact(skill_dir, case_dir, name, answers):
    if name in CANNOT_RUN_WITH_SENTINEL:
        pytest.skip(CANNOT_RUN_WITH_SENTINEL[name])
    collector = all_collectors()[name]
    targets = {key: sentinel_value(key) for key in (*collector.required, *collector.optional)}
    assert_sentinel_refused(skill_dir, case_dir, name, targets, answers)


def assert_sentinel_refused(skill_dir, case_dir, name, targets, answers):
    runner = FakeAws({}) if answers == "empty" else FakeAws({}, default=access_denied("Describe"))
    run_collector(skill_dir, case_dir, name, targets, runner)
    facts = load_facts(case_dir)
    findings = [probe(n, fact_id, quote) for n, (fact_id, quote) in enumerate(
        ((fact_id, quote) for fact_id, fact in facts.items() for quote in sentinel_quotes(fact.get("summary") or "")),
        start=1)]
    if not findings:
        return
    result = write_probe(case_dir, findings)
    assert result["valid"] == [], [(item["fact_ids"], item["excerpt"]) for item in result["valid"]]
