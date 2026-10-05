import json

import pytest

from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, Evidence
from triage.findings import check_findings, load_facts, valid_findings
from triage.redact import Redactor
from triage.window import make_window

WINDOW = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", 24)


def add_evidence(case_dir, collector="ecs", region="eu-west-1", facts=(), suffix=""):
    evidence = Evidence(collector, "prod-main", region, WINDOW)
    for kind, summary, excerpt in facts:
        evidence.add(kind=kind, resource="svc", summary=summary, time="2026-10-04T10:41:00Z", excerpt=excerpt)
    return evidence.write(case_dir, suffix)


def write_findings(case_dir, analyst, findings, **extra):
    directory = case_dir / "findings"
    directory.mkdir(exist_ok=True)
    (directory / f"{analyst}.json").write_text(json.dumps({"analyst": analyst, "findings": findings, **extra}))


def finding(**overrides):
    base = {
        "id": "compute-1",
        "claim": "Deployment failed",
        "fact_ids": ["ecs-0001"],
        "excerpt": "container exited with code 137",
        "provenance": "incident_time",
        "confidence": "high",
    }
    base.update(overrides)
    return base


@pytest.fixture
def case_dir(tmp_path):
    add_evidence(tmp_path, facts=[
        (INCIDENT_TIME, "Essential container exited with code 137", ""),
        (CURRENT, "Service has 0 running tasks", "desired 2,\n  running 0"),
        (DERIVED, "Derived note", ""),
    ])
    return tmp_path


def check(case_dir, findings, analyst="compute", **extra):
    write_findings(case_dir, analyst, findings, **extra)
    return check_findings(case_dir)


def reasons_of(result):
    assert len(result["rejected"]) == 1, result
    return result["rejected"][0]["reasons"]


def test_load_facts_keys_every_fact_by_file_stem_and_id(case_dir):
    add_evidence(case_dir, collector="rds", facts=[(CURRENT, "db up", "")])
    facts = load_facts(case_dir)
    assert set(facts) == {"ecs-prod-main-eu-west-1:ecs-0001", "ecs-prod-main-eu-west-1:ecs-0002", "ecs-prod-main-eu-west-1:ecs-0003", "rds-prod-main-eu-west-1:rds-0001"}
    assert facts["rds-prod-main-eu-west-1:rds-0001"]["file"] == "rds-prod-main-eu-west-1.json"
    assert facts["rds-prod-main-eu-west-1:rds-0001"]["id"] == "rds-0001"


def test_load_facts_keeps_same_id_from_two_files_apart(case_dir):
    add_evidence(case_dir, region="eu-central-1", facts=[(CURRENT, "second region", "")])
    facts = load_facts(case_dir)
    assert facts["ecs-prod-main-eu-west-1:ecs-0001"]["summary"].startswith("Essential")
    assert facts["ecs-prod-main-eu-central-1:ecs-0001"]["summary"] == "second region"


def test_load_facts_skips_a_fact_whose_id_is_not_text_and_warns(case_dir):
    path = case_dir / "evidence" / "ecs-prod-main-eu-west-1.json"
    document = json.loads(path.read_text())
    document["facts"].append({"id": 7, "kind": "current", "summary": "odd"})
    path.write_text(json.dumps(document))
    warnings = []
    assert len(load_facts(case_dir, warnings)) == 3
    assert len(warnings) == 1


def test_bare_id_in_two_files_is_ambiguous_and_rejected(tmp_path):
    add_evidence(tmp_path, collector="dynamodb", suffix="orders", facts=[(INCIDENT_TIME, "No throttling was recorded for any operation", "")])
    add_evidence(tmp_path, collector="dynamodb", suffix="payments", facts=[(INCIDENT_TIME, "ReadThrottleEvents peaked at 500 for GetItem", "")])
    result = check(tmp_path, [finding(fact_ids=["dynamodb-0001"], excerpt="throttling was recorded")])
    reasons = reasons_of(result)
    assert any("exists in more than one evidence file" in r and "dynamodb-prod-main-eu-west-1-orders:dynamodb-0001" in r
               and "dynamodb-prod-main-eu-west-1-payments:dynamodb-0001" in r for r in reasons)


def test_qualified_id_picks_the_right_file_and_is_stored_qualified(tmp_path):
    add_evidence(tmp_path, collector="dynamodb", suffix="orders", facts=[(INCIDENT_TIME, "No throttling was recorded for any operation", "")])
    add_evidence(tmp_path, collector="dynamodb", suffix="payments", facts=[(INCIDENT_TIME, "ReadThrottleEvents peaked at 500 for GetItem", "")])
    qualified = "dynamodb-prod-main-eu-west-1-payments:dynamodb-0001"
    result = check(tmp_path, [finding(fact_ids=[qualified], excerpt="ReadThrottleEvents peaked at 500")])
    assert result["rejected"] == []
    assert result["valid"][0]["fact_ids"] == [qualified]
    assert result["valid"][0]["fact_summaries"] == {qualified: "ReadThrottleEvents peaked at 500 for GetItem"}


def test_bare_id_unique_to_one_file_is_stored_qualified(case_dir):
    result = check(case_dir, [finding()])
    assert result["valid"][0]["fact_ids"] == ["ecs-prod-main-eu-west-1:ecs-0001"]


def test_same_fact_cited_twice_is_stored_once(case_dir):
    result = check(case_dir, [finding(fact_ids=["ecs-0001", "ecs-prod-main-eu-west-1:ecs-0001"])])
    assert result["valid"][0]["fact_ids"] == ["ecs-prod-main-eu-west-1:ecs-0001"]


def test_load_facts_without_evidence_is_empty(tmp_path):
    assert load_facts(tmp_path) == {}


def test_valid_finding_is_kept_with_summaries_and_written(case_dir):
    result = check(case_dir, [finding()], checked=["ECS events"])
    assert result["rejected"] == []
    assert result["valid"][0]["id"] == "compute-1"
    assert result["valid"][0]["analyst"] == "compute"
    assert result["valid"][0]["fact_summaries"] == {"ecs-prod-main-eu-west-1:ecs-0001": "Essential container exited with code 137"}
    assert result["checked"] == {"compute": ["ECS events"]}
    assert json.loads((case_dir / "findings" / "checked.json").read_text()) == result
    assert valid_findings(case_dir)["compute-1"]["claim"] == "Deployment failed"


def test_valid_findings_without_checked_file_is_empty(tmp_path):
    assert valid_findings(tmp_path) == {}


def test_excerpt_matching_ignores_whitespace_runs(case_dir):
    result = check(case_dir, [finding(excerpt="desired   2, running\t0", fact_ids=["ecs-0002"], provenance="current")])
    assert result["rejected"] == []


def test_excerpt_may_match_only_the_fact_excerpt_field(case_dir):
    result = check(case_dir, [finding(excerpt="desired 2, running 0", fact_ids=["ecs-0002"], provenance="current")])
    assert [item["id"] for item in result["valid"]] == ["compute-1"]


def test_excerpt_found_in_any_cited_fact(case_dir):
    result = check(case_dir, [finding(fact_ids=["ecs-0002", "ecs-0001"])])
    assert result["rejected"] == []


def test_excerpt_not_in_cited_facts_is_rejected(case_dir):
    reasons = reasons_of(check(case_dir, [finding(excerpt="out of memory")]))
    assert any("excerpt" in reason and "not found" in reason for reason in reasons)


def test_empty_excerpt_is_rejected(case_dir):
    assert any("excerpt" in reason for reason in reasons_of(check(case_dir, [finding(excerpt="  ")])))


def test_unknown_fact_id_is_rejected(case_dir):
    assert "fact id ecs-0099 does not exist" in reasons_of(check(case_dir, [finding(fact_ids=["ecs-0099", "ecs-0001"])]))


def test_empty_fact_ids_is_rejected(case_dir):
    assert any("fact_ids" in reason for reason in reasons_of(check(case_dir, [finding(fact_ids=[])])))


@pytest.mark.parametrize("field", ["id", "claim", "fact_ids", "excerpt", "provenance", "confidence"])
def test_missing_field_is_rejected(case_dir, field):
    item = finding()
    del item[field]
    assert any(field in reason for reason in reasons_of(check(case_dir, [item])))


@pytest.mark.parametrize("field,value", [("claim", 5), ("fact_ids", "ecs-0001"), ("fact_ids", [1]), ("excerpt", None), ("id", 3)])
def test_wrong_type_is_rejected(case_dir, field, value):
    assert any(field in reason for reason in reasons_of(check(case_dir, [finding(**{field: value})])))


def test_bad_provenance_and_confidence_values_are_rejected(case_dir):
    reasons = reasons_of(check(case_dir, [finding(provenance="guess", confidence="certain")]))
    assert any("provenance" in reason for reason in reasons)
    assert any("confidence" in reason for reason in reasons)


def test_incident_time_provenance_needs_an_incident_time_fact(case_dir):
    reasons = reasons_of(check(case_dir, [finding(fact_ids=["ecs-0002"], excerpt="desired 2, running 0")]))
    assert any("incident_time" in reason for reason in reasons)


def test_current_provenance_needs_a_current_fact(case_dir):
    reasons = reasons_of(check(case_dir, [finding(provenance="current")]))
    assert any("current" in reason for reason in reasons)


def test_inferred_provenance_needs_no_particular_kind(case_dir):
    assert check(case_dir, [finding(provenance="inferred", fact_ids=["ecs-0003"], excerpt="Derived note")])["rejected"] == []


def test_bad_time_is_rejected_and_null_time_allowed(case_dir):
    assert any("time" in reason for reason in reasons_of(check(case_dir, [finding(time="yesterday")])))
    assert check(case_dir, [finding(time=None)])["rejected"] == []
    assert check(case_dir, [finding(time="2026-10-04T10:41:10Z")])["rejected"] == []


def test_id_must_start_with_analyst_name(case_dir):
    assert any("start with" in reason for reason in reasons_of(check(case_dir, [finding(id="network-1")])))


def test_duplicate_id_across_analysts_is_rejected(case_dir):
    # "a-b-1" passes the prefix rule for both analyst "a" and analyst "a-b".
    write_findings(case_dir, "a", [finding(id="a-b-1")])
    write_findings(case_dir, "a-b", [finding(id="a-b-1")])
    result = check_findings(case_dir)
    assert len(result["valid"]) == 1
    assert any("repeats" in reason for reason in reasons_of(result))


def test_duplicate_id_inside_one_file_is_rejected(case_dir):
    result = check(case_dir, [finding(), finding()])
    assert len(result["valid"]) == 1
    assert any("repeats" in reason for reason in reasons_of(result))


def test_several_reasons_are_listed_together(case_dir):
    reasons = reasons_of(check(case_dir, [finding(id="x-1", fact_ids=["ecs-0099"], excerpt="", provenance="bad", time="no")]))
    assert len(reasons) >= 5


def test_non_object_finding_is_rejected(case_dir):
    result = check(case_dir, ["text"])
    assert result["rejected"][0]["id"] is None


def test_unreadable_and_malformed_files_are_reported_not_fatal(case_dir):
    directory = case_dir / "findings"
    directory.mkdir()
    (directory / "edge.json").write_text("{not json")
    (directory / "list.json").write_text("[1]")
    (directory / "nofindings.json").write_text(json.dumps({"analyst": "x", "findings": "no"}))
    write_findings(case_dir, "compute", [finding()])
    result = check_findings(case_dir)
    files = {item["file"]: item["reason"] for item in result["unreadable"]}
    assert files["findings/edge.json"] == "not valid JSON"
    assert set(files) == {"findings/edge.json", "findings/list.json", "findings/nofindings.json"}
    assert len(result["valid"]) == 1


def test_checked_json_is_not_read_as_a_finding_file(case_dir):
    check(case_dir, [finding()])
    assert check_findings(case_dir)["unreadable"] == []


def test_requests_are_carried_through_with_analyst(case_dir):
    request = {"collector": "rds", "targets": {"db": "checkout-prod-db"}, "reason": "errors"}
    result = check(case_dir, [finding()], requests=[request])
    assert result["requests"] == [{"analyst": "compute", **request}]


def test_secret_looking_claim_is_redacted(case_dir):
    secret = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    result = check(case_dir, [finding(claim=f"Key {secret} was used")])
    assert secret not in json.dumps(result)
    assert secret not in (case_dir / "findings" / "checked.json").read_text()


def test_analyst_name_defaults_to_file_name(case_dir):
    write_findings(case_dir, "compute", [finding()])
    path = case_dir / "findings" / "compute.json"
    data = json.loads(path.read_text())
    del data["analyst"]
    path.write_text(json.dumps(data))
    assert check_findings(case_dir)["valid"][0]["analyst"] == "compute"


def test_short_excerpt_is_rejected(case_dir):
    reasons = reasons_of(check(case_dir, [finding(excerpt="exited")]))
    assert any("12 characters" in reason for reason in reasons)


def test_short_excerpt_that_is_a_whole_summary_is_accepted(tmp_path):
    add_evidence(tmp_path, facts=[(INCIDENT_TIME, "OOMKilled", "")])
    assert check(tmp_path, [finding(excerpt="OOMKilled")])["rejected"] == []


def test_short_excerpt_that_is_a_whole_data_string_is_accepted(tmp_path):
    evidence = Evidence("ecs", "prod-main", "eu-west-1", WINDOW)
    evidence.add(kind=INCIDENT_TIME, resource="svc", summary="Task stopped: OOMKilled by the kernel", time="2026-10-04T10:41:00Z",
                 data={"detail": {"reason": "OOMKilled"}})
    evidence.write(tmp_path)
    assert check(tmp_path, [finding(excerpt="OOMKilled")])["rejected"] == []


def test_provenance_kind_must_come_from_a_fact_that_contains_the_excerpt(tmp_path):
    add_evidence(tmp_path, collector="rds", facts=[(CURRENT, "CPU is at 99% right now", ""), (INCIDENT_TIME, "Failover started on the writer", "")])
    reasons = reasons_of(check(tmp_path, [finding(fact_ids=["rds-0001", "rds-0002"], excerpt="CPU is at 99% right now")]))
    assert any("incident_time" in reason for reason in reasons)


def test_analyst_field_must_match_the_file_name(case_dir):
    write_findings(case_dir, "compute", [finding()], checked=["real"])
    (case_dir / "findings" / "evil.json").write_text(json.dumps({"analyst": "compute", "findings": [], "checked": ["fake"]}))
    result = check_findings(case_dir)
    assert result["checked"] == {"compute": ["real"]}
    assert [item["file"] for item in result["unreadable"]] == ["findings/evil.json"]
    assert "analyst" in result["unreadable"][0]["reason"]


@pytest.mark.parametrize("stem_word", ["auth", "token", "password", "api-keys", "credentials", "secret"])
def test_stored_ids_and_summaries_are_never_redacted(tmp_path, stem_word):
    add_evidence(tmp_path, collector="lambda", suffix=f"{stem_word}-service",
                 facts=[(INCIDENT_TIME, "Throttles peaked at 40 for the function", "")])
    qualified = f"lambda-prod-main-eu-west-1-{stem_word}-service:lambda-0001"
    result = check(tmp_path, [finding(fact_ids=[qualified], excerpt="Throttles peaked at 40")])
    assert result["rejected"] == []
    stored = json.loads((tmp_path / "findings" / "checked.json").read_text())["valid"][0]
    assert stored["fact_ids"] == [qualified]
    assert stored["fact_summaries"] == {qualified: "Throttles peaked at 40 for the function"}


def test_short_excerpt_must_be_a_whole_value_not_a_substring_of_the_summary(tmp_path):
    evidence = Evidence("ecs", "prod-main", "eu-west-1", WINDOW)
    evidence.add(kind=INCIDENT_TIME, resource="svc", summary="Instance db is available", time="2026-10-04T10:41:00Z", data={"az": "a"})
    evidence.write(tmp_path)
    assert check(tmp_path, [finding(excerpt="a")])["rejected"] != []


def test_whole_value_shorter_than_three_characters_never_qualifies(tmp_path):
    add_evidence(tmp_path, facts=[(INCIDENT_TIME, "ok", "")])
    assert check(tmp_path, [finding(excerpt="ok")])["rejected"] != []


def test_short_excerpt_equal_to_the_facts_own_excerpt_field_is_accepted(tmp_path):
    add_evidence(tmp_path, facts=[(INCIDENT_TIME, "Task stopped with a reason", "OOMKilled")])
    assert check(tmp_path, [finding(excerpt="OOMKilled")])["rejected"] == []


def test_short_excerpt_equal_to_a_data_value_is_accepted_without_appearing_in_the_summary(tmp_path):
    evidence = Evidence("ecs", "prod-main", "eu-west-1", WINDOW)
    evidence.add(kind=INCIDENT_TIME, resource="svc", summary="Task stopped", time="2026-10-04T10:41:00Z", data={"reason": "OOMKilled"})
    evidence.write(tmp_path)
    assert check(tmp_path, [finding(excerpt="OOMKilled")])["rejected"] == []


@pytest.mark.parametrize("facts", [5, "x", [1], [None]])
def test_evidence_file_with_malformed_facts_is_reported_unreadable(case_dir, facts):
    (case_dir / "evidence" / "bad-prod-main-eu-west-1.json").write_text(json.dumps({"collector": "bad", "facts": facts}))
    result = check(case_dir, [finding()])
    assert len(result["valid"]) == 1
    assert any("bad-prod-main-eu-west-1.json" in warning and "unreadable" in warning for warning in result["warnings"])


def _fact_with_data(tmp_path, data, summary="Security group has 3 rules"):
    evidence = Evidence("vpc", "prod-main", "eu-west-1", WINDOW)
    evidence.add(kind=INCIDENT_TIME, resource="sg", summary=summary, time="2026-10-04T10:41:00Z", data=data)
    evidence.write(tmp_path)
    return tmp_path


DATA = {"changes": ["image changed", "cpu changed", "tcp 5432 from sg-0bbb2222 was added"],
        "nested": {"deep": [{"note": "listener port moved to 8443"}]}, "count": 4242, "keyname": "x"}


def test_excerpt_found_only_in_a_data_list_entry_is_accepted_with_matched_text(tmp_path):
    result = check(_fact_with_data(tmp_path, DATA), [finding(fact_ids=["vpc-0001"], excerpt="tcp 5432 from sg-0bbb2222")])
    assert result["rejected"] == []
    assert result["valid"][0]["matched_text"] == "tcp 5432 from sg-0bbb2222 was added"


def test_excerpt_found_only_in_a_nested_dict_is_accepted(tmp_path):
    result = check(_fact_with_data(tmp_path, DATA), [finding(fact_ids=["vpc-0001"], excerpt="listener port moved")])
    assert result["rejected"] == []


def test_excerpt_spanning_two_list_entries_is_refused(tmp_path):
    result = check(_fact_with_data(tmp_path, DATA), [finding(fact_ids=["vpc-0001"], excerpt="cpu changed tcp 5432 from sg-0bbb2222")])
    assert any("not found" in reason for reason in reasons_of(result))


def test_a_number_in_data_quoted_as_text_is_refused(tmp_path):
    assert check(_fact_with_data(tmp_path, DATA), [finding(fact_ids=["vpc-0001"], excerpt="4242 4242 4242")])["rejected"] != []
    other = tmp_path / "other"
    other.mkdir()
    assert check(_fact_with_data(other, {"count": 998877665}), [finding(fact_ids=["vpc-0001"], excerpt="998877665")])["rejected"] != []


def test_a_data_key_name_quoted_is_refused(tmp_path):
    result = check(_fact_with_data(tmp_path, {"securityGroupRules": ["a"]}), [finding(fact_ids=["vpc-0001"], excerpt="securityGroupRules")])
    assert result["rejected"] != []


def test_matched_text_is_cut_to_500_characters(tmp_path):
    long_text = "needle " + "x" * 800
    result = check(_fact_with_data(tmp_path, {"rows": [long_text]}), [finding(fact_ids=["vpc-0001"], excerpt="needle xxxxxxx")])
    assert len(result["valid"][0]["matched_text"]) == 500


def test_provenance_uses_the_fact_where_the_excerpt_was_found_in_data(tmp_path):
    add_evidence(tmp_path, collector="rds", facts=[(CURRENT, "CPU is at 99% right now", "")])
    evidence = Evidence("vpc", "prod-main", "eu-west-1", WINDOW)
    evidence.add(kind=INCIDENT_TIME, resource="sg", summary="rules", time="2026-10-04T10:41:00Z", data={"rules": ["tcp 5432 open"]})
    evidence.write(tmp_path)
    ok = check(tmp_path, [finding(fact_ids=["rds-0001", "vpc-0001"], excerpt="tcp 5432 open")])
    assert ok["rejected"] == []


def _search_case(tmp_path, cluster):
    """Evidence written by the real search query: one hit whose message does not mention the query."""
    from test_opensearch_queries import hit, make_context
    from triage.opensearch import queries

    hits = {"hits": {"total": {"value": 1}, "hits": [hit("GET /health returned 200 for the load balancer", level="INFO")]}}
    ctx, _ = make_context(cluster, {"app-logs-*/_search": hits})
    queries.search(ctx, "app-logs-*", query="OutOfMemoryError checkout", filters={"service": "checkout"})
    ctx.evidence.write(tmp_path)
    return tmp_path


@pytest.fixture
def search_cluster(config_data):
    from triage import config as config_module

    return config_module.parse_config(config_data).opensearch_clusters["logs-prod"]


@pytest.mark.parametrize("excerpt", ["OutOfMemoryError checkout", "app-logs-*/", "2026-10-04T10:00:00Z", "app-logs-*"])
def test_what_was_asked_is_never_quotable(tmp_path, search_cluster, excerpt):
    case = _search_case(tmp_path, search_cluster)
    fact_id = next(iter(load_facts(case)))
    result = check(case, [finding(fact_ids=[fact_id], excerpt=excerpt, provenance="incident_time")])
    assert result["valid"] == [], excerpt


def test_a_real_hit_message_in_the_same_fact_is_accepted(tmp_path, search_cluster):
    case = _search_case(tmp_path, search_cluster)
    fact_id = next(iter(load_facts(case)))
    result = check(case, [finding(fact_ids=[fact_id], excerpt="GET /health returned 200", provenance="incident_time")])
    assert result["rejected"] == []


@pytest.mark.parametrize("key", ["asked", "Asked"])
def test_strings_under_asked_are_not_quotable_at_any_depth(tmp_path, key):
    case = _fact_with_data(tmp_path, {"outer": {key: {"deep": ["searched for needle phrase"]}}})
    assert check(case, [finding(fact_ids=["vpc-0001"], excerpt="searched for needle phrase")])["rejected"] != []


@pytest.mark.parametrize("key", ["query", "index", "filters", "window", "method", "command", "request", "target", "parameters"])
def test_real_values_under_other_key_names_are_evidence(tmp_path, key):
    case = _fact_with_data(tmp_path, {"outer": {key: {"deep": ["upstream connect error or disconnect"]}}})
    assert check(case, [finding(fact_ids=["vpc-0001"], excerpt="upstream connect error")])["rejected"] == []


def test_a_short_value_under_a_former_bookkeeping_name_is_a_whole_value(tmp_path):
    case = _fact_with_data(tmp_path, {"method": "POST"})
    assert check(case, [finding(fact_ids=["vpc-0001"], excerpt="POST")])["rejected"] == []


def test_strings_under_asked_never_count_as_whole_values(tmp_path):
    case = _fact_with_data(tmp_path, {"asked": {"method": "terms"}})
    assert check(case, [finding(fact_ids=["vpc-0001"], excerpt="terms")])["rejected"] != []


def test_a_summary_that_is_not_text_is_not_quotable(tmp_path):
    path = _fact_with_data(tmp_path, {})
    file = next((path / "evidence").glob("*.json"))
    document = json.loads(file.read_text())
    document["facts"][0]["summary"] = {"secretkey": "value"}
    file.write_text(json.dumps(document))
    assert check(path, [finding(fact_ids=["vpc-0001"], excerpt="{'secretkey': 'value'}")])["rejected"] != []


@pytest.mark.parametrize("placeholder", ["<SECRET-1>", "<TOKEN-2>"])
def test_a_lone_redaction_placeholder_is_never_an_excerpt(tmp_path, placeholder):
    case = _fact_with_data(tmp_path, {"value": placeholder}, summary=placeholder)
    assert check(case, [finding(fact_ids=["vpc-0001"], excerpt=placeholder)])["rejected"] != []


def test_matched_text_is_cut_around_the_match(tmp_path):
    # Collectors cap strings at 500 characters, so a longer one has to be written by hand.
    case = _fact_with_data(tmp_path, {"rows": ["placeholder"]})
    path = next((case / "evidence").glob("*.json"))
    document = json.loads(path.read_text())
    document["facts"][0]["data"]["rows"] = ["lorem ipsum " * 55 + "OOMKilled by kernel" + " dolor sit amet" * 50]
    path.write_text(json.dumps(document))
    result = check(case, [finding(fact_ids=["vpc-0001"], excerpt="OOMKilled by kernel")])
    matched = result["valid"][0]["matched_text"]
    assert len(matched) == 500 and "OOMKilled by kernel" in matched


def test_rejection_message_names_summary_excerpt_or_data(case_dir):
    reasons = reasons_of(check(case_dir, [finding(excerpt="out of memory")]))
    assert any("summary, excerpt, or data" in reason for reason in reasons)


# What was asked never serves as evidence (ruling 2)

REPEATS = "only repeats what was asked"


def _asked_fact(case_dir, summary, data=None, file_asked=None, collector="changes", kind=INCIDENT_TIME, suffix=""):
    evidence = Evidence(collector, "prod-main", "eu-west-1", WINDOW)
    if file_asked is not None:
        evidence.set_asked(file_asked, {"start": "2026-10-04T10:00:00Z", "end": "2026-10-04T12:00:00Z"})
    evidence.add(kind=kind, resource="r", summary=summary, time="2026-10-04T10:41:00Z", data=data)
    evidence.write(case_dir, suffix)
    return case_dir


def test_an_excerpt_inside_a_facts_asked_string_is_refused_even_when_the_summary_echoes_it(tmp_path):
    case = _asked_fact(tmp_path, "Found nothing for OutOfMemoryError checkout today",
                       data={"asked": {"query": "OutOfMemoryError checkout"}})
    reasons = reasons_of(check(case, [finding(fact_ids=["changes-0001"], excerpt="OutOfMemoryError checkout", provenance="inferred")]))
    assert any(REPEATS in reason and "quote what was found" in reason for reason in reasons)


def test_an_excerpt_inside_a_file_level_asked_target_is_refused(tmp_path):
    case = _asked_fact(tmp_path, "No change was recorded for OutOfMemoryError in checkout between two times",
                       file_asked={"resource_names": "OutOfMemoryError in checkout"})
    reasons = reasons_of(check(case, [finding(fact_ids=["changes-0001"], excerpt="OutOfMemoryError in checkout", provenance="inferred")]))
    assert any(REPEATS in reason for reason in reasons)


def test_an_excerpt_inside_one_item_of_an_asked_list_is_refused(tmp_path):
    case = _asked_fact(tmp_path, "skipped: /aws/a, /aws/checkout/OutOfMemoryError-killed",
                       file_asked={"log_groups": ["/aws/a", "/aws/checkout/OutOfMemoryError-killed"]})
    assert check(case, [finding(fact_ids=["changes-0001"], excerpt="OutOfMemoryError", provenance="inferred")])["valid"] == []


def test_asked_matching_ignores_case_and_whitespace(tmp_path):
    case = _asked_fact(tmp_path, "outofmemoryerror checkout seen", data={"asked": {"query": "OutOfMemoryError\n   Checkout"}})
    assert check(case, [finding(fact_ids=["changes-0001"], excerpt="outofmemoryerror  CHECKOUT", provenance="inferred")])["valid"] == []


def test_the_whole_value_exception_never_applies_to_an_asked_string(tmp_path):
    case = _asked_fact(tmp_path, "checkout", data={"service": "checkout"}, file_asked={"service": "checkout"})
    reasons = reasons_of(check(case, [finding(fact_ids=["changes-0001"], excerpt="checkout", provenance="inferred")]))
    assert any(REPEATS in reason for reason in reasons)


def test_an_excerpt_with_an_asked_string_plus_found_text_is_accepted(tmp_path):
    case = _asked_fact(tmp_path, "No change was recorded for checkout-api between 10:00 and 10:55",
                       file_asked={"resource_names": "checkout-api"})
    result = check(case, [finding(fact_ids=["changes-0001"], excerpt="No change was recorded for checkout-api", provenance="inferred")])
    assert result["rejected"] == []


def test_asked_strings_of_one_fact_do_not_refuse_the_excerpt_in_another_cited_fact(tmp_path):
    _asked_fact(tmp_path, "OutOfMemoryError checkout", data={"asked": {"query": "OutOfMemoryError checkout"}}, collector="opensearch")
    _asked_fact(tmp_path, "java.lang.OutOfMemoryError checkout heap", collector="logs")
    result = check(tmp_path, [finding(fact_ids=["opensearch-0001", "logs-0001"], excerpt="OutOfMemoryError checkout")])
    assert result["rejected"] == []
    assert result["valid"][0]["matched_text"] == "java.lang.OutOfMemoryError checkout heap"


def test_asked_strings_of_another_evidence_file_do_not_refuse_an_excerpt(tmp_path):
    _asked_fact(tmp_path, "unrelated", file_asked={"resource_names": "OutOfMemoryError checkout"}, collector="changes")
    _asked_fact(tmp_path, "java.lang.OutOfMemoryError checkout heap", collector="logs")
    assert check(tmp_path, [finding(fact_ids=["logs-0001"], excerpt="OutOfMemoryError checkout")])["rejected"] == []


def test_the_asked_window_is_an_asked_string(tmp_path):
    case = _asked_fact(tmp_path, "first line at 2026-10-04T10:00:00Z", file_asked={"service": "x"})
    assert check(case, [finding(fact_ids=["changes-0001"], excerpt="2026-10-04T10:00:00Z", provenance="inferred")])["valid"] == []


def test_a_finding_refused_for_repeating_the_request_is_not_also_called_missing(tmp_path):
    case = _asked_fact(tmp_path, "Found nothing for OutOfMemoryError checkout", data={"asked": {"query": "OutOfMemoryError checkout"}})
    reasons = reasons_of(check(case, [finding(fact_ids=["changes-0001"], excerpt="OutOfMemoryError checkout", provenance="inferred")]))
    assert not any("not found" in reason for reason in reasons)


# Excerpt length and placeholder-only excerpts (ruling 3)

def test_an_excerpt_of_300_characters_is_accepted_and_301_refused(tmp_path):
    text = "x" * 150 + " " + "y" * 200
    case = _fact_with_data(tmp_path, {"rows": [text]})
    assert check(case, [finding(fact_ids=["vpc-0001"], excerpt=text[:300])])["rejected"] == []
    reasons = reasons_of(check(case, [finding(fact_ids=["vpc-0001"], excerpt=text[:301])]))
    assert any("300 characters" in reason for reason in reasons)


@pytest.mark.parametrize("excerpt", ["<SECRET-1> <TOKEN-2>", "  <SECRET-1>   <SECRET-2>  <EMAIL-3> "])
def test_an_excerpt_made_only_of_placeholders_is_refused(tmp_path, excerpt):
    case = _fact_with_data(tmp_path, {"value": excerpt}, summary=excerpt)
    reasons = reasons_of(check(case, [finding(fact_ids=["vpc-0001"], excerpt=excerpt)]))
    assert any("placeholder" in reason for reason in reasons)


def test_an_excerpt_with_placeholders_and_found_text_is_accepted(tmp_path):
    case = _fact_with_data(tmp_path, {"value": "login failed for <EMAIL-1> from <IP-2>"})
    assert check(case, [finding(fact_ids=["vpc-0001"], excerpt="login failed for <EMAIL-1>")])["rejected"] == []


def test_matched_text_always_holds_a_300_character_excerpt(tmp_path):
    case = _fact_with_data(tmp_path, {"rows": ["placeholder"]})
    path = next((case / "evidence").glob("*.json"))
    document = json.loads(path.read_text())
    needle = "N" * 299 + "E"
    document["facts"][0]["data"]["rows"] = ["a" * 499 + " " + needle + " " + "b" * 900]
    path.write_text(json.dumps(document))
    matched = check(case, [finding(fact_ids=["vpc-0001"], excerpt=needle)])["valid"][0]["matched_text"]
    assert len(matched) == 500 and needle in matched
