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
    assert check(_fact_with_data(tmp_path, {"count": 998877665}), [finding(fact_ids=["vpc-0001"], excerpt="998877665")])["rejected"] != []


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
