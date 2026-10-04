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


def test_load_facts_across_files_adds_file_name(case_dir):
    add_evidence(case_dir, collector="rds", facts=[(CURRENT, "db up", "")])
    facts = load_facts(case_dir)
    assert set(facts) == {"ecs-0001", "ecs-0002", "ecs-0003", "rds-0001"}
    assert facts["rds-0001"]["file"] == "rds-prod-main-eu-west-1.json"


def test_load_facts_keeps_duplicate_under_file_prefix_and_warns(case_dir):
    add_evidence(case_dir, region="eu-central-1", facts=[(CURRENT, "second region", "")])
    warnings = []
    facts = load_facts(case_dir, warnings)
    assert facts["ecs-0001"]["file"] == "ecs-prod-main-eu-central-1.json" or facts["ecs-0001"]["summary"].startswith("Essential")
    duplicates = [key for key in facts if key.endswith(":ecs-0001")]
    assert len(duplicates) == 1
    assert len(warnings) == 1 and "ecs-0001" in warnings[0]


def test_check_reports_duplicate_warning(case_dir):
    add_evidence(case_dir, region="eu-central-1", facts=[(CURRENT, "second region", "")])
    result = check(case_dir, [finding()])
    assert len(result["warnings"]) == 1


def test_load_facts_without_evidence_is_empty(tmp_path):
    assert load_facts(tmp_path) == {}


def test_valid_finding_is_kept_with_summaries_and_written(case_dir):
    result = check(case_dir, [finding()], checked=["ECS events"])
    assert result["rejected"] == []
    assert result["valid"][0]["id"] == "compute-1"
    assert result["valid"][0]["analyst"] == "compute"
    assert result["valid"][0]["fact_summaries"] == ["Essential container exited with code 137"]
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
    reasons = reasons_of(check(case_dir, [finding(fact_ids=["ecs-0002"], excerpt="running 0")]))
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
