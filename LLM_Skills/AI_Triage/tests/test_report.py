import copy
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

import pytest
import yaml

from conftest import SKILL_SRC
from triage.case import create_case, load_case, parse_incident
from triage.config import parse_config
from triage.evidence import CURRENT, INCIDENT_TIME, Evidence
from triage.findings import check_findings, load_facts, valid_findings
from triage.compose import LABEL_ORDER
from triage.digest import action_digest, case_identity, cause_digest, draft_digest
from triage.report import (
    REQUIRED_HEADINGS,
    build_work_order,
    check_case_inputs,
    check_draft,
    coverage_from_evidence,
    display_case_folder,
    render_report,
    validate_report,
    validate_work_order,
)
from triage.service_map import ServiceMap
from triage.timeline import build_timeline
from triage.window import make_window

NOW = datetime(2026, 10, 4, 11, 0, 0, tzinfo=timezone.utc)
RENDERED_AT = datetime(2026, 10, 4, 11, 30, 0, tzinfo=timezone.utc)
WINDOW = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", 24)
INCIDENT = {
    "number": "INC-123",
    "title": "Checkout API is down",
    "url": "https://oneuptime.example.com/dashboard/incidents/123",
    "severity": "Critical",
    "state": "Acknowledged",
    "declared_at": "2026-10-04T10:45:00Z",
    "impact_started_at": "2026-10-04T10:42:00Z",
    "monitors": [{"name": "Checkout API", "type": "API", "target": "https://checkout.example.com/health"}],
}

ACTION_TARGET = {
    "account_alias": "prod-main", "account_id": "111111111111", "region": "eu-west-1",
    "service": "checkout-api", "resource_id": "checkout/checkout-api",
    "arn": "arn:aws:ecs:eu-west-1:111111111111:service/checkout/checkout-api",
}

VALID_REPORT = {
    "status": "cause_found",
    "summary": {
        "what_broke": "The checkout API stopped serving requests.",
        "impact": "Customers could not complete checkout for 12 minutes.",
        "scope": "Only checkout-api in prod was affected; payments-api was healthy.",
        "top_cause": "C1",
    },
    "symptoms": ["The health check of checkout.example.com returns 502"],
    "causes": [
        {"id": "C1", "statement": "Revision 42 of checkout-api exits with code 137 because its memory limit is too low",
         "label": "confirmed", "supporting": ["compute-1"], "contradicting": []},
        {"id": "C2", "statement": "A load balancer fault", "label": "candidate",
         "supporting": [], "contradicting": ["compute-2"]},
    ],
    "hypotheses": [
        {"id": "H1", "statement": "Containers are killed for memory", "prediction": "Tasks stop with code 137",
         "test": "Read the stopped task reasons", "result": "confirmed", "finding_ids": ["compute-1"],
         "cause": "C1"},
        {"id": "H2", "statement": "The load balancer is unhealthy", "prediction": "Targets are unhealthy | all zones",
         "test": "Read target health", "result": "rejected", "finding_ids": ["compute-2"],
         "cause": "C2"},
    ],
    "actions": [
        {"id": "A1", "type": "mitigation", "label": "recommended", "cause": "C1",
         "title": "Raise the memory limit of checkout-api",
         "target": ACTION_TARGET,
         "current_state": "Memory limit is 512 MiB", "required_state": "Memory limit is 1024 MiB",
         "change": "Register a task definition revision with 1024 MiB and update the service",
         "rationale": "Containers are killed at the memory limit",
         "finding_ids": ["compute-1"], "risk": "Higher cost", "blast_radius": "checkout-api only",
         "preconditions": ["Capacity for two more tasks"],
         "verification": ["The service reaches 2 running tasks"], "rollback": ["Update the service to revision 41"]},
        {"id": "A2", "type": "permanent_fix", "label": "candidate", "cause": "C1",
         "title": "Add a memory alarm",
         "target": ACTION_TARGET,
         "current_state": "No memory alarm", "required_state": "An alarm at 80 percent",
         "change": "Create a CloudWatch alarm", "rationale": "Catch the problem earlier",
         "finding_ids": ["compute-1"], "risk": "Noise", "blast_radius": "none",
         "preconditions": [], "verification": ["The alarm exists"], "rollback": ["Delete the alarm"]},
    ],
    "open_questions": ["Was the limit changed by hand?"],
    "coverage": {"not_checked": [{"what": "Application logs", "why": "No log group in the map"}],
                 "typesafe": "available"},
    "map_changes": [],
    "run": {"engineer": "jane-doe", "duration_minutes": 14},
}

UNRESOLVED_REPORT = {
    **copy.deepcopy(VALID_REPORT),
    "status": "unresolved",
    "summary": {**VALID_REPORT["summary"], "top_cause": None},
    "causes": [{"id": "C1", "statement": "Memory limit", "label": "candidate",
                "supporting": ["compute-1"], "contradicting": []}],
    "hypotheses": [{"id": "H1", "statement": "Memory", "prediction": "p", "test": "t",
                    "result": "inconclusive", "finding_ids": ["compute-1"], "cause": None}],
    "actions": [{**copy.deepcopy(VALID_REPORT["actions"][0]), "label": "candidate"}],
}


GATES_PASSED = {"evidence": True, "no_contradiction": True, "rank": True, "timing": True,
                "symptom_fit": True, "scope": True}
SUMMARY = {
    "typesafe": "available",
    "model": "jev-test",
    "thresholds": {"evidence_supports": 0.8, "cause_top_probability": 0.6, "ask_engineer_below": 0.5},
    "uncalibrated": True,
    "judged": True,
    "findings": {
        "compute-1": {"relation": "supports", "confidence": 0.93, "verdict": "verified"},
        "compute-2": {"relation": "supports", "confidence": 0.9, "verdict": "verified"},
    },
    "causes": {
        "C1": {"label": "confirmed", "gates": GATES_PASSED, "rank_probability": 0.72,
               "symptom_fit": 0.83, "scope": "matches", "reasons": []},
        "C2": {"label": "candidate", "gates": {**GATES_PASSED, "rank": False, "timing": False},
               "rank_probability": 0.14, "symptom_fit": 0.5, "scope": "broader",
               "reasons": ["Ranking did not pick this cause in both orderings",
                           "No supporting finding has a time"]},
    },
    "actions": {
        "A1": {"label": "recommended", "target": "addresses_cause", "target_confidence": 0.9,
               "specific": 0.88, "reasons": []},
        "A2": {"label": "candidate", "target": "partly_addresses_cause", "target_confidence": 0.7,
               "specific": 0.5, "reasons": ["The cause is labelled candidate, not confirmed"]},
    },
    "ask_engineer": ["The ranking changed with the order of the options"],
    "adhoc": [{"id": "deploy_trigger", "reason": "No fixed question covers deploy timing"}],
}


def store_summary(case_dir, summary, report=None, digests=True):
    """Write the summary as a judging run of `report` would: each entry gets the digest of its cause or action.

    An entry that already has a "digest" key keeps it. With digests=False the summary is written as given.
    """
    summary = copy.deepcopy(summary)
    if digests:
        summary.setdefault("status", "complete")
        summary.setdefault("draft_digest", draft_digest(report or VALID_REPORT, valid_findings(case_dir), case_identity(load_case(case_dir))))
        findings = valid_findings(case_dir)
        report = report or VALID_REPORT
        for cause in report["causes"]:
            if isinstance(summary["causes"].get(cause["id"]), dict):
                summary["causes"][cause["id"]].setdefault("digest", cause_digest(cause, findings))
        for action in report["actions"]:
            if isinstance(summary["actions"].get(action["id"]), dict):
                summary["actions"][action["id"]].setdefault("digest", action_digest(action))
    (case_dir / "judgments").mkdir(exist_ok=True)
    (case_dir / "judgments" / "summary.json").write_text(json.dumps(summary))


def rejudge(case_dir, report):
    """Store the unchanged judgments again with digests of `report`, as if judging had been run on it."""
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    for entry in [*summary["causes"].values(), *summary["actions"].values()]:
        entry.pop("digest", None)
    summary.pop("draft_digest", None)
    store_summary(case_dir, summary, report)


def summary_with(**changes):
    summary = copy.deepcopy(SUMMARY)
    summary.update(changes)
    return summary


def add_evidence(case_dir, facts, errors=(), truncated=False, collector="ecs"):
    evidence = Evidence(collector, "prod-main", "eu-west-1", WINDOW)
    for kind, summary, excerpt, command in facts:
        evidence.add(kind=kind, resource="checkout/checkout-api", summary=summary,
                     time="2026-10-04T10:41:00Z", excerpt=excerpt, command=command)
    for command, code, message in errors:
        evidence.add_error(command, code, message)
    evidence.truncated = truncated
    return evidence.write(case_dir)


def write_findings(case_dir, findings):
    (case_dir / "findings" / "compute.json").write_text(json.dumps({"analyst": "compute", "findings": findings}))


@pytest.fixture
def config(config_data, tmp_path):
    config_data["cases_dir"] = str(tmp_path / "cases")
    return parse_config(config_data)


@pytest.fixture
def case_dir(config, tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "VERSION").write_text("0.1.0\n")
    path = create_case(parse_incident(INCIDENT), config, ServiceMap({}), NOW, skill_dir)
    add_evidence(path, [
        (INCIDENT_TIME, "Essential container exited with code 137", "exit code 137", "aws ecs describe-tasks"),
        (CURRENT, "Service has 0 running tasks", "desired 2, running 0", "aws ecs describe-services"),
    ], errors=[("aws ecs list-tasks", "AccessDenied", "not allowed"), ("aws ecs list-services", "AccessDenied", "no")])
    write_findings(path, [
        {"id": "compute-1", "claim": "Containers exit with code 137", "fact_ids": ["ecs-0001"],
         "excerpt": "exit code 137", "provenance": "incident_time", "confidence": "high"},
        {"id": "compute-2", "claim": "Service is down now", "fact_ids": ["ecs-0002"],
         "excerpt": "desired 2, running 0", "provenance": "current", "confidence": "medium"},
        {"id": "compute-3", "claim": "Bad", "fact_ids": ["ecs-0099"],
         "excerpt": "x", "provenance": "current", "confidence": "low"},
    ])
    check_findings(path)
    store_summary(path, SUMMARY)
    return path


@pytest.fixture
def case(case_dir):
    return load_case(case_dir)


@pytest.fixture
def findings(case_dir):
    return valid_findings(case_dir)


def problems_for(report, case, findings, config):
    return validate_report(report, case, findings, config)


def mutated(base, mutate):
    report = copy.deepcopy(base)
    mutate(report)
    return report


def assert_problem(problems, *needles):
    assert any(all(needle in problem for needle in needles) for problem in problems), problems


def test_valid_reports_have_no_problems(case_dir, case, findings, config):
    assert problems_for(VALID_REPORT, case, findings, config) == []
    rejudge(case_dir, UNRESOLVED_REPORT)
    assert problems_for(UNRESOLVED_REPORT, case, findings, config) == []


def test_label_order_constant():
    assert LABEL_ORDER == ("candidate", "probable", "confirmed")


# one test per rule

def test_not_an_object(case, findings, config):
    assert_problem(problems_for([], case, findings, config), "report", "object")


@pytest.mark.parametrize("mutate,needles", [
    (lambda r: r.pop("causes"), ("causes", "missing")),
    (lambda r: r.pop("run"), ("run", "missing")),
    (lambda r: r.update(status="done"), ("status", "cause_found", "unresolved")),
    (lambda r: r.update(symptoms="x"), ("symptoms", "list")),
    (lambda r: r["causes"][0].update(label="sure"), ("causes[0].label", "candidate")),
    (lambda r: r["causes"][0].pop("supporting"), ("causes[0].supporting", "missing")),
    (lambda r: r["hypotheses"][0].update(result="maybe"), ("hypotheses[0].result",)),
    (lambda r: r["actions"][0].update(type="other"), ("actions[0].type", "mitigation")),
    (lambda r: r["actions"][0].update(label="other"), ("actions[0].label", "recommended")),
    (lambda r: r["actions"][0]["target"].pop("arn"), ("actions[0].target.arn", "missing")),
    (lambda r: r["actions"][0].update(verification="x"), ("actions[0].verification", "list")),
    (lambda r: r["coverage"].update(not_checked=[{"what": "x"}]), ("coverage.not_checked[0].why",)),
    (lambda r: r["run"].update(duration_minutes="long"), ("run.duration_minutes", "number")),
    (lambda r: r.update(map_changes="x"), ("map_changes", "list")),
])
def test_shape_problems(case, findings, config, mutate, needles):
    assert_problem(problems_for(mutated(VALID_REPORT, mutate), case, findings, config), *needles)


@pytest.mark.parametrize("section,items", [("causes", 0), ("hypotheses", 0), ("actions", 0)])
def test_duplicate_ids(case, findings, config, section, items):
    def duplicate(report):
        report[section].append(copy.deepcopy(report[section][0]))
    assert_problem(problems_for(mutated(VALID_REPORT, duplicate), case, findings, config), section, "duplicate", "id")


@pytest.mark.parametrize("field", ["what_broke", "impact", "scope"])
def test_summary_fields_must_not_be_empty(case, findings, config, field):
    report = mutated(VALID_REPORT, lambda r: r["summary"].update({field: "  "}))
    assert_problem(problems_for(report, case, findings, config), f"summary.{field}", "empty")


def test_symptoms_need_one_real_entry(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r.update(symptoms=["", "  "]))
    assert_problem(problems_for(report, case, findings, config), "symptoms", "at least one")


def test_top_cause_must_be_a_cause_id(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["summary"].update(top_cause="C9"))
    assert_problem(problems_for(report, case, findings, config), "top_cause", "known cause id")


def test_unresolved_top_cause_must_be_empty(case, findings, config):
    report = mutated(UNRESOLVED_REPORT, lambda r: r["summary"].update(top_cause="C1"))
    assert_problem(problems_for(report, case, findings, config), "top_cause", "unresolved")


def test_unresolved_accepts_empty_string_top_cause(case_dir, case, findings, config):
    report = mutated(UNRESOLVED_REPORT, lambda r: r["summary"].update(top_cause=""))
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_unknown_and_rejected_finding_ids_are_named_everywhere(case, findings, config):
    def break_ids(report):
        report["causes"][0]["supporting"].append("compute-3")
        report["causes"][1]["contradicting"].append("ghost-1")
        report["hypotheses"][0]["finding_ids"].append("ghost-2")
        report["actions"][0]["finding_ids"].append("ghost-3")
    problems = problems_for(mutated(VALID_REPORT, break_ids), case, findings, config)
    assert_problem(problems, "causes[0].supporting[1]", "not a valid finding")
    assert_problem(problems, "causes[1].contradicting[1]", "not a valid finding")
    assert_problem(problems, "hypotheses[0].finding_ids[1]", "not a valid finding")
    assert_problem(problems, "actions[0].finding_ids[1]", "not a valid finding")
    assert not any(name in problem for problem in problems for name in ("compute-3", "ghost-1", "ghost-2", "ghost-3"))


@pytest.mark.parametrize("label", ["confirmed", "probable"])
def test_strong_cause_needs_supporting_finding(case, findings, config, label):
    def strip(report):
        report["causes"][1].update(label=label, supporting=[], contradicting=[])
        report["actions"] = report["actions"][:1]
    assert_problem(problems_for(mutated(VALID_REPORT, strip), case, findings, config), "causes[1]", "supporting")


def test_confirmed_cause_cannot_have_contradicting_finding(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(contradicting=["compute-2"]))
    assert_problem(problems_for(report, case, findings, config), "causes[0]", "contradicting")


def test_confirmed_cause_needs_incident_time_support(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(supporting=["compute-2"]))
    assert_problem(problems_for(report, case, findings, config), "causes[0]", "incident_time")


def test_probable_cause_does_not_need_incident_time_support(case_dir, case, findings, config):
    def weaken(report):
        report["causes"][0].update(label="probable", supporting=["compute-2"])
        report["actions"] = [{**report["actions"][0], "label": "candidate"}]
    report = mutated(VALID_REPORT, weaken)
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_cause_found_needs_strong_top_cause_and_confirmed_hypothesis(case, findings, config):
    def weaken(report):
        report["causes"][0]["label"] = "candidate"
        report["hypotheses"][0]["result"] = "inconclusive"
        report["actions"] = [{**report["actions"][0], "label": "candidate"}]
    problems = problems_for(mutated(VALID_REPORT, weaken), case, findings, config)
    assert_problem(problems, "top cause", "confirmed or probable")
    assert_problem(problems, "hypothesis", "confirmed")


def test_three_rejected_hypotheses_force_unresolved(case_dir, case, findings, config):
    def reject(report):
        report["hypotheses"][0]["result"] = "rejected"
        report["hypotheses"].append({**report["hypotheses"][1], "id": "H3"})
    problems = problems_for(mutated(VALID_REPORT, reject), case, findings, config)
    assert_problem(problems, "rejected", "unresolved")
    report = mutated(UNRESOLVED_REPORT, lambda r: r["hypotheses"].extend(
        {**r["hypotheses"][0], "id": f"H{i}", "result": "rejected"} for i in (2, 3, 4)))
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_unresolved_forbids_confirmed_cause_and_recommended_action(case, findings, config):
    def overreach(report):
        report["causes"][0]["label"] = "confirmed"
        report["actions"][0]["label"] = "recommended"
    problems = problems_for(mutated(UNRESOLVED_REPORT, overreach), case, findings, config)
    assert_problem(problems, "unresolved", "confirmed")
    assert_problem(problems, "unresolved", "recommended")


@pytest.mark.parametrize("field", ["title", "current_state", "required_state", "change", "rationale", "risk", "blast_radius"])
def test_action_text_fields_must_not_be_empty(case, findings, config, field):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0].update({field: ""}))
    assert_problem(problems_for(report, case, findings, config), f"actions[0].{field}", "empty")


def test_action_cause_must_exist(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0].update(cause="C9"))
    assert_problem(problems_for(report, case, findings, config), "actions[0].cause", "known cause id")


def test_action_target_account_must_be_in_config(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0]["target"].update(account_alias="nowhere"))
    assert_problem(problems_for(report, case, findings, config), "actions[0].target.account_alias", "account in the config")


@pytest.mark.parametrize("field", ["region", "service", "resource_id"])
def test_action_target_fields_must_not_be_empty(case, findings, config, field):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0]["target"].update({field: ""}))
    assert_problem(problems_for(report, case, findings, config), f"actions[0].target.{field}", "empty")


@pytest.mark.parametrize("field", ["verification", "rollback"])
def test_action_needs_verification_and_rollback_steps(case, findings, config, field):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0].update({field: [" "]}))
    assert_problem(problems_for(report, case, findings, config), f"actions[0].{field}", "at least one")


def test_action_needs_a_finding(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0].update(finding_ids=[]))
    assert_problem(problems_for(report, case, findings, config), "actions[0].finding_ids", "at least one")


def test_recommended_action_needs_confirmed_cause(case, findings, config):
    def point_at_candidate(report):
        report["actions"][0]["cause"] = "C2"
    assert_problem(problems_for(mutated(VALID_REPORT, point_at_candidate), case, findings, config),
                   "actions[0]", "recommended", "confirmed")


def test_typesafe_value_is_checked(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="down"))
    assert_problem(problems_for(report, case, findings, config), "coverage.typesafe", "available")


def test_unavailable_typesafe_forbids_confirmed(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: no key"))
    assert_problem(problems_for(report, case, findings, config), "TypeSafe", "confirmed")


def test_unavailable_typesafe_is_fine_without_confirmed(case_dir, case, findings, config):
    store_summary(case_dir, summary_with(typesafe="unavailable: no key", causes={
        "C1": {**SUMMARY["causes"]["C1"], "label": "probable"}, "C2": SUMMARY["causes"]["C2"]}))
    def downgrade(report):
        report["coverage"]["typesafe"] = "unavailable: no key"
        report["causes"][0]["label"] = "probable"
        report["actions"] = [{**a, "label": "candidate"} for a in report["actions"]]
    assert problems_for(mutated(VALID_REPORT, downgrade), case, findings, config) == []


def test_all_problems_are_reported_together(case, findings, config):
    def break_many(report):
        report["summary"]["impact"] = ""
        report["actions"][0]["title"] = ""
        report["causes"][0]["supporting"] = ["ghost-1"]
        report["coverage"]["typesafe"] = "?"
    assert len(problems_for(mutated(VALID_REPORT, break_many), case, findings, config)) >= 4


# judgments summary cap

def write_summary(case_dir, causes):
    store_summary(case_dir, summary_with(causes=causes))


def remove_summary(case_dir):
    (case_dir / "judgments" / "summary.json").unlink()


def test_cause_cannot_exceed_the_judged_label(case_dir, case, findings, config):
    write_summary(case_dir, {"C1": {"label": "probable"}, "C2": {"label": "candidate"}})
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "causes[0]", "confirmed", "probable")


def test_cause_may_equal_or_undercut_the_judged_label(case_dir, case, findings, config):
    write_summary(case_dir, {"C1": {"label": "confirmed"}, "C2": {"label": "probable"}})
    assert problems_for(VALID_REPORT, case, findings, config) == []


def test_cause_missing_from_summary_is_at_most_candidate(case_dir, case, findings, config):
    write_summary(case_dir, {"C2": {"label": "candidate"}})
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "causes[0]", "not in", "candidate")
    assert not any("causes[1]" in problem for problem in problems)


def test_unreadable_summary_is_a_problem(case_dir, case, findings, config):
    (case_dir / "judgments").mkdir(exist_ok=True)
    (case_dir / "judgments" / "summary.json").write_text("{not json")
    assert_problem(problems_for(VALID_REPORT, case, findings, config), "summary.json")


# secrets

def secret_value():
    return "".join(["hunter", "2hunter", "2value"])


def test_secret_in_any_field_is_reported_by_path_and_category_not_value(case, findings, config):
    leaked = f"pass{'word'}={secret_value()}"
    def leak(report):
        report["actions"][0]["change"] = f"Run it with {leaked}"
        report["symptoms"].append(leaked)
        report["causes"][0]["statement"] += f" {leaked}"
        report["coverage"]["not_checked"][0]["why"] = leaked
    problems = problems_for(mutated(VALID_REPORT, leak), case, findings, config)
    for path in ("actions[0].change", "symptoms[1]", "causes[0].statement", "coverage.not_checked[0].why"):
        assert_problem(problems, path, "secret")
    assert not any(secret_value() in problem for problem in problems)


# work order

def test_work_order_matches_the_contract(case, findings, config):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT)
    assert set(order) == {"incident", "generated_at", "skill_version", "cause", "causes", "findings", "actions",
                          "open_questions", "coverage_gaps"}
    assert order["incident"] == {"number": "INC-123", "title": "Checkout API is down", "url": INCIDENT["url"]}
    assert order["generated_at"] == "2026-10-04T11:30:00Z"
    assert order["skill_version"] == "0.1.0"
    assert order["cause"] == {"statement": VALID_REPORT["causes"][0]["statement"], "label": "confirmed",
                              "finding_ids": ["compute-1"]}
    assert [a["id"] for a in order["actions"]] == ["A1", "A2"]
    assert [action["cause"] for action in order["actions"]] == ["C1", "C1"]
    assert order["open_questions"] == ["Was the limit changed by hand?"]
    assert order["coverage_gaps"] == ["Application logs: No log group in the map"]
    assert validate_work_order(order) == []
    json.dumps(order)


def test_work_order_does_not_alias_the_report(case):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT)
    order["actions"][0]["verification"].append("x")
    assert VALID_REPORT["actions"][0]["verification"] == ["The service reaches 2 running tasks"]


def test_unresolved_work_order_is_valid(case):
    order = build_work_order(UNRESOLVED_REPORT, case, RENDERED_AT)
    assert order["cause"]["label"] == "unresolved" and order["cause"]["finding_ids"] == []
    assert validate_work_order(order) == []


def test_unavailable_typesafe_is_a_coverage_gap(case):
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: no key"))
    assert "TypeSafe unavailable: no key" in build_work_order(report, case, RENDERED_AT)["coverage_gaps"]


def test_validate_work_order_rejects_non_objects():
    assert validate_work_order([]) != []


@pytest.mark.parametrize("path", [
    ("incident",), ("generated_at",), ("skill_version",), ("cause",), ("actions",), ("open_questions",),
    ("coverage_gaps",), ("incident", "number"), ("incident", "title"), ("incident", "url"),
    ("cause", "statement"), ("cause", "label"), ("cause", "finding_ids"),
    ("actions", 0, "id"), ("actions", 0, "type"), ("actions", 0, "label"), ("actions", 0, "title"),
    ("actions", 0, "target"), ("actions", 0, "target", "arn"), ("actions", 0, "target", "account_alias"),
    ("actions", 0, "current_state"), ("actions", 0, "required_state"), ("actions", 0, "change"),
    ("actions", 0, "rationale"), ("actions", 0, "finding_ids"), ("actions", 0, "risk"),
    ("actions", 0, "blast_radius"), ("actions", 0, "preconditions"), ("actions", 0, "verification"),
    ("actions", 0, "rollback"),
])
def test_validate_work_order_rejects_each_missing_field(case, path):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT)
    node = order
    for step in path[:-1]:
        node = node[step]
    del node[path[-1]]
    assert_problem(validate_work_order(order), path[-1], "missing")


def test_validate_work_order_checks_values(case):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT)
    order["generated_at"] = "yesterday"
    order["cause"]["label"] = "sure"
    order["actions"][0]["type"] = "x"
    order["actions"][0]["label"] = "y"
    order["actions"][0]["title"] = ""
    order["actions"][0]["verification"] = []
    problems = validate_work_order(order)
    for needle in ("generated_at", "cause.label", "actions[0].type", "actions[0].label", "actions[0].title",
                   "actions[0].verification"):
        assert_problem(problems, needle)


# coverage_from_evidence

def test_coverage_groups_errors_by_code_and_reports_truncation(case_dir):
    add_evidence(case_dir, [], errors=[("aws rds describe-db-instances", "Throttling", "slow")],
                 truncated=True, collector="rds")
    gaps = coverage_from_evidence(case_dir)
    by_code = {gap["code"]: gap for gap in gaps}
    assert [gap["code"] for gap in gaps] == sorted(by_code)
    assert [entry["command"] for entry in by_code["AccessDenied"]["entries"]] == [
        "aws ecs list-tasks", "aws ecs list-services"]
    assert by_code["Throttling"]["entries"][0]["file"] == "rds-prod-main-eu-west-1.json"
    assert by_code["truncated"]["entries"][0]["file"] == "rds-prod-main-eu-west-1.json"


def test_coverage_is_empty_without_errors(tmp_path):
    (tmp_path / "evidence").mkdir()
    add_evidence(tmp_path, [(CURRENT, "ok", "", "")])
    assert coverage_from_evidence(tmp_path) == []


# rendering

def render(report, case_dir, case):
    findings = valid_findings(case_dir)
    return render_report(report, case, findings, build_timeline(case_dir), coverage_from_evidence(case_dir), RENDERED_AT)


def headings_of(text):
    return [line for line in text.splitlines() if line.startswith(("# ", "## "))]


def assert_headings(text):
    found = headings_of(text)
    assert len(found) == len(REQUIRED_HEADINGS), found
    for heading, required in zip(found, REQUIRED_HEADINGS):
        assert heading.startswith(required), (heading, required)


def section(text, heading):
    start = text.index(heading)
    rest = text[start + len(heading):]
    next_heading = rest.find("\n## ")
    return rest if next_heading == -1 else rest[:next_heading]


@pytest.mark.parametrize("report", [VALID_REPORT, UNRESOLVED_REPORT], ids=["cause_found", "unresolved"])
def test_every_heading_once_and_in_order(case_dir, case, report):
    text = render(report, case_dir, case)
    assert_headings(text)
    assert text.startswith("# Triage report: INC-123 Checkout API is down\n")


def test_summary_and_incident_sections(case_dir, case):
    text = render(VALID_REPORT, case_dir, case)
    summary = section(text, "## 1. Summary")
    for needle in ("The checkout API stopped serving requests.", "Customers could not complete checkout",
                   "Only checkout-api in prod", "The health check of checkout.example.com returns 502", "confirmed"):
        assert needle in summary
    incident = section(text, "## 2. Incident and window")
    for needle in (INCIDENT["url"], "Critical", "Acknowledged", "2026-10-04T10:42:00Z", "2026-10-04T10:45:00Z",
                   "2026-10-04T09:42:00Z", "2026-10-04T11:00:00Z"):
        assert needle in incident


def test_unresolved_summary_says_no_cause_was_established(case_dir, case):
    summary = section(render(UNRESOLVED_REPORT, case_dir, case), "## 1. Summary")
    assert "No cause was established" in summary


def test_timeline_findings_and_causes(case_dir, case):
    text = render(VALID_REPORT, case_dir, case)
    assert "| Time | Relative to incident start | Event | Source |" in section(text, "## 3. Timeline")
    findings = section(text, "## 4. Findings")
    assert "### compute" in findings
    for needle in ("compute-1", "Containers exit with code 137", "incident_time", "high", "ecs-0001",
                   "aws ecs describe-tasks", "checkout/checkout-api", "2026-10-04T10:41:00Z", "exit code 137"):
        assert needle in findings
    assert "compute-3" not in findings
    causes = section(text, "## 5. Ranked causes")
    assert causes.index("C1") < causes.index("C2")
    for needle in ("confirmed", "candidate", "compute-1", "compute-2", "H1", "Tasks stop with code 137",
                   "Read the stopped task reasons"):
        assert needle in causes


def test_hypotheses_are_shown_under_their_cause_and_the_rest_under_other(case_dir, case):
    def add(report):
        report["hypotheses"].append({"id": "H9", "statement": "Unrelated", "prediction": "p9", "test": "t9",
                                     "result": "inconclusive", "finding_ids": ["compute-1"], "cause": None})
        report["hypotheses"].append({"id": "H8", "statement": "No key", "prediction": "p8", "test": "t8",
                                     "result": "inconclusive", "finding_ids": ["compute-1"]})
    causes = section(render(mutated(VALID_REPORT, add), case_dir, case), "## 5. Ranked causes")
    first, second = causes.index("### 1."), causes.index("### 2.")
    other = causes.index("### Other hypotheses")
    assert first < causes.index("H1") < second < causes.index("H2") < other
    assert causes.index("H9") > other and causes.index("H8") > other


def test_a_hypothesis_does_not_attach_to_a_cause_by_shared_findings(case_dir, case):
    def share(report):
        report["hypotheses"][0]["cause"] = None
    causes = section(render(mutated(VALID_REPORT, share), case_dir, case), "## 5. Ranked causes")
    assert causes.index("H1") > causes.index("### Other hypotheses")


def test_mitigations_come_before_permanent_fixes_and_candidates_are_marked(case_dir, case):
    def reorder(report):
        report["actions"].reverse()
    order = section(render(mutated(VALID_REPORT, reorder), case_dir, case), "## 6. Remediation work order")
    assert order.index("A1") < order.index("A2")
    assert "needs more evidence" in order.lower()
    assert order.lower().count("needs more evidence") == 1
    for needle in ("Raise the memory limit of checkout-api", "prod-main", "111111111111", "eu-west-1",
                   "checkout/checkout-api", "arn:aws:ecs", "Memory limit is 512 MiB", "Memory limit is 1024 MiB",
                   "Register a task definition", "Containers are killed at the memory limit", "compute-1",
                   "Higher cost", "checkout-api only", "Capacity for two more tasks",
                   "The service reaches 2 running tasks", "Update the service to revision 41", "C1"):
        assert needle in order


def test_coverage_section_order_and_content(case_dir, case):
    coverage = section(render(VALID_REPORT, case_dir, case), "## 7. Coverage notes")
    markers = ["Application logs", "AccessDenied", "aws ecs list-tasks", "TypeSafe", "compute-3",
               "ecs-0099", "Was the limit changed by hand?"]
    positions = [coverage.index(marker) for marker in markers]
    assert positions == sorted(positions)


def test_typesafe_unavailability_is_stated(case_dir, case):
    store_summary(case_dir, summary_with(typesafe="unavailable: no key", model=None))
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: no key"))
    assert "unavailable: no key" in section(render(report, case_dir, case), "## 7. Coverage notes")


def test_empty_sections_say_none(case_dir, case):
    def empty(report):
        report["causes"] = []
        report["hypotheses"] = []
        report["actions"] = []
        report["open_questions"] = []
        report["coverage"]["not_checked"] = []
        report["status"] = "unresolved"
        report["summary"]["top_cause"] = None
    text = render(mutated(VALID_REPORT, empty), case_dir, case)
    assert section(text, "## 5. Ranked causes").strip().startswith("None.")
    assert section(text, "## 6. Remediation work order").strip().startswith("None.")
    assert section(text, "## 8. Proposed service map changes").strip().startswith("None.")
    assert "None." in section(text, "## 7. Coverage notes")


def test_findings_section_says_none_when_no_valid_findings(tmp_path, case):
    text = render_report(UNRESOLVED_REPORT, {**case, "case_dir": str(tmp_path)}, {}, [], [], RENDERED_AT)
    assert section(text, "## 4. Findings").strip().startswith("None.")
    assert section(text, "## 3. Timeline").strip().startswith("None.")


def test_map_changes_are_listed(case_dir, case):
    report = mutated(VALID_REPORT, lambda r: r.update(map_changes=["Add log group /ecs/checkout-api"]))
    assert "Add log group /ecs/checkout-api" in section(render(report, case_dir, case), "## 8. Proposed service map changes")


def test_run_details(case_dir, case):
    details = section(render(VALID_REPORT, case_dir, case), "## 9. Run details")
    for needle in ("jane-doe", "14", "0.1.0", "cases/INC-123/20261004-110000", "2026-10-04T11:30:00Z"):
        assert needle in details


def test_pipes_and_newlines_cannot_break_tables_or_headings(case_dir, case):
    def nasty(report):
        report["hypotheses"][1]["prediction"] = "a | b\n## 1. Summary"
        report["causes"][0]["statement"] = "line one\n# Triage report: fake"
    text = render(mutated(VALID_REPORT, nasty), case_dir, case)
    assert_headings(text)
    assert "a \\| b" in text
    table_rows = [line for line in text.splitlines() if line.startswith("| H")]
    assert table_rows and all(row.replace("\\|", "").count("|") == table_rows[0].replace("\\|", "").count("|")
                              for row in table_rows)


def test_secret_never_appears_in_rendered_output(case_dir, case, findings, config):
    leaked = f"pass{'word'}={secret_value()}"
    report = mutated(VALID_REPORT, lambda r: r["actions"][0].update(change=f"Use {leaked}"))
    assert_problem(problems_for(report, case, findings, config), "actions[0].change")
    assert secret_value() not in render(report, case_dir, case)


# hypothesis cause key

@pytest.mark.parametrize("value", [None, "C1", "C2"])
def test_hypothesis_cause_may_be_null_a_cause_id_or_absent(case_dir, case, findings, config, value):
    report = mutated(VALID_REPORT, lambda r: r["hypotheses"][1].update(cause=value))
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []
    report = mutated(VALID_REPORT, lambda r: r["hypotheses"][1].pop("cause"))
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_hypothesis_cause_must_be_a_cause_id(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["hypotheses"][0].update(cause="C9"))
    assert_problem(problems_for(report, case, findings, config), "hypotheses[0].cause", "known cause id")
    report = mutated(VALID_REPORT, lambda r: r["hypotheses"][0].update(cause=3))
    assert_problem(problems_for(report, case, findings, config), "hypotheses[0].cause", "text or null")


# rules bound to the stored judgments

def test_recommended_action_needs_the_summary_to_recommend_it(case_dir, case, findings, config):
    actions = {**SUMMARY["actions"], "A1": {**SUMMARY["actions"]["A1"], "label": "candidate"}}
    store_summary(case_dir, summary_with(actions=actions))
    assert_problem(problems_for(VALID_REPORT, case, findings, config), "actions[0]", "recommended", "summary")


def test_recommended_action_missing_from_the_summary_is_a_problem(case_dir, case, findings, config):
    store_summary(case_dir, summary_with(actions={"A2": SUMMARY["actions"]["A2"]}))
    assert_problem(problems_for(VALID_REPORT, case, findings, config), "actions[0]", "not in")


def test_candidate_action_may_be_recommended_by_the_summary_without_a_problem(case_dir, case, findings, config):
    actions = {**SUMMARY["actions"], "A2": {**SUMMARY["actions"]["A2"], "label": "recommended"}}
    store_summary(case_dir, summary_with(actions=actions))
    assert problems_for(VALID_REPORT, case, findings, config) == []


def test_typesafe_must_equal_the_summary_value(case_dir, case, findings, config):
    store_summary(case_dir, summary_with(typesafe="unavailable: the connection failed", causes={
        "C1": {**SUMMARY["causes"]["C1"], "label": "probable"}}))
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(label="probable"))
    report["actions"] = [{**a, "label": "candidate"} for a in report["actions"]]
    assert_problem(problems_for(report, case, findings, config), "coverage.typesafe", "must equal")
    report["coverage"]["typesafe"] = "unavailable: the connection failed"
    assert problems_for(report, case, findings, config) == []


@pytest.mark.parametrize("verdict", ["contradicted", "unsupported"])
def test_finding_judged_against_the_claim_cannot_support_a_cause(case_dir, case, findings, config, verdict):
    judged = {**SUMMARY["findings"], "compute-2": {"relation": "contradicts", "confidence": 0.9, "verdict": verdict}}
    store_summary(case_dir, summary_with(findings=judged))
    def support(report):
        report["causes"][1].update(supporting=["compute-2"], contradicting=[])
    problems = problems_for(mutated(VALID_REPORT, support), case, findings, config)
    assert_problem(problems, "causes[1].supporting[0]", verdict)


def test_a_contradicted_finding_may_still_be_listed_as_contradicting(case_dir, case, findings, config):
    judged = {**SUMMARY["findings"], "compute-2": {"relation": "contradicts", "confidence": 0.9, "verdict": "contradicted"}}
    store_summary(case_dir, summary_with(findings=judged))
    assert problems_for(VALID_REPORT, case, findings, config) == []


def test_without_a_summary_typesafe_must_be_unavailable(case_dir, case, findings, config):
    remove_summary(case_dir)
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "coverage.typesafe", "unavailable: ")
    assert_problem(problems, "above candidate")
    report = mutated(UNRESOLVED_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: judging was not run"))
    assert problems_for(report, case, findings, config) == []


def test_a_summary_that_was_not_judged_counts_as_no_summary_for_the_rules(case_dir, case, findings, config):
    store_summary(case_dir, summary_with(judged=False, causes={}, actions={}, findings={}))
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "coverage.typesafe", "unavailable: ")
    assert_problem(problems, "above candidate")
    assert not any("judgments/summary.json" in problem for problem in problems)


def test_a_summary_without_the_judged_flag_is_not_trusted(case_dir, case, findings, config):
    summary = copy.deepcopy(SUMMARY)
    del summary["judged"]
    store_summary(case_dir, summary)
    assert_problem(problems_for(VALID_REPORT, case, findings, config), "coverage.typesafe", "unavailable: ")


# rendering with the judgments

def test_findings_show_verdict_and_confidence_when_the_summary_has_them(case_dir, case):
    findings = section(render(VALID_REPORT, case_dir, case), "## 4. Findings")
    assert "verified" in findings and "0.93" in findings and "supports" in findings


def test_causes_show_gates_reasons_probability_fit_and_scope(case_dir, case):
    causes = section(render(VALID_REPORT, case_dir, case), "## 5. Ranked causes")
    first, second = causes[:causes.index("### 2.")], causes[causes.index("### 2."):]
    assert "evidence" in first and "Gates not met: none" in first
    assert "0.72" in first and "0.83" in first and "matches" in first
    assert "Gates not met: rank, timing" in second and "Gates met: evidence, no_contradiction, symptom_fit, scope" in second
    assert "Ranking did not pick this cause in both orderings" in second and "No supporting finding has a time" in second
    assert "0.14" in second and "broader" in second


def test_actions_show_target_answer_and_candidate_reasons(case_dir, case):
    order = section(render(VALID_REPORT, case_dir, case), "## 6. Remediation work order")
    first, second = order[:order.index("### A2")], order[order.index("### A2"):]
    assert "addresses_cause" in first and "0.9" in first
    assert "partly_addresses_cause" in second and "The cause is labelled candidate, not confirmed" in second


def test_coverage_states_typesafe_engineer_questions_and_adhoc_entries(case_dir, case):
    coverage = section(render(VALID_REPORT, case_dir, case), "## 7. Coverage notes")
    assert "TypeSafe: available (model jev-test); thresholds are uncalibrated" in coverage
    assert "The ranking changed with the order of the options" in coverage
    assert "deploy_trigger" in coverage and "No fixed question covers deploy timing" in coverage


def test_unavailable_summary_is_stated_with_its_reason_and_empty_gates_render(case_dir, case):
    causes = {"C1": {"label": "probable", "gates": {}, "rank_probability": None, "symptom_fit": None,
                     "scope": None, "reasons": ["TypeSafe was unavailable"]}}
    store_summary(case_dir, summary_with(typesafe="unavailable: the connection failed", model=None,
                                         findings={}, causes=causes, actions={}, ask_engineer=[], adhoc=[]))
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: the connection failed"))
    text = render(report, case_dir, case)
    assert "TypeSafe: unavailable: the connection failed" in section(text, "## 7. Coverage notes")
    assert "TypeSafe was unavailable" in section(text, "## 5. Ranked causes")


def test_rendering_without_a_summary_still_works(case_dir, case):
    remove_summary(case_dir)
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: judging was not run"))
    text = render(report, case_dir, case)
    assert_headings(text)
    assert "TypeSafe: unavailable: judging was not run" in section(text, "## 7. Coverage notes")
    assert "Gates" not in text


def test_adhoc_entries_of_an_unjudged_summary_are_still_rendered(case_dir, case):
    store_summary(case_dir, summary_with(judged=False, causes={}, actions={}, findings={}, ask_engineer=[]))
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: judging was not run"))
    text = render(report, case_dir, case)
    assert "No fixed question covers deploy timing" in section(text, "## 7. Coverage notes")
    assert "Gates" not in text and "verified" not in text
    assert "TypeSafe: unavailable: judging was not run" in section(text, "## 7. Coverage notes")


# fail closed on a malformed judgments summary

@pytest.mark.parametrize("break_label", [
    lambda entry: entry.pop("label"),
    lambda entry: entry.update(label=None),
    lambda entry: entry.update(label="Confirmed"),
    lambda entry: entry.update(label=["confirmed"]),
], ids=["missing", "null", "case", "list"])
def test_a_cause_entry_with_a_bad_label_counts_as_candidate_and_is_a_problem(case_dir, case, findings, config, break_label):
    summary = copy.deepcopy(SUMMARY)
    break_label(summary["causes"]["C1"])
    store_summary(case_dir, summary)
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "causes[0]", "missing or invalid label")
    assert_problem(problems, "causes[0]", "stronger than the judged label candidate")


def test_a_recommended_action_whose_summary_label_is_invalid_is_a_problem(case_dir, case, findings, config):
    summary = copy.deepcopy(SUMMARY)
    summary["actions"]["A1"]["label"] = "Recommended"
    store_summary(case_dir, summary)
    assert_problem(problems_for(VALID_REPORT, case, findings, config), "actions[0]", "missing or invalid label")


def test_a_cited_finding_with_an_invalid_verdict_is_a_problem(case_dir, case, findings, config):
    summary = copy.deepcopy(SUMMARY)
    summary["findings"]["compute-1"]["verdict"] = "Verified"
    store_summary(case_dir, summary)
    assert_problem(problems_for(VALID_REPORT, case, findings, config), "causes[0].supporting[0]", "verdict")


# validation never raises

WRONG_TYPES = [["C1"], {"a": 1}, None, 5, True]
POSITIONS = [
    lambda r, v: r["causes"][0].update(id=v),
    lambda r, v: r["causes"][0].update(label=v),
    lambda r, v: r["summary"].update(top_cause=v),
    lambda r, v: r["actions"][0].update(cause=v),
    lambda r, v: r["actions"][0].update(id=v),
    lambda r, v: r["actions"][0].update(finding_ids=[v]),
    lambda r, v: r["actions"][0]["target"].update(account_alias=v),
    lambda r, v: r["causes"][0].update(supporting=[v]),
    lambda r, v: r["causes"][1].update(contradicting=[v]),
    lambda r, v: r["hypotheses"][0].update(finding_ids=[v]),
    lambda r, v: r["hypotheses"][0].update(cause=v),
    lambda r, v: r["hypotheses"][0].update(id=v),
    lambda r, v: r["hypotheses"][0].update(result=v),
    lambda r, v: r.update(status=v),
    lambda r, v: r["coverage"].update(typesafe=v),
    lambda r, v: r["coverage"].update(not_checked=[v]),
]


@pytest.mark.parametrize("value", WRONG_TYPES, ids=["list", "dict", "null", "number", "bool"])
@pytest.mark.parametrize("position", range(len(POSITIONS)))
def test_a_wrong_type_is_reported_and_never_raises(case, findings, config, position, value):
    report = copy.deepcopy(VALID_REPORT)
    POSITIONS[position](report, value)
    problems = problems_for(report, case, findings, config)
    assert isinstance(problems, list)
    assert problems or (position == 10 and value is None)  # a null hypothesis cause is valid
    assert all(isinstance(problem, str) for problem in problems)


@pytest.mark.parametrize("value", WRONG_TYPES, ids=["list", "dict", "null", "number", "bool"])
def test_wrong_types_with_a_summary_and_unresolved_status_never_raise(case, findings, config, value):
    for position in range(len(POSITIONS)):
        report = copy.deepcopy(UNRESOLVED_REPORT)
        try:
            POSITIONS[position](report, value)
        except (KeyError, IndexError):
            continue
        assert isinstance(problems_for(report, case, findings, config), list)


# problems never repeat a report value

def aws_key():
    return "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])


@pytest.mark.parametrize("position", [
    lambda r, v: r["summary"].update(top_cause=v),
    lambda r, v: r["actions"][0].update(cause=v),
    lambda r, v: r["actions"][0]["target"].update(account_alias=v),
    lambda r, v: r["causes"][0]["supporting"].append(v),
    lambda r, v: r["hypotheses"][0].update(cause=v),
    lambda r, v: r["causes"].append({**copy.deepcopy(r["causes"][1]), "id": "C1", "statement": v}),
    lambda r, v: r["coverage"].update(typesafe=v),
    lambda r, v: r["causes"][0].update(id=v),
    lambda r, v: r["actions"][0].update(finding_ids=[v]),
    lambda r, v: r.update(map_changes=[{v: v}]),
    lambda r, v: r.update(unexpected={v: [v]}),
], ids=["top_cause", "action_cause", "alias", "supporting", "hyp_cause", "duplicate", "typesafe", "cause_id",
        "action_finding", "map_key", "unknown_key"])
def test_problems_never_echo_a_value_from_the_report(case, findings, config, position):
    secret = aws_key()
    report = copy.deepcopy(VALID_REPORT)
    position(report, secret)
    problems = problems_for(report, case, findings, config)
    assert problems
    assert not any(secret in problem for problem in problems), problems


def test_a_secret_dict_key_is_reported_by_its_parent_not_its_value(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r.update(map_changes=[{aws_key(): "x"}]))
    problems = problems_for(report, case, findings, config)
    assert_problem(problems, "a key under map_changes[0]", "secret")
    assert not any(aws_key() in problem for problem in problems)


def test_a_very_long_value_is_not_echoed(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["summary"].update(top_cause="X" * 5000))
    assert all(len(problem) < 300 for problem in problems_for(report, case, findings, config))


# ids

@pytest.mark.parametrize("bad", ["C 1", "C1\n## 9. Run details", "", "-C1", "a" * 129, "C1|x", "../C1"])
@pytest.mark.parametrize("where", [
    lambda r, v: r["causes"][1].update(id=v),
    lambda r, v: r["actions"][1].update(id=v),
    lambda r, v: r["hypotheses"][1].update(id=v),
    lambda r, v: r["causes"][0]["supporting"].append(v),
    lambda r, v: r["actions"][0]["finding_ids"].append(v),
])
def test_ids_must_match_the_pattern(case, findings, config, bad, where):
    report = copy.deepcopy(VALID_REPORT)
    where(report, bad)
    assert any("not a valid id" in problem for problem in problems_for(report, case, findings, config))


@pytest.mark.parametrize("good", ["a", "ecs-prod-main-eu-west-1:ecs-0001", "A_1.2", "0abc"])
def test_valid_ids_are_accepted(case_dir, case, findings, config, good):
    report = mutated(VALID_REPORT, lambda r: r["causes"][1].update(id=good))
    report["hypotheses"][1]["cause"] = good
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_a_finding_id_with_a_newline_cannot_inject_a_heading(case_dir, case):
    findings = {"compute-9\n## 9. Run details": {"id": "compute-9\n## 9. Run details", "analyst": "compute",
                                                  "claim": "c", "fact_ids": [], "provenance": "current",
                                                  "confidence": "low"}}
    text = render_report(UNRESOLVED_REPORT, case, findings, [], [], RENDERED_AT)
    assert_headings(text)


def test_ids_are_collapsed_when_rendering_even_without_validation(case_dir, case):
    def nasty(report):
        report["causes"][1]["id"] = "C2\n## 9. Run details"
        report["actions"][1]["id"] = "A2\n## 8. Proposed service map changes"
        report["summary"]["top_cause"] = "C1\n## 1. Summary"
    assert_headings(render(mutated(VALID_REPORT, nasty), case_dir, case))


# minor rules

def test_an_action_may_not_cite_a_contradicted_finding(case_dir, case, findings, config):
    judged = {**SUMMARY["findings"], "compute-2": {"relation": "contradicts", "confidence": 0.9, "verdict": "contradicted"}}
    store_summary(case_dir, summary_with(findings=judged))
    report = mutated(VALID_REPORT, lambda r: r["actions"][0]["finding_ids"].append("compute-2"))
    assert_problem(problems_for(report, case, findings, config), "actions[0].finding_ids[1]", "contradicted")


def test_an_action_may_cite_an_unsupported_finding(case_dir, case, findings, config):
    judged = {**SUMMARY["findings"], "compute-2": {"relation": "says_nothing", "confidence": 0.9, "verdict": "unsupported"}}
    store_summary(case_dir, summary_with(findings=judged))
    report = mutated(VALID_REPORT, lambda r: r["actions"][0]["finding_ids"].append("compute-2"))
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_cause_found_needs_a_confirmed_hypothesis_of_the_top_cause(case, findings, config):
    def move(report):
        report["hypotheses"][0]["cause"] = "C2"
    assert_problem(problems_for(mutated(VALID_REPORT, move), case, findings, config), "confirmed hypothesis", "top cause")


def test_duplicate_ids_do_not_hide_later_problems(case, findings, config):
    def duplicate(report):
        report["causes"].append({**report["causes"][1], "id": "C1", "label": "confirmed", "supporting": []})
    problems = problems_for(mutated(VALID_REPORT, duplicate), case, findings, config)
    assert_problem(problems, "causes[2].id", "duplicate")
    assert_problem(problems, "causes[2]", "no supporting finding")


def test_work_order_rejects_keys_outside_the_contract(case, case_dir):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT, checked=checked_findings(case_dir))
    cases = [
        lambda o: o.update(extra=1),
        lambda o: o["incident"].update(extra=1),
        lambda o: o["cause"].update(extra=1),
        lambda o: o["actions"][0].update(extra=1),
        lambda o: o["causes"][0].update(extra=1),
        lambda o: o["findings"][0].update(extra=1),
        lambda o: o["actions"][0]["target"].update(extra=1),
    ]
    for break_it in cases:
        broken = copy.deepcopy(order)
        break_it(broken)
        assert_problem(validate_work_order(broken), "not in the work order contract")


def test_build_work_order_copies_only_contract_keys_of_an_action(case):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0].update(notes="x"))
    order = build_work_order(report, case, RENDERED_AT)
    assert "notes" not in order["actions"][0] and validate_work_order(order) == []


# labels are bound to what was judged

def edited_problems(problems, path):
    assert_problem(problems, path, "edited after judging", "run the judgments again")


def test_a_report_that_matches_what_was_judged_passes(case, findings, config):
    assert problems_for(VALID_REPORT, case, findings, config) == []


def test_a_rewritten_cause_statement_fails(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(statement="The payments database ran out of connections"))
    problems = problems_for(report, case, findings, config)
    edited_problems(problems, "causes[0]")
    assert_problem(problems, "causes[0]", "stronger than", "candidate")
    assert_problem(problems, "actions[0]", "recommended", "cause was edited")


def test_an_unjudged_supporting_finding_fails(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0]["supporting"].append("compute-2"))
    edited_problems(problems_for(report, case, findings, config), "causes[0]")


def test_a_changed_action_change_and_target_fail(case, findings, config):
    def edit(report):
        report["actions"][0]["change"] = "Reboot the RDS instance payments-prod"
        report["actions"][0]["target"] = {**ACTION_TARGET, "resource_id": "payments-prod"}
    problems = problems_for(mutated(VALID_REPORT, edit), case, findings, config)
    edited_problems(problems, "actions[0]")
    assert_problem(problems, "actions[0]", "recommended", "edited after judging")


def test_a_changed_action_target_alone_fails(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["actions"][1]["target"].update(resource_id="other/service"))
    edited_problems(problems_for(report, case, findings, config), "actions[1]")


def test_swapping_the_statements_of_two_causes_fails(case, findings, config):
    def swap(report):
        first, second = report["causes"][0]["statement"], report["causes"][1]["statement"]
        report["causes"][0]["statement"], report["causes"][1]["statement"] = second, first
    problems = problems_for(mutated(VALID_REPORT, swap), case, findings, config)
    edited_problems(problems, "causes[0]")
    edited_problems(problems, "causes[1]")


def test_a_changed_claim_of_a_cited_finding_fails(case_dir, case, config):
    path = case_dir / "findings" / "checked.json"
    checked = json.loads(path.read_text())
    for item in checked["valid"]:
        if item["id"] == "compute-1":
            item["claim"] = "The database was restarted"
    path.write_text(json.dumps(checked))
    edited_problems(problems_for(VALID_REPORT, case, valid_findings(case_dir), config), "causes[0]")


@pytest.mark.parametrize("digest", ["missing", None, 5, ["x"]])
def test_a_missing_or_invalid_stored_digest_fails(case_dir, case, findings, config, digest):
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    for entry in [*summary["causes"].values(), *summary["actions"].values()]:
        if digest == "missing":
            entry.pop("digest", None)
        else:
            entry["digest"] = digest
    store_summary(case_dir, summary, digests=False)
    problems = problems_for(VALID_REPORT, case, findings, config)
    for path in ("causes[0]", "causes[1]", "actions[0]", "actions[1]"):
        edited_problems(problems, path)


def test_only_labels_and_reasons_may_change_after_judging(case_dir, case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(label="probable"))
    report["actions"][0].update(label="candidate")
    assert problems_for(report, case, findings, config) == []
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    summary["causes"]["C2"]["reasons"] = ["Something else"]
    store_summary(case_dir, summary, digests=False)
    assert problems_for(report, case, findings, config) == []


def test_judging_again_after_an_edit_restores_the_label(case_dir, case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(statement="A reworded statement of the same cause"))
    assert problems_for(report, case, findings, config) != []
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_an_unjudged_summary_has_no_digests_to_check(case_dir, case, findings, config):
    store_summary(case_dir, summary_with(judged=False, causes={}, actions={}, findings={}), digests=False)
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert not any("edited after judging" in problem for problem in problems)


@pytest.mark.parametrize("edit", [
    lambda r: r["causes"][0].update(statement="A different cause entirely"),
    lambda r: r["causes"][0]["supporting"].append("compute-2"),
    lambda r: r["actions"][0].update(change="Delete the production database"),
    lambda r: r["actions"][0]["target"].update(service="payments-api"),
])
def test_an_edited_report_is_never_rendered_as_confirmed_or_recommended(skill_dir, case_dir, edit):
    report = copy.deepcopy(VALID_REPORT)
    edit(report)
    (case_dir / "report.json").write_text(json.dumps(report))
    result = subprocess.run([sys.executable, str(SKILL_SRC / "scripts" / "report.py"), "render", "--case-dir", str(case_dir),
                             "--skill-dir", str(skill_dir)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "edited after judging" in result.stderr
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()


@pytest.fixture
def skill_dir(tmp_path, config_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "digest-skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return root


# what was checked, and unreadable inputs

def write_checked(case_dir, **changes):
    path = case_dir / "findings" / "checked.json"
    checked = json.loads(path.read_text())
    checked.update(changes)
    path.write_text(json.dumps(checked))


def empty_report(report):
    report["causes"], report["hypotheses"], report["actions"], report["map_changes"] = [], [], [], []
    report["status"], report["summary"]["top_cause"] = "unresolved", None


def test_empty_sections_say_what_the_analysts_checked(case_dir, case):
    write_checked(case_dir, checked={"compute": ["ECS service events", "stopped tasks"], "edge": ["Load balancer health"]})
    text = render(mutated(VALID_REPORT, empty_report), case_dir, case)
    for heading in ("## 5. Ranked causes", "## 6. Remediation work order"):
        body = section(text, heading)
        assert "ECS service events; stopped tasks" in body and "Load balancer health" in body, heading
        assert "compute" in body and "edge" in body


def test_empty_findings_say_what_was_checked(case_dir, case):
    write_checked(case_dir, valid=[], checked={"compute": ["ECS service events"]})
    findings = section(render_report(UNRESOLVED_REPORT, case, {}, build_timeline(case_dir), [], RENDERED_AT), "## 4. Findings")
    assert findings.strip().startswith("None.") and "ECS service events" in findings


def test_none_alone_says_that_nothing_was_recorded(case_dir, case):
    write_checked(case_dir, checked={})
    text = render(mutated(VALID_REPORT, empty_report), case_dir, case)
    assert "None. No checks were recorded." in section(text, "## 5. Ranked causes")


def test_an_unreadable_evidence_file_is_a_coverage_gap(case_dir, case):
    (case_dir / "evidence" / "rds-prod-main-eu-west-1.json").write_text("{broken")
    gaps = coverage_from_evidence(case_dir)
    unreadable = next(gap for gap in gaps if gap["code"] == "unreadable")
    assert [entry["file"] for entry in unreadable["entries"]] == ["rds-prod-main-eu-west-1.json"]
    assert "rds-prod-main-eu-west-1.json" in section(render(VALID_REPORT, case_dir, case), "## 7. Coverage notes")


def test_unreadable_finding_files_and_check_warnings_are_listed(case_dir, case):
    write_checked(case_dir, unreadable=[{"file": "findings/network.json", "reason": "not valid JSON"}],
                  warnings=["a fact in x.json has no text id and was skipped"])
    coverage = section(render(VALID_REPORT, case_dir, case), "## 7. Coverage notes")
    assert "findings/network.json" in coverage and "not valid JSON" in coverage
    assert "a fact in x.json has no text id and was skipped" in coverage


def test_the_findings_section_shows_the_checks_next_to_the_findings(case_dir, case):
    write_checked(case_dir, checked={"compute": ["ECS service events"]})
    assert "ECS service events" in section(render(VALID_REPORT, case_dir, case), "## 4. Findings")


# round 2: what is written into report.md

def checked_findings(case_dir):
    return json.loads((case_dir / "findings" / "checked.json").read_text())


def add_checked_finding(case_dir, **overrides):
    checked = checked_findings(case_dir)
    entry = {**checked["valid"][0], "id": "compute-4", "claim": "Uncited claim", "fact_ids": ["ecs-0001"], **overrides}
    checked["valid"].append(entry)
    (case_dir / "findings" / "checked.json").write_text(json.dumps(checked))


def test_a_finding_with_a_forged_id_or_fact_id_is_a_problem_and_is_not_rendered(case_dir, case, config):
    forged = "nope\n## 9. Run details\n\n# Forged"
    add_checked_finding(case_dir, fact_ids=[forged])
    add_checked_finding(case_dir, id="compute-5\n## 9. Run details")
    findings, problems = check_case_inputs(case_dir)
    assert any("valid[2]" in problem and "id" in problem for problem in problems), problems
    assert any("valid[3]" in problem for problem in problems), problems
    assert not any("Forged" in problem or "Run details" in problem for problem in problems)
    assert set(findings) == {"compute-1", "compute-2"}
    text = render_report(VALID_REPORT, case, {**findings, "x": {"id": forged, "analyst": "a", "claim": "c", "fact_ids": [],
                                                           "provenance": "current", "confidence": "low"}},
                         build_timeline(case_dir), [], RENDERED_AT)
    assert_headings(text) and "Forged" not in text


def test_a_forged_fact_id_in_an_evidence_file_is_a_problem_and_cannot_reach_a_heading(case_dir, case):
    path = next((case_dir / "evidence").glob("ecs-*.json"))
    document = json.loads(path.read_text())
    document["facts"][0]["id"] = "ecs-0001\n## 9. Run details"
    document["facts"][0]["time"] = "t\n## 8. Proposed service map changes"
    path.write_text(json.dumps(document))
    _, problems = check_case_inputs(case_dir)
    assert any("evidence" in problem and "valid id" in problem for problem in problems), problems
    findings = {"compute-1": {"id": "compute-1", "analyst": "compute", "claim": "c", "provenance": "current",
                              "confidence": "low", "fact_ids": [document["facts"][0]["id"]]}}
    assert_headings(render_report(VALID_REPORT, case, findings, [], [], RENDERED_AT))


def test_a_fact_time_is_reformatted_in_utc_or_reads_unreadable(case_dir, case, findings):
    path = next((case_dir / "evidence").glob("ecs-*.json"))
    document = json.loads(path.read_text())
    document["facts"][0]["time"] = "2026-10-04T12:41:00+02:00"
    document["facts"][1]["time"] = "yesterday\n## 9. Run details"
    path.write_text(json.dumps(document))
    both = {**findings, "compute-2": {**findings["compute-2"], "fact_ids": ["ecs-prod-main-eu-west-1:ecs-0002"]}}
    text = render_report(VALID_REPORT, case, both, [], [], RENDERED_AT)
    assert "time 2026-10-04T10:41:00Z" in text and "unreadable time" in text
    assert_headings(text)


def test_angle_brackets_and_links_in_report_text_cannot_make_html_or_a_link(case_dir, case):
    def nasty(report):
        report["summary"]["what_broke"] = "<script>alert(1)</script> see [x](javascript:alert(1)) and <!-- hide"
        report["causes"][0]["statement"] = "<b>bold</b> [a](http://example.com)"
    text = render(mutated(VALID_REPORT, nasty), case_dir, case)
    assert "<script>" not in text and "<b>" not in text and "<!--" not in text
    assert "](" not in text
    assert "&lt;script&gt;" in text


def test_angle_brackets_in_timeline_rows_are_escaped(case_dir, case):
    rows = [{"time": "2026-10-04T10:41:00+00:00", "offset": "1 minute before", "text": "<img src=x> and [a](b)",
             "source": "ecs", "fact_id": None, "resource": ""}]
    text = render_report(VALID_REPORT, case, valid_findings(case_dir), rows, [], RENDERED_AT)
    timeline = section(text, "## 3. Timeline")
    assert "<img" not in timeline and "](" not in timeline and "2026-10-04 10:41:00Z" in timeline


def test_the_verdict_line_comes_after_the_cited_facts(case_dir, case):
    findings = section(render(VALID_REPORT, case_dir, case), "## 4. Findings")
    lines = findings.splitlines()
    verdict = next(i for i, line in enumerate(lines) if line.startswith("- TypeSafe verdict"))
    fact = max(i for i, line in enumerate(lines[:verdict]) if line.startswith("  - "))
    assert fact < verdict
    assert not lines[verdict].startswith("  ")


# round 2: shape of the stored inputs

@pytest.mark.parametrize("change", [
    {"findings": [1]}, {"actions": [1]}, {"causes": {"C1": 5}}, {"adhoc": 5}, {"ask_engineer": 5}, {"typesafe": 5},
    {"findings": {"compute-1": 5}}, {"model": 5},
    {"causes": {"C1": {**SUMMARY["causes"]["C1"], "reasons": 5}}},
    {"causes": {"C1": {**SUMMARY["causes"]["C1"], "gates": [1]}}},
    {"causes": {"C1": {**SUMMARY["causes"]["C1"], "rank_probability": "high"}}},
    {"actions": {"A1": {**SUMMARY["actions"]["A1"], "reasons": [5]}}},
    {"adhoc": [5]}, {"ask_engineer": [5]},
])
def test_a_malformed_summary_is_a_list_of_problems_never_a_crash(case_dir, case, findings, config, change):
    store_summary(case_dir, summary_with(**change), digests=False)
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert isinstance(problems, list) and any("judgments/summary.json" in problem for problem in problems)


@pytest.mark.parametrize("checked", [
    [1], {"valid": {"a": 1}}, {"valid": [1]}, {"valid": [{"claim": "no id"}]},
    {"valid": [{"id": "compute-1"}]}, {"rejected": 5}, {"rejected": [5]}, {"unreadable": 5}, {"warnings": 5},
    {"checked": 5}, {"checked": {"a": 5}}, {"valid": [], "warnings": [5]},
])
def test_a_malformed_checked_json_is_a_list_of_problems_never_a_crash(case_dir, checked):
    (case_dir / "findings" / "checked.json").write_text(json.dumps(checked))
    findings, problems = check_case_inputs(case_dir)
    assert isinstance(findings, dict) and any("checked.json" in problem for problem in problems)


def test_an_unparseable_checked_json_is_a_problem(case_dir):
    (case_dir / "findings" / "checked.json").write_text("{nope")
    assert any("checked.json" in problem for problem in check_case_inputs(case_dir)[1])


def test_a_missing_checked_json_is_not_a_problem(case_dir):
    (case_dir / "findings" / "checked.json").unlink()
    assert check_case_inputs(case_dir) == ({}, [])


def test_wellformed_inputs_have_no_problems(case_dir):
    findings, problems = check_case_inputs(case_dir)
    assert problems == [] and set(findings) == {"compute-1", "compute-2"}


# round 2: nothing above candidate without a judging run

def test_without_a_summary_every_cause_is_capped_at_candidate(case_dir, case, findings, config):
    remove_summary(case_dir)
    def probable(report):
        report["coverage"]["typesafe"] = "unavailable: x"
        report["causes"][0]["label"] = "probable"
        report["actions"] = [{**a, "label": "candidate"} for a in report["actions"]]
    problems = problems_for(mutated(VALID_REPORT, probable), case, findings, config)
    assert_problem(problems, "causes[0]", "no judging run", "candidate")


def test_without_a_summary_candidate_causes_are_fine_when_unresolved(case_dir, case, findings, config):
    remove_summary(case_dir)
    report = mutated(UNRESOLVED_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: judging was not run"))
    assert problems_for(report, case, findings, config) == []


def test_a_stale_summary_never_counts(case_dir, case, findings, config):
    (case_dir / "judgments" / "summary.json").rename(case_dir / "judgments" / "summary.json.stale")
    def probable(report):
        report["coverage"]["typesafe"] = "unavailable: x"
        report["causes"][0]["label"] = "probable"
        report["actions"] = [{**a, "label": "candidate"} for a in report["actions"]]
    assert_problem(problems_for(mutated(VALID_REPORT, probable), case, findings, config), "causes[0]", "no judging run")


def test_a_deleted_summary_cannot_promote_a_cause_judged_candidate(case_dir, case, findings, config):
    remove_summary(case_dir)
    def promote(report):
        report["coverage"]["typesafe"] = "unavailable: x"
        report["summary"]["top_cause"] = "C2"
        report["causes"][1].update(label="probable", supporting=["compute-2"], contradicting=[])
        report["hypotheses"][1]["result"] = "confirmed"
    assert problems_for(mutated(VALID_REPORT, promote), case, findings, config) != []


# round 2: hypotheses without a cause

def test_a_causeless_confirmed_hypothesis_counts_only_with_exactly_one_cause(case_dir, case, findings, config):
    def single(report):
        report["causes"] = report["causes"][:1]
        report["hypotheses"] = [{**report["hypotheses"][0], "cause": None}]
        report["actions"] = report["actions"][:1]
    one = mutated(VALID_REPORT, single)
    rejudge(case_dir, one)
    assert problems_for(one, case, findings, config) == []
    two = mutated(VALID_REPORT, lambda r: r["hypotheses"][0].update(cause=None))
    assert_problem(problems_for(two, case, findings, config), "confirmed hypothesis", "top cause")


# round 2: depth

def test_a_report_nested_deeper_than_fifty_levels_is_a_problem(case, findings, config):
    nested = value = []
    for _ in range(60):
        inner = []
        value.append(inner)
        value = inner
    report = mutated(VALID_REPORT, lambda r: r.update(map_changes=[nested]))
    assert problems_for(report, case, findings, config) == ["report: nested deeper than 50 levels"]


def test_a_report_at_fifty_levels_is_not_refused_for_depth(case, findings, config):
    nested = value = []
    for _ in range(40):
        inner = []
        value.append(inner)
        value = inner
    report = mutated(VALID_REPORT, lambda r: r.update(map_changes=[nested]))
    assert "nested deeper" not in " ".join(problems_for(report, case, findings, config))


# round 2: the work order lists unreadable finding files

def test_unreadable_finding_files_are_work_order_coverage_gaps(case_dir, case):
    write_checked(case_dir, unreadable=[{"file": "findings/network.json", "reason": "not valid JSON"}])
    gaps = build_work_order(VALID_REPORT, case, RENDERED_AT, checked=checked_findings(case_dir))["coverage_gaps"]
    assert "Finding file not read: findings/network.json (not valid JSON)" in gaps


# round 2, N1: the report is bound to the whole judged draft (the summary comes from the real judging code)

import random

from fakes import FakeJudge
from test_judge import QUESTIONS, make_responder
from triage.judge import run_judgments


@pytest.fixture
def judged(case_dir, case, config):
    """The case judged by run_judgments with a fake judge: C1 confirmed, C2 candidate, A1 recommended."""
    write_findings(case_dir, [
        {"id": "compute-1", "claim": "Containers exit with code 137", "fact_ids": ["ecs-0001"], "excerpt": "exit code 137",
         "provenance": "incident_time", "confidence": "high", "time": "2026-10-04T10:41:10Z"},
        {"id": "compute-2", "claim": "Service is down now", "fact_ids": ["ecs-0002"],
         "excerpt": "desired 2, running 0", "provenance": "current", "confidence": "medium"},
    ])
    check_findings(case_dir)
    (case_dir / "report.json").write_text(json.dumps(VALID_REPORT))
    summary = run_judgments(case_dir, config, FakeJudge(make_responder()), QUESTIONS, random.Random(1))
    assert summary["status"] == "complete" and summary["causes"]["C1"]["label"] == "confirmed", summary
    assert summary["actions"]["A1"]["label"] == "recommended"
    return case_dir


def judged_problems(judged, config, report=VALID_REPORT):
    findings, input_problems = check_case_inputs(judged)
    return input_problems + validate_report(report, load_case(judged), findings, config)


def stored_summary(case_dir):
    return json.loads((case_dir / "judgments" / "summary.json").read_text())


def test_the_judged_draft_validates(judged, config):
    assert judged_problems(judged, config) == []


def assert_draft_refused(problems):
    assert_problem(problems, "draft", "changed after judging", "run the judgments again")
    assert_problem(problems, "causes[0]", "stronger than candidate")


@pytest.mark.parametrize("edit", [
    lambda r: r.update(symptoms=["Payments API returns 500 for every request"]),
    lambda r: r["summary"].update(scope="All services in all regions were affected"),
    lambda r: r["causes"].append({"id": "C3", "statement": "A third cause", "label": "candidate",
                                  "supporting": [], "contradicting": []}),
    lambda r: r["causes"][1].update(statement="A different competing cause"),
    lambda r: r["causes"][1].update(contradicting=["compute-2", "compute-1"]),
    lambda r: r["causes"].reverse() or r["causes"].reverse() or r["causes"].pop(1),
], ids=["symptoms", "scope", "added_cause", "competing_statement", "competing_findings", "removed_cause"])
def test_a_changed_draft_caps_every_label_at_candidate(judged, config, edit):
    report = mutated(VALID_REPORT, edit)
    assert_draft_refused(judged_problems(judged, config, report))


def test_a_changed_action_title_caps_every_action(judged, config):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0].update(title="Raise the memory limit of checkout-api now"))
    problems = judged_problems(judged, config, report)
    assert_problem(problems, "actions[0]", "recommended")
    assert_problem(problems, "draft", "changed after judging")


def test_a_changed_finding_time_in_checked_json_fails(judged, config):
    path = judged / "findings" / "checked.json"
    checked = json.loads(path.read_text())
    for item in checked["valid"]:
        if item["id"] == "compute-1":
            item["time"] = "2026-10-04T11:30:00Z"
    path.write_text(json.dumps(checked))
    assert_problem(judged_problems(judged, config), "causes[0]", "edited after judging")


def test_a_summary_copied_from_another_case_fails(judged, config):
    summary = stored_summary(judged)
    findings, _ = check_case_inputs(judged)
    summary["draft_digest"] = draft_digest(VALID_REPORT, findings, "INC-999/20260101-000000")
    store_summary(judged, summary, digests=False)
    assert_draft_refused(judged_problems(judged, config))


@pytest.mark.parametrize("digest", ["missing", None, 5, ["x"]])
def test_a_missing_or_invalid_draft_digest_fails(judged, config, digest):
    summary = stored_summary(judged)
    if digest == "missing":
        del summary["draft_digest"]
    else:
        summary["draft_digest"] = digest
    store_summary(judged, summary, digests=False)
    assert_draft_refused(judged_problems(judged, config))


def test_a_label_only_edit_still_passes(judged, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(label="probable"))
    report["actions"][0]["label"] = "candidate"
    assert judged_problems(judged, config, report) == []


def test_a_changed_hypothesis_or_open_question_changes_the_draft(judged, config):
    def edit(report):
        report["hypotheses"][0]["test"] = "Read the stopped task reasons again"
        report["open_questions"] = ["Another question"]
    assert_problem(judged_problems(judged, config, mutated(VALID_REPORT, edit)), "draft", "changed after judging")


def test_the_draft_digest_is_recomputed_with_this_cases_identity(judged):
    findings, _ = check_case_inputs(judged)
    assert stored_summary(judged)["draft_digest"] == draft_digest(VALID_REPORT, findings, case_identity(load_case(judged)))


# status

def with_status(judged, status, **changes):
    summary = stored_summary(judged)
    summary.update(changes)
    if status == "missing":
        summary.pop("status", None)
    else:
        summary["status"] = status
    store_summary(judged, summary, digests=False)


@pytest.mark.parametrize("status", ["failed", "missing", "weird", None, 5])
def test_any_status_but_complete_or_unavailable_caps_everything_at_candidate(judged, config, status):
    with_status(judged, status)
    problems = judged_problems(judged, config)
    assert_problem(problems, "causes[0]", "stronger than candidate")
    assert_problem(problems, "actions[0]", "recommended")


@pytest.fixture
def failed_run(case_dir, case, config):
    """A real judging run that failed: the fake judge answers every call with nothing."""
    write_findings(case_dir, [
        {"id": "compute-1", "claim": "Containers exit with code 137", "fact_ids": ["ecs-0001"], "excerpt": "exit code 137",
         "provenance": "incident_time", "confidence": "high", "time": "2026-10-04T10:41:10Z"},
        {"id": "compute-2", "claim": "Service is down now", "fact_ids": ["ecs-0002"],
         "excerpt": "desired 2, running 0", "provenance": "current", "confidence": "medium"},
    ])
    check_findings(case_dir)
    (case_dir / "report.json").write_text(json.dumps(VALID_REPORT))
    (case_dir / "report.json").write_text(json.dumps(all_candidate_report("available")))
    summary = run_judgments(case_dir, config, FakeJudge(lambda state, questions: {}), QUESTIONS, random.Random(1))
    assert summary["status"] == "failed" and summary["typesafe"].startswith("failed: "), summary
    return case_dir


def all_candidate_report(typesafe, cause_label="candidate"):
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe=typesafe))
    report["status"], report["summary"]["top_cause"] = "unresolved", None
    for hypothesis in report["hypotheses"]:
        hypothesis["result"] = "inconclusive"
    for cause in report["causes"]:
        cause["label"] = cause_label if cause["id"] == "C1" else "candidate"
    report["actions"] = [{**a, "label": "candidate"} for a in report["actions"]]
    return report


def test_a_report_with_every_label_candidate_validates_and_renders_after_a_failed_run(failed_run, config):
    typesafe = stored_summary(failed_run)["typesafe"]
    report = all_candidate_report(typesafe)
    assert judged_problems(failed_run, config, report) == []
    case = load_case(failed_run)
    findings, _ = check_case_inputs(failed_run)
    text = render_report(report, case, findings, build_timeline(failed_run), [], RENDERED_AT)
    assert_headings(text)
    assert f"TypeSafe: {typesafe}" in section(text, "## 7. Coverage notes")
    assert "(confirmed)" not in text and "(probable)" not in text
    assert any("TypeSafe failed: " in gap for gap in build_work_order(report, case, RENDERED_AT)["coverage_gaps"])


@pytest.mark.parametrize("label", ["probable", "confirmed"])
def test_any_label_above_candidate_is_a_problem_after_a_failed_run(failed_run, config, label):
    report = all_candidate_report(stored_summary(failed_run)["typesafe"], cause_label=label)
    problems = judged_problems(failed_run, config, report)
    assert_problem(problems, "causes[0]", "stronger than candidate")
    assert_problem(problems, "causes[0]", "TypeSafe", "failed")


def test_a_failed_typesafe_value_must_equal_the_summarys(failed_run, config):
    report = all_candidate_report("failed: something else")
    assert_problem(judged_problems(failed_run, config, report), "coverage.typesafe", "must equal")


def test_a_failed_typesafe_value_without_a_summary_is_refused(case_dir, case, findings, config):
    remove_summary(case_dir)
    report = all_candidate_report("failed: judging failed")
    assert_problem(problems_for(report, case, findings, config), "coverage.typesafe", "no judging run")


def test_an_unavailable_status_follows_the_unavailable_rules(judged, config):
    summary = stored_summary(judged)
    summary["causes"]["C1"]["label"] = "probable"
    store_summary(judged, summary, digests=False)
    with_status(judged, "unavailable", typesafe="unavailable: service down")
    def probable(report):
        report["coverage"]["typesafe"] = "unavailable: service down"
        report["causes"][0]["label"] = "probable"
        report["actions"] = [{**a, "label": "candidate"} for a in report["actions"]]
    assert judged_problems(judged, config, mutated(VALID_REPORT, probable)) == []
    confirmed = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: service down"))
    problems = judged_problems(judged, config, confirmed)
    assert_problem(problems, "causes[0]", "confirmed")


def test_the_report_typesafe_must_agree_with_the_summary_for_every_status(judged, config):
    with_status(judged, "complete")
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: x"))
    assert_problem(judged_problems(judged, config, report), "coverage.typesafe", "must equal")


# round 3, m8: shapes of case.json and evidence files that render reads

def rewrite_case(case_dir, change):
    path = case_dir / "case.json"
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data))


@pytest.mark.parametrize("change", [
    lambda d: d.pop("skill_version"), lambda d: d.update(skill_version=5), lambda d: d.update(case_dir=5),
    lambda d: d.update(incident=5), lambda d: d["incident"].pop("number"), lambda d: d["incident"].update(title=None),
    lambda d: d["incident"].update(url=5), lambda d: d["incident"].update(declared_at=[1]),
    lambda d: d.update(window=5), lambda d: d["window"].pop("start"), lambda d: d["window"].update(end=5),
    lambda d: d.update(incident_start=5), lambda d: d.update(target=5),
    lambda d: d.update(target={"source": "map"}), lambda d: d.update(target={"source": "map", "account": 5, "region": "r"}),
])
def test_a_malformed_case_json_is_a_problem(case_dir, change):
    rewrite_case(case_dir, change)
    _, problems = check_case_inputs(case_dir)
    assert any("case.json" in problem for problem in problems), problems


def test_a_wellformed_case_json_with_a_target_is_not_a_problem(case_dir):
    rewrite_case(case_dir, lambda d: d.update(target={"source": "map", "service": "checkout-api", "environment": "prod",
                                                       "account": "prod-main", "region": "eu-west-1", "resources": {},
                                                       "depends_on": []}))
    assert check_case_inputs(case_dir)[1] == []


@pytest.mark.parametrize("change", [
    lambda d: d.update(errors=5), lambda d: d.update(errors=True), lambda d: d.update(errors=[5]),
    lambda d: d.update(truncated="yes"),
])
def test_a_malformed_evidence_file_is_a_problem_not_a_crash(case_dir, change):
    path = next((case_dir / "evidence").glob("ecs-*.json"))
    document = json.loads(path.read_text())
    change(document)
    path.write_text(json.dumps(document))
    _, problems = check_case_inputs(case_dir)
    assert any("evidence file" in problem for problem in problems), problems


@pytest.mark.parametrize("facts", [5, [5], "x", None])
def test_malformed_facts_never_crash_the_input_check(case_dir, facts):
    path = next((case_dir / "evidence").glob("ecs-*.json"))
    document = json.loads(path.read_text())
    document["facts"] = facts
    path.write_text(json.dumps(document))
    findings, problems = check_case_inputs(case_dir)
    assert isinstance(findings, dict) and isinstance(problems, list)


def test_a_report_that_validates_does_not_fail_in_render_for_a_shape_reason(case_dir, case, config):
    path = next((case_dir / "evidence").glob("ecs-*.json"))
    document = json.loads(path.read_text())
    document["errors"] = 5
    path.write_text(json.dumps(document))
    assert judged_problems_without_fixture(case_dir, config) != []


def judged_problems_without_fixture(case_dir, config):
    findings, input_problems = check_case_inputs(case_dir)
    return input_problems + validate_report(VALID_REPORT, load_case(case_dir), findings, config)


# no absolute local paths

def test_the_case_folder_is_shown_relative_to_the_cases_root(case):
    assert display_case_folder(case) == "cases/INC-123/20261004-110000"


def test_a_case_folder_not_under_a_cases_root_shows_its_last_two_components(case):
    other = {**case, "case_dir": "/home/pavel/work/some-folder/run-1"}
    assert display_case_folder(other) == "some-folder/run-1"
    assert display_case_folder({**case, "case_dir": "relative"}) == "relative"
    assert display_case_folder({**case, "case_dir": 5}) == "-"


def test_the_incident_folder_name_is_matched_the_way_case_folders_are_named(case):
    odd = {**case, "incident": {**case["incident"], "number": "INC 7/x"}, "case_dir": "/r/INC-7-x/20261004-110000"}
    assert display_case_folder(odd) == "cases/INC-7-x/20261004-110000"


def test_no_absolute_path_reaches_the_report(case_dir, case, tmp_path):
    home = str(Path.home())
    text = render(VALID_REPORT, case_dir, case)
    assert str(tmp_path) not in text and home not in text and str(case_dir) not in text
    assert "- Case folder: cases/INC-123/20261004-110000" in section(text, "## 9. Run details")


def test_a_path_in_collected_text_is_shown_without_its_local_prefix(case_dir, case):
    path = next((case_dir / "evidence").glob("ecs-*.json"))
    document = json.loads(path.read_text())
    document["facts"][0]["command"] = f"aws ecs describe-tasks --cli-input-json {case_dir}/in.json {Path.home()}/x"
    path.write_text(json.dumps(document))
    text = render(VALID_REPORT, case_dir, case)
    assert str(case_dir) not in text and str(Path.home()) not in text


# the judgment-independent draft checks

def deeply_nested(levels):
    value = []
    for _ in range(levels):
        value = [value]
    return value


LABEL_ONLY_DRAFTS = {
    "confirmed without support": lambda r: r["causes"][1].update(label="confirmed", supporting=[], contradicting=[]),
    "recommended on a candidate cause": lambda r: r["actions"][0].update(cause="C2"),
    "top cause labelled candidate": lambda r: r["causes"][0].update(label="candidate"),
    "unresolved with a confirmed cause": lambda r: r.update(status="unresolved") or r["summary"].update(top_cause=None),
    "typesafe unavailable with confirmed": lambda r: r["coverage"].update(typesafe="unavailable: x"),
    "a different typesafe value": lambda r: r["coverage"].update(typesafe="failed: x"),
}

BROKEN_DRAFTS = {
    "string preconditions": lambda r: r["actions"][0].update(preconditions="Capacity first"),
    "missing field": lambda r: r.pop("causes"),
    "bad cause id": lambda r: r["causes"][1].update(id="C 2"),
    "unknown finding": lambda r: r["causes"][0]["supporting"].append("ghost-1"),
    "unknown action cause": lambda r: r["actions"][0].update(cause="C9"),
    "unknown hypothesis cause": lambda r: r["hypotheses"][0].update(cause="C9"),
    "unknown top cause": lambda r: r["summary"].update(top_cause="C9"),
    "unresolved with a top cause": lambda r: r.update(status="unresolved"),
    "no confirmed hypothesis": lambda r: r["hypotheses"][0].update(result="inconclusive"),
    "unknown account": lambda r: r["actions"][0]["target"].update(account_alias="nowhere"),
    "empty verification": lambda r: r["actions"][0].update(verification=[]),
    "secret": lambda r: r["actions"][0].update(change=f"Use pass{'word'}={secret_value()}"),
    "wrong type": lambda r: r["causes"][0].update(id=["C1"]),
    "bad status": lambda r: r.update(status="done"),
    "bad label value": lambda r: r["causes"][0].update(label="sure"),
    "too deep": lambda r: r.update(map_changes=[deeply_nested(60)]),
}


def test_a_valid_draft_has_no_draft_problems(case, findings, config):
    assert check_draft(VALID_REPORT, findings, config) == []
    assert check_draft(UNRESOLVED_REPORT, findings, config) == []


@pytest.mark.parametrize("name", sorted(LABEL_ONLY_DRAFTS))
def test_a_draft_with_only_label_or_summary_problems_has_no_draft_problems(case, findings, config, name):
    report = mutated(VALID_REPORT, LABEL_ONLY_DRAFTS[name])
    assert check_draft(report, findings, config) == []
    assert problems_for(report, case, findings, config) != []


@pytest.mark.parametrize("name", sorted(BROKEN_DRAFTS))
def test_the_draft_problems_are_a_subset_of_the_validation_problems_in_the_same_wording(case, findings, config, name):
    report = mutated(VALID_REPORT, BROKEN_DRAFTS[name])
    draft = check_draft(report, findings, config)
    assert draft, name
    full = problems_for(report, case, findings, config)
    assert set(draft) <= set(full) and len(draft) <= len(full)


def test_a_draft_without_a_summary_file_has_the_same_draft_problems(case_dir, case, findings, config):
    report = mutated(VALID_REPORT, BROKEN_DRAFTS["string preconditions"])
    with_summary = check_draft(report, findings, config)
    remove_summary(case_dir)
    assert check_draft(report, findings, config) == with_summary


def test_check_draft_never_raises_on_the_wrong_types(findings, config):
    for value in (None, 5, [], "x", {}, {"status": []}):
        assert isinstance(check_draft(value, findings, config), list)


# final review fixes

REPLAY_LINE = "REPLAY: the evidence in this report comes from recordings, not from live systems."


@pytest.mark.parametrize("word", ["confirmed", "probable", "candidate", "recommended", "root cause", "Root Cause",
                                  "TypeSafe", "TYPESAFE", "CONFIRMED"])
@pytest.mark.parametrize("where", [
    ("summary", "what_broke"), ("summary", "impact"), ("open_questions", 0), ("hypotheses", 0, "statement"),
    ("hypotheses", 0, "prediction"), ("hypotheses", 1, "test"), ("actions", 0, "rationale"),
    ("summary", "scope"), ("symptoms", 0), ("causes", 0, "statement"), ("causes", 1, "statement"),
    ("actions", 0, "title"), ("actions", 1, "change"), ("actions", 0, "current_state"), ("actions", 0, "required_state"),
    ("actions", 0, "risk"), ("actions", 0, "blast_radius"), ("actions", 0, "preconditions", 0),
    ("actions", 0, "verification", 0), ("actions", 1, "rollback", 0),
    ("coverage", "not_checked", 0, "what"), ("coverage", "not_checked", 0, "why"),
])
def test_free_text_may_not_state_a_label(findings, config, word, where):
    def put(report):
        node = report
        for step in where[:-1]:
            node = node[step]
        node[where[-1]] = f"The team says this is {word} and should be done now"
    problems = check_draft(mutated(VALID_REPORT, put), findings, config)
    path = where[0] + "".join(f"[{step}]" if isinstance(step, int) else f".{step}" for step in where[1:])
    assert any(problem.startswith(path + ": labels are printed from the judgments; describe what happened without them")
               for problem in problems), problems


@pytest.mark.parametrize("text", ["The unconfirmed theory", "a candidates list", "recommendation", "probably slow",
                                  "rootcause", "Containers are killed for memory"])
def test_label_words_inside_other_words_are_fine(findings, config, text):
    report = mutated(VALID_REPORT, lambda r: r["summary"].update(impact=text))
    assert check_draft(report, findings, config) == []


@pytest.mark.parametrize("change", ["Confirmed: add the queue", {"note": "the root cause service", "service": "orders"}])
def test_map_changes_may_not_state_a_label(findings, config, change):
    report = mutated(VALID_REPORT, lambda r: r["map_changes"].append(change))
    assert any(problem.startswith("map_changes[0]") and "labels are printed" in problem
               for problem in check_draft(report, findings, config))


def test_identifiers_and_judged_fields_are_not_free_text(findings, config):
    def put(report):
        report["actions"][0]["target"]["service"] = "confirmed-api"
        report["actions"][0]["target"]["resource_id"] = "candidate-queue"
    report = mutated(VALID_REPORT, put)
    assert not any("labels are printed" in problem for problem in check_draft(report, findings, config))
    # the hypothesis result "confirmed" and the labels themselves are enums decided after judging
    assert check_draft(VALID_REPORT, findings, config) == []


def test_a_confirmed_hypothesis_needs_a_cause_the_summary_labels_probable_or_confirmed(case_dir, case, findings, config):
    assert problems_for(VALID_REPORT, case, findings, config) == []
    summary = stored_summary_plain(case_dir)
    summary["causes"]["C1"]["label"] = "candidate"
    store_summary(case_dir, summary, digests=False)
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "hypotheses[0].result", "confirmed")


def stored_summary_plain(case_dir):
    return json.loads((case_dir / "judgments" / "summary.json").read_text())


def test_a_confirmed_hypothesis_without_a_judged_summary_is_a_problem(case_dir, case, findings, config):
    remove_summary(case_dir)
    report = mutated(UNRESOLVED_REPORT, lambda r: r["hypotheses"][0].update(result="confirmed", cause="C1"))
    report["coverage"]["typesafe"] = "unavailable: judging was not run"
    assert_problem(problems_for(report, case, findings, config), "hypotheses[0].result", "confirmed")


def test_a_confirmed_hypothesis_with_no_cause_counts_only_for_a_single_cause_report(case_dir, case, findings, config):
    def causeless(report):
        report["hypotheses"][0]["cause"] = None
    assert_problem(problems_for(mutated(VALID_REPORT, causeless), case, findings, config), "hypotheses[0].result")


def test_inconclusive_and_rejected_hypotheses_need_no_judged_cause(case_dir, case, findings, config):
    def soften(report):
        report["hypotheses"][1]["result"] = "inconclusive"
    report = mutated(VALID_REPORT, soften)
    rejudge(case_dir, report)
    assert problems_for(report, case, findings, config) == []


def test_emphasis_markers_in_text_are_neutralised(case_dir, case):
    def bold(report):
        report["summary"]["scope"] = "Only **checkout** was hit and *payments* was not"
    text = render(mutated(VALID_REPORT, bold), case_dir, case)
    assert "**checkout**" not in text and "\\*\\*checkout" in text


def summary_block(text):
    return section(text, "## 1. Summary")


def test_what_broke_is_the_judged_top_cause_with_its_label(case_dir, case):
    block = summary_block(render(VALID_REPORT, case_dir, case))
    first = block.strip().splitlines()[0]
    assert first == "**What broke:** Revision 42 of checkout-api exits with code 137 because its memory limit is too low (confirmed)"
    assert block.index("What broke") < block.index("Author's summary (not scored)")
    author = block[block.index("Author's summary (not scored)"):]
    assert "The checkout API stopped serving requests." in author and "Customers could not complete checkout" in author
    assert "**Top cause" not in block


def test_the_label_comes_from_the_summary_not_the_report(case_dir, case):
    summary = stored_summary_plain(case_dir)
    summary["causes"]["C1"]["label"] = "probable"
    store_summary(case_dir, summary, digests=False)
    assert "(probable)" in summary_block(render(VALID_REPORT, case_dir, case)).splitlines()[2]


def test_without_a_judged_cause_the_page_says_none_was_established(case_dir, case):
    block = summary_block(render(UNRESOLVED_REPORT, case_dir, case))
    assert block.strip().splitlines()[0] == "**What broke:** No cause was established."
    assert "Author's summary (not scored)" in block
    remove_summary(case_dir)
    assert "No cause was established." in summary_block(render(VALID_REPORT, case_dir, case)).splitlines()[2]


def test_a_replay_case_prints_the_replay_line_under_the_title_and_marks_the_work_order(case_dir, case):
    replay = {**case, "replay": True}
    text = render_report(VALID_REPORT, replay, valid_findings(case_dir), [], [], RENDERED_AT)
    lines = text.splitlines()
    assert lines[0].startswith("# Triage report:") and lines[2] == REPLAY_LINE
    assert build_work_order(VALID_REPORT, replay, RENDERED_AT)["replay"] is True
    assert "replay" not in build_work_order(VALID_REPORT, case, RENDERED_AT)
    assert REPLAY_LINE not in render_report(VALID_REPORT, case, valid_findings(case_dir), [], [], RENDERED_AT)


def test_a_work_order_with_replay_validates_and_a_non_boolean_does_not(case):
    order = build_work_order(VALID_REPORT, {**case, "replay": True}, RENDERED_AT)
    assert validate_work_order(order) == []
    order["replay"] = "yes"
    assert_problem(validate_work_order(order), "replay")


def test_case_json_replay_must_be_a_boolean(case_dir):
    rewrite_case(case_dir, lambda d: d.update(replay="yes"))
    assert any("replay" in problem for problem in check_case_inputs(case_dir)[1])


def test_each_finding_shows_its_own_quote_and_each_fact_its_summary_and_excerpt(case_dir, case):
    findings_section = section(render(VALID_REPORT, case_dir, case), "## 4. Findings")
    assert "- Quote: exit code 137" in findings_section
    assert "summary: Essential container exited with code 137" in findings_section
    assert "excerpt: desired 2, running 0" in findings_section
    first_fact = next(line for line in findings_section.splitlines() if "ecs-0001" in line and "command" in line)
    assert "excerpt" not in first_fact or "exit code 137" in first_fact


METRIC_COMMAND = ("aws --profile triage-prod-main cloudwatch get-metric-data --region eu-west-1 --metric-data-queries "
                  + json.dumps([{"Id": "m0", "MetricStat": {"Metric": {"Namespace": "AWS/ECS", "MetricName": "CPUUtilization",
                                                                      "Dimensions": [{"Name": "ServiceName", "Value": "x" * 800}]},
                                                       "Period": 60, "Stat": "Average"}, "ReturnData": True}])
                  + " --start-time 2026-10-04T10:00:00Z --end-time 2026-10-04T12:00:00Z")


def test_a_metric_command_is_shortened_to_operation_metric_statistic_and_period(case_dir, case):
    path = next((case_dir / "evidence").glob("ecs-*.json"))
    document = json.loads(path.read_text())
    document["facts"][0]["command"] = METRIC_COMMAND
    path.write_text(json.dumps(document))
    text = section(render(VALID_REPORT, case_dir, case), "## 4. Findings")
    assert "get-metric-data" in text and "CPUUtilization" in text and "Average" in text and "60" in text
    assert "x" * 100 not in text and "--metric-data-queries" not in text


def test_other_commands_are_not_shortened(case_dir, case):
    assert "aws ecs describe-tasks" in section(render(VALID_REPORT, case_dir, case), "## 4. Findings")


def test_the_work_order_keeps_each_actions_cause_and_lists_every_cause_with_an_action(case_dir, case):
    def second(report):
        report["actions"][1]["cause"] = "C2"
    report = mutated(VALID_REPORT, second)
    order = build_work_order(report, case, RENDERED_AT, checked=checked_findings(case_dir))
    assert [a["cause"] for a in order["actions"]] == ["C1", "C2"]
    assert [(c["id"], c["label"]) for c in order["causes"]] == [("C1", "confirmed"), ("C2", "candidate")]
    assert order["causes"][0]["statement"] == VALID_REPORT["causes"][0]["statement"]
    assert order["causes"][0]["finding_ids"] == ["compute-1"]
    assert validate_work_order(order) == []


def test_a_cause_without_an_action_is_not_listed(case_dir, case):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT, checked=checked_findings(case_dir))
    assert [c["id"] for c in order["causes"]] == ["C1"]


def test_the_work_order_embeds_each_cited_findings_claim_quote_and_provenance(case_dir, case):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT, checked=checked_findings(case_dir))
    assert order["findings"] == [{"id": "compute-1", "claim": "Containers exit with code 137",
                                  "quote": "exit code 137", "provenance": "incident_time"}]


def test_findings_cited_only_by_an_action_are_embedded_once(case_dir, case):
    def cite(report):
        report["actions"][1]["finding_ids"] = ["compute-2", "compute-1"]
    order = build_work_order(mutated(VALID_REPORT, cite), case, RENDERED_AT, checked=checked_findings(case_dir))
    assert [f["id"] for f in order["findings"]] == ["compute-1", "compute-2"]


def test_the_work_order_findings_must_have_text_fields(case, case_dir):
    order = build_work_order(VALID_REPORT, case, RENDERED_AT, checked=checked_findings(case_dir))
    order["findings"][0]["quote"] = 5
    assert_problem(validate_work_order(order), "findings[0].quote")
    order = build_work_order(VALID_REPORT, case, RENDERED_AT)
    order.pop("findings")
    assert_problem(validate_work_order(order), "findings", "missing")


def test_section_8_does_not_print_the_check_list_and_says_a_discovered_target_is_proposed(case_dir, case):
    write_checked(case_dir, checked={"compute": ["ECS service events"]})
    text = render(mutated(VALID_REPORT, lambda r: None), case_dir, case)
    assert section(text, "## 8. Proposed service map changes").strip() == "None."
    discovered = {**case, "target": {"source": "discovered", "service": None, "environment": None, "account": "prod-main",
                                     "region": "eu-west-1", "resources": {}, "depends_on": []}}
    block = section(render_report(VALID_REPORT, discovered, valid_findings(case_dir), [], [], RENDERED_AT),
                    "## 8. Proposed service map changes")
    assert "The target was discovered, not mapped; a map entry is proposed after publishing." in block
    assert "ECS service events" not in block


def test_rows_dated_before_the_window_get_their_own_sub_heading_after_the_window_rows(case_dir, case):
    rows = [
        {"time": "2026-10-04T08:00:00Z", "offset": "2 hours before", "text": "An older deployment", "source": "changes",
         "fact_id": None, "resource": "", "group": "before the window"},
        {"time": "2026-10-04T10:41:00Z", "offset": "1 minute before", "text": "Container exited", "source": "ecs",
         "fact_id": None, "resource": ""},
    ]
    text = render_report(VALID_REPORT, case, valid_findings(case_dir), rows, [], RENDERED_AT)
    timeline = section(text, "## 3. Timeline")
    assert_headings(text)
    assert timeline.index("Container exited") < timeline.index("### Before the window") < timeline.index("An older deployment")
    main = timeline[:timeline.index("### Before the window")]
    assert "An older deployment" not in main
    assert timeline.count("| Time | Relative to incident start | Event | Source |") == 2


def test_a_timeline_without_such_rows_has_no_sub_heading(case_dir, case):
    rows = [{"time": "2026-10-04T10:41:00Z", "offset": "1 minute before", "text": "Container exited", "source": "ecs",
             "fact_id": None, "resource": ""}]
    text = render_report(VALID_REPORT, case, valid_findings(case_dir), rows, [], RENDERED_AT)
    assert "Before the window" not in text


@pytest.mark.parametrize("cause_label", ["probable", "candidate"])
def test_a_recommended_action_needs_a_confirmed_cause_not_just_a_probable_one(case_dir, case, findings, config, cause_label):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(label=cause_label))
    assert report["actions"][0]["label"] == "recommended"
    problems = problems_for(report, case, findings, config)
    assert_problem(problems, "actions[0]", "recommended", "cause is not labelled confirmed")
    assert check_draft(report, findings, config) == []
    assert not any("actions[1]" in problem for problem in problems)
    confirmed = problems_for(VALID_REPORT, case, findings, config)
    assert not any("cause is not labelled confirmed" in problem for problem in confirmed)


def test_making_hypothesis_results_agree_after_judging_is_not_an_edit(case_dir, case, findings, config):
    """SKILL step 9 on the unresolved path: judged candidate everywhere, so the confirmed hypothesis becomes inconclusive."""
    def placeholders(r):
        r["status"], r["summary"]["top_cause"], r["coverage"]["typesafe"] = "unresolved", None, ""
        for entry in r["causes"] + r["actions"]:
            entry["label"] = "candidate"
    draft = mutated(VALID_REPORT, placeholders)
    summary = copy.deepcopy(SUMMARY)
    summary["causes"]["C1"]["label"] = "candidate"
    summary["actions"]["A1"]["label"] = "candidate"
    store_summary(case_dir, summary, report=draft)

    def step_nine(r):
        r["coverage"]["typesafe"] = "available"
        r["hypotheses"][0]["result"] = "inconclusive"
    assert problems_for(mutated(draft, step_nine), case, findings, config) == []

