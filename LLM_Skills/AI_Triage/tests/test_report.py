import copy
import json
from datetime import datetime, timezone

import pytest

from triage.case import create_case, load_case, parse_incident
from triage.config import parse_config
from triage.evidence import CURRENT, INCIDENT_TIME, Evidence
from triage.findings import check_findings, load_facts, valid_findings
from triage.report import (
    LABEL_ORDER,
    REQUIRED_HEADINGS,
    build_work_order,
    coverage_from_evidence,
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
         "test": "Read the stopped task reasons", "result": "confirmed", "finding_ids": ["compute-1"]},
        {"id": "H2", "statement": "The load balancer is unhealthy", "prediction": "Targets are unhealthy | all zones",
         "test": "Read target health", "result": "rejected", "finding_ids": ["compute-2"]},
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
                    "result": "inconclusive", "finding_ids": ["compute-1"]}],
    "actions": [{**copy.deepcopy(VALID_REPORT["actions"][0]), "label": "candidate"}],
}


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
         "excerpt": "running 0", "provenance": "current", "confidence": "medium"},
        {"id": "compute-3", "claim": "Bad", "fact_ids": ["ecs-0099"],
         "excerpt": "x", "provenance": "current", "confidence": "low"},
    ])
    check_findings(path)
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


def test_valid_reports_have_no_problems(case, findings, config):
    assert problems_for(VALID_REPORT, case, findings, config) == []
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
    assert_problem(problems_for(report, case, findings, config), "top_cause", "C9")


def test_unresolved_top_cause_must_be_empty(case, findings, config):
    report = mutated(UNRESOLVED_REPORT, lambda r: r["summary"].update(top_cause="C1"))
    assert_problem(problems_for(report, case, findings, config), "top_cause", "unresolved")


def test_unresolved_accepts_empty_string_top_cause(case, findings, config):
    report = mutated(UNRESOLVED_REPORT, lambda r: r["summary"].update(top_cause=""))
    assert problems_for(report, case, findings, config) == []


def test_unknown_and_rejected_finding_ids_are_named_everywhere(case, findings, config):
    def break_ids(report):
        report["causes"][0]["supporting"].append("compute-3")
        report["causes"][1]["contradicting"].append("ghost-1")
        report["hypotheses"][0]["finding_ids"].append("ghost-2")
        report["actions"][0]["finding_ids"].append("ghost-3")
    problems = problems_for(mutated(VALID_REPORT, break_ids), case, findings, config)
    assert_problem(problems, "causes[0].supporting", "compute-3")
    assert_problem(problems, "causes[1].contradicting", "ghost-1")
    assert_problem(problems, "hypotheses[0].finding_ids", "ghost-2")
    assert_problem(problems, "actions[0].finding_ids", "ghost-3")


@pytest.mark.parametrize("label", ["confirmed", "probable"])
def test_strong_cause_needs_supporting_finding(case, findings, config, label):
    def strip(report):
        report["causes"][1].update(label=label, supporting=[], contradicting=[])
        report["actions"] = report["actions"][:1]
    assert_problem(problems_for(mutated(VALID_REPORT, strip), case, findings, config), "C2", "supporting")


def test_confirmed_cause_cannot_have_contradicting_finding(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(contradicting=["compute-2"]))
    assert_problem(problems_for(report, case, findings, config), "C1", "contradicting")


def test_confirmed_cause_needs_incident_time_support(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(supporting=["compute-2"]))
    assert_problem(problems_for(report, case, findings, config), "C1", "incident_time")


def test_probable_cause_does_not_need_incident_time_support(case, findings, config):
    def weaken(report):
        report["causes"][0].update(label="probable", supporting=["compute-2"])
        report["actions"] = [{**report["actions"][0], "label": "candidate"}]
    assert problems_for(mutated(VALID_REPORT, weaken), case, findings, config) == []


def test_cause_found_needs_strong_top_cause_and_confirmed_hypothesis(case, findings, config):
    def weaken(report):
        report["causes"][0]["label"] = "candidate"
        report["hypotheses"][0]["result"] = "inconclusive"
        report["actions"] = [{**report["actions"][0], "label": "candidate"}]
    problems = problems_for(mutated(VALID_REPORT, weaken), case, findings, config)
    assert_problem(problems, "top cause", "confirmed or probable")
    assert_problem(problems, "hypothesis", "confirmed")


def test_three_rejected_hypotheses_force_unresolved(case, findings, config):
    def reject(report):
        report["hypotheses"][0]["result"] = "rejected"
        report["hypotheses"].append({**report["hypotheses"][1], "id": "H3"})
    problems = problems_for(mutated(VALID_REPORT, reject), case, findings, config)
    assert_problem(problems, "rejected", "unresolved")
    report = mutated(UNRESOLVED_REPORT, lambda r: r["hypotheses"].extend(
        {**r["hypotheses"][0], "id": f"H{i}", "result": "rejected"} for i in (2, 3, 4)))
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
    assert_problem(problems_for(report, case, findings, config), "actions[0].cause", "C9")


def test_action_target_account_must_be_in_config(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["actions"][0]["target"].update(account_alias="nowhere"))
    assert_problem(problems_for(report, case, findings, config), "actions[0].target.account_alias", "nowhere")


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
    assert_problem(problems_for(report, case, findings, config), "coverage.typesafe", "unavailable: ")


def test_unavailable_typesafe_forbids_confirmed(case, findings, config):
    report = mutated(VALID_REPORT, lambda r: r["coverage"].update(typesafe="unavailable: no key"))
    assert_problem(problems_for(report, case, findings, config), "TypeSafe", "confirmed")


def test_unavailable_typesafe_is_fine_without_confirmed(case, findings, config):
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
    (case_dir / "judgments").mkdir(exist_ok=True)
    (case_dir / "judgments" / "summary.json").write_text(json.dumps({"causes": causes}))


def test_no_summary_means_no_cap(case, findings, config):
    assert problems_for(VALID_REPORT, case, findings, config) == []


def test_cause_cannot_exceed_the_judged_label(case_dir, case, findings, config):
    write_summary(case_dir, {"C1": {"label": "probable"}, "C2": {"label": "candidate"}})
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "C1", "confirmed", "probable")


def test_cause_may_equal_or_undercut_the_judged_label(case_dir, case, findings, config):
    write_summary(case_dir, {"C1": {"label": "confirmed"}, "C2": {"label": "probable"}})
    assert problems_for(VALID_REPORT, case, findings, config) == []


def test_cause_missing_from_summary_is_at_most_candidate(case_dir, case, findings, config):
    write_summary(case_dir, {"C2": {"label": "candidate"}})
    problems = problems_for(VALID_REPORT, case, findings, config)
    assert_problem(problems, "C1", "not in", "candidate")
    assert not any("C2" in problem for problem in problems)


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
    assert set(order) == {"incident", "generated_at", "skill_version", "cause", "actions", "open_questions", "coverage_gaps"}
    assert order["incident"] == {"number": "INC-123", "title": "Checkout API is down", "url": INCIDENT["url"]}
    assert order["generated_at"] == "2026-10-04T11:30:00Z"
    assert order["skill_version"] == "0.1.0"
    assert order["cause"] == {"statement": VALID_REPORT["causes"][0]["statement"], "label": "confirmed",
                              "finding_ids": ["compute-1"]}
    assert [a["id"] for a in order["actions"]] == ["A1", "A2"]
    assert all("cause" not in action for action in order["actions"])
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
                   "Only checkout-api in prod", "The health check of checkout.example.com returns 502", "confirmed", "C1"):
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


def test_hypotheses_without_a_matching_cause_are_not_lost(case_dir, case):
    report = mutated(VALID_REPORT, lambda r: r["hypotheses"].append(
        {"id": "H9", "statement": "Unrelated", "prediction": "p9", "test": "t9", "result": "inconclusive",
         "finding_ids": []}))
    assert "H9" in section(render(report, case_dir, case), "## 5. Ranked causes")


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
    assert section(text, "## 5. Ranked causes").strip() == "None."
    assert section(text, "## 6. Remediation work order").strip() == "None."
    assert section(text, "## 8. Proposed service map changes").strip() == "None."
    assert "None." in section(text, "## 7. Coverage notes")


def test_findings_section_says_none_when_no_valid_findings(tmp_path, case):
    text = render_report(UNRESOLVED_REPORT, {**case, "case_dir": str(tmp_path)}, {}, [], [], RENDERED_AT)
    assert section(text, "## 4. Findings").strip() == "None."
    assert section(text, "## 3. Timeline").strip() == "None."


def test_map_changes_are_listed(case_dir, case):
    report = mutated(VALID_REPORT, lambda r: r.update(map_changes=["Add log group /ecs/checkout-api"]))
    assert "Add log group /ecs/checkout-api" in section(render(report, case_dir, case), "## 8. Proposed service map changes")


def test_run_details(case_dir, case):
    details = section(render(VALID_REPORT, case_dir, case), "## 9. Run details")
    for needle in ("jane-doe", "14", "0.1.0", case["case_dir"], "2026-10-04T11:30:00Z"):
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
