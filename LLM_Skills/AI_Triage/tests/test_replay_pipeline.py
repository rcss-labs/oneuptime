"""The whole skill pipeline, run end to end on recorded incidents without AWS, Kubernetes, or a network.

Each scenario folder under tests/replay is a recorded incident. replay_support.run_pipeline runs the real commands
on it (init, target, plan, every collector, the findings check, the timeline, judging, the report, the audit, and
the Slack message) and these tests look at what came out.
"""
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from conftest import SKILL_SRC
from fakes import FakeJudge
from replay_support import (
    REPLAY_DIR,
    SCENARIOS,
    PipelineError,
    contradicting_judge,
    favourable_judge,
    load_log,
    run_pipeline,
    skill_style,
    start_case,
)
from triage.config import load_config
from triage.findings import (
    REPEATS_REQUEST,
    asked_strings,
    check_findings,
    evidence_documents,
    qualified_id,
    quotable_strings,
)
from triage.guard import context_from_config, decide
from triage.report import validate_work_order
from triage.verdict import ALLOW, ASK

SECRET = "fixture-db-password-do-not-leak"
NEIGHBOURS = 11


def expected_of(scenario: str) -> dict:
    return json.loads((REPLAY_DIR / scenario / "expected.json").read_text())


@pytest.fixture(scope="module", params=SCENARIOS)
def run(request, tmp_path_factory):
    """One full pipeline per scenario, with a judge that answers in favour of the canned cause."""
    scenario = REPLAY_DIR / request.param
    base = tmp_path_factory.mktemp(request.param)
    judge = favourable_judge(scenario)
    case_dir = run_pipeline(scenario, base, judge)
    return {"name": request.param, "scenario": scenario, "base": base, "case_dir": case_dir, "judge": judge,
            "log": load_log(base), "expected": expected_of(request.param)}


@pytest.fixture(scope="module")
def ecs_run(tmp_path_factory):
    scenario = REPLAY_DIR / "ecs-bad-deploy"
    base = tmp_path_factory.mktemp("ecs-single")
    judge = favourable_judge(scenario)
    case_dir = run_pipeline(scenario, base, judge)
    return {"scenario": scenario, "base": base, "case_dir": case_dir, "judge": judge, "log": load_log(base)}


def read_json(path: Path):
    return json.loads(path.read_text())


# --- the happy path, for both scenarios -----------------------------------------------------

def test_every_command_of_the_pipeline_exits_zero(run):
    failed = [(record["step"], record["returncode"], record["stderr"][-300:]) for record in run["log"]
              if record["returncode"] != 0]
    assert failed == []


def test_the_pipeline_runs_the_planned_collectors_and_every_later_stage(run):
    steps = [record["step"] for record in run["log"]]
    assert steps[:3] == ["case init", "case target", "case plan"]
    assert sum(step.startswith("plan: ") for step in steps) >= 6
    assert steps[-6:] == ["findings check", "timeline", "report render", "publish audit", "publish confluence",
                          "publish slack-message"]


def test_no_evidence_file_holds_an_error(run):
    evidence = sorted((run["case_dir"] / "evidence").glob("*.json"))
    assert len(evidence) >= 6
    errors = {path.name: read_json(path)["errors"] for path in evidence if read_json(path)["errors"]}
    assert errors == {}


def test_the_canned_findings_are_all_valid(run):
    canned = {}
    for path in (run["scenario"] / "findings").glob("*.json"):
        for finding in read_json(path)["findings"]:
            canned[finding["id"]] = path.stem
    assert canned
    checked = read_json(run["case_dir"] / "findings" / "checked.json")
    assert checked["rejected"] == [] and checked["unreadable"] == []
    assert sorted(item["id"] for item in checked["valid"]) == sorted(canned)


def test_the_report_renders_the_expected_cause_and_never_the_forbidden_text(run):
    report = (run["case_dir"] / "report.md").read_text()
    for keyword in run["expected"]["cause_keywords"]:
        assert keyword in report, keyword
    for forbidden in run["expected"]["must_not_contain"]:
        assert forbidden not in report
    work_order = (run["case_dir"] / "work-order.json").read_text()
    for keyword in run["expected"]["mitigation_keywords"]:
        assert keyword in work_order, keyword


def test_the_top_cause_does_not_name_a_distractor(run):
    report = read_json(run["case_dir"] / "report.json")
    top = next(cause for cause in report["causes"] if cause["id"] == report["summary"]["top_cause"])
    for word in run["expected"]["not_the_cause"]:
        assert word.lower() not in top["statement"].lower(), word
    assert top["label"] == "confirmed"


def test_the_work_order_validates(run):
    work_order = read_json(run["case_dir"] / "work-order.json")
    assert validate_work_order(work_order) == []
    mitigations = [action for action in work_order["actions"] if action["type"] == "mitigation"]
    permanent = [action for action in work_order["actions"] if action["type"] == "permanent_fix"]
    assert len(mitigations) == 1 and len(permanent) == 1


def test_the_audit_is_clean_and_the_slack_message_is_ready(run):
    audit = read_json(run["case_dir"] / "audit.json")
    assert audit["clean"] is True
    assert {name: (entry["redact_hits"], entry["scan_hits"]) for name, entry in audit["files"].items()} == {
        name: ([], []) for name in audit["checked"]}
    message = (run["case_dir"] / "slack-message.md").read_text()
    assert run["expected"]["cause_keywords"][0] in message
    request = next(record for record in run["log"] if record["step"] == "publish confluence")
    assert read_json_text(request["stdout"])["existing_page"] is None


def read_json_text(text: str):
    return json.loads(text)


def test_replay_never_leaves_the_scenario_folder_or_the_case_folder(run):
    names = sorted(path.name for path in (run["case_dir"]).iterdir())
    for name in ("case.md", "case.json", "evidence", "findings", "judgments", "report.md", "work-order.json"):
        assert name in names


# --- the secret ----------------------------------------------------------------------------

def test_the_static_secret_is_really_in_the_fixtures():
    text = (REPLAY_DIR / "ecs-bad-deploy" / "aws.json").read_text()
    assert text.count(SECRET) == 2  # both task definitions


def test_the_secret_is_in_no_file_of_the_case_and_no_command_output(ecs_run):
    holders = [str(path) for path in ecs_run["case_dir"].rglob("*")
               if path.is_file() and SECRET.encode() in path.read_bytes()]
    assert holders == []
    assert [r["step"] for r in ecs_run["log"] if SECRET in r["stdout"] + r["stderr"]] == []
    sent = json.dumps([state for state, _ in ecs_run["judge"].calls])
    assert SECRET not in sent


# --- the timeline --------------------------------------------------------------------------

def test_the_timeline_puts_the_deployment_before_the_impact_and_says_how_many_minutes(ecs_run):
    rows = read_json(ecs_run["case_dir"] / "timeline.json")
    rows = rows["rows"] if isinstance(rows, dict) else rows
    texts = [row["text"] for row in rows]
    update = next(row for row in rows if row["text"].startswith("UpdateService"))
    impact = next(row for row in rows if row["text"] == "Impact started")
    assert update["time"] < impact["time"]
    assert texts.index(update["text"]) < texts.index("Impact started")
    assert "5 minutes before the incident started" in update["text"]
    printed = next(r for r in ecs_run["log"] if r["step"] == "timeline")["stdout"]
    line = next(line for line in printed.splitlines() if "UpdateService" in line)
    assert "5 minutes before the incident started" in line


# --- judging without or against the canned cause --------------------------------------------

def test_without_typesafe_the_report_still_renders_and_nothing_is_confirmed(tmp_path):
    scenario = REPLAY_DIR / "ecs-bad-deploy"
    case_dir = run_pipeline(scenario, tmp_path, FakeJudge(fail_with="TypeSafe cannot be reached in this test"))
    report = read_json(case_dir / "report.json")
    assert report["coverage"]["typesafe"].startswith("unavailable")
    assert all(cause["label"] != "confirmed" for cause in report["causes"])
    text = (case_dir / "report.md").read_text()
    assert "TypeSafe" in text and "unavailable" in text.lower()
    assert "(confirmed)" not in text and "confirmed**" not in text
    assert read_json(case_dir / "audit.json")["clean"] is True


def test_a_contradicting_evidence_answer_stops_a_confirmed_label_from_rendering(tmp_path):
    scenario = REPLAY_DIR / "ecs-bad-deploy"
    case = start_case(scenario, tmp_path)
    case.judge(contradicting_judge(scenario))
    # The canned report still says "confirmed"; the judgments no longer allow it.
    result = case.render()
    assert result["returncode"] == 1
    assert "confirmed" in result["stderr"]
    assert not (case.case_dir / "report.md").exists()


def test_pipeline_error_names_the_step_that_failed(tmp_path):
    scenario = REPLAY_DIR / "ecs-bad-deploy"
    judge = contradicting_judge(scenario)
    case = start_case(scenario, tmp_path)
    case.judge(judge)
    with pytest.raises(PipelineError, match="report render"):
        case.render(required=True)


# --- no real call ---------------------------------------------------------------------------

def test_replay_makes_no_call_to_aws_or_kubectl(tmp_path, monkeypatch):
    stubs, marker = tmp_path / "stubs", tmp_path / "real-call-marker"
    stubs.mkdir()
    for tool in ("aws", "kubectl"):
        script = stubs / tool
        script.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{marker}"\nexit 99\n')
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{stubs}{os.pathsep}{os.environ['PATH']}")
    run_pipeline(REPLAY_DIR / SCENARIOS[-1], tmp_path / "run", favourable_judge(REPLAY_DIR / SCENARIOS[-1]))
    assert not marker.exists()


# --- the guard ------------------------------------------------------------------------------

def test_the_guard_allows_every_command_the_pipeline_ran_and_asks_before_a_map_change(run, monkeypatch):
    home = run["base"] / "home"
    monkeypatch.setenv("HOME", str(home))
    skill_dir = home / ".claude" / "skills" / "ai-triage"
    context = context_from_config(load_config(skill_dir / "config" / "triage-config.yaml"), skill_dir)
    verdicts = {record["step"]: decide(skill_style(record["argv"], home), context).kind for record in run["log"]}
    assert {step: kind for step, kind in verdicts.items() if kind != ALLOW} == {}
    apply_command = skill_style(
        [str(skill_dir / ".venv" / "bin" / "python"), str(skill_dir / "scripts" / "map_suggest.py"), "apply",
         "--case-dir", str(run["case_dir"]), "--service-name", "checkout-api"], home)
    assert decide(apply_command, context).kind == ASK


# --- the asked rule on real evidence --------------------------------------------------------

def probes_for(case_dir: Path) -> list[tuple[str, str]]:
    """(fact id, excerpt) pairs: each asked string that occurs in a quotable string of its fact, alone and
    with NEIGHBOURS characters of the found text on either side."""
    probes: set[tuple[str, str]] = set()
    for file_name, document in evidence_documents(case_dir):
        file_asked = document.get("asked")
        for fact in document["facts"]:
            asked = [text for text in asked_strings(fact, file_asked, with_keys=False) if len(text) >= 3]
            for text in quotable_strings(fact):
                lowered = text.lower()
                for needle in asked:
                    at = lowered.find(needle)
                    if at < 0:
                        continue
                    end = at + len(needle)
                    for first, last in ((at, end), (max(0, at - NEIGHBOURS), end), (at, end + NEIGHBOURS)):
                        probes.add((qualified_id(file_name, fact["id"]), text[first:last]))
    return sorted(probes)


def test_a_finding_that_quotes_only_what_was_asked_is_refused_on_real_evidence(run, tmp_path):
    case_copy = tmp_path / "case"
    shutil.copytree(run["case_dir"], case_copy)
    for old in (case_copy / "findings").glob("*"):
        old.unlink()
    probes = probes_for(case_copy)
    assert len(probes) > 20
    findings = [{"id": f"probe-{number}", "claim": "a probe", "fact_ids": [fact_id], "excerpt": excerpt,
                 "provenance": "inferred", "confidence": "low"} for number, (fact_id, excerpt) in enumerate(probes)]
    (case_copy / "findings" / "probe.json").write_text(json.dumps({"analyst": "probe", "findings": findings}))
    result = check_findings(case_copy)
    assert result["valid"] == [], [item["excerpt"] for item in result["valid"]][:5]
    long_enough = {f"probe-{n}" for n, (_, excerpt) in enumerate(probes) if len(excerpt) >= 12}
    wrong_reason = [item["id"] for item in result["rejected"]
                    if item["id"] in long_enough and REPEATS_REQUEST not in item["reasons"]]
    assert wrong_reason == []


def test_the_canned_findings_quote_found_text_not_the_request(run):
    checked = read_json(run["case_dir"] / "findings" / "checked.json")
    assert all(item["matched_text"] for item in checked["valid"])


# --- the judge sees what was asked of each source -------------------------------------------

def finding_states(judge):
    """Claim to the evidence list of the state sent for that finding."""
    return {state["claim"]: state["evidence"] for state, questions in judge.calls
            if isinstance(state, dict) and "evidence" in state and "evidence_relation" in questions}


def test_the_state_sent_for_an_opensearch_finding_names_the_query(ecs_run):
    claims = {finding["id"]: finding["claim"]
              for finding in read_json(ecs_run["scenario"] / "findings" / "logs.json")["findings"]}
    evidence = finding_states(ecs_run["judge"])[claims["logs-2"]]
    asked = evidence[0]["asked"]
    assert asked
    assert "app-logs-checkout-*" in asked and "service=checkout-api" in asked


def test_the_state_sent_for_a_collector_finding_carries_the_collector_targets(ecs_run):
    claims = {finding["id"]: finding["claim"]
              for finding in read_json(ecs_run["scenario"] / "findings" / "compute.json")["findings"]}
    evidence = finding_states(ecs_run["judge"])[claims["compute-3"]]
    assert "cluster=checkout" in evidence[0]["asked"] and "service=checkout-api" in evidence[0]["asked"]
    changes = finding_states(ecs_run["judge"])[claims["compute-2"]]
    assert "resource_names=" in changes[0]["asked"] and "checkout-api" in changes[0]["asked"]


# --- the scenario folders -------------------------------------------------------------------

def test_the_scenario_folders_hold_what_the_readme_says():
    readme = (REPLAY_DIR / "README.md").read_text()
    for scenario in SCENARIOS:
        folder = REPLAY_DIR / scenario
        for name in ("incident.json", "aws.json", "triage-config.yaml", "service-map.yaml", "report.json", "expected.json"):
            assert (folder / name).is_file(), f"{scenario}/{name}"
            assert name in readme
        assert any((folder / "findings").glob("*.json"))
    assert (REPLAY_DIR / "ecs-bad-deploy" / "opensearch.json").is_file()
    assert not (REPLAY_DIR / "cert-expired" / "opensearch.json").exists()
    assert "AI_TRIAGE_FIXTURES" in readme and "replay_support" in readme
