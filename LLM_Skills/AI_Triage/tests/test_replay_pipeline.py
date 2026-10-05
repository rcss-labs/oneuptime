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
    distractor_draft,
    favourable_judge,
    load_call_log,
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


@pytest.fixture(scope="module")
def cert_run(tmp_path_factory):
    scenario = REPLAY_DIR / "cert-expired"
    base = tmp_path_factory.mktemp("cert-single")
    return {"case_dir": run_pipeline(scenario, base, favourable_judge(scenario))}


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
    assert steps[-7:] == ["findings check", "timeline", "judge run", "report render", "publish audit",
                          "publish confluence", "publish slack-message"]


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


def test_the_case_folder_holds_the_output_of_every_stage(run):
    names = {path.name for path in run["case_dir"].iterdir() if not path.name.endswith(".tmp")}
    assert {"case.md", "case.json", "incident.json", "evidence", "findings", "judgments", "timeline.json", "report.json",
            "report.md", "work-order.json", "render.json", "audit.json", "slack-message.md"} <= names
    assert not any(path.name.endswith((".stale", ".tmp")) for path in run["case_dir"].rglob("*"))


def test_an_expired_certificate_is_a_confirmed_cause_with_a_recommended_mitigation(cert_run):
    report = read_json(cert_run["case_dir"] / "report.json")
    summary = read_json(cert_run["case_dir"] / "judgments" / "summary.json")
    assert summary["causes"]["C1"]["gates"]["timing"] is True
    assert report["causes"][0]["label"] == "confirmed"
    assert report["actions"][0]["label"] == "recommended"


def test_the_report_names_both_database_hosts_of_the_mismatch(ecs_run):
    report = (ecs_run["case_dir"] / "report.md").read_text()
    assert "checkout-prod-db.cluster-abc.eu-west-1.rds.example.com" in report
    assert "checkout-db.internal.example.com" in report
    checked = read_json(ecs_run["case_dir"] / "findings" / "checked.json")
    assert "data-4" in {item["id"] for item in checked["valid"]}


def test_no_call_was_missed_and_every_recorded_answer_was_used(run):
    calls = load_call_log(run["base"])
    assert calls
    missed = [call.get("argv") or f"{call['method']} {call['url']}" for call in calls if call["entry"] is None]
    assert missed == []
    unused = []
    for tool, name in (("aws", "aws.json"), ("opensearch", "opensearch.json")):
        recorded = read_json(run["scenario"] / name) if (run["scenario"] / name).is_file() else []
        used = {call["entry"] for call in calls if call["tool"] == tool}
        unused += [f"{name}[{index}] {entry.get('match') or entry.get('path_contains')}"
                   for index, entry in enumerate(recorded) if index not in used]
    assert unused == []


def test_every_planned_collector_wrote_a_fact_or_is_listed_with_its_reason(run):
    allowed = run["expected"].get("no_facts_expected", {})
    assert all(isinstance(reason, str) and reason.strip() for reason in allowed.values())
    documents = [read_json(path) for path in sorted((run["case_dir"] / "evidence").glob("*.json"))]
    planned = {record["step"][len("plan: "):] for record in run["log"] if record["step"].startswith("plan: ")}
    assert planned <= {document["collector"] for document in documents}
    silent = {document["collector"] for document in documents if not document["facts"]}
    assert silent == set(allowed)


# --- the secret ----------------------------------------------------------------------------

def test_the_static_secret_is_in_the_fixtures_where_only_the_redactor_can_stop_it():
    text = (REPLAY_DIR / "ecs-bad-deploy" / "aws.json").read_text()
    assert text.count(SECRET) == 4  # both task definitions (hidden by name), one log line, one service event
    for answer, needle in (("a Logs Insights line", "connect failed for postgres://"), ("an ECS service event", "stopped: container command failed")):
        assert any(needle in line and SECRET in line for line in text.splitlines()), answer


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


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_a_draft_that_blames_the_distractor_is_not_confirmed_and_its_actions_are_not_recommended(scenario, tmp_path):
    folder = REPLAY_DIR / scenario
    draft = distractor_draft(folder)
    distractor = draft["summary"]["top_cause"]
    case = start_case(folder, tmp_path)
    summary = case.judge(favourable_judge(folder), apply_labels=True, draft=draft)
    assert summary["causes"][distractor]["label"] != "confirmed"
    blamed = [action["id"] for action in draft["actions"] if action["cause"] == distractor]
    assert blamed
    assert {summary["actions"][action_id]["label"] for action_id in blamed} == {"candidate"}
    report = read_json(case.case_dir / "report.json")
    assert next(cause for cause in report["causes"] if cause["id"] == distractor)["label"] != "confirmed"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_publishing_after_a_change_to_report_json_needs_a_new_render(scenario, tmp_path):
    folder = REPLAY_DIR / scenario
    case = start_case(folder, tmp_path)
    case.judge(favourable_judge(folder), apply_labels=True)
    case.render(required=True)
    report = read_json(case.case_dir / "report.json")
    report["open_questions"].append("Who approved the change, and when?")
    (case.case_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    refused = case.script("publish audit", "publish.py", "audit", "--case-dir", str(case.case_dir), required=False)
    assert refused["returncode"] == 1 and "rendered again" in refused["stderr"]
    assert not (case.case_dir / "audit.json").exists()
    case.render(required=True)
    case.publish()
    assert read_json(case.case_dir / "audit.json")["clean"] is True


# --- no real call ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", SCENARIOS)
def test_replay_makes_no_call_to_aws_or_kubectl(scenario, tmp_path, monkeypatch):
    stubs, marker = tmp_path / "stubs", tmp_path / "real-call-marker"
    stubs.mkdir()
    for tool in ("aws", "kubectl"):
        script = stubs / tool
        script.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{marker}"\nexit 99\n')
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{stubs}{os.pathsep}{os.environ['PATH']}")
    run_pipeline(REPLAY_DIR / scenario, tmp_path / "run", favourable_judge(REPLAY_DIR / scenario))
    assert not marker.exists()
    assert load_call_log(tmp_path / "run")  # the replay did answer calls


# --- the guard ------------------------------------------------------------------------------

def test_the_guard_allows_every_command_the_pipeline_ran_and_asks_before_a_map_change(run, monkeypatch):
    home = run["base"] / "home"
    monkeypatch.setenv("HOME", str(home))
    skill_dir = home / ".claude" / "skills" / "ai-triage"
    context = context_from_config(load_config(skill_dir / "config" / "triage-config.yaml"), skill_dir)
    checked = [(record["step"], skill_style(record["argv"], home)) for record in run["log"]]
    assert [step for step, _ in checked].count("plan: opensearch") == (3 if run["name"] == "ecs-bad-deploy" else 0)
    assert "judge run" in [step for step, _ in checked]
    assert len({command for _, command in checked}) == len(checked)  # no command stands in for another
    refused = [(step, command[-120:]) for step, command in checked if decide(command, context).kind != ALLOW]
    assert refused == []
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


def test_every_valid_finding_keeps_the_found_text_that_holds_its_excerpt(run):
    checked = read_json(run["case_dir"] / "findings" / "checked.json")
    collapse = lambda text: " ".join(text.split())  # noqa: E731
    assert checked["valid"]
    assert all(collapse(item["excerpt"]) in collapse(item["matched_text"]) for item in checked["valid"])


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
