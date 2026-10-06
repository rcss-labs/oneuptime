import importlib.util
import json
import os
import random
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC
from fakes import FakeJudge
from test_judge import build_case, locate_answer, make_responder
from triage.config import parse_config

COMMAND = [str(SKILL_SRC / "scripts" / "run.py"), "judge"]


def load_command():
    return importlib.import_module("triage.commands.judge")


@pytest.fixture
def command():
    return load_command()


@pytest.fixture
def skill_dir(tmp_path, config_data, map_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "judgments").mkdir()
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    (root / "config" / "service-map.yaml").write_text(yaml.safe_dump(map_data))
    shutil.copy(SKILL_SRC / "judgments" / "questions.json", root / "judgments" / "questions.json")
    return root


@pytest.fixture
def case_dir(tmp_path, config_data):
    folder = tmp_path / "cases" / "INC-123" / "20261004-110000"
    folder.mkdir(parents=True)
    config_data["cases_dir"] = str(tmp_path / "cases")
    return build_case(folder, parse_config(config_data))


def invoke(command, skill_dir, *args, judge=None):
    return command.main([*args, "--skill-dir", str(skill_dir)], judge=judge)


def test_help_works():
    result = subprocess.run([sys.executable, *COMMAND, "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "run" in result.stdout and "locate" in result.stdout and "adhoc" in result.stdout


def test_run_writes_the_summary_and_prints_its_path(command, skill_dir, case_dir, capsys):
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 0
    summary_path = case_dir / "judgments" / "summary.json"
    assert capsys.readouterr().out.strip() == str(summary_path)
    assert json.loads(summary_path.read_text())["causes"]["C1"]["label"] == "confirmed"
    assert len(judge.calls) == 9


def test_run_seeds_the_shuffle_with_the_incident_number(command, skill_dir, case_dir):
    judge = FakeJudge(make_responder())
    invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge)
    expected = ["C1", "C2"]
    random.Random("INC-123").shuffle(expected)
    ranking = [call for call in judge.calls if "cause_rank" in call[1]]
    assert list(ranking[0][1]["cause_rank"]["criteria"]) == expected + ["insufficient_evidence"]


def test_run_without_a_report_draft_exits_1(command, skill_dir, case_dir, capsys):
    (case_dir / "report.json").unlink()
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(make_responder())) == 1
    assert "report.json" in capsys.readouterr().err


def test_run_with_an_unusable_report_draft_exits_1(command, skill_dir, case_dir, capsys):
    (case_dir / "report.json").write_text(json.dumps({"symptoms": ["x"], "causes": []}))
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(make_responder())) == 1
    assert "causes" in capsys.readouterr().err


def test_run_with_a_report_that_is_not_json_exits_1(command, skill_dir, case_dir):
    (case_dir / "report.json").write_text("{not json")
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(make_responder())) == 1


def test_run_without_a_case_exits_2(command, skill_dir, tmp_path):
    assert invoke(command, skill_dir, "run", "--case-dir", str(tmp_path / "nowhere"), judge=FakeJudge()) == 2


def test_run_without_a_config_exits_2(command, tmp_path, case_dir):
    assert invoke(command, tmp_path / "empty-skill", "run", "--case-dir", str(case_dir), judge=FakeJudge()) == 2


def test_run_with_a_broken_question_file_exits_1(command, skill_dir, case_dir, capsys):
    (skill_dir / "judgments" / "questions.json").write_text("{}")
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge()) == 1
    assert "version" in capsys.readouterr().err


def test_run_without_a_key_records_unavailable_and_exits_0(skill_dir, case_dir):
    env = {key: value for key, value in os.environ.items() if key != "TYPESAFE_API_KEY"}
    result = subprocess.run([sys.executable, *COMMAND, "run", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir)],
                            capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stderr
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["typesafe"].startswith("unavailable: ")
    assert summary["causes"]["C1"]["label"] == "probable"


# locate

@pytest.fixture
def located_case(case_dir):
    case = json.loads((case_dir / "case.json").read_text())
    case["match"] = {"status": "many", "candidates": [
        {"service": "checkout-api", "environment": "prod", "reasons": []},
        {"service": "checkout-api", "environment": "staging", "reasons": []},
    ]}
    (case_dir / "case.json").write_text(json.dumps(case))
    (case_dir / "incident.json").write_text(json.dumps({
        "number": "INC-123", "title": "Checkout API is down", "description": "502s", "declared_at": "2026-10-04T10:45:00Z",
        "monitors": [{"name": "Checkout API"}], "labels": ["checkout"], "hostnames": ["checkout.example.com"],
        "timeline": [{"time": "x", "text": "not sent"}]}))
    return case_dir


def test_locate_prints_the_decision(command, skill_dir, located_case, capsys):
    judge = FakeJudge(locate_answer("checkout-api/prod", 0.9))
    assert invoke(command, skill_dir, "locate", "--case-dir", str(located_case), judge=judge) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "checkout-api/prod" and out["confidence"] == 0.9
    state = judge.calls[0][0]
    assert state["incident"] == {"title": "Checkout API is down", "description": "502s", "monitors": [{"name": "Checkout API"}],
                                 "labels": ["checkout"], "hostnames": ["checkout.example.com"]}
    prod = state["candidates"]["checkout-api/prod"]
    assert prod.startswith("prod-main, eu-west-1, resources: ")
    assert "ecs_service=checkout/checkout-api" in prod and "log_groups" in prod and "log_groups=" not in prod
    assert state["candidates"]["checkout-api/staging"].startswith("staging, eu-west-1")
    assert (located_case / "judgments" / "001-locate.json").is_file()


def test_locate_asks_when_typesafe_is_unavailable(command, skill_dir, located_case, capsys):
    assert invoke(command, skill_dir, "locate", "--case-dir", str(located_case), judge=FakeJudge(fail_with="down")) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "ask"


def test_locate_without_candidates_exits_1(command, skill_dir, case_dir, capsys):
    assert invoke(command, skill_dir, "locate", "--case-dir", str(case_dir), judge=FakeJudge()) == 1
    assert "candidates" in capsys.readouterr().err


# adhoc

ADHOC_QUESTION = {"type": "choice", "instructions": "Is `deploy` the likely trigger of `symptom`?",
                  "criteria": {"yes": "The deploy is the likely trigger", "no": "The deploy is not the likely trigger"}}


def adhoc_file(tmp_path, **overrides):
    document = {"id": "deploy_trigger", "reason": "No fixed question covers deploy timing",
                "state": {"deploy": "checkout-api:42 at 10:40", "symptom": "502 at 10:41"}, "question": ADHOC_QUESTION}
    document.update(overrides)
    path = tmp_path / "adhoc.json"
    path.write_text(json.dumps(document))
    return str(path)


def adhoc_judge():
    return FakeJudge({"deploy_trigger": {"type": "choice", "choice": "yes", "confidence": 0.8, "probabilities": {"yes": 0.8, "no": 0.2}}})


def test_adhoc_prints_and_stores_the_answer(command, skill_dir, case_dir, tmp_path, capsys):
    judge = adhoc_judge()
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=judge) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["id"] == "deploy_trigger" and out["answer"]["choice"] == "yes"
    assert judge.calls[0][1] == {"deploy_trigger": ADHOC_QUESTION}
    stored = json.loads((case_dir / "judgments" / "001-adhoc.json").read_text())
    assert stored["subject"] == "deploy_trigger" and stored["answers"]["deploy_trigger"]["confidence"] == 0.8


def test_adhoc_creates_a_minimal_summary_when_none_exists(command, skill_dir, case_dir, tmp_path):
    invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=adhoc_judge())
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["adhoc"] == [{"id": "deploy_trigger", "reason": "No fixed question covers deploy timing"}]
    assert summary["typesafe"] == "available" and summary["uncalibrated"] is True
    assert summary["findings"] == {} and summary["causes"] == {} and summary["actions"] == {} and summary["ask_engineer"] == []


def test_adhoc_appends_to_an_existing_summary(command, skill_dir, case_dir, tmp_path):
    invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(make_responder()))
    invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=adhoc_judge())
    invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path, id="deploy_trigger"), judge=adhoc_judge())
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["causes"]["C1"]["label"] == "confirmed"
    assert [entry["id"] for entry in summary["adhoc"]] == ["deploy_trigger", "deploy_trigger"]
    assert (case_dir / "judgments" / "010-adhoc.json").is_file()


def test_adhoc_when_unavailable_prints_that_and_records_it_in_a_minimal_summary(command, skill_dir, case_dir, tmp_path, capsys):
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=FakeJudge(fail_with="down")) == 0
    assert json.loads(capsys.readouterr().out) == {"id": "deploy_trigger", "unavailable": "down"}
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["adhoc"] == [{"id": "deploy_trigger", "reason": "No fixed question covers deploy timing", "unavailable": "down"}]
    assert summary["judged"] is False and summary["typesafe"] == "unavailable: down"


def test_adhoc_when_unavailable_appends_to_an_existing_summary(command, skill_dir, case_dir, tmp_path):
    invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(make_responder()))
    invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=FakeJudge(fail_with="down"))
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["typesafe"] == "available" and summary["causes"]["C1"]["label"] == "confirmed"
    assert summary["adhoc"][0]["unavailable"] == "down"


@pytest.mark.parametrize("fixed_id", ["evidence_relation", "symptom_fit", "cause_rank", "resource_match"])
def test_adhoc_may_not_reuse_a_fixed_question_id(command, skill_dir, case_dir, tmp_path, fixed_id, capsys):
    judge = adhoc_judge()
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path, id=fixed_id), judge=judge) == 1
    assert fixed_id in capsys.readouterr().err and judge.calls == []


def test_adhoc_refuses_a_state_that_is_too_long(command, skill_dir, case_dir, tmp_path, capsys):
    judge = adhoc_judge()
    path = adhoc_file(tmp_path, state={"evidence": "word " * 3000})
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", path, judge=judge) == 1
    assert "8000" in capsys.readouterr().err and judge.calls == []


@pytest.mark.parametrize("overrides", [
    {"question": {"type": "choice", "instructions": "Pick", "criteria": {"only": "one option"}}},
    {"question": {"type": "maybe", "instructions": "x"}},
    {"question": {**ADHOC_QUESTION, "criteria": None, "criteria_from": "candidates", "fallback": {"none": "none"}}},
    {"id": ""},
    {"reason": ""},
    {"state": None},
])
def test_adhoc_with_an_invalid_file_exits_1(command, skill_dir, case_dir, tmp_path, overrides, capsys):
    path = adhoc_file(tmp_path, **overrides)
    judge = adhoc_judge()
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", path, judge=judge) == 1
    assert capsys.readouterr().err and judge.calls == []


def test_adhoc_with_a_missing_or_malformed_file_exits_1(command, skill_dir, case_dir, tmp_path):
    missing = str(tmp_path / "none.json")
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", missing, judge=adhoc_judge()) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("[1]")
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", str(bad), judge=adhoc_judge()) == 1


def test_adhoc_question_text_and_options_are_redacted_before_sending(command, skill_dir, case_dir, tmp_path, config_data):
    account_id = config_data["accounts"]["prod-main"]["account_id"]
    secret = "hunter" + "2"
    question = {"type": "choice", "instructions": f"Did the role in {account_id} lose access, with password={secret}?",
                "criteria": {"yes": f"It lost access in {account_id}", "no": "It did not lose access"}}
    path = adhoc_file(tmp_path, question=question)
    judge = adhoc_judge()
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", path, judge=judge) == 0
    stored = (case_dir / "judgments" / "001-adhoc.json").read_text()
    for text in (json.dumps(judge.calls), stored):
        assert account_id not in text and secret not in text


def test_run_with_a_draft_that_breaks_a_rule_exits_2_and_asks_nothing(command, skill_dir, case_dir, capsys):
    report = json.loads((case_dir / "report.json").read_text())
    report["causes"].append(dict(report["causes"][0]))
    (case_dir / "report.json").write_text(json.dumps(report))
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 2
    assert "duplicate cause id C1" in capsys.readouterr().err and judge.calls == []


# the run command retires the summary first

@pytest.fixture
def judged_case(command, skill_dir, case_dir):
    invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(make_responder()))
    assert (case_dir / "judgments" / "summary.json").is_file()
    return case_dir


def test_a_failure_before_judging_still_retires_the_old_summary(command, skill_dir, judged_case):
    def retired():
        return not (judged_case / "judgments" / "summary.json").exists() and (judged_case / "judgments" / "summary.json.stale").is_file()

    (skill_dir / "judgments" / "questions.json").write_text("{}")
    assert invoke(command, skill_dir, "run", "--case-dir", str(judged_case), judge=FakeJudge()) == 1 and retired()


def test_a_broken_config_still_retires_the_old_summary(command, skill_dir, judged_case):
    (skill_dir / "config" / "triage-config.yaml").write_text("x: 1")
    assert invoke(command, skill_dir, "run", "--case-dir", str(judged_case), judge=FakeJudge()) == 2
    assert not (judged_case / "judgments" / "summary.json").exists()


def test_a_broken_case_still_retires_the_old_summary(command, skill_dir, judged_case):
    (judged_case / "case.json").write_text("{}")
    assert invoke(command, skill_dir, "run", "--case-dir", str(judged_case), judge=FakeJudge()) == 2
    assert not (judged_case / "judgments" / "summary.json").exists()


def test_a_run_for_a_case_without_a_summary_just_fails_normally(command, skill_dir, tmp_path):
    assert invoke(command, skill_dir, "run", "--case-dir", str(tmp_path / "nowhere"), judge=FakeJudge()) == 2


def test_an_oversized_draft_exits_2_with_no_calls_and_no_files(command, skill_dir, case_dir, capsys):
    report = json.loads((case_dir / "report.json").read_text())
    report["causes"][0]["statement"] = "word " * 2000
    (case_dir / "report.json").write_text(json.dumps(report))
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 2
    assert "8000" in capsys.readouterr().err and judge.calls == []
    assert list((case_dir / "judgments").glob("0*.json")) == []


def test_an_action_without_a_cause_exits_2(command, skill_dir, case_dir):
    report = json.loads((case_dir / "report.json").read_text())
    report["actions"][0]["cause"] = "C9"
    (case_dir / "report.json").write_text(json.dumps(report))
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 2 and judge.calls == []


def failing_judge(reason):
    from triage.judge_client import JudgeUnavailable
    judge = FakeJudge()
    base = make_responder()

    def answer(state, questions):
        if len(judge.calls) == 9:
            raise JudgeUnavailable(reason)
        return base(state, questions)

    judge.answers = answer
    return judge


def test_a_malformed_answer_run_writes_a_failed_summary_and_exits_1(command, skill_dir, case_dir, capsys):
    judge = failing_judge("MalformedAnswer: action_specific")
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 1
    captured = capsys.readouterr()
    assert str(case_dir / "judgments" / "summary.json") in captured.out
    assert "judging failed" in captured.err and "run again" in captured.err
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["status"] == "failed" and summary["typesafe"].startswith("failed: MalformedAnswer")


def test_any_other_failure_after_calls_began_exits_1_with_a_failed_summary(command, skill_dir, case_dir):
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(lambda state, questions: {})) == 1
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["status"] == "failed" and summary["typesafe"].startswith("failed: ")


def test_an_unavailable_service_run_exits_0_with_an_unavailable_value(command, skill_dir, case_dir):
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=failing_judge("the connection failed")) == 0
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["status"] == "unavailable" and summary["typesafe"] == "unavailable: the connection failed"


def test_a_complete_run_exits_0_and_is_available(command, skill_dir, case_dir):
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=FakeJudge(make_responder())) == 0
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["status"] == "complete" and summary["typesafe"] == "available"


# ad hoc: id, reason, size, odd summaries

@pytest.mark.parametrize("bad_id", ["Deploy", "1deploy", "deploy-trigger", "d" * 41, "deploy trigger", "a/b"])
def test_adhoc_id_must_be_a_short_lowercase_name(command, skill_dir, case_dir, tmp_path, bad_id):
    judge = adhoc_judge()
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path, id=bad_id), judge=judge) == 1
    assert judge.calls == []


def test_adhoc_reason_is_redacted_before_it_is_stored(command, skill_dir, case_dir, tmp_path, config_data):
    account_id = config_data["accounts"]["prod-main"]["account_id"]
    secret = "hunter" + "2"
    path = adhoc_file(tmp_path, reason=f"Checking {account_id} with password={secret}")
    invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", path, judge=adhoc_judge())
    stored = (case_dir / "judgments" / "summary.json").read_text()
    assert account_id not in stored and secret not in stored and "prod-main" in stored


def test_adhoc_question_text_is_limited_to_2000_characters(command, skill_dir, case_dir, tmp_path, capsys):
    question = {**ADHOC_QUESTION, "instructions": "Is it? " + "x" * 2000}
    judge = adhoc_judge()
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path, question=question), judge=judge) == 1
    assert "2000" in capsys.readouterr().err and judge.calls == []


@pytest.mark.parametrize("text", ["[1, 2]", "null", '"x"'])
def test_adhoc_with_a_summary_that_is_not_an_object_exits_1(command, skill_dir, case_dir, tmp_path, text, capsys):
    (case_dir / "judgments").mkdir(exist_ok=True)
    (case_dir / "judgments" / "summary.json").write_text(text)
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=adhoc_judge()) == 1
    assert "summary.json" in capsys.readouterr().err


def test_adhoc_checks_the_summary_before_paying_for_the_call(command, skill_dir, case_dir, tmp_path):
    (case_dir / "judgments").mkdir(exist_ok=True)
    (case_dir / "judgments" / "summary.json").write_text("[1]")
    judge = adhoc_judge()
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=judge) == 1
    assert judge.calls == [] and not list((case_dir / "judgments").glob("0*.json"))


def test_a_checked_json_of_the_wrong_shape_exits_2_with_one_line(command, skill_dir, case_dir, capsys):
    path = case_dir / "findings" / "checked.json"
    checked = json.loads(path.read_text())
    checked["valid"][0].pop("claim")
    path.write_text(json.dumps(checked))
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 2
    err = capsys.readouterr().err.strip()
    assert err.count("\n") == 0 and "findings check" in err and "Traceback" not in err and judge.calls == []


def test_a_draft_with_a_wrong_field_exits_2_with_the_reports_wording_and_no_calls(command, skill_dir, case_dir, capsys):
    report = json.loads((case_dir / "report.json").read_text())
    report["actions"][0]["preconditions"] = "A free slot"
    (case_dir / "report.json").write_text(json.dumps(report))
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 2
    assert "actions[0].preconditions: must be a list of text" in capsys.readouterr().err
    assert judge.calls == [] and list((case_dir / "judgments").glob("*.json")) == []


# a case folder is only a run folder under the cases root

@pytest.fixture
def copied_case(case_dir, tmp_path):
    elsewhere = tmp_path / "intake" / "INC-123" / "20261004-111000"
    shutil.copytree(case_dir, elsewhere)
    return elsewhere


@pytest.mark.parametrize("subcommand", ["run", "locate", "adhoc"])
def test_every_subcommand_refuses_a_folder_outside_the_cases_root_and_writes_nothing(
        command, skill_dir, copied_case, tmp_path, capsys, subcommand):
    extra = ["--question-file", adhoc_file(tmp_path)] if subcommand == "adhoc" else []
    (copied_case / "judgments").mkdir(exist_ok=True)
    (copied_case / "judgments" / "summary.json").write_text("{}")
    before = sorted(str(path.relative_to(copied_case)) for path in copied_case.rglob("*"))
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, subcommand, "--case-dir", str(copied_case), *extra, judge=judge) == 2
    assert "not a case folder under" in capsys.readouterr().err and judge.calls == []
    assert sorted(str(path.relative_to(copied_case)) for path in copied_case.rglob("*")) == before


def test_a_folder_that_is_not_two_levels_under_the_root_is_refused(command, skill_dir, case_dir, capsys):
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir.parent), judge=FakeJudge()) == 2
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir / "findings"), judge=FakeJudge()) == 2


def test_a_symbolic_link_to_a_copy_elsewhere_is_refused(command, skill_dir, copied_case, tmp_path):
    link = tmp_path / "cases" / "INC-9" / "20261004-120000"
    link.parent.mkdir(parents=True)
    link.symlink_to(copied_case)
    assert invoke(command, skill_dir, "run", "--case-dir", str(link), judge=FakeJudge()) == 2


def test_a_case_whose_replay_state_differs_from_the_environment_is_refused(command, skill_dir, case_dir, monkeypatch, capsys):
    case = json.loads((case_dir / "case.json").read_text())
    case["replay"] = True
    (case_dir / "case.json").write_text(json.dumps(case))
    monkeypatch.delenv("AI_TRIAGE_FIXTURES", raising=False)
    judge = FakeJudge(make_responder())
    assert invoke(command, skill_dir, "run", "--case-dir", str(case_dir), judge=judge) == 2
    assert "replay" in capsys.readouterr().err and judge.calls == []


def test_locate_without_the_service_picks_the_one_candidate_matched_by_name(command, skill_dir, located_case, capsys):
    case = json.loads((located_case / "case.json").read_text())
    case["match"]["candidates"][0]["reasons"] = ["monitor:checkout api", "hostname:checkout.example.com"]
    case["match"]["candidates"][1]["reasons"] = ["label:checkout"]
    (located_case / "case.json").write_text(json.dumps(case))
    judge = FakeJudge(fail_with="down")
    assert invoke(command, skill_dir, "locate", "--case-dir", str(located_case), judge=judge) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "checkout-api/prod"
    assert "matched by: monitor:checkout api" in judge.calls[0][0]["candidates"]["checkout-api/prod"]
