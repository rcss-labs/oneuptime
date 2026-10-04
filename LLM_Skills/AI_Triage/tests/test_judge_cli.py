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

COMMAND = SKILL_SRC / "scripts" / "judge.py"


def load_command():
    spec = importlib.util.spec_from_file_location("judge_command", COMMAND)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def command():
    return load_command()


@pytest.fixture
def skill_dir(tmp_path, config_data, map_data):
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "judgments").mkdir()
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    (root / "config" / "service-map.yaml").write_text(yaml.safe_dump(map_data))
    shutil.copy(SKILL_SRC / "judgments" / "questions.json", root / "judgments" / "questions.json")
    return root


@pytest.fixture
def case_dir(tmp_path, config_data):
    (tmp_path / "case-folder").mkdir()
    return build_case(tmp_path / "case-folder", parse_config(config_data))


def invoke(command, skill_dir, *args, judge=None):
    return command.main([*args, "--skill-dir", str(skill_dir)], judge=judge)


def test_help_works():
    result = subprocess.run([sys.executable, str(COMMAND), "--help"], capture_output=True, text=True)
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
    result = subprocess.run([sys.executable, str(COMMAND), "run", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir)],
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


def test_adhoc_when_unavailable_prints_that_and_records_nothing(command, skill_dir, case_dir, tmp_path, capsys):
    assert invoke(command, skill_dir, "adhoc", "--case-dir", str(case_dir), "--question-file", adhoc_file(tmp_path), judge=FakeJudge(fail_with="down")) == 0
    assert json.loads(capsys.readouterr().out) == {"id": "deploy_trigger", "unavailable": "down"}
    assert not (case_dir / "judgments" / "summary.json").exists()


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
