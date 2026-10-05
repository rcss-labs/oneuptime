import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conftest import SKILL_SRC

COMMAND = SKILL_SRC / "scripts" / "case.py"
INCIDENT = {
    "number": "INC-123",
    "title": "Checkout API is down",
    "declared_at": "2026-10-04T10:45:00Z",
    "impact_started_at": "2026-10-04T10:42:00Z",
    "monitors": [{"name": "Checkout API", "type": "API", "target": "https://checkout.example.com/health"}],
    "labels": ["checkout"],
}
NOW = "2026-10-04T11:00:00Z"


@pytest.fixture
def skill_dir(tmp_path, config_data, map_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    (root / "config" / "service-map.yaml").write_text(yaml.safe_dump(map_data))
    return root


def run(skill_dir, *args):
    return subprocess.run([sys.executable, str(COMMAND), *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True)


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


@pytest.fixture
def case_dir(skill_dir, tmp_path):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "incident.json", INCIDENT), "--now", NOW)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["case_dir"]


def test_help_works():
    result = subprocess.run([sys.executable, str(COMMAND), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "init" in result.stdout and "plan" in result.stdout


def test_init_prints_the_case_summary(skill_dir, tmp_path):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["case_dir"].endswith("INC-123/20261004-110000")
    assert Path(out["case_dir"], "case.md").is_file()
    assert out["window"] == {"start": "2026-10-04T09:42:00Z", "end": "2026-10-04T11:00:00Z"}
    assert out["incident_start"] == "2026-10-04T10:42:00Z"
    assert out["match"]["status"] == "one"


def test_init_reads_the_clock_when_now_is_not_given(skill_dir, tmp_path):
    incident = {**INCIDENT, "declared_at": "2999-01-01T00:00:00Z", "impact_started_at": None}
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", incident))
    assert result.returncode == 2  # the window would end before it starts


def test_init_lists_every_problem_and_exits_2(skill_dir, tmp_path):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", {"labels": "x"}), "--now", NOW)
    assert result.returncode == 2
    for word in ("number", "title", "declared_at", "labels"):
        assert word in result.stderr


@pytest.mark.parametrize("args", [["--incident", "missing.json"], ["--incident", "BAD", "--now", "later"]])
def test_init_usage_errors_exit_2(skill_dir, tmp_path, args):
    args = [str(tmp_path / "bad.json") if a == "BAD" else a for a in args]
    (tmp_path / "bad.json").write_text("{not json")
    assert run(skill_dir, "init", *args).returncode == 2


def test_init_in_the_same_second_takes_the_next_run_name(skill_dir, tmp_path, case_dir):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 0 and json.loads(result.stdout)["case_dir"].endswith("20261004-110001")


def test_init_after_five_taken_names_exits_2(skill_dir, tmp_path, case_dir):
    codes = [run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW) for _ in range(5)]
    assert [c.returncode for c in codes] == [0, 0, 0, 0, 2]
    assert len(codes[-1].stderr.strip().splitlines()) == 1


def test_init_works_without_a_service_map(skill_dir, tmp_path):
    (skill_dir / "config" / "service-map.yaml").unlink()
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 0 and json.loads(result.stdout)["match"]["status"] == "none"


def test_init_with_a_missing_config_exits_2(tmp_path):
    result = run(tmp_path, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 2


def test_target_from_the_map(skill_dir, case_dir):
    result = run(skill_dir, "target", "--case-dir", case_dir, "--service", "checkout-api", "--environment", "prod")
    assert result.returncode == 0, result.stderr
    target = json.loads(result.stdout)
    assert target["account"] == "prod-main" and target["source"] == "map"
    assert json.loads(Path(case_dir, "case.json").read_text())["target"] == target


def test_target_unknown_service_exits_2(skill_dir, case_dir):
    result = run(skill_dir, "target", "--case-dir", case_dir, "--service", "nope", "--environment", "prod")
    assert result.returncode == 2 and "nope" in result.stderr


def test_target_from_a_discovery_file(skill_dir, case_dir, tmp_path):
    discovery = {"hostname": "checkout.example.com", "account": "prod-main", "region": "eu-west-1",
                 "resources": {"rds": "checkout-prod-db"}, "steps": [], "notes": []}
    for payload in (discovery, {"discovery": discovery, "proposed_entry": {}}):
        result = run(skill_dir, "target", "--case-dir", case_dir, "--discovery", write(tmp_path, "d.json", payload))
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["source"] == "discovered"


def test_target_from_a_discovery_without_an_account_exits_2(skill_dir, case_dir, tmp_path):
    discovery = {"account": None, "region": None, "resources": {}}
    result = run(skill_dir, "target", "--case-dir", case_dir, "--discovery", write(tmp_path, "d.json", discovery))
    assert result.returncode == 2 and "account" in result.stderr


def test_target_needs_either_a_service_or_a_discovery(skill_dir, case_dir, tmp_path):
    assert run(skill_dir, "target", "--case-dir", case_dir).returncode == 2
    both = run(skill_dir, "target", "--case-dir", case_dir, "--service", "a", "--environment", "b",
               "--discovery", write(tmp_path, "d.json", {}))
    assert both.returncode == 2
    assert run(skill_dir, "target", "--case-dir", case_dir, "--service", "a").returncode == 2


def test_plan_prints_shell_quoted_commands(skill_dir, case_dir):
    run(skill_dir, "target", "--case-dir", case_dir, "--service", "checkout-api", "--environment", "prod")
    result = run(skill_dir, "plan", "--case-dir", case_dir)
    assert result.returncode == 0, result.stderr
    planned = json.loads(result.stdout)
    assert all(set(item) == {"domain", "tool", "name", "command", "reason"} for item in planned)
    ecs = next(item for item in planned if item["name"] == "ecs")
    assert ecs["command"].startswith(f"{skill_dir}/.venv/bin/python {skill_dir}/scripts/collect.py ecs ")
    assert "--target cluster=checkout --target service=checkout-api" in ecs["command"]
    assert {"changes", "platform", "opensearch"} <= {item["name"] for item in planned}
    log_group = next(item for item in planned if item["name"] == "logs")
    assert "log_groups=/ecs/checkout-api" in log_group["command"]


def test_plan_without_a_target_exits_2(skill_dir, case_dir):
    result = run(skill_dir, "plan", "--case-dir", case_dir)
    assert result.returncode == 2 and "target" in result.stderr


def test_show_prints_case_json(skill_dir, case_dir):
    result = run(skill_dir, "show", "--case-dir", case_dir)
    assert result.returncode == 0
    assert json.loads(result.stdout) == json.loads(Path(case_dir, "case.json").read_text())


def test_show_with_a_missing_case_exits_2(skill_dir, tmp_path):
    assert run(skill_dir, "show", "--case-dir", str(tmp_path / "nowhere")).returncode == 2


def assert_clean_exit_2(result):
    assert result.returncode == 2, result.stderr
    assert "Traceback" not in result.stderr
    assert len(result.stderr.strip().splitlines()) == 1


def test_a_very_long_incident_number_exits_2_in_one_line(skill_dir, tmp_path):
    incident = {**INCIDENT, "number": "x" * 300}
    assert_clean_exit_2(run(skill_dir, "init", "--incident", write(tmp_path, "i.json", incident), "--now", NOW))


@pytest.mark.parametrize("discovery", ["text", ["x"], {"account": ["a"], "region": "r", "resources": {}},
                                       {"account": "prod-main", "region": "eu-west-1", "resources": ["x"]},
                                       {"discovery": "text"}, {"discovery": ["x"]}])
def test_a_discovery_of_the_wrong_shape_exits_2_in_one_line(skill_dir, case_dir, tmp_path, discovery):
    result = run(skill_dir, "target", "--case-dir", case_dir, "--discovery", write(tmp_path, "d.json", discovery))
    assert_clean_exit_2(result)


def test_a_discovery_file_that_is_not_utf8_exits_2(skill_dir, case_dir, tmp_path):
    (tmp_path / "d.json").write_bytes(b"\xff\xfe\x00")
    assert_clean_exit_2(run(skill_dir, "target", "--case-dir", case_dir, "--discovery", str(tmp_path / "d.json")))


@pytest.mark.parametrize("subcommand", ["show", "plan"])
def test_a_corrupt_case_json_exits_2_in_one_line(skill_dir, case_dir, subcommand):
    Path(case_dir, "case.json").write_text("{not json")
    assert_clean_exit_2(run(skill_dir, subcommand, "--case-dir", case_dir))


def test_a_run_folder_that_cannot_be_created_exits_2(skill_dir, tmp_path):
    (tmp_path / "cases").write_text("a file")
    assert_clean_exit_2(run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW))


@pytest.mark.parametrize("subcommand", ["plan", "target"])
def test_a_case_json_with_wrong_value_types_exits_2_in_one_line(skill_dir, case_dir, subcommand):
    path = Path(case_dir, "case.json")
    case = json.loads(path.read_text())
    case["window"]["start"] = 1
    case["match"]["candidates"] = [{"service": "s", "environment": "e", "reasons": 5}]
    case["incident"]["hostnames"] = 5
    path.write_text(json.dumps(case))
    extra = ["--service", "checkout-api", "--environment", "prod"] if subcommand == "target" else []
    assert_clean_exit_2(run(skill_dir, subcommand, "--case-dir", case_dir, *extra))


def test_a_bad_opensearch_filter_key_exits_2_from_plan(skill_dir, case_dir, tmp_path):
    discovery = {"account": "prod-main", "region": "eu-west-1", "resources": {
        "opensearch": {"cluster": "logs-prod", "index_pattern": "app-logs-checkout-*", "filter": {"-dash": "v"}}}}
    run(skill_dir, "target", "--case-dir", case_dir, "--discovery", write(tmp_path, "d.json", discovery))
    assert_clean_exit_2(run(skill_dir, "plan", "--case-dir", case_dir))


# collect

import importlib.util
import os

from fakes import FakeJudge  # noqa: F401  (replay_support imports it too)
from replay_support import (CALL_LOG_NAME, REPLAY_DIR, ReplayCase, _build_skill_dir, load_call_log, skill_style,
                            start_case)
from triage.config import load_config
from triage.guard import context_from_config, decide
from triage.verdict import ALLOW

SCENARIO = REPLAY_DIR / "ecs-bad-deploy"


def start_uncollected(base):
    base.mkdir(parents=True, exist_ok=True)
    skill_dir, _ = _build_skill_dir(SCENARIO, base)
    case = ReplayCase(SCENARIO, base, skill_dir, case_dir=base)
    incident = json.loads((SCENARIO / "incident.json").read_text())
    init = json.loads(case.script("init", "case.py", "init", "--incident", str(SCENARIO / "incident.json"),
                                  "--now", incident["observed_at"])["stdout"])
    case.case_dir = Path(init["case_dir"])
    candidate = init["match"]["candidates"][0]
    case.script("target", "case.py", "target", "--case-dir", str(case.case_dir),
                "--service", candidate["service"], "--environment", candidate["environment"])
    return case


def evidence_files(case_dir):
    return {path.name: json.loads(path.read_text()) for path in sorted((case_dir / "evidence").glob("*.json"))}


def test_collect_writes_the_same_evidence_as_running_the_planned_commands_one_by_one(tmp_path):
    reference = start_case(SCENARIO, tmp_path / "one-by-one")
    case = start_uncollected(tmp_path / "collect")
    done = case.script("collect", "case.py", "collect", "--case-dir", str(case.case_dir))
    report = json.loads(done["stdout"])
    assert evidence_files(case.case_dir) == evidence_files(reference.case_dir)
    assert len(evidence_files(case.case_dir)) >= 6
    for entry in report["commands"]:
        assert entry["status"] == "collected" and entry["exit_code"] == 0
        document = json.loads((case.case_dir / entry["evidence"]).read_text())
        assert entry["facts"] == len(document["facts"]) and entry["errors"] == len(document["errors"])
        assert set(entry) == {"name", "tool", "suffix", "status", "exit_code", "evidence", "facts", "errors", "stderr"}
    assert not Path(report["commands"][0]["evidence"]).is_absolute()


def test_a_second_collect_reports_already_collected_and_makes_no_call(tmp_path):
    case = start_uncollected(tmp_path / "again")
    case.script("collect", "case.py", "collect", "--case-dir", str(case.case_dir))
    calls = load_call_log(case.base)
    assert calls
    before = evidence_files(case.case_dir)
    again = json.loads(case.script("collect again", "case.py", "collect", "--case-dir", str(case.case_dir))["stdout"])
    assert {entry["status"] for entry in again["commands"]} == {"already collected"}
    assert load_call_log(case.base) == calls
    assert evidence_files(case.case_dir) == before


def load_command_module():
    spec = importlib.util.spec_from_file_location("case_command_under_test", COMMAND)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_command_that_cannot_start_gives_exit_1_and_the_others_still_run(skill_dir, tmp_path, case_dir, capsys, monkeypatch):
    run(skill_dir, "target", "--case-dir", case_dir, "--service", "checkout-api", "--environment", "prod")
    module = load_command_module()
    import triage.collection_plan as plan_module
    started = []

    def launch(argv, timeout):
        started.append(argv[2])
        if argv[2] == "rds":
            raise FileNotFoundError(2, "No such file or directory")
        return 0, ""

    monkeypatch.setattr(plan_module, "_launch", launch)
    code = module.main(["collect", "--case-dir", case_dir, "--skill-dir", str(skill_dir)])
    statuses = {e["name"]: e["status"] for e in json.loads(capsys.readouterr().out)["commands"]}
    assert code == 1 and statuses["rds"] == "not started"
    assert "changes" in started and "platform" in started


def test_a_failing_command_still_gives_exit_0(skill_dir, case_dir, capsys, monkeypatch):
    run(skill_dir, "target", "--case-dir", case_dir, "--service", "checkout-api", "--environment", "prod")
    module = load_command_module()
    import triage.collection_plan as plan_module
    monkeypatch.setattr(plan_module, "_launch", lambda argv, timeout: (3, "Sign-in expired\n"))
    assert module.main(["collect", "--case-dir", case_dir, "--skill-dir", str(skill_dir)]) == 0
    entries = json.loads(capsys.readouterr().out)["commands"]
    assert all(e["status"] in ("failed", "skipped") for e in entries)


def test_collect_without_a_target_exits_2(skill_dir, case_dir):
    assert_clean_exit_2(run(skill_dir, "collect", "--case-dir", case_dir))


def test_the_guard_allows_collect_in_the_skills_form(tmp_path, monkeypatch):
    case = start_uncollected(tmp_path / "guard")
    home = case.skill_dir.parents[2]  # the fake home that holds .claude/skills/ai-triage
    monkeypatch.setenv("HOME", str(home))
    context = context_from_config(load_config(case.skill_dir / "config" / "triage-config.yaml"), case.skill_dir)
    command = skill_style([str(case.python), str(case.skill_dir / "scripts" / "case.py"), "collect",
                           "--case-dir", str(case.case_dir)], home)
    assert command.startswith('"$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/case.py" collect')
    assert decide(command, context).kind == ALLOW
