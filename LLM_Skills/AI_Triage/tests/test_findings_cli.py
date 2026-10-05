import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC

SCRIPT = SKILL_SRC / "scripts" / "findings.py"
FIXTURE_ENV = "AI_TRIAGE_FIXTURES"


@pytest.fixture
def skill_dir(tmp_path, config_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return root


def run(skill_dir, *args, replay=False):
    env = {key: value for key, value in os.environ.items() if key != FIXTURE_ENV}
    if replay:
        env[FIXTURE_ENV] = str(skill_dir / "recordings")
    return subprocess.run([sys.executable, str(SCRIPT), "--skill-dir", str(skill_dir), *args],
                          capture_output=True, text=True, env=env)


def write_case(tmp_path, replay=False):
    from test_findings import add_evidence, finding, write_findings
    from triage.evidence import INCIDENT_TIME

    case_dir = tmp_path / "cases" / "INC-1" / "20261004-110000"
    case_dir.mkdir(parents=True)
    (case_dir / "case.json").write_text(json.dumps({"incident_start": "2026-10-04T10:42:00Z", "replay": replay}))
    add_evidence(case_dir, facts=[(INCIDENT_TIME, "container exited with code 137", "")])
    write_findings(case_dir, "compute", [finding(), finding(id="compute-2", fact_ids=["ecs-0099"])],
                   requests=[{"collector": "rds", "targets": {}, "reason": "x"}])
    return case_dir


def test_check_prints_summary_line_and_writes_checked_json(tmp_path, skill_dir):
    case_dir = write_case(tmp_path)
    result = run(skill_dir, "check", "--case-dir", str(case_dir))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "valid=1 rejected=1 unreadable=0 requests=1"
    checked = json.loads((case_dir / "findings" / "checked.json").read_text())
    assert [item["id"] for item in checked["valid"]] == ["compute-1"]


def test_missing_case_dir_exits_two(tmp_path, skill_dir):
    result = run(skill_dir, "check", "--case-dir", str(tmp_path / "cases" / "INC-1" / "none"))
    assert result.returncode == 2
    assert "not a case folder" in result.stderr


def test_a_copied_run_folder_is_refused_and_nothing_is_written(tmp_path, skill_dir):
    copy = tmp_path / "elsewhere" / "INC-1" / "20261004-110000"
    shutil.copytree(write_case(tmp_path), copy)
    result = run(skill_dir, "check", "--case-dir", str(copy))
    assert result.returncode == 2
    assert "not a case folder" in result.stderr
    assert not (copy / "findings" / "checked.json").exists()


def test_a_replay_case_prints_replay_first(tmp_path, skill_dir):
    result = run(skill_dir, "check", "--case-dir", str(write_case(tmp_path, replay=True)), replay=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[0].startswith("REPLAY")


def test_a_replay_case_without_replay_mode_is_refused(tmp_path, skill_dir):
    case_dir = write_case(tmp_path, replay=True)
    result = run(skill_dir, "check", "--case-dir", str(case_dir))
    assert result.returncode == 2
    assert not (case_dir / "findings" / "checked.json").exists()


def test_usage_errors_exit_two(skill_dir):
    assert run(skill_dir).returncode == 2
    assert run(skill_dir, "check").returncode == 2
    assert run(skill_dir, "--help").returncode == 0
