import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC

SCRIPT = [str(SKILL_SRC / "scripts" / "run.py"), "timeline"]
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
    return subprocess.run([sys.executable, *SCRIPT, *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True, env=env)


def write_case(tmp_path, replay=False):
    case_dir = tmp_path / "cases" / "INC-1" / "20261004-110000"
    case_dir.mkdir(parents=True)
    (case_dir / "case.json").write_text(json.dumps({
        "incident_start": "2026-10-04T10:42:00Z", "replay": replay,
        "incident": {"declared_at": "2026-10-04T10:45:00Z", "impact_started_at": None, "resolved_at": None},
    }))
    (case_dir / "incident.json").write_text(json.dumps({"number": "INC-1", "declared_at": "2026-10-04T10:45:00Z"}))
    return case_dir


def test_prints_the_table_and_writes_timeline_json(tmp_path, skill_dir):
    case_dir = write_case(tmp_path)
    result = run(skill_dir, "--case-dir", str(case_dir))
    assert result.returncode == 0, result.stderr
    assert "| Time | Relative to incident start | Event | Source |" in result.stdout
    assert "Incident declared" in result.stdout
    assert not result.stdout.startswith("REPLAY")
    rows = json.loads((case_dir / "timeline.json").read_text())
    assert rows[0]["text"] == "Incident declared"


def test_missing_case_dir_exits_two(tmp_path, skill_dir):
    result = run(skill_dir, "--case-dir", str(tmp_path / "cases" / "INC-1" / "none"))
    assert result.returncode == 2
    assert "not a case folder" in result.stderr


def test_case_dir_without_case_json_exits_two(tmp_path, skill_dir):
    case_dir = tmp_path / "cases" / "INC-1" / "20261004-110000"
    case_dir.mkdir(parents=True)
    assert run(skill_dir, "--case-dir", str(case_dir)).returncode == 2


def test_a_copied_run_folder_is_refused_and_nothing_is_written(tmp_path, skill_dir):
    copy = tmp_path / "elsewhere" / "INC-1" / "20261004-110000"
    shutil.copytree(write_case(tmp_path), copy)
    result = run(skill_dir, "--case-dir", str(copy))
    assert result.returncode == 2
    assert "not a case folder" in result.stderr
    assert not (copy / "timeline.json").exists()


def test_a_replay_case_prints_replay_first(tmp_path, skill_dir):
    result = run(skill_dir, "--case-dir", str(write_case(tmp_path, replay=True)), replay=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[0].startswith("REPLAY")


def test_a_replay_case_without_replay_mode_is_refused(tmp_path, skill_dir):
    case_dir = write_case(tmp_path, replay=True)
    assert run(skill_dir, "--case-dir", str(case_dir)).returncode == 2
    assert not (case_dir / "timeline.json").exists()


def test_usage_error_exits_two(skill_dir):
    assert run(skill_dir).returncode == 2
