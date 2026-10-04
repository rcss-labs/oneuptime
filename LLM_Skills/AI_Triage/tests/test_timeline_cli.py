import json
import subprocess
import sys

from conftest import SKILL_SRC

SCRIPT = SKILL_SRC / "scripts" / "timeline.py"


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def write_case(tmp_path):
    (tmp_path / "case.json").write_text(json.dumps({
        "incident_start": "2026-10-04T10:42:00Z",
        "incident": {"declared_at": "2026-10-04T10:45:00Z", "impact_started_at": None, "resolved_at": None},
    }))
    (tmp_path / "incident.json").write_text(json.dumps({"number": "INC-1", "declared_at": "2026-10-04T10:45:00Z"}))
    return tmp_path


def test_prints_the_table_and_writes_timeline_json(tmp_path):
    result = run("--case-dir", str(write_case(tmp_path)))
    assert result.returncode == 0, result.stderr
    assert "| Time | Relative to incident start | Event | Source |" in result.stdout
    assert "Incident declared" in result.stdout
    rows = json.loads((tmp_path / "timeline.json").read_text())
    assert rows[0]["text"] == "Incident declared"


def test_missing_case_dir_exits_two(tmp_path):
    result = run("--case-dir", str(tmp_path / "none"))
    assert result.returncode == 2
    assert "none" in result.stderr


def test_case_dir_without_case_json_exits_two(tmp_path):
    assert run("--case-dir", str(tmp_path)).returncode == 2


def test_usage_error_exits_two():
    assert run().returncode == 2
