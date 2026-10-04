import json
import subprocess
import sys

from conftest import SKILL_SRC

SCRIPT = SKILL_SRC / "scripts" / "findings.py"


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def write_case(tmp_path):
    from test_findings import add_evidence, finding, write_findings
    from triage.evidence import INCIDENT_TIME

    add_evidence(tmp_path, facts=[(INCIDENT_TIME, "container exited with code 137", "")])
    write_findings(tmp_path, "compute", [finding(), finding(id="compute-2", fact_ids=["ecs-0099"])],
                   requests=[{"collector": "rds", "targets": {}, "reason": "x"}])
    return tmp_path


def test_check_prints_summary_line_and_writes_checked_json(tmp_path):
    result = run("check", "--case-dir", str(write_case(tmp_path)))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "valid=1 rejected=1 unreadable=0 requests=1"
    checked = json.loads((tmp_path / "findings" / "checked.json").read_text())
    assert [item["id"] for item in checked["valid"]] == ["compute-1"]


def test_missing_case_dir_exits_two(tmp_path):
    result = run("check", "--case-dir", str(tmp_path / "none"))
    assert result.returncode == 2
    assert "none" in result.stderr


def test_usage_errors_exit_two():
    assert run().returncode == 2
    assert run("check").returncode == 2
    assert run("--help").returncode == 0
