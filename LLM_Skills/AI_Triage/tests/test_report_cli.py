import copy
import json
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC
from test_report import VALID_REPORT, config, case_dir, case, findings  # noqa: F401  (fixtures)
from triage.report import REQUIRED_HEADINGS, validate_work_order

SCRIPT = SKILL_SRC / "scripts" / "report.py"
NOW = "2026-10-04T11:30:00Z"


@pytest.fixture
def skill_dir(tmp_path, config_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "cmd-skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return root


def run(skill_dir, *args):
    return subprocess.run([sys.executable, str(SCRIPT), *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True)


def write_report(case_dir, report):
    (case_dir / "report.json").write_text(json.dumps(report))


def test_help_works():
    result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "validate" in result.stdout and "render" in result.stdout


def test_validate_valid_report_exits_zero(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 0, result.stderr
    assert "valid" in result.stdout


def test_validate_invalid_report_prints_every_problem_and_exits_one(skill_dir, case_dir):
    report = copy.deepcopy(VALID_REPORT)
    report["summary"]["impact"] = ""
    report["actions"][0]["title"] = ""
    write_report(case_dir, report)
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 1
    assert "summary.impact" in result.stderr and "actions[0].title" in result.stderr


def test_unparseable_report_exits_one(skill_dir, case_dir):
    (case_dir / "report.json").write_text("{nope")
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "report.json" in result.stderr


def test_missing_report_exits_two(skill_dir, case_dir):
    for command in ("validate", "render"):
        result = run(skill_dir, command, "--case-dir", str(case_dir))
        assert result.returncode == 2 and "report.json" in result.stderr


def test_missing_case_dir_and_usage_errors_exit_two(skill_dir, tmp_path):
    assert run(skill_dir, "validate", "--case-dir", str(tmp_path / "none")).returncode == 2
    assert subprocess.run([sys.executable, str(SCRIPT)], capture_output=True).returncode == 2
    assert run(skill_dir, "render").returncode == 2


def test_bad_config_exits_two(tmp_path, case_dir):
    empty = tmp_path / "empty-skill"
    empty.mkdir()
    write_report(case_dir, VALID_REPORT)
    assert run(empty, "validate", "--case-dir", str(case_dir)).returncode == 2


def test_render_writes_report_and_work_order(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    result = run(skill_dir, "render", "--case-dir", str(case_dir), "--now", NOW)
    assert result.returncode == 0, result.stderr
    assert str(case_dir / "report.md") in result.stdout and str(case_dir / "work-order.json") in result.stdout
    text = (case_dir / "report.md").read_text()
    assert text.count(REQUIRED_HEADINGS[1]) == 1
    order = json.loads((case_dir / "work-order.json").read_text())
    assert validate_work_order(order) == []
    assert order["generated_at"] == NOW
    assert any("AccessDenied" in gap for gap in order["coverage_gaps"])
    assert (case_dir / "timeline.json").is_file()


def test_invalid_report_is_not_rendered(skill_dir, case_dir):
    report = copy.deepcopy(VALID_REPORT)
    report["causes"][0]["supporting"] = ["ghost-1"]
    write_report(case_dir, report)
    result = run(skill_dir, "render", "--case-dir", str(case_dir), "--now", NOW)
    assert result.returncode == 1 and "causes[0].supporting[0]" in result.stderr
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()
