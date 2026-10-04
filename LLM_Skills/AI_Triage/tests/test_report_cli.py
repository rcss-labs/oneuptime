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


# stale and atomic outputs

import importlib.util


def load_command():
    spec = importlib.util.spec_from_file_location("report_command", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def render_ok(skill_dir, case_dir):
    result = run(skill_dir, "render", "--case-dir", str(case_dir), "--now", NOW)
    assert result.returncode == 0, result.stderr


def test_a_failed_render_renames_the_previous_outputs_to_stale(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    old_report, old_order = (case_dir / "report.md").read_text(), (case_dir / "work-order.json").read_text()
    broken = copy.deepcopy(VALID_REPORT)
    broken["summary"]["impact"] = ""
    write_report(case_dir, broken)
    result = run(skill_dir, "render", "--case-dir", str(case_dir), "--now", NOW)
    assert result.returncode == 1
    assert "report.md.stale" in result.stderr and "work-order.json.stale" in result.stderr
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()
    assert (case_dir / "report.md.stale").read_text() == old_report
    assert (case_dir / "work-order.json.stale").read_text() == old_order


def test_a_newer_failure_replaces_an_older_stale_copy(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    (case_dir / "report.md.stale").write_text("older")
    render_ok(skill_dir, case_dir)
    (case_dir / "report.json").write_text("{nope")
    assert run(skill_dir, "render", "--case-dir", str(case_dir), "--now", NOW).returncode == 1
    assert (case_dir / "report.md.stale").read_text().startswith("# Triage report")


def test_a_missing_report_json_also_marks_the_outputs_stale(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    (case_dir / "report.json").unlink()
    result = run(skill_dir, "render", "--case-dir", str(case_dir), "--now", NOW)
    assert result.returncode == 2 and "stale" in result.stderr
    assert (case_dir / "report.md.stale").is_file() and not (case_dir / "report.md").exists()


def test_a_failed_validate_also_marks_the_outputs_stale(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    broken = copy.deepcopy(VALID_REPORT)
    broken["summary"]["impact"] = ""
    write_report(case_dir, broken)
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "report.md.stale" in result.stderr
    assert not (case_dir / "report.md").exists() and (case_dir / "report.md.stale").is_file()


def test_a_successful_validate_leaves_the_outputs_alone(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    assert run(skill_dir, "validate", "--case-dir", str(case_dir)).returncode == 0
    assert (case_dir / "report.md").is_file() and not (case_dir / "report.md.stale").exists()


def test_a_successful_render_leaves_no_temporary_files(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    assert sorted(path.name for path in case_dir.glob("*.tmp")) == []


def test_a_failure_while_moving_the_second_file_leaves_neither_output(skill_dir, case_dir, monkeypatch, capsys):
    command = load_command()
    write_report(case_dir, VALID_REPORT)
    real_replace, calls = command.os.replace, []

    def flaky(source, target):
        calls.append(target)
        if len(calls) == 2:
            raise OSError("disk full")
        return real_replace(source, target)

    monkeypatch.setattr(command.os, "replace", flaky)
    code = command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", NOW])
    assert code == 2
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()
    assert sorted(path.name for path in case_dir.glob("*.tmp")) == []
    assert "disk full" in capsys.readouterr().err


def test_an_invalid_work_order_writes_neither_output(skill_dir, case_dir, monkeypatch, capsys):
    command = load_command()
    write_report(case_dir, VALID_REPORT)
    monkeypatch.setattr(command, "validate_work_order", lambda order: ["cause.label: broken"])
    assert command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", NOW]) == 1
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()
    assert "cause.label: broken" in capsys.readouterr().err


# round 2

def summary_path(case_dir):
    return case_dir / "judgments" / "summary.json"


def test_a_malformed_summary_makes_validate_exit_one_with_problems_not_a_traceback(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    summary = json.loads(summary_path(case_dir).read_text())
    summary["findings"] = [1]
    summary_path(case_dir).write_text(json.dumps(summary))
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "Traceback" not in result.stderr and "judgments/summary.json" in result.stderr


def test_a_malformed_checked_json_makes_validate_exit_one_with_problems(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    (case_dir / "findings" / "checked.json").write_text(json.dumps({"valid": [1]}))
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "Traceback" not in result.stderr and "checked.json" in result.stderr


def test_a_render_that_raises_is_a_failed_render_with_stale_outputs(skill_dir, case_dir, monkeypatch, capsys):
    command = load_command()
    write_report(case_dir, VALID_REPORT)
    assert command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", NOW]) == 0
    capsys.readouterr()

    def boom(*args, **kwargs):
        raise KeyError("claim")

    monkeypatch.setattr(command, "render_report", boom)
    assert command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", NOW]) == 1
    err = capsys.readouterr().err
    assert len(err.strip().splitlines()) <= 3 and "Traceback" not in err and "stale" in err
    assert not (case_dir / "report.md").exists() and (case_dir / "report.md.stale").is_file()


def test_validate_that_raises_unexpectedly_exits_one_without_a_traceback(skill_dir, case_dir, monkeypatch, capsys):
    command = load_command()
    write_report(case_dir, VALID_REPORT)

    def boom(*args, **kwargs):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(command, "validate_report", boom)
    assert command.main(["validate", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir)]) == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "secret detail" not in err


def test_a_very_deeply_nested_report_is_a_problem_not_a_recursion_error(skill_dir, case_dir):
    (case_dir / "report.json").write_text('{"a":' * 20000 + "1" + "}" * 20000)
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "Traceback" not in result.stderr and "nested" in result.stderr


def test_a_failure_while_moving_a_file_marks_every_output_stale(skill_dir, case_dir, monkeypatch):
    command = load_command()
    write_report(case_dir, VALID_REPORT)
    assert command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", NOW]) == 0
    real_replace, count = command.os.replace, {"n": 0}

    def flaky(source, target):
        if str(target).endswith(("report.md", "work-order.json")) and not str(source).endswith(".stale"):
            count["n"] += 1
            if count["n"] == 2:
                raise OSError("disk full")
        return real_replace(source, target)

    monkeypatch.setattr(command.os, "replace", flaky)
    code = command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", NOW])
    assert code == 2
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()
    assert (case_dir / "report.md.stale").is_file() and (case_dir / "work-order.json.stale").is_file()


def test_a_blocked_temporary_name_still_marks_the_old_outputs_stale(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    (case_dir / "work-order.json.tmp").mkdir()
    result = run(skill_dir, "render", "--case-dir", str(case_dir), "--now", NOW)
    assert result.returncode == 2
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()
    assert (case_dir / "work-order.json.stale").is_file()


def test_unreadable_finding_files_reach_the_work_order(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    checked = json.loads((case_dir / "findings" / "checked.json").read_text())
    checked["unreadable"] = [{"file": "findings/network.json", "reason": "not valid JSON"}]
    (case_dir / "findings" / "checked.json").write_text(json.dumps(checked))
    render_ok(skill_dir, case_dir)
    order = json.loads((case_dir / "work-order.json").read_text())
    assert "Finding file not read: findings/network.json (not valid JSON)" in order["coverage_gaps"]
