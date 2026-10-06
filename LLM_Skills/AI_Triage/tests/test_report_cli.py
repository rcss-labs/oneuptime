import copy
import json
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC
from fakes import FakeJudge
from test_judge import QUESTIONS, make_responder
from test_report import VALID_REPORT, config, case_dir, case, findings, judged, mutated  # noqa: F401  (fixtures)
from triage.judge import run_judgments
from triage.report import REQUIRED_HEADINGS, render_is_current, validate_work_order

SCRIPT = [str(SKILL_SRC / "scripts" / "run.py"), "report"]
NOW = "2026-10-04T11:30:00Z"


@pytest.fixture
def skill_dir(tmp_path, config_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "cmd-skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return root


def run(skill_dir, *args):
    return subprocess.run([sys.executable, *SCRIPT, *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True)


def write_report(case_dir, report):
    (case_dir / "report.json").write_text(json.dumps(report))


def test_help_works():
    result = subprocess.run([sys.executable, *SCRIPT, "--help"], capture_output=True, text=True)
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
    assert subprocess.run([sys.executable, *SCRIPT], capture_output=True).returncode == 2
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
    return importlib.import_module("triage.commands.report")


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


# round 3, m7: the render marker

import hashlib


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_render_writes_a_marker_with_the_hash_of_both_outputs(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    marker = json.loads((case_dir / "render.json").read_text())
    assert marker == {"report.md": sha(case_dir / "report.md"), "work-order.json": sha(case_dir / "work-order.json"),
                      "report.json": sha(case_dir / "report.json"),
                      "judgments/summary.json": sha(case_dir / "judgments" / "summary.json"),
                      "findings/checked.json": sha(case_dir / "findings" / "checked.json")}


@pytest.mark.parametrize("command", ["validate", "render"])
def test_a_missing_marker_marks_both_outputs_stale(skill_dir, case_dir, command):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    (case_dir / "render.json").unlink()
    result = run(skill_dir, command, "--case-dir", str(case_dir), "--now", NOW) if command == "render" else \
        run(skill_dir, command, "--case-dir", str(case_dir))
    assert result.returncode == 0, result.stderr
    assert "report.md.stale" in result.stderr and "work-order.json.stale" in result.stderr
    if command == "validate":
        assert not (case_dir / "report.md").exists() and (case_dir / "work-order.json.stale").is_file()


@pytest.mark.parametrize("name", ["report.md", "work-order.json"])
def test_an_output_that_no_longer_matches_the_marker_marks_both_stale(skill_dir, case_dir, name):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    (case_dir / name).write_text("edited")
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 0 and "stale" in result.stderr
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()
    assert (case_dir / "report.md.stale").is_file() and (case_dir / "work-order.json.stale").is_file()


def test_a_matching_pair_is_left_alone(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 0 and result.stderr == ""
    assert (case_dir / "report.md").is_file() and not (case_dir / "report.md.stale").exists()


def test_a_missing_output_with_a_marker_marks_the_other_stale(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    (case_dir / "work-order.json").unlink()
    run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert not (case_dir / "report.md").exists() and (case_dir / "report.md.stale").is_file()


def test_a_folder_without_outputs_needs_no_marker(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 0 and result.stderr == ""


def test_a_process_killed_between_the_two_moves_leaves_nothing_current_looking(skill_dir, case_dir, monkeypatch):
    command = load_command()
    write_report(case_dir, VALID_REPORT)
    assert command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", NOW]) == 0
    real_replace, count = command.os.replace, {"n": 0}

    def killed(source, target):
        if str(target).endswith(("report.md", "work-order.json")) and not str(source).endswith(".stale"):
            count["n"] += 1
            if count["n"] == 2:
                raise KeyboardInterrupt
        return real_replace(source, target)

    monkeypatch.setattr(command.os, "replace", killed)
    with pytest.raises(KeyboardInterrupt):
        command.main(["render", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir), "--now", "2026-10-04T12:00:00Z"])
    monkeypatch.setattr(command.os, "replace", real_replace)
    assert (case_dir / "report.md").is_file()
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 0 and "stale" in result.stderr
    assert not (case_dir / "report.md").exists() and not (case_dir / "work-order.json").exists()


# round 4: the outputs are tied to the inputs they were rendered from

import random


def lowered_report():
    report = mutated(VALID_REPORT, lambda r: r["causes"][0].update(label="candidate"))
    report["status"], report["summary"]["top_cause"] = "unresolved", None
    report["actions"] = [{**a, "label": "candidate"} for a in report["actions"]]
    return report


def test_a_rejudged_and_lowered_report_makes_the_old_outputs_stale_at_validate(skill_dir, judged, config):
    assert run(skill_dir, "render", "--case-dir", str(judged), "--now", NOW).returncode == 0
    assert "(confirmed)" in (judged / "report.md").read_text()
    again = run_judgments(judged, config, FakeJudge(make_responder(rank=(("C2", 0.72), ("C2", 0.72)))), QUESTIONS, random.Random(2))
    assert again["causes"]["C1"]["label"] == "candidate"
    write_report(judged, lowered_report())
    result = run(skill_dir, "validate", "--case-dir", str(judged))
    assert "render" in result.stderr and "again" in result.stderr
    assert not (judged / "report.md").exists() and not (judged / "work-order.json").exists()
    assert "(confirmed)" in (judged / "report.md.stale").read_text()


def test_an_untouched_case_stays_current_through_validate_render_validate(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    assert run(skill_dir, "validate", "--case-dir", str(case_dir)).stderr == ""
    render_ok(skill_dir, case_dir)
    assert render_is_current(case_dir) == []
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 0 and result.stderr == ""
    assert render_is_current(case_dir) == []
    assert (case_dir / "report.md").is_file() and not (case_dir / "report.md.stale").exists()


def rendered(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    assert render_is_current(case_dir) == []


@pytest.mark.parametrize("relative", ["report.json", "judgments/summary.json", "findings/checked.json"])
def test_a_changed_input_makes_the_render_not_current(skill_dir, case_dir, relative):
    rendered(skill_dir, case_dir)
    path = case_dir / relative
    path.write_text(path.read_text() + "\n ")
    reasons = render_is_current(case_dir)
    assert reasons and any(relative in reason for reason in reasons)
    assert not (case_dir / "report.md").exists() and (case_dir / "report.md.stale").is_file()
    assert (case_dir / "work-order.json.stale").is_file()


def test_a_deleted_summary_makes_the_render_not_current(skill_dir, case_dir):
    rendered(skill_dir, case_dir)
    (case_dir / "judgments" / "summary.json").unlink()
    assert any("summary.json" in reason for reason in render_is_current(case_dir))


def test_a_missing_summary_is_recorded_as_null_and_stays_current(skill_dir, case_dir):
    (case_dir / "judgments" / "summary.json").unlink()
    write_report(case_dir, mutated(VALID_REPORT, lambda r: None))
    report = lowered_report()
    for hypothesis in report["hypotheses"]:
        hypothesis["result"] = "inconclusive"
    report["coverage"]["typesafe"] = "unavailable: judging was not run"
    report["causes"][0]["label"] = "candidate"
    write_report(case_dir, report)
    render_ok(skill_dir, case_dir)
    assert json.loads((case_dir / "render.json").read_text())["judgments/summary.json"] is None
    assert render_is_current(case_dir) == []
    (case_dir / "judgments" / "summary.json").write_text("{}")
    assert render_is_current(case_dir) != []


def test_a_marker_copied_from_another_render_is_not_current(skill_dir, case_dir):
    rendered(skill_dir, case_dir)
    first_marker = (case_dir / "render.json").read_text()
    assert run(skill_dir, "render", "--case-dir", str(case_dir), "--now", "2026-10-04T12:00:00Z").returncode == 0
    (case_dir / "render.json").write_text(first_marker)
    assert render_is_current(case_dir) != []
    assert (case_dir / "report.md.stale").is_file()


@pytest.mark.parametrize("damage", ["{broken", "[]", "5", "null", '{"report.md": 5}', "\udcff"])
def test_a_damaged_marker_is_a_reason_not_a_traceback(skill_dir, case_dir, damage):
    rendered(skill_dir, case_dir)
    (case_dir / "render.json").write_text(damage, errors="surrogateescape") if damage == "\udcff" else \
        (case_dir / "render.json").write_text(damage)
    reasons = render_is_current(case_dir)
    assert isinstance(reasons, list) and reasons and all(isinstance(reason, str) for reason in reasons)
    assert not (case_dir / "report.md").exists()


def test_a_binary_marker_is_a_reason_not_a_traceback(skill_dir, case_dir):
    rendered(skill_dir, case_dir)
    (case_dir / "render.json").write_bytes(b"\xff\xfe\x00")
    assert render_is_current(case_dir) != []


def test_nothing_rendered_is_not_current_and_creates_nothing(skill_dir, case_dir):
    reasons = render_is_current(case_dir)
    assert reasons and not list(case_dir.glob("*.stale"))


def test_a_missing_folder_is_a_reason_not_a_traceback(tmp_path):
    assert render_is_current(tmp_path / "nowhere") != []


def test_a_leftover_marker_temporary_file_is_removed_by_the_next_render(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    (case_dir / "render.json.tmp").write_text("left over")
    render_ok(skill_dir, case_dir)
    assert not (case_dir / "render.json.tmp").exists()


# no absolute local paths in either output

def test_neither_output_holds_an_absolute_local_path(skill_dir, case_dir, tmp_path):
    from pathlib import Path
    write_report(case_dir, VALID_REPORT)
    render_ok(skill_dir, case_dir)
    for name in ("report.md", "work-order.json"):
        text = (case_dir / name).read_text()
        assert str(tmp_path) not in text and str(Path.home()) not in text and str(case_dir) not in text, name
        assert "/private/" not in text and "/var/folders" not in text, name


# final review: only run folders under the cases root

import shutil


@pytest.mark.parametrize("command", ["validate", "render"])
def test_a_copy_of_a_run_outside_the_cases_root_is_refused_and_nothing_is_renamed(skill_dir, case_dir, tmp_path, command):
    write_report(case_dir, VALID_REPORT)
    elsewhere = tmp_path / "intake" / "INC-123" / "20261004-111000"
    shutil.copytree(case_dir, elsewhere)
    (elsewhere / "report.md").write_text("an unrelated report")
    (elsewhere / "work-order.json").write_text("{}")
    result = run(skill_dir, command, "--case-dir", str(elsewhere))
    assert result.returncode == 2 and "not a case folder" in result.stderr
    assert (elsewhere / "report.md").read_text() == "an unrelated report"
    assert not list(elsewhere.glob("*.stale"))


@pytest.mark.parametrize("command", ["validate", "render"])
def test_a_scratch_folder_with_outputs_is_refused_without_renames(skill_dir, tmp_path, command):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "report.md").write_text("mine")
    (scratch / "work-order.json").write_text("{}")
    assert run(skill_dir, command, "--case-dir", str(scratch)).returncode == 2
    assert sorted(path.name for path in scratch.iterdir()) == ["report.md", "work-order.json"]


def test_a_run_folder_reached_through_a_link_is_accepted(skill_dir, case_dir, tmp_path):
    write_report(case_dir, VALID_REPORT)
    link = tmp_path / "link"
    link.symlink_to(case_dir)
    assert run(skill_dir, "validate", "--case-dir", str(link)).returncode == 0


def test_a_case_json_that_names_another_folder_is_refused(skill_dir, case_dir):
    write_report(case_dir, VALID_REPORT)
    data = json.loads((case_dir / "case.json").read_text())
    data["case_dir"] = str(case_dir.parent / "20991231-000000")
    (case_dir / "case.json").write_text(json.dumps(data))
    result = run(skill_dir, "validate", "--case-dir", str(case_dir))
    assert result.returncode == 2 and "case.json" in result.stderr
