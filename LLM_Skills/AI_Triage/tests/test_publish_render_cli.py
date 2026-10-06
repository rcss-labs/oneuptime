"""The publishing commands refuse a rendered report that no longer matches what it was rendered from.

The cases are built with the real report code: judged by run_judgments, validated and rendered by run.py report.
"""
import copy
import json
import random
import shutil
import subprocess
import sys
import tempfile

import pytest
import yaml

from conftest import SKILL_SRC
from fakes import FakeJudge
from test_judge import QUESTIONS
from test_report import VALID_REPORT, case_dir, case, findings, judged  # noqa: F401  (fixtures)
from triage.config import parse_config
from triage.judge import run_judgments

PUBLISH = [str(SKILL_SRC / "scripts" / "run.py"), "publish"]
REPORT = [str(SKILL_SRC / "scripts" / "run.py"), "report"]
NOW = "2026-10-04T11:30:00Z"
COMMANDS = (("audit",), ("confluence",), ("slack-message",))


@pytest.fixture
def cases_root():
    """A short, plain path: the rendered report names the case folder, and pytest's long random
    temporary names would be flagged by the entropy rule."""
    root = tempfile.mkdtemp(prefix="gate-", dir="/tmp")
    yield root + "/cases"
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def config(config_data, cases_root):
    config_data["cases_dir"] = cases_root
    return parse_config(config_data)


@pytest.fixture
def skill_dir(tmp_path, config_data, cases_root):
    config_data["cases_dir"] = cases_root
    root = tmp_path / "gate-skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return root


def run_script(script, skill_dir, *args):
    return subprocess.run([sys.executable, *script, *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True)


@pytest.fixture
def rendered(judged, skill_dir):  # noqa: F811
    result = run_script(REPORT, skill_dir, "render", "--case-dir", str(judged), "--now", NOW)
    assert result.returncode == 0, result.stderr
    return judged


def assert_refused(result, case_dir):
    assert result.returncode == 1, result.stderr
    assert result.stdout == ""
    assert "rendered again" in result.stderr
    assert not (case_dir / "slack-message.md").exists()
    assert not (case_dir / "audit.json").exists()


@pytest.mark.parametrize("command", COMMANDS)
def test_an_untouched_rendered_case_publishes(skill_dir, rendered, command):
    result = run_script(PUBLISH, skill_dir, *command, "--case-dir", str(rendered))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("command", COMMANDS)
def test_a_case_with_no_render_marker_is_refused(skill_dir, rendered, command):
    (rendered / "render.json").unlink()
    assert_refused(run_script(PUBLISH, skill_dir, *command, "--case-dir", str(rendered)), rendered)


@pytest.mark.parametrize("command", COMMANDS)
def test_a_case_that_was_never_rendered_is_refused(skill_dir, judged, command):  # noqa: F811
    assert_refused(run_script(PUBLISH, skill_dir, *command, "--case-dir", str(judged)), judged)


@pytest.mark.parametrize("command", COMMANDS)
def test_judging_run_again_after_the_render_is_refused(skill_dir, config, rendered, command):  # noqa: F811
    run_judgments(rendered, config, FakeJudge(lambda state, questions: {}), QUESTIONS, random.Random(2))
    result = run_script(PUBLISH, skill_dir, *command, "--case-dir", str(rendered))
    assert_refused(result, rendered)
    assert "judgments/summary.json" in result.stderr


@pytest.mark.parametrize("command", COMMANDS)
def test_report_json_edited_after_the_render_is_refused_and_no_message_is_built(skill_dir, rendered, command):
    edited = copy.deepcopy(VALID_REPORT)
    edited["causes"][1]["label"] = "confirmed"
    (rendered / "report.json").write_text(json.dumps(edited))
    result = run_script(PUBLISH, skill_dir, *command, "--case-dir", str(rendered))
    assert_refused(result, rendered)
    assert "report.json" in result.stderr and "Top cause" not in result.stdout + result.stderr


def test_the_refusal_prints_reasons_naming_files_never_contents(skill_dir, rendered):
    (rendered / "report.md").write_text("# edited by hand\n")
    result = run_script(PUBLISH, skill_dir, "confluence", "--case-dir", str(rendered))
    assert_refused(result, rendered)
    assert "report.md" in result.stderr and "edited by hand" not in result.stderr
