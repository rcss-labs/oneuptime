import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import EXAMPLE_CONFIG, SKILL_SRC

import guard_hook

AWS_OK = "--profile triage-prod-main --region eu-west-1"


def payload(command, tool="Bash"):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": command}})


@pytest.fixture
def skill_dir(tmp_path):
    """A skill folder with a valid config, as the installer would leave it."""
    (tmp_path / "config").mkdir()
    shutil.copy(EXAMPLE_CONFIG, tmp_path / "config" / "triage-config.yaml")
    return tmp_path


def decision(output):
    return json.loads(output)["hookSpecificOutput"]


def test_allowed_read_prints_an_allow_decision(skill_dir):
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), skill_dir))
    assert result["hookEventName"] == "PreToolUse"
    assert result["permissionDecision"] == "allow"
    assert result["permissionDecisionReason"].startswith("AI Triage guard: ")


def test_write_prints_a_deny_decision(skill_dir):
    result = decision(guard_hook.evaluate(payload(f"aws ecs stop-task --task t {AWS_OK}"), skill_dir))
    assert result["permissionDecision"] == "deny"


def test_unchecked_command_prints_an_ask_decision(skill_dir):
    result = decision(guard_hook.evaluate(payload(f"bash -c 'aws ecs list-clusters {AWS_OK}'"), skill_dir))
    assert result["permissionDecision"] == "ask"


def test_unrelated_command_prints_nothing(skill_dir):
    assert guard_hook.evaluate(payload("ls -la"), skill_dir) == ""


def test_other_tools_are_ignored(skill_dir):
    assert guard_hook.evaluate(payload("aws ecs stop-task", tool="Read"), skill_dir) == ""


def test_missing_config_denies_aws_but_not_other_commands(tmp_path):
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), tmp_path))
    assert result["permissionDecision"] == "deny"
    assert "no valid config" in result["permissionDecisionReason"]
    assert guard_hook.evaluate(payload("ls"), tmp_path) == ""


def test_invalid_config_denies_aws(skill_dir):
    path = skill_dir / "config" / "triage-config.yaml"
    data = yaml.safe_load(path.read_text())
    data["accounts"]["prod-main"]["profile"] = "admin"
    path.write_text(yaml.safe_dump(data))
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), skill_dir))
    assert result["permissionDecision"] == "deny"


def test_unreadable_input_denies_only_when_it_mentions_aws_or_kubectl(skill_dir):
    assert decision(guard_hook.evaluate("not json aws ecs stop-task", skill_dir))["permissionDecision"] == "deny"
    assert guard_hook.evaluate("not json at all", skill_dir) == ""


def test_internal_error_fails_closed(skill_dir, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(guard_hook, "decide", boom)
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), skill_dir))
    assert result["permissionDecision"] == "deny" and "internal error" in result["permissionDecisionReason"]
    assert guard_hook.evaluate(payload("ls"), skill_dir) == ""


WRAPPER = SKILL_SRC / "scripts" / "guard_hook.sh"


def run_wrapper(stdin, python_bin):
    env = dict(os.environ, AI_TRIAGE_PYTHON=str(python_bin))
    return subprocess.run(["bash", str(WRAPPER)], input=stdin, capture_output=True, text=True, env=env)


def test_wrapper_runs_the_python_guard():
    # The source tree has no real config, so an aws command is denied for that reason.
    result = run_wrapper(payload(f"aws ecs list-clusters {AWS_OK}"), sys.executable)
    assert result.returncode == 0
    assert decision(result.stdout)["permissionDecision"] == "deny"
    assert "no valid config" in decision(result.stdout)["permissionDecisionReason"]


def test_wrapper_without_python_denies_sensitive_commands(tmp_path):
    result = run_wrapper(payload("kubectl get pods"), tmp_path / "missing-python")
    assert result.returncode == 0
    assert decision(result.stdout)["permissionDecision"] == "deny"
    assert "not installed correctly" in decision(result.stdout)["permissionDecisionReason"]


def test_wrapper_without_python_stays_silent_for_other_commands(tmp_path):
    result = run_wrapper(payload("ls -la"), tmp_path / "missing-python")
    assert result.returncode == 0 and result.stdout == ""


def test_wrapper_denies_when_the_python_guard_crashes(tmp_path):
    broken = tmp_path / "python"
    broken.write_text("#!/usr/bin/env bash\nexit 1\n")
    broken.chmod(0o755)
    result = run_wrapper(payload(f"aws ecs list-clusters {AWS_OK}"), broken)
    assert result.returncode == 0
    assert "failed to run" in decision(result.stdout)["permissionDecisionReason"]


def test_wrapper_help():
    result = subprocess.run(["bash", str(WRAPPER), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.startswith("Usage: guard_hook.sh")
