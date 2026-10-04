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


def run_wrapper(stdin, python_bin, **extra_env):
    env = dict(os.environ, AI_TRIAGE_PYTHON=str(python_bin), AI_TRIAGE_TEST="1")
    env.update(extra_env)
    return subprocess.run(["bash", str(WRAPPER)], input=stdin, capture_output=True, text=True, env=env)


def test_wrapper_runs_the_python_guard(skill_dir):
    # A temporary skill folder with a valid config, so a developer's own config cannot change the result.
    result = run_wrapper(
        payload(f"aws ecs list-clusters {AWS_OK}"), sys.executable,
        AI_TRIAGE_TEST="1", AI_TRIAGE_SKILL_DIR=str(skill_dir),
    )
    assert result.returncode == 0
    assert decision(result.stdout)["permissionDecision"] == "allow"


def test_wrapper_runs_the_python_guard_without_a_config(tmp_path):
    result = run_wrapper(
        payload(f"aws ecs list-clusters {AWS_OK}"), sys.executable,
        AI_TRIAGE_TEST="1", AI_TRIAGE_SKILL_DIR=str(tmp_path),
    )
    assert result.returncode == 0
    assert decision(result.stdout)["permissionDecision"] == "deny"
    assert "no valid config" in decision(result.stdout)["permissionDecisionReason"]


def test_the_skill_folder_override_needs_the_test_flag():
    import pathlib

    default = guard_hook.SKILL_DIR
    assert guard_hook.skill_dir_from({}) == default
    assert guard_hook.skill_dir_from({"AI_TRIAGE_SKILL_DIR": "/elsewhere"}) == default
    assert guard_hook.skill_dir_from({"AI_TRIAGE_TEST": "0", "AI_TRIAGE_SKILL_DIR": "/elsewhere"}) == default
    assert guard_hook.skill_dir_from({"AI_TRIAGE_TEST": "1"}) == default
    assert guard_hook.skill_dir_from({"AI_TRIAGE_TEST": "1", "AI_TRIAGE_SKILL_DIR": "/elsewhere"}) == pathlib.Path("/elsewhere")


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


# ---- fix round 1 -------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cd /tmp\naws ecs delete-cluster --cluster prod --profile admin",
        "true;\tkubectl delete ns prod",
        "cd /tmp\n\tkubectl delete ns prod",
        "echo x\raws ecs stop-task",
        "xaws ecs stop-task",
        "echo kubectl",
    ],
)
def test_wrapper_without_python_denies_a_command_with_aws_or_kubectl_anywhere(command, tmp_path):
    raw = payload(command)
    result = run_wrapper(raw, tmp_path / "missing-python")
    assert result.returncode == 0
    assert decision(result.stdout)["permissionDecision"] == "deny"


def test_the_json_escapes_really_are_in_the_payload_text():
    raw = payload("cd /tmp\naws ecs stop-task")
    assert "\\naws" in raw
    assert "\\tkubectl" in payload("true;\tkubectl get pods")


def test_wrapper_with_a_crashing_python_denies_a_multi_line_command(tmp_path):
    broken = tmp_path / "python"
    broken.write_text("#!/usr/bin/env bash\nexit 1\n")
    broken.chmod(0o755)
    result = run_wrapper(payload("cd /tmp\nkubectl delete ns prod"), broken)
    assert decision(result.stdout)["permissionDecision"] == "deny"


@pytest.mark.parametrize("raw", ["[]", "[\"aws ecs stop-task\"]", "\"aws ecs stop-task\"", "5", "null", "true"])
def test_a_payload_that_is_not_an_object_never_raises(raw, skill_dir):
    output = guard_hook.evaluate(raw, skill_dir)
    if "aws" in raw:
        assert decision(output)["permissionDecision"] == "deny"
    else:
        assert output == ""


def test_a_string_tool_input_never_raises_and_denies_when_it_mentions_aws(skill_dir):
    raw = json.dumps({"tool_name": "Bash", "tool_input": "aws ecs stop-task --task t"})
    assert decision(guard_hook.evaluate(raw, skill_dir))["permissionDecision"] == "deny"
    raw = json.dumps({"tool_name": "Bash", "tool_input": "ls"})
    assert guard_hook.evaluate(raw, skill_dir) == ""
    raw = json.dumps({"tool_name": "Bash", "tool_input": None})
    assert guard_hook.evaluate(raw, skill_dir) == ""
    raw = json.dumps({"tool_name": "Bash", "tool_input": ["aws"]})
    assert decision(guard_hook.evaluate(raw, skill_dir))["permissionDecision"] == "deny"


def test_wrapper_with_a_non_object_payload_exits_zero(tmp_path):
    result = run_wrapper("[1, 2]", sys.executable, AI_TRIAGE_TEST="1", AI_TRIAGE_SKILL_DIR=str(tmp_path))
    assert result.returncode == 0 and result.stdout == ""


def test_unreadable_input_is_matched_without_word_boundaries(skill_dir):
    assert decision(guard_hook.evaluate("{bad\\naws ecs stop-task", skill_dir))["permissionDecision"] == "deny"
    assert decision(guard_hook.evaluate("{bad\\tkubectl delete", skill_dir))["permissionDecision"] == "deny"
    assert guard_hook.evaluate("{bad json", skill_dir) == ""


def test_the_sensitive_check_in_the_wrapper_and_in_python_agree():
    assert guard_hook.FALLBACK_RE.search("x\\naws")
    assert not guard_hook.FALLBACK_RE.search("ls -la")


def test_the_python_override_needs_the_test_flag(tmp_path):
    # Without AI_TRIAGE_TEST the override is ignored: the (missing) skill venv is used and
    # a sensitive command is denied as "not installed", not run by the override.
    marker = tmp_path / "ran"
    fake = tmp_path / "python"
    fake.write_text(f"#!/usr/bin/env bash\ntouch {marker}\nexit 0\n")
    fake.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "AI_TRIAGE_TEST"}
    env["AI_TRIAGE_PYTHON"] = str(fake)
    result = subprocess.run(["bash", str(WRAPPER)], input=payload("kubectl get pods"), capture_output=True, text=True, env=env)
    assert not marker.exists()
    assert result.returncode == 0
    if not (SKILL_SRC / ".venv" / "bin" / "python").exists():
        assert "not installed correctly" in decision(result.stdout)["permissionDecisionReason"]
