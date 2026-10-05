#!/usr/bin/env python3
"""PreToolUse hook entry point for the AI Triage guard.

Reads the hook input JSON on stdin and prints a permission decision, or
nothing when the guard has no opinion. Bash commands go to the command guard;
Write, Edit, MultiEdit and NotebookEdit go to the protected-files check;
connector tools (mcp__<server>__<tool>) go to the connector check. It
never exits non-zero: an internal error becomes a deny for commands that touch
aws or kubectl, and an ask for a file tool.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from triage.config import ConfigError, default_config_path, load_config
from triage.guard import context_from_config, decide
import yaml

from triage.guard_mcp import decide_mcp
from triage.guard_paths import DEFAULT_CASES_DIR, FILE_TOOLS, decide_file_tool, protected_roots
from triage.verdict import ASK, DENY, PASS, Verdict

SKILL_DIR = Path(__file__).resolve().parent.parent
# Used when the guard cannot understand its input. No word boundaries: a false deny is
# acceptable when the guard is broken, a miss is not (JSON escapes such as a backslash-n hide a boundary).
FALLBACK_RE = re.compile("aws|kubectl")


def skill_dir_from(environ: Mapping[str, str]) -> Path:
    """The skill folder. Tests may point at a temporary one; production never honours this."""
    override = environ.get("AI_TRIAGE_SKILL_DIR", "")
    if environ.get("AI_TRIAGE_TEST") == "1" and override:
        return Path(override)
    return SKILL_DIR


def render(verdict: Verdict) -> str:
    if verdict.kind == PASS:
        return ""
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": verdict.kind,
                "permissionDecisionReason": f"AI Triage guard: {verdict.reason}",
            }
        }
    )


def _fail_closed(stdin_text: str, reason: str) -> str:
    return render(Verdict(DENY, reason) if FALLBACK_RE.search(stdin_text) else Verdict(PASS))


def _file_tool_verdict(tool: str, payload: dict, skill_dir: Path) -> Verdict:
    try:
        try:
            cases_dir = str(load_config(default_config_path(skill_dir)).cases_dir)
        except ConfigError:
            cases_dir = ""  # the default case root and the skill folder are still protected
        return decide_file_tool(tool, payload.get("tool_input"), payload.get("cwd"), protected_roots(str(skill_dir), cases_dir))
    except Exception as exc:  # a file tool the guard cannot judge goes to the engineer
        return Verdict(ASK, f"internal error while checking {tool} ({exc})")


def _configured_oneuptime_server(skill_dir: Path) -> str | None:
    """oneuptime.mcp_server from the raw config file, when it is set."""
    try:
        data = yaml.safe_load(default_config_path(skill_dir).read_text())
        value = data["oneuptime"]["mcp_server"]
    except (OSError, yaml.YAMLError, KeyError, TypeError):
        return None
    return value if isinstance(value, str) and value.strip() else None


def _mcp_verdict(tool: str, payload: dict, skill_dir: Path) -> Verdict:
    try:
        try:
            cases_dir = str(load_config(default_config_path(skill_dir)).cases_dir)
        except ConfigError:
            cases_dir = os.path.expanduser(DEFAULT_CASES_DIR)
        return decide_mcp(tool, payload.get("tool_input"), cases_dir, _configured_oneuptime_server(skill_dir),
                          datetime.now(timezone.utc))
    except Exception as exc:  # a connector call the guard cannot judge goes to the engineer
        return Verdict(ASK, f"internal error while checking {tool} ({exc})")


def evaluate(stdin_text: str, skill_dir: Path) -> str:
    try:
        try:
            payload = json.loads(stdin_text)
        except json.JSONDecodeError:
            return _fail_closed(stdin_text, "unreadable hook input")
        if not isinstance(payload, dict):
            return _fail_closed(stdin_text, "unexpected hook input")
        tool = payload.get("tool_name")
        if isinstance(tool, str) and tool in FILE_TOOLS:
            return render(_file_tool_verdict(tool, payload, skill_dir))
        if isinstance(tool, str) and tool.startswith("mcp__"):
            return render(_mcp_verdict(tool, payload, skill_dir))
        if tool != "Bash":
            return ""
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            return _fail_closed(stdin_text, "unexpected hook input")
        command = str(tool_input.get("command", ""))
        try:
            context, error = context_from_config(load_config(default_config_path(skill_dir)), skill_dir), ""
        except ConfigError as exc:
            context, error = None, exc.errors[0]
        cwd = payload.get("cwd")
        return render(decide(command, context, error, cwd if isinstance(cwd, str) else ""))
    except Exception as exc:  # fail closed for anything that touches aws or kubectl
        return _fail_closed(stdin_text, f"internal error ({exc})")


def main() -> int:
    raw = sys.stdin.buffer.read()
    try:
        stdin_text = raw.decode("utf-8")
    except UnicodeDecodeError:  # fail closed: deny when the bytes mention aws or kubectl, as for unreadable JSON
        output = _fail_closed(raw.decode("utf-8", errors="replace"), "hook input is not UTF-8")
    else:
        output = evaluate(stdin_text, skill_dir_from(os.environ))
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
