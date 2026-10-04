#!/usr/bin/env python3
"""PreToolUse hook entry point for the AI Triage guard.

Reads the hook input JSON on stdin and prints a permission decision, or
nothing when the guard has no opinion. It never exits non-zero: any internal
error becomes a deny for commands that touch aws or kubectl.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Mapping

from triage.config import ConfigError, default_config_path, load_config
from triage.guard import context_from_config, decide
from triage.verdict import DENY, PASS, Verdict

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


def evaluate(stdin_text: str, skill_dir: Path) -> str:
    try:
        try:
            payload = json.loads(stdin_text)
        except json.JSONDecodeError:
            return _fail_closed(stdin_text, "unreadable hook input")
        if not isinstance(payload, dict):
            return _fail_closed(stdin_text, "unexpected hook input")
        if payload.get("tool_name") != "Bash":
            return ""
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            return _fail_closed(stdin_text, "unexpected hook input")
        command = str(tool_input.get("command", ""))
        try:
            context, error = context_from_config(load_config(default_config_path(skill_dir)), skill_dir), ""
        except ConfigError as exc:
            context, error = None, exc.errors[0]
        return render(decide(command, context, error))
    except Exception as exc:  # fail closed for anything that touches aws or kubectl
        return _fail_closed(stdin_text, f"internal error ({exc})")


def main() -> int:
    output = evaluate(sys.stdin.read(), skill_dir_from(os.environ))
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
