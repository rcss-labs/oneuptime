#!/usr/bin/env python3
"""PreToolUse hook entry point for the AI Triage guard.

Reads the hook input JSON on stdin and prints a permission decision, or
nothing when the guard has no opinion. It never exits non-zero: any internal
error becomes a deny for commands that touch aws or kubectl.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from triage.config import ConfigError, default_config_path, load_config
from triage.guard import context_from_config, decide, is_sensitive
from triage.verdict import DENY, PASS, Verdict

SKILL_DIR = Path(__file__).resolve().parent.parent


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


def evaluate(stdin_text: str, skill_dir: Path) -> str:
    try:
        payload = json.loads(stdin_text)
    except json.JSONDecodeError:
        return render(Verdict(DENY, "unreadable hook input") if is_sensitive(stdin_text) else Verdict(PASS))
    if payload.get("tool_name") != "Bash":
        return ""
    command = str((payload.get("tool_input") or {}).get("command", ""))
    try:
        try:
            context, error = context_from_config(load_config(default_config_path(skill_dir)), skill_dir), ""
        except ConfigError as exc:
            context, error = None, exc.errors[0]
        return render(decide(command, context, error))
    except Exception as exc:  # fail closed for anything that touches aws or kubectl
        return render(Verdict(DENY, f"internal error ({exc})") if is_sensitive(command) else Verdict(PASS))


def main() -> int:
    output = evaluate(sys.stdin.read(), SKILL_DIR)
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
