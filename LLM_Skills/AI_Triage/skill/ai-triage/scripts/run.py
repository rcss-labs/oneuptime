#!/usr/bin/env python3
"""Run one AI Triage command: run.py <command> [arguments]; run.py <command> --help shows its arguments."""
from __future__ import annotations

import importlib
import sys

from triage.cli import EXIT_CODES, run
from triage.commands import COMMANDS

USAGE_ERROR = 2


def _summary(name: str) -> str:
    doc = importlib.import_module(f"triage.commands.{name}").__doc__ or ""
    return doc.strip().split("\n\n")[0].replace("\n", " ")


def _help() -> str:
    width = max(len(name) for name in COMMANDS)
    lines = ["usage: run.py <command> [arguments]", "", (__doc__ or "").strip(), "", "commands:"]
    lines += [f"  {name.ljust(width)}  {_summary(name)}" for name in COMMANDS]
    return "\n".join(lines) + "\n\n" + EXIT_CODES


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] in (["-h"], ["--help"]):
        print(_help().rstrip())
        return 0
    if not argv or argv[0] not in COMMANDS:
        problem = f"unknown command {argv[0]}" if argv else "no command given"
        print(f"usage: run.py <command> [arguments]\nrun.py: {problem}; one of: {', '.join(COMMANDS)}", file=sys.stderr)
        return USAGE_ERROR
    name = argv[0]
    return run(importlib.import_module(f"triage.commands.{name}").main, argv[1:], name=name)


if __name__ == "__main__":
    sys.exit(main())
