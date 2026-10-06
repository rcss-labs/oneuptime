#!/usr/bin/env python3
"""Merge the incident and all evidence into one timeline and print it as a table.

Exit codes: 0 built, 2 usage error or missing case folder.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.timeline import build_timeline, render_rows

SKILL_DIR = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="timeline", description=__doc__.split("\n\n")[0])
    parser.add_argument("--case-dir", type=Path, required=True, help="the case folder")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not args.case_dir.is_dir():
        print(f"case folder not found: {args.case_dir}", file=sys.stderr)
        return 2
    try:
        rows = build_timeline(args.case_dir)
    except (OSError, ValueError, KeyError) as error:
        print(f"cannot build the timeline from {args.case_dir}: {error!r}", file=sys.stderr)
        return 2
    print(render_rows(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
