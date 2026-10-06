#!/usr/bin/env python3
"""Check analyst findings against the evidence they cite.

Exit codes: 0 checked, 2 usage error or missing case folder.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.findings import check_findings

SKILL_DIR = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="findings", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check every findings/*.json and write findings/checked.json")
    check.add_argument("--case-dir", type=Path, required=True, help="the case folder")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not args.case_dir.is_dir():
        print(f"case folder not found: {args.case_dir}", file=sys.stderr)
        return 2
    result = check_findings(args.case_dir)
    print(
        f"valid={len(result['valid'])} rejected={len(result['rejected'])} "
        f"unreadable={len(result['unreadable'])} requests={len(result['requests'])}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
