"""Check analyst findings against the evidence they cite.

Exit codes: 0 checked, 2 usage error or missing case folder.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from triage.case import REPLAY_NOTICE
from triage.findings import check_findings
from triage.cli import add_exit_codes
from triage.commands.common import SKILL_DIR, load_skill_config, open_case


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run.py findings", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check every findings/*.json and write findings/checked.json")
    check.add_argument("--case-dir", type=Path, required=True, help="the case folder")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    add_exit_codes(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    case_dir, case = open_case(args.case_dir, load_skill_config(args.skill_dir))
    if case.get("replay"):
        print(REPLAY_NOTICE)
    result = check_findings(case_dir)
    print(
        f"valid={len(result['valid'])} rejected={len(result['rejected'])} "
        f"unreadable={len(result['unreadable'])} requests={len(result['requests'])}"
    )
    return 0
