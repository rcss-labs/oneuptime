#!/usr/bin/env python3
"""Check that a triage run can start: config, service map, sign-in, tools.

Exit codes: 0 ready, 1 a check failed, 2 usage error, 3 only a sign-in is needed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from triage.preflight import as_dicts, exit_code, render_text, run_preflight

SKILL_DIR = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="preflight", description=__doc__.split("\n\n")[0])
    parser.add_argument("--account", action="append", default=[], metavar="ALIAS", help="check sign-in only for this account; repeatable")
    parser.add_argument("--json", action="store_true", help="print the checks as JSON")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    checks = run_preflight(args.skill_dir, args.account)
    code = exit_code(checks)
    if args.json:
        print(json.dumps({"exit_code": code, "checks": as_dicts(checks)}, indent=2))
    else:
        print(render_text(checks))
    return code


if __name__ == "__main__":
    sys.exit(main())
