"""Check that a triage run can start: config, service map, sign-in, tools.

Exit codes: 0 ready, 1 a check failed, 2 usage error, 3 only a sign-in is needed.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from triage.awscli import subprocess_runner
from triage.fixtures import FixtureError, fixture_dir, replay_banner, runner_from_env
from triage.preflight import as_dicts, exit_code, render_text, run_preflight
from triage.cli import add_exit_codes
from triage.commands.common import SKILL_DIR



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run.py preflight", description=__doc__.split("\n\n")[0])
    parser.add_argument("--account", action="append", default=[], metavar="ALIAS", help="check sign-in only for this account; repeatable")
    parser.add_argument("--allow-replay", action="store_true", help="accept AI_TRIAGE_FIXTURES: answers come from recorded files, not AWS")
    parser.add_argument("--json", action="store_true", help="print the checks as JSON")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    add_exit_codes(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        replay = fixture_dir()
        if replay:
            print(replay_banner(replay), file=sys.stderr)
        runner = runner_from_env() or subprocess_runner
    except FixtureError as error:
        print(error, file=sys.stderr)
        return 2
    # In replay mode aws and kubectl are never run, so they count as present.
    which = (lambda name: f"replay/{name}") if replay else shutil.which
    checks = run_preflight(args.skill_dir, args.account, runner=runner, which=which, replay=bool(replay), allow_replay=args.allow_replay)
    code = exit_code(checks)
    if args.json:
        print(json.dumps({"exit_code": code, "checks": as_dicts(checks)}, indent=2))
    else:
        print(render_text(checks))
    return code
