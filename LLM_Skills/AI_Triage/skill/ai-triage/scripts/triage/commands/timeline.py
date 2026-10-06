"""Merge the incident and all evidence into one timeline and print it as a table.

Exit codes: 0 built, 2 usage error or missing case folder.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from triage.case import REPLAY_NOTICE, CaseError, check_replay, resolve_case_dir
from triage.config import ConfigError, default_config_path, load_config
from triage.timeline import build_timeline, render_rows
from triage.cli import add_exit_codes
from triage.commands.common import SKILL_DIR



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run.py timeline", description=__doc__.split("\n\n")[0])
    parser.add_argument("--case-dir", type=Path, required=True, help="the case folder")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    add_exit_codes(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        case_dir = resolve_case_dir(args.case_dir, load_config(default_config_path(args.skill_dir)))
        case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        check_replay(case if isinstance(case, dict) else {})
    except (ConfigError, CaseError) as error:
        print("; ".join(error.errors), file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f"cannot read case.json in {args.case_dir}: {error}", file=sys.stderr)
        return 2
    try:
        rows = build_timeline(case_dir)
    except KeyError as error:
        print(f"cannot build the timeline from {args.case_dir}: missing {error.args[0] if error.args else 'a field'}",
              file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f"cannot build the timeline from {args.case_dir}: {error}", file=sys.stderr)
        return 2
    if isinstance(case, dict) and case.get("replay"):
        print(REPLAY_NOTICE)
    print(render_rows(rows))
    return 0
