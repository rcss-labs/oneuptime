"""Propose a service map entry from a discovered target, or append it to the engineer's service map.

Exit codes: 0 done, 1 the suggestion cannot be made or applied, 2 usage or config error.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from triage.case import CaseError
from triage.config import ConfigError, default_config_path, load_config
from triage.map_suggest import SuggestError, apply, propose
from triage.service_map import default_map_path
from triage.cli import add_exit_codes
from triage.commands.common import SKILL_DIR



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run.py map_suggest", description=__doc__.split("\n\n")[0])
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text, description=help_text)
        child.add_argument("--skill-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        child.add_argument("--case-dir", type=Path, required=True)
        child.add_argument("--service-name", required=True, help="the name for the new service entry")
        child.add_argument("--environment", default="prod", help="the environment name (default: prod)")
        return child

    add("propose", "print the entry that would be added; changes nothing")
    add("apply", "back up the service map, append the entry, and check that the map still loads")
    add_exit_codes(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = datetime.now(timezone.utc)
    try:
        config = load_config(default_config_path(args.skill_dir))
        map_path = default_map_path(args.skill_dir)
        if args.subcommand == "propose":
            result = propose(args.case_dir, config, map_path, args.service_name, args.environment, now.date())
            print(result["yaml"], end="")
            print(f"assumed environment {args.environment}; to name another, add --environment NAME", file=sys.stderr)
        else:
            backup = apply(args.case_dir, config, map_path, args.service_name, args.environment, now.date(), now)
            print(f"added {args.service_name} to {map_path}\nbackup: {backup or 'none (the map file did not exist)'}")
        return 0
    except SuggestError as error:
        print(error, file=sys.stderr)
        return 1
    except (ConfigError, CaseError) as error:
        print("\n".join(error.errors), file=sys.stderr)
        return 2
