#!/usr/bin/env python3
"""Collect read-only evidence from one source into the evidence format.

Exit codes: 0 collected, 2 usage or config error, 3 sign-in expired, 4 unknown collector or bad target key.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.awscli import Runner, subprocess_runner
from triage.collectors import Collector, all_collectors
from triage.config import ConfigError, default_config_path, load_config
from triage.context import CollectContext, SignInExpired
from triage.evidence import Evidence
from triage.window import WindowError, make_window

SKILL_DIR = Path(__file__).resolve().parent.parent


def _list_line(collector: Collector) -> str:
    keys = ",".join(collector.required) or "-"
    return f"{collector.name}  {keys}  {collector.description}"


def _parse_targets(pairs: list[str]) -> dict[str, str] | None:
    targets = {}
    for pair in pairs:
        key, separator, value = pair.partition("=")
        if not separator or not key:
            return None
        targets[key] = value
    return targets


def _target_problem(collector: Collector, targets: dict[str, str]) -> str | None:
    keys = f"required: {', '.join(collector.required) or 'none'}; optional: {', '.join(collector.optional) or 'none'}"
    missing = [key for key in collector.required if key not in targets]
    unknown = [key for key in targets if key not in collector.required + collector.optional]
    if missing:
        return f"{collector.name} needs target {', '.join(missing)} ({keys})"
    if unknown:
        return f"{collector.name} has no target {', '.join(unknown)} ({keys})"
    return None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="collect", description=__doc__.split("\n\n")[0])
    parser.add_argument("name", nargs="?", help="collector name; see --list")
    parser.add_argument("--list", action="store_true", help="list the collectors and their target keys")
    parser.add_argument("--account", metavar="ALIAS", help="account alias from the config")
    parser.add_argument("--start", help="window start, ISO 8601 with a timezone")
    parser.add_argument("--end", help="window end, ISO 8601 with a timezone")
    parser.add_argument("--region", help="AWS region; defaults to the account's first region")
    parser.add_argument("--target", action="append", default=[], metavar="KEY=VALUE", help="what to collect; repeatable")
    parser.add_argument("--case-dir", type=Path, help="write the evidence file into this case folder")
    parser.add_argument("--suffix", default="", help="added to the evidence file name")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    return parser


def _fail(message: str, code: int) -> int:
    print(message, file=sys.stderr)
    return code


def main(argv: list[str] | None = None, runner: Runner | None = None, kube_runner: Runner | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    collectors = all_collectors()
    if args.list:
        print("\n".join(_list_line(collector) for collector in collectors.values()))
        return 0
    if not (args.name and args.account and args.start and args.end):
        parser.error("name, --account, --start, and --end are required")
    try:
        config = load_config(default_config_path(args.skill_dir))
    except ConfigError as error:
        return _fail("; ".join(error.errors), 2)
    collector = collectors.get(args.name)
    if collector is None:
        return _fail(f"unknown collector {args.name}; available: {', '.join(sorted(collectors))}", 4)
    targets = _parse_targets(args.target)
    if targets is None:
        return _fail("--target must look like KEY=VALUE", 2)
    problem = _target_problem(collector, targets)
    if problem:
        return _fail(problem, 4)
    account = config.accounts.get(args.account)
    if account is None:
        return _fail(f"unknown account {args.account}; configured: {', '.join(config.accounts)}", 2)
    try:
        window = make_window(args.start, args.end, config.limits["max_window_hours"])
    except WindowError as error:
        return _fail(str(error), 2)
    region = args.region or account.regions[0]
    evidence = Evidence(collector.name, account.alias, region, window)
    ctx = CollectContext(
        config, account, region, window, evidence, args.skill_dir,
        runner=runner or subprocess_runner, kube_runner=kube_runner or subprocess_runner,
    )
    try:
        collector.run(ctx, targets)
    except SignInExpired as expired:
        return _fail(f"Sign-in expired. Run: aws sso login --profile {expired.profile}", 3)
    if args.case_dir:
        path = evidence.write(args.case_dir, args.suffix)
        print(f"{path} facts={len(evidence.facts)} errors={len(evidence.errors)} truncated={evidence.truncated}")
    else:
        print(evidence.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
