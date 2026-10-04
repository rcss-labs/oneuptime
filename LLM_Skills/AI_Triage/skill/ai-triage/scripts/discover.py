#!/usr/bin/env python3
"""Discover the AWS resources behind a hostname and propose a service map entry.

Exit codes: 0 something was found, 1 nothing was found, 2 usage or config error, 3 sign-in expired.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from triage.awscli import Runner, subprocess_runner
from triage.config import ConfigError, default_config_path, load_config
from triage.context import SignInExpired
from triage.discover import discover_hostname

SKILL_DIR = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="discover", description=__doc__.split("\n\n")[0])
    parser.add_argument("--hostname", required=True, help="the incident's hostname")
    parser.add_argument("--account", action="append", default=[], metavar="ALIAS", help="search only this account; repeatable")
    parser.add_argument("--service-name", help="name for the proposed entry; defaults to the hostname's first label")
    parser.add_argument("--monitor", action="append", default=[], metavar="NAME", help="monitor name to match; repeatable")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    return parser


def _fail(message: str, code: int) -> int:
    print(message, file=sys.stderr)
    return code


def main(argv: list[str] | None = None, runner: Runner | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        config = load_config(default_config_path(args.skill_dir))
    except ConfigError as error:
        return _fail("; ".join(error.errors), 2)
    unknown = [alias for alias in args.account if alias not in config.accounts]
    if unknown:
        return _fail(f"unknown account {', '.join(unknown)}; configured: {', '.join(config.accounts)}", 2)
    try:
        discovery = discover_hostname(args.hostname, config, runner or subprocess_runner, args.account)
    except SignInExpired as expired:
        return _fail(f"Sign-in expired. Run: aws sso login --profile {expired.profile}", 3)
    found = bool(discovery.resources)
    service_name = args.service_name or discovery.hostname.split(".")[0]
    entry = discovery.proposed_entry(service_name, args.monitor) if found else None
    print(json.dumps({"discovery": discovery.to_dict(), "proposed_entry": entry}, indent=2))
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
