#!/usr/bin/env python3
"""Check that each triage profile can read what triage needs and cannot write.

Reads are proven by harmless list and describe calls. Writes are checked with
the IAM policy simulator, so no write is ever attempted.

Exit codes: 0 all checks passed, 1 a check failed, 2 usage or config error,
3 a sign-in session has expired.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.config import ConfigError, default_config_path, load_config
from triage.fixtures import FixtureError, fixture_dir
from triage.verify import EXPIRED, exit_code, render_table, verify_all
from triage.cli import add_exit_codes, run

SKILL_DIR = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_access", description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, default=default_config_path(SKILL_DIR), help="path to the config file")
    parser.add_argument("--account", action="append", default=[], metavar="ALIAS", help="check only this account; repeatable")
    add_exit_codes(parser)
    args = parser.parse_args(argv)
    try:
        replaying = fixture_dir() is not None
    except FixtureError as error:
        print(error, file=sys.stderr)
        return 2
    if replaying:
        print("verify_access is not available in replay mode", file=sys.stderr)
        return 2
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("Config is invalid:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return 2
    unknown = [alias for alias in args.account if alias not in config.accounts]
    if unknown:
        print(f"Unknown account: {', '.join(unknown)}", file=sys.stderr)
        return 2
    results = verify_all(config, args.account)
    print(render_table(results))
    for result in results:
        if result.status == EXPIRED:
            profile = config.accounts[result.account].profile
            print(f"\nSign-in expired. Run: aws sso login --profile {profile}", file=sys.stderr)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(run(main))
