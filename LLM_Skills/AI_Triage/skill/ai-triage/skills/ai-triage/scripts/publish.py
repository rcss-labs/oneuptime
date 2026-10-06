#!/usr/bin/env python3
"""Check the report for secrets, prepare what is published to Confluence and Slack, and record what was published.

Exit codes: 0 done, 1 the audit found something or a precondition failed, 2 usage or config error.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from triage.config import ConfigError, default_config_path, load_config
from triage.publish import (
    PublishError,
    audit_case,
    confluence_request,
    record_confluence,
    record_slack,
    slack_message,
)
from triage.window import WindowError, parse_time

SKILL_DIR = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="publish", description=__doc__.split("\n\n")[0])
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text, description=help_text)
        child.add_argument("--skill-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        child.add_argument("--case-dir", type=Path, required=True)
        return child

    add("audit", "check the published files for secrets and write audit.json")
    add("confluence", "print the Confluence request; needs a clean, fresh audit")
    slack = add("slack-message", "write and print the Slack message, then audit again")
    slack.add_argument("--confluence-url", help="link to the Confluence page")
    confluence = add("record-confluence", "record the Confluence page that was published")
    confluence.add_argument("--page-id", required=True)
    confluence.add_argument("--url", required=True)
    confluence.add_argument("--now", help="the current time, ISO 8601 with a timezone; defaults to the clock")
    slack_record = add("record-slack", "record a Slack post")
    slack_record.add_argument("--destination", required=True, help="channel or person the message went to")
    slack_record.add_argument("--now", help="the current time, ISO 8601 with a timezone; defaults to the clock")
    return parser


def _now(args: argparse.Namespace) -> datetime:
    return parse_time(args.now) if args.now else datetime.now(timezone.utc)


def _print_audit(result: dict, stream) -> None:
    if result["clean"]:
        print("clean", file=stream)
    for hit in result["hits"]:
        print(f"{hit['file']}:{hit['line']}:{hit['column']} {hit['category']}", file=stream)


def _audit(args: argparse.Namespace) -> int:
    result = audit_case(args.case_dir)
    _print_audit(result, sys.stdout)
    return 0 if result["clean"] else 1


def _confluence(args: argparse.Namespace) -> int:
    config = load_config(default_config_path(args.skill_dir))
    print(json.dumps(confluence_request(args.case_dir, config), indent=2))
    return 0


def _slack_message(args: argparse.Namespace) -> int:
    print(slack_message(args.case_dir, args.confluence_url))
    result = audit_case(args.case_dir)
    if not result["clean"]:
        _print_audit(result, sys.stderr)
        return 1
    return 0


def _record_confluence(args: argparse.Namespace) -> int:
    record_confluence(args.case_dir, args.page_id, args.url, _now(args))
    return 0


def _record_slack(args: argparse.Namespace) -> int:
    record_slack(args.case_dir, args.destination, _now(args))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handler = {"audit": _audit, "confluence": _confluence, "slack-message": _slack_message,
               "record-confluence": _record_confluence, "record-slack": _record_slack}[args.subcommand]
    try:
        return handler(args)
    except PublishError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (ConfigError, WindowError) as error:
        print("\n".join(error.errors) if isinstance(error, ConfigError) else str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
