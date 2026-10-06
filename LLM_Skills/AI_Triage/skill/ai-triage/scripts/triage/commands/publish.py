"""Check the report for secrets, prepare what is published to Confluence and Slack, and record what was published.

Exit codes: 0 done, 1 the audit found something or a precondition failed (including a replay case), 2 usage,
config, or case folder error.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from triage.case import CaseError, resolve_case_dir
from triage.config import ConfigError, default_config_path, load_config
from triage.publish import (
    PublishError,
    audit_case,
    configured_account_ids,
    confluence_request,
    hit_lines,
    load_audit,
    load_case_file,
    may_proceed,
    publish_digests,
    publish_state_entry,
    read_audited,
    record_confluence,
    record_slack,
    slack_context,
    slack_message,
    verify_confluence,
    write_publish_state,
)
from triage.report import render_is_current
from triage.window import WindowError, parse_time
from triage.cli import add_exit_codes
from triage.commands.common import SKILL_DIR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run.py publish", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")

    def add_accept(child: argparse.ArgumentParser) -> None:
        child.add_argument("--accept-hits", metavar="SHA256", default=None,
                           help="engineer only: proceed past audit hits when this is the set sha256 the refusal printed")

    def add(name: str, help_text: str, aliases: tuple[str, ...] = ()) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text, description=help_text, aliases=list(aliases), allow_abbrev=False)
        child.add_argument("--skill-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        child.add_argument("--case-dir", type=Path, required=True)
        return child

    audit = add("audit", "check the published files for secrets and write audit.json")
    audit.add_argument("--confluence-url", help="link the Slack message will carry, so its digest can be predicted")
    confluence_request_parser = add("confluence", "audit now and print the Confluence request when the audit is clean",
                                    aliases=("confluence-request",))
    add_accept(confluence_request_parser)
    confluence_request_parser.add_argument("--now", help=argparse.SUPPRESS)
    slack = add("slack-message", "write the Slack message, audit, and print it when the audit is clean")
    add_accept(slack)
    slack.add_argument("--now", help=argparse.SUPPRESS)
    slack.add_argument("--confluence-url", help="link to the Confluence page")
    verify = add("verify-confluence", "compare text read back from the Confluence page with the audited report")
    verify.add_argument("--body-file", type=Path, required=True,
                        help="the text the agent saved from the page, under the intake folder")
    confluence = add("record-confluence", "record the Confluence page that was published")
    confluence.add_argument("--page-id", required=True)
    confluence.add_argument("--url", required=True)
    confluence.add_argument("--now", help="the current time, ISO 8601 with a timezone; defaults to the clock")
    slack_record = add("record-slack", "record a Slack post")
    slack_record.add_argument("--destination", required=True, help="channel or person the message went to")
    slack_record.add_argument("--now", help="the current time, ISO 8601 with a timezone; defaults to the clock")
    add_exit_codes(parser)
    return parser


def _now(args: argparse.Namespace) -> datetime:
    return parse_time(args.now) if args.now else datetime.now(timezone.utc)


def _render_is_current(case_dir: Path) -> bool:
    """False, after saying why on stderr, when the report is not what was rendered from its inputs."""
    reasons = render_is_current(case_dir)
    if not reasons:
        return True
    for reason in reasons:
        print(reason, file=sys.stderr)
    print("the report must be validated and rendered again before anything is published", file=sys.stderr)
    return False


def _print_audit(result: dict, stream) -> None:
    if result["clean"]:
        print("clean", file=stream)
    for line in hit_lines(result):
        print(line, file=stream)


def _print_refusal(result: dict) -> None:
    _print_audit(result, sys.stderr)
    print(f"set sha256 of the audited items: {result['set_sha256']}", file=sys.stderr)


def _note_accepted(result: dict) -> None:
    if result.get("accepted_by_flag"):
        print("accepted by --accept-hits; hits at:", file=sys.stderr)
        _print_audit(result, sys.stderr)


def _account_ids(config) -> frozenset[str]:
    return configured_account_ids(config)


def _audit(args: argparse.Namespace, config) -> int:
    if not _render_is_current(args.case_dir):
        return 1
    result = audit_case(args.case_dir, allowed_account_ids=_account_ids(config))
    _print_audit(result, sys.stdout)
    if not result["clean"]:
        for label, digest in publish_digests(args.case_dir, args.confluence_url).items():
            print(f"for {label}: {digest or 'not available (the Slack message cannot be built)'}", file=sys.stderr)
    return 0 if result["clean"] else 1


def _confluence(args: argparse.Namespace, config) -> int:
    if not _render_is_current(args.case_dir):
        return 1
    request = confluence_request(args.case_dir, config, args.accept_hits)
    write_publish_state(args.case_dir.parent.parent, "confluence",
                        publish_state_entry(args.case_dir, "confluence", request, _now(args)))
    _note_accepted(load_audit(args.case_dir))
    print(json.dumps(request, indent=2))
    return 0


def _slack_message(args: argparse.Namespace, config) -> int:
    if not _render_is_current(args.case_dir):
        return 1
    slack_message(args.case_dir, args.confluence_url)
    result = audit_case(args.case_dir, args.accept_hits, _account_ids(config))
    if not may_proceed(result):
        _print_refusal(result)
        return 1
    text = read_audited(args.case_dir, "slack-message.md", result)
    write_publish_state(args.case_dir.parent.parent, "slack", publish_state_entry(args.case_dir, "slack", text, _now(args)))
    _note_accepted(result)
    print(text)
    for name, value in slack_context(load_case_file(args.case_dir), config).items():
        print(f"{name}: {value if value else '(none)'}", file=sys.stderr)
    return 0


def _verify_confluence(args: argparse.Namespace, config) -> int:
    result = verify_confluence(args.case_dir, args.body_file, config)
    if result["matches"]:
        print("matches")
        return 0
    print(f"line {result['line']} differs")
    print(f"expected: {result['expected']}")
    print(f"got:      {result['got']}")
    return 1


def _record_confluence(args: argparse.Namespace, config) -> int:
    record_confluence(args.case_dir, args.page_id, args.url, _now(args))
    return 0


def _record_slack(args: argparse.Namespace, config) -> int:
    record_slack(args.case_dir, args.destination, _now(args))
    return 0


def _refuse_replay(args: argparse.Namespace, allow_replay: bool) -> bool:
    if load_case_file(args.case_dir).get("replay") and not allow_replay:
        print("this case is a replay: its evidence comes from recordings, not from live systems; nothing is published",
              file=sys.stderr)
        return True
    return False


def main(argv: list[str] | None = None, *, allow_replay: bool = False) -> int:
    """allow_replay has no command-line option: a replay case is never published from the command line, and the
    tests that publish one call this function."""
    args = build_parser().parse_args(argv)
    handler = {"audit": _audit, "confluence": _confluence, "confluence-request": _confluence, "slack-message": _slack_message,
               "verify-confluence": _verify_confluence, "record-confluence": _record_confluence,
               "record-slack": _record_slack}[args.subcommand]
    try:
        config = load_config(default_config_path(args.skill_dir))
        args.case_dir = resolve_case_dir(args.case_dir, config)
        if _refuse_replay(args, allow_replay):
            return 1
        return handler(args, config)
    except PublishError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (ConfigError, CaseError) as error:
        print("\n".join(error.errors), file=sys.stderr)
        return 2
    except WindowError as error:
        print(str(error), file=sys.stderr)
        return 2
