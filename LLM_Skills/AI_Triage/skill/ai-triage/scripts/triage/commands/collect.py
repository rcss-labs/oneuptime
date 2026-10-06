"""Collect read-only evidence from one source into the evidence format.

Exit codes: 0 collected, 2 usage or config error, 3 sign-in expired, 4 unknown collector or bad target key.
A collector that raises is recorded as a CollectorError evidence error and the evidence is still output.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from triage.awscli import Runner, subprocess_runner
from triage.collectors import Collector, all_collectors
from triage.collectors.common import split_csv
from triage.config import ConfigError, default_config_path, load_config
from triage.context import CollectContext, SignInExpired
from triage.case import CaseError, check_replay, resolve_case_dir
from triage.evidence import Evidence, EvidenceExists
from triage.fixtures import FixtureError, fixture_dir, kube_runner_from_env, replay_banner, runner_from_env
from triage.window import WindowError, make_window
from triage.cli import add_exit_codes
from triage.commands.common import SKILL_DIR

GLOBAL_REGION = "us-east-1"  # hosts the global services


def _read_case(case_dir: Path) -> dict:
    """case.json as a dict, so its replay state can be compared with the session's before anything is collected."""
    case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    return case if isinstance(case, dict) else {}


def _list_line(collector: Collector) -> str:
    keys = ",".join(collector.required) or "-"
    optional = f"  optional: {', '.join(collector.optional)}" if collector.optional else ""
    one_of = f"  one of: {', '.join(collector.one_of)}" if collector.one_of else ""
    return f"{collector.name}  {keys}{optional}{one_of}  {collector.description}"


def _parse_targets(pairs: list[str]) -> tuple[dict[str, str], list[str]] | None:
    """The targets and the keys given more than once; None when a pair is not KEY=VALUE."""
    targets: dict[str, str] = {}
    repeated: list[str] = []
    for pair in pairs:
        key, separator, value = pair.partition("=")
        if not separator or not key:
            return None
        if key in targets and key not in repeated:
            repeated.append(key)
        targets[key] = value
    return targets, repeated


def _target_problem(collector: Collector, targets: dict[str, str]) -> str | None:
    keys = f"required: {', '.join(collector.required) or 'none'}; optional: {', '.join(collector.optional) or 'none'}"
    missing = [key for key in collector.required if key not in targets]
    unknown = [key for key in targets if key not in collector.required + collector.optional]
    if missing:
        return f"{collector.name} needs target {', '.join(missing)} ({keys})"
    empty = [key for key in collector.required if not split_csv(targets[key])]
    if empty:
        return f"{collector.name} target {', '.join(empty)} must not be empty ({keys})"
    if collector.one_of and not any(split_csv(targets.get(key)) for key in collector.one_of):
        return f"{collector.name} needs at least one of these targets: {', '.join(collector.one_of)} ({keys})"
    if unknown:
        return f"{collector.name} has no target {', '.join(unknown)} ({keys})"
    return None


def _asked_items(collector: Collector, targets: dict[str, str]) -> dict[str, list[str]]:
    """The items of each given target that the collector declares as a list (Collector.list_targets).

    Until the registry declares list targets, a target with a comma is itemised too: extra asked strings
    only make the findings check stricter, and the raw value is always kept whole under "targets".
    """
    list_keys = getattr(collector, "list_targets", None)
    if list_keys is None:
        return {key: split_csv(value) for key, value in targets.items() if "," in value}
    return {key: split_csv(value) for key, value in targets.items() if key in list_keys}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run.py collect", description=__doc__.split("\n\n")[0])
    parser.add_argument("name", nargs="?", help="collector name; see --list")
    parser.add_argument("--list", action="store_true", help="list the collectors and their target keys")
    parser.add_argument("--account", metavar="ALIAS", help="account alias from the config")
    parser.add_argument("--start", help="window start, ISO 8601 with a timezone")
    parser.add_argument("--end", help="window end, ISO 8601 with a timezone")
    parser.add_argument("--region", help="AWS region: one of the account's regions or us-east-1; defaults to the account's first")
    parser.add_argument("--target", action="append", default=[], metavar="KEY=VALUE", help="what to collect; repeatable")
    parser.add_argument("--case-dir", type=Path, help="write the evidence file into this case folder")
    parser.add_argument("--suffix", default="", help="added to the evidence file name")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    add_exit_codes(parser)
    return parser


def _fail(message: str, code: int) -> int:
    print(message, file=sys.stderr)
    return code


def main(argv: list[str] | None = None, runner: Runner | None = None, kube_runner: Runner | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    collectors = all_collectors()
    if args.list:
        print("\n".join(_list_line(collector) for collector in collectors.values()))
        return 0
    if not (args.name and args.account and args.start and args.end):
        parser.error("name, --account, --start, and --end are required")
    try:
        replay = fixture_dir()
        if replay and (runner is None or kube_runner is None):
            print(replay_banner(replay), file=sys.stderr)
        runner, kube_runner = runner or runner_from_env(), kube_runner or kube_runner_from_env()
    except FixtureError as error:
        return _fail(str(error), 2)
    try:
        config = load_config(default_config_path(args.skill_dir))
    except ConfigError as error:
        return _fail("; ".join(error.errors), 2)
    collector = collectors.get(args.name)
    if collector is None:
        return _fail(f"unknown collector {args.name}; available: {', '.join(sorted(collectors))}", 4)
    parsed = _parse_targets(args.target)
    if parsed is None:
        return _fail("--target must look like KEY=VALUE", 2)
    targets, repeated = parsed
    if repeated:
        return _fail(f"target {', '.join(repeated)} was given more than once", 4)
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
    allowed_regions = (*account.regions, GLOBAL_REGION) if GLOBAL_REGION not in account.regions else account.regions
    if region not in allowed_regions:
        return _fail(f"region {region} is not allowed for {account.alias}; use one of: {', '.join(allowed_regions)}", 2)
    evidence = Evidence(collector.name, account.alias, region, window, replay=replay is not None)
    evidence.set_asked(dict(targets), {"start": args.start, "end": args.end}, _asked_items(collector, targets))
    if args.case_dir:
        try:
            args.case_dir = resolve_case_dir(args.case_dir, config)
            check_replay(_read_case(args.case_dir))
            evidence.ensure_new(args.case_dir, args.suffix)
        except CaseError as error:
            return _fail("; ".join(error.errors), 2)
        except (OSError, ValueError) as error:
            return _fail(f"cannot read case.json in {args.case_dir}: {error}", 2)
        except EvidenceExists as error:
            return _fail(str(error), 2)
    ctx = CollectContext(
        config, account, region, window, evidence, args.skill_dir,
        runner=runner or subprocess_runner, kube_runner=kube_runner or subprocess_runner,
        now=datetime.now(timezone.utc),
    )
    try:
        collector.run(ctx, targets)
    except SignInExpired as expired:
        return _fail(f"Sign-in expired. Run: aws sso login --profile {expired.profile}", 3)
    except Exception as error:  # noqa: BLE001 - one bad field must not cost the evidence already collected
        evidence.add_error("", "CollectorError", f"{type(error).__name__}: {error}")
    if args.case_dir:
        try:
            path = evidence.write_new(args.case_dir, args.suffix)
        except EvidenceExists as error:
            return _fail(str(error), 2)
        print(f"{path} facts={len(evidence.facts)} errors={len(evidence.errors)} truncated={evidence.truncated}")
    else:
        print(evidence.to_json())
    return 0
