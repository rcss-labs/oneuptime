"""Discover the AWS resources behind a hostname and propose a service map entry.

Exit codes: 0 something was found, 1 nothing was found, 2 usage or config error, 3 sign-in expired.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from triage.awscli import Runner, subprocess_runner
from triage.config import ConfigError, TriageConfig, default_config_path, load_config
from triage.context import SignInExpired
from triage.discover import discover_hostname
from triage.service_map import MapError, parse_map
from triage.fixtures import FixtureError, fixture_dir, replay_banner, kube_runner_from_env, runner_from_env
from triage.cli import add_exit_codes, run
INTAKE_DIR_NAME = 'intake'
OUTPUT_KEYS = {'discovery', 'service_name', 'proposed_entry', 'validation'}
PLACEHOLDER_SERVICE_NAME = 'discovered-service'
SKILL_DIR = Path(__file__).resolve().parent.parent

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='discover', description=__doc__.split('\n\n')[0])
    parser.add_argument('--hostname', required=True, help="the incident's hostname")
    parser.add_argument('--account', action='append', default=[], metavar='ALIAS', help='search only this account; repeatable')
    parser.add_argument('--service-name', help='service name to validate the proposed entry under')
    parser.add_argument('--monitor', action='append', default=[], metavar='NAME', help='monitor name to match; repeatable')
    parser.add_argument('--save', type=Path, metavar='PATH', help='also write the JSON output here; the path must be under the intake folder next to cases_dir')
    parser.add_argument('--skill-dir', type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    add_exit_codes(parser)
    return parser

def _validation_problems(entry: dict, service_name: str, config: TriageConfig) -> list[str]:
    try:
        parse_map({'services': {service_name: entry}}, config)
    except MapError as error:
        return error.errors
    return []

def _save_problem(path: Path, config: TriageConfig) -> str | None:
    """Why `path` may not be written, or None. Only the intake folder, and only over an earlier discovery output."""
    intake = (config.cases_dir.parent / INTAKE_DIR_NAME).resolve()
    target = path.expanduser().resolve()
    if intake not in target.parents:
        return f'--save must name a file under the intake folder {intake}'
    if target.is_dir():
        return f'--save {target} is a folder'
    if target.exists():
        try:
            earlier = json.loads(target.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            earlier = None
        if not isinstance(earlier, dict) or set(earlier) != OUTPUT_KEYS:
            return f'--save {target} exists and is not an earlier discovery output; it was not overwritten'
    return None

def _fail(message: str, code: int) -> int:
    print(message, file=sys.stderr)
    return code

def main(argv: list[str] | None=None, runner: Runner | None=None, kube_runner: Runner | None=None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        replay = fixture_dir()
        if replay and runner is None:
            print(replay_banner(replay), file=sys.stderr)
        runner, kube_runner = (runner or runner_from_env(), kube_runner or kube_runner_from_env())
    except FixtureError as error:
        return _fail(str(error), 2)
    try:
        config = load_config(default_config_path(args.skill_dir))
    except ConfigError as error:
        return _fail('; '.join(error.errors), 2)
    unknown = [alias for alias in args.account if alias not in config.accounts]
    if unknown:
        return _fail(f"unknown account {', '.join(unknown)}; configured: {', '.join(config.accounts)}", 2)
    if args.save:
        problem = _save_problem(args.save, config)
        if problem:
            return _fail(problem, 2)
    try:
        discovery = discover_hostname(args.hostname, config, runner or subprocess_runner, args.account, kube_runner=kube_runner or subprocess_runner, skill_dir=args.skill_dir)
    except SignInExpired as expired:
        return _fail(f'Sign-in expired. Run: aws sso login --profile {expired.profile}', 3)
    found = bool(discovery.resources)
    entry = discovery.proposed_entry(args.monitor) if found else None
    problems = _validation_problems(entry, args.service_name or PLACEHOLDER_SERVICE_NAME, config) if entry else []
    text = json.dumps({'discovery': discovery.to_dict(), 'service_name': args.service_name, 'proposed_entry': entry, 'validation': problems}, indent=2)
    if args.save:
        target = args.save.expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0 if found else 1
if __name__ == '__main__':
    sys.exit(run(main))