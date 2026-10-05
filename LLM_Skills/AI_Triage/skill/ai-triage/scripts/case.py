#!/usr/bin/env python3
"""Create a case folder for an incident, choose its target, and print the collection plan.

Exit codes: 0 done, 1 a planned command could not be started or timed out (collect), 2 usage, config, or incident error.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from triage.case import (
    CaseError,
    REPLAY_NOTICE,
    check_replay,
    create_case,
    load_case,
    parse_incident,
    resolve_case_dir,
    set_target_from_discovery,
    set_target_from_map,
)
from triage.collection_plan import plan_collection, run_collection
from triage.config import ConfigError, default_config_path, load_config
from triage.service_map import MapError, ServiceMap, default_map_path, load_map
from triage.window import WindowError, parse_time
from triage.cli import add_exit_codes, run

SKILL_DIR = Path(__file__).resolve().parent.parent


MANUAL_TARGET_HELP = """\
manual target: when discovery finds nothing (it prints "account": null), or the incident names no host, ask the
engineer which account and resources are involved, write them to a file in this form, and pass it with --discovery:

  {"account": "<account alias from the config>", "region": "<region>",
   "resources": {"rds": "<db identifier>", "log_groups": ["/ecs/<service>"]}}

The resource keys are those of the service map (ecs_service, ec2_instances, auto_scaling_group, lambda_functions,
eks, load_balancer, api_gateway, cloudfront_distribution, rds, elasticache, dynamodb_tables, efs, sqs_queues,
sns_topics, log_groups, opensearch, alarms, ecr_repository, opensearch_domain) and are checked the same way.
Add what discovery could not find to a discovery file the same way.
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="case", description=__doc__.split("\n\n")[0])
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text, description=help_text)
        child.add_argument("--skill-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        return child

    init = add("init", "create the case folder from an incident file")
    init.add_argument("--incident", type=Path, required=True, help="incident JSON file")
    init.add_argument("--now", help="the current time, ISO 8601 with a timezone; defaults to the clock")
    target = add("target", "choose the target from the service map or from a discovery result")
    target.epilog = MANUAL_TARGET_HELP
    target.formatter_class = argparse.RawDescriptionHelpFormatter
    target.add_argument("--case-dir", type=Path, required=True)
    target.add_argument("--service", help="service name in the service map")
    target.add_argument("--environment", help="environment name in the service map")
    target.add_argument("--discovery", type=Path, help="JSON printed by discover.py")
    plan = add("plan", "print the collector commands for the chosen target")
    plan.add_argument("--case-dir", type=Path, required=True)
    collect = add("collect", "run every planned command (at most 4 at a time) and report what each wrote")
    collect.add_argument("--case-dir", type=Path, required=True)
    show = add("show", "print case.json")
    show.add_argument("--case-dir", type=Path, required=True)
    add_exit_codes(parser)
    return parser


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except OSError as error:
        raise CaseError([f"{path}: {error.strerror or error}"]) from error
    except ValueError as error:
        raise CaseError([f"{path}: not valid JSON ({error})"]) from error


def _service_map(skill_dir: Path, config, required: bool) -> ServiceMap:
    path = default_map_path(skill_dir)
    if not required and not path.is_file():
        return ServiceMap({})
    return load_map(path, config)


def _load_checked(case_dir: Path) -> dict:
    case = load_case(case_dir)
    check_replay(case)
    return case


def _init(args: argparse.Namespace, config) -> int:
    incident = parse_incident(_read_json(args.incident))
    now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
    case_dir = create_case(incident, config, _service_map(args.skill_dir, config, required=False), now, args.skill_dir)
    case = load_case(case_dir)
    print(json.dumps({"case_dir": str(case_dir), "window": case["window"],
                      "incident_start": case["incident_start"], "match": case["match"]}, indent=2))
    return 0


def _target(args: argparse.Namespace, config) -> int:
    if args.discovery and (args.service or args.environment):
        raise CaseError(["use either --service with --environment, or --discovery, not both"])
    if args.discovery:
        data = _read_json(args.discovery)
        discovery = data.get("discovery", data) if isinstance(data, dict) else data
        target = set_target_from_discovery(args.case_dir, config, discovery)
    elif args.service and args.environment:
        service_map = _service_map(args.skill_dir, config, required=True)
        target = set_target_from_map(args.case_dir, service_map, config, args.service, args.environment)
    else:
        raise CaseError(["give --service and --environment, or --discovery"])
    print(json.dumps(target, indent=2))
    return 0


def _plan(args: argparse.Namespace, config) -> int:
    commands = plan_collection(_load_checked(args.case_dir), config, args.skill_dir)
    print(json.dumps([
        {"domain": c.domain, "tool": c.tool, "name": c.name, "command": shlex.join(c.argv), "reason": c.reason}
        for c in commands
    ], indent=2))
    return 0


def _collect(args: argparse.Namespace, config) -> int:
    commands = plan_collection(_load_checked(args.case_dir), config, args.skill_dir)
    results = run_collection(commands, args.case_dir)
    print(json.dumps({"commands": results}, indent=2))
    return 1 if any(result["status"] in ("not started", "timed out") for result in results) else 0


def _show(args: argparse.Namespace, config) -> int:
    case = _load_checked(args.case_dir)
    if case.get("replay"):
        print(REPLAY_NOTICE)
    print(json.dumps(case, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handler = {"init": _init, "target": _target, "plan": _plan, "collect": _collect, "show": _show}[args.subcommand]
    try:
        config = load_config(default_config_path(args.skill_dir))
        if getattr(args, "case_dir", None) is not None:
            args.case_dir = resolve_case_dir(args.case_dir, config)
            if args.subcommand == "target":
                check_replay(load_case(args.case_dir))
        return handler(args, config)
    except (ConfigError, MapError, CaseError) as error:
        return _fail("; ".join(error.errors))
    except OSError as error:
        return _fail(str(error).replace("\n", " "))
    except WindowError as error:
        return _fail(str(error))


if __name__ == "__main__":
    sys.exit(run(main))
