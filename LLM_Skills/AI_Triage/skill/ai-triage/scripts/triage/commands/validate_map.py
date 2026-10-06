"""Validate the team config and the service map.

Exit codes: 0 valid, 1 the service map is invalid, 2 usage error or an invalid config.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.config import ConfigError, default_config_path, load_config
from triage.service_map import MapError, default_map_path, load_map
from triage.cli import add_exit_codes
from triage.commands.common import SKILL_DIR



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run.py validate_map", description="Validate triage-config.yaml and service-map.yaml."
    )
    parser.add_argument("--config", type=Path, default=default_config_path(SKILL_DIR), help="path to the config file")
    parser.add_argument("--map", type=Path, default=default_map_path(SKILL_DIR), help="path to the service map")
    add_exit_codes(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("Config is invalid:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return 2
    try:
        service_map = load_map(args.map, config)
    except MapError as exc:
        print("Service map is invalid:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {len(config.accounts)} accounts, {len(service_map.services)} services")
    return 0
