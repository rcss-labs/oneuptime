#!/usr/bin/env python3
"""List every word the installed AWS CLI accepts after `aws` as a service or command.

Walks the service models bundled with the installed AWS CLI (renamed as the CLI
names them) and adds the CLI's own commands that have no model. It only reads
files; it runs no aws command. Paste the output into AWS_SERVICE_NAMES in
guard_aws.py. The guard denies any other word, because an alias from
~/.aws/cli/alias could run anything under an allowed-looking name.

Exit codes: 0 the list was printed, 2 no model folder was found.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from list_streaming_operations import CLI_SERVICE_NAMES, find_data_dir

# Commands of AWS CLI v2 without a service model, from the AVAILABLE SERVICES list of `aws help`.
CLI_CUSTOM_COMMANDS = ("cli-dev", "configure", "ddb", "help", "history", "login", "logout", "s3")


def service_names(data_dir: Path) -> list[str]:
    names = {CLI_SERVICE_NAMES.get(child.name, child.name) for child in data_dir.iterdir()
             if child.is_dir() and any(version.is_dir() for version in child.iterdir())}
    return sorted(names | set(CLI_CUSTOM_COMMANDS))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="list_aws_services", description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", type=Path, help="botocore data folder (default: the installed AWS CLI's)")
    args = parser.parse_args(argv)
    data_dir = args.data_dir or find_data_dir()
    if data_dir is None or not data_dir.is_dir():
        print("No AWS CLI service models found; pass --data-dir.", file=sys.stderr)
        return 2
    for name in service_names(data_dir):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
