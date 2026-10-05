#!/usr/bin/env python3
"""List every AWS CLI operation that writes its response body to a local output file.

The AWS CLI gives an operation a required <outfile> positional when the output
shape's payload member is a blob (botocore's "streaming output" rule, whether or
not the model marks it streaming). This tool walks the service models bundled
with the installed AWS CLI and prints each such operation as `service operation`
in CLI spelling, one per line, sorted. It only reads files; it runs no aws command.
Paste the output into STREAMING_OUTPUT_OPERATIONS in guard_aws.py.

Exit codes: 0 the list was printed, 2 no model folder was found.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

# The CLI's own command names that differ from the botocore model folder (as `aws help` lists them).
CLI_SERVICE_NAMES = {"s3": "s3api", "config": "configservice", "codedeploy": "deploy"}
KNOWN_DATA_DIRS = (Path("/usr/local/aws-cli/awscli/botocore/data"),)
_SPECIAL_CASE = re.compile("[A-Z]{2,}s$")
_FIRST_CAP = re.compile("(.)([A-Z][a-z]+)")
_END_CAP = re.compile("([a-z0-9])([A-Z])")


def cli_operation_name(name: str) -> str:
    """botocore.xform_name(name, "-"): GetObjectTorrent -> get-object-torrent."""
    special = _SPECIAL_CASE.search(name)
    if special:
        matched = special.group()
        name = f"{name[: -len(matched)]}-{matched.lower()}"
    return _END_CAP.sub(r"\1-\2", _FIRST_CAP.sub(r"\1-\2", name)).lower()


def find_data_dir() -> Path | None:
    """The botocore data folder of the installed AWS CLI, if one can be found on disk."""
    candidates = list(KNOWN_DATA_DIRS)
    aws = shutil.which("aws")
    if aws:
        candidates.insert(0, Path(os.path.realpath(aws)).parent / "awscli" / "botocore" / "data")
    return next((path for path in candidates if path.is_dir()), None)


def _newest_model(service_dir: Path) -> Path | None:
    versions = sorted(child for child in service_dir.iterdir() if child.is_dir())
    for version in reversed(versions):
        model = version / "service-2.json"
        if model.is_file():
            return model
    return None


def streaming_operations(data_dir: Path) -> list[str]:
    found: set[str] = set()
    for service_dir in sorted(child for child in data_dir.iterdir() if child.is_dir()):
        model_path = _newest_model(service_dir)
        if model_path is None:
            continue
        model = json.loads(model_path.read_text())
        shapes = model.get("shapes", {})
        service = CLI_SERVICE_NAMES.get(service_dir.name, service_dir.name)
        for operation_name, operation in model.get("operations", {}).items():
            output = shapes.get(operation.get("output", {}).get("shape", ""), {})
            payload = output.get("payload")
            if not payload:
                continue
            member_shape = shapes.get(output.get("members", {}).get(payload, {}).get("shape", ""), {})
            if member_shape.get("type") == "blob":
                found.add(f"{service} {cli_operation_name(operation_name)}")
    return sorted(found)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="list_streaming_operations", description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", type=Path, help="botocore data folder (default: the installed AWS CLI's)")
    args = parser.parse_args(argv)
    data_dir = args.data_dir or find_data_dir()
    if data_dir is None or not data_dir.is_dir():
        print("No AWS CLI service models found; pass --data-dir.", file=sys.stderr)
        return 2
    for line in streaming_operations(data_dir):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
