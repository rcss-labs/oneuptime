#!/usr/bin/env python3
"""Check every action in the inline policy against the AWS Service Reference.

This needs network access, so it is a manual tool and not part of the test
suite. Run it after editing iam/ai-triage-inline-policy.json.

Exit codes: 0 all actions exist, 1 unknown actions found, 2 usage or network error.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

INDEX_URL = "https://servicereference.us-east-1.amazonaws.com/"
DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "iam" / "ai-triage-inline-policy.json"


def fetch(url: str) -> object:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_policy_actions", description=__doc__.splitlines()[0])
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="path to the inline policy JSON")
    args = parser.parse_args(argv)
    policy = json.loads(args.policy.read_text())
    try:
        service_urls = {entry["service"]: entry["url"] for entry in fetch(INDEX_URL)}
        known: dict[str, set[str]] = {}
        unknown: list[str] = []
        checked = 0
        for statement in policy["Statement"]:
            actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            for action in actions:
                service, _, name = action.partition(":")
                checked += 1
                if service not in service_urls:
                    unknown.append(f"{action} (unknown service)")
                    continue
                if service not in known:
                    known[service] = {entry["Name"] for entry in fetch(service_urls[service])["Actions"]}
                if name != "*" and name not in known[service]:
                    unknown.append(action)
    except (urllib.error.URLError, TimeoutError, KeyError) as exc:
        print(f"Could not read the AWS Service Reference: {exc}", file=sys.stderr)
        return 2
    if unknown:
        print("Unknown actions:", file=sys.stderr)
        for action in unknown:
            print(f"  - {action}", file=sys.stderr)
        return 1
    print(f"OK: {checked} actions exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
