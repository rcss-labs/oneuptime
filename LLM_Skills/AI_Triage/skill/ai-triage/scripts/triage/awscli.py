"""Run one read-only AWS CLI call with an explicit profile and region.

run_aws refuses anything the guard would not allow, so no collector can issue a write.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from triage.guard_aws import classify, global_option_in
from triage.verdict import ALLOW

SSO_EXPIRED = "SsoSessionExpired"
CLI_MISSING = "AwsCliMissing"
TIMEOUT = "Timeout"
BAD_OUTPUT = "UnreadableOutput"
UNKNOWN = "Unknown"
REFUSED = "RefusedByGuard"
TRIAGE_PROFILE_PREFIX = "triage-"

ERROR_CODE_RE = re.compile(r"An error occurred \(([\w.]+)\)")
SSO_EXPIRED_MARKERS = (
    "Error loading SSO Token",
    "Token has expired",
    "SSO session associated with this profile has expired",
    "The SSO session associated with this profile is invalid",
    "Error when retrieving token from sso",
)

# A runner takes the full argv and a timeout, and returns (exit code, stdout, stderr).
Runner = Callable[[list[str], int], tuple[int, str, str]]


@dataclass(frozen=True)
class AwsResult:
    ok: bool
    data: Any
    error_code: str | None
    error_message: str | None
    argv: tuple[str, ...]


def subprocess_runner(argv: list[str], timeout: int) -> tuple[int, str, str]:
    # Output may be cut inside a multi-byte character (kubectl logs --limit-bytes), so never decode strictly.
    completed = subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
    )
    return completed.returncode, completed.stdout, completed.stderr


def run_aws(
    service: str,
    operation: str,
    args: Sequence[str] = (),
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess_runner,
    timeout: int = 60,
) -> AwsResult:
    argv = ["aws", service, operation, *args, "--profile", profile, "--region", region, "--output", "json", "--no-cli-pager"]
    frozen = tuple(argv)
    if not profile.startswith(TRIAGE_PROFILE_PREFIX):
        return AwsResult(False, None, REFUSED, f"profile '{profile}' is not a triage profile (its name must start with {TRIAGE_PROFILE_PREFIX})", frozen)
    global_option = global_option_in(args)
    if global_option:
        return AwsResult(False, None, REFUSED, f"option {global_option} is set by run_aws, not by the caller", frozen)
    verdict = classify(service, operation, args)
    if verdict.kind != ALLOW:
        return AwsResult(False, None, REFUSED, verdict.reason, frozen)
    try:
        code, stdout, stderr = runner(argv, timeout)
    except FileNotFoundError:
        return AwsResult(False, None, CLI_MISSING, "the aws command was not found", frozen)
    except subprocess.TimeoutExpired:
        return AwsResult(False, None, TIMEOUT, f"no answer within {timeout} seconds", frozen)
    if code != 0:
        message = stderr.strip()
        if any(marker in message for marker in SSO_EXPIRED_MARKERS):
            return AwsResult(False, None, SSO_EXPIRED, message, frozen)
        match = ERROR_CODE_RE.search(message)
        return AwsResult(False, None, match.group(1) if match else UNKNOWN, message, frozen)
    if not stdout.strip():
        return AwsResult(True, None, None, None, frozen)
    try:
        return AwsResult(True, json.loads(stdout), None, None, frozen)
    except json.JSONDecodeError:
        return AwsResult(False, None, BAD_OUTPUT, "the aws command did not print JSON", frozen)
