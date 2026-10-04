"""Static checks on the inline policy of the triage permission set."""
from __future__ import annotations

import re
from typing import Any

MAX_BYTES = 32768
MAX_NON_WHITESPACE_BYTES = 10240
READ_NAME_PREFIXES = ("Describe", "Get", "List", "BatchGet", "Lookup", "Filter", "Download", "Simulate")
# Actions that are reads despite their names.
READ_EXCEPTIONS = frozenset({"logs:StartQuery", "logs:StopQuery", "apigateway:GET"})
# Never grant these, even though some of them look like reads.
FORBIDDEN_ALLOWS = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "kms:Decrypt",
        "ssm:StartSession",
        "ssm:SendCommand",
        "ecs:ExecuteCommand",
        "ec2:GetPasswordData",
        "lambda:GetFunction",
        "s3:GetObject",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetAuthorizationToken",
        "kinesis:GetRecords",
        "sts:GetSessionToken",
        "sts:GetFederationToken",
    }
)
REQUIRED_DENIES = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "kms:Decrypt",
        "ssm:StartSession",
        "ssm:SendCommand",
        "ecs:ExecuteCommand",
        "ec2:GetPasswordData",
        "ec2-instance-connect:*",
        "rds-data:*",
        "rds-db:connect",
    }
)
ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def check_policy(document: Any, raw_text: str) -> list[str]:
    """Return every problem found. An empty list means the policy is acceptable."""
    problems: list[str] = []
    size = len(raw_text.encode())
    compact = len(re.sub(r"\s", "", raw_text).encode())
    if size > MAX_BYTES:
        problems.append(f"policy is {size} bytes, over the {MAX_BYTES} byte limit")
    if compact > MAX_NON_WHITESPACE_BYTES:
        problems.append(f"policy has {compact} non-whitespace bytes, over the {MAX_NON_WHITESPACE_BYTES} limit")
    if ACCOUNT_ID_RE.search(raw_text):
        problems.append("policy contains an account id")
    if not isinstance(document, dict) or document.get("Version") != "2012-10-17":
        return problems + ["policy must be an object with Version 2012-10-17"]
    statements = document.get("Statement")
    if not isinstance(statements, list) or not statements:
        return problems + ["policy must have a non-empty Statement list"]

    sids: set[str] = set()
    denied: set[str] = set()
    for index, statement in enumerate(statements):
        sid = statement.get("Sid") if isinstance(statement, dict) else None
        where = f"statement {sid or index}"
        if not isinstance(statement, dict):
            problems.append(f"{where}: must be an object")
            continue
        if not sid or sid in sids:
            problems.append(f"{where}: needs a unique Sid")
        sids.add(sid)
        if "NotAction" in statement or "NotResource" in statement:
            problems.append(f"{where}: NotAction and NotResource are not allowed")
        effect = statement.get("Effect")
        actions = [str(action) for action in _as_list(statement.get("Action", []))]
        if not actions:
            problems.append(f"{where}: needs at least one Action")
        if effect == "Deny":
            denied.update(actions)
            if _as_list(statement.get("Resource")) != ["*"]:
                problems.append(f"{where}: a Deny must apply to every resource")
            continue
        if effect != "Allow":
            problems.append(f"{where}: Effect must be Allow or Deny")
            continue
        for action in actions:
            service, _, name = action.partition(":")
            if not service or not name:
                problems.append(f"{where}: '{action}' is not a service:Action pair")
            elif "*" in action:
                problems.append(f"{where}: '{action}' uses a wildcard")
            elif action in FORBIDDEN_ALLOWS:
                problems.append(f"{where}: '{action}' must never be granted")
            elif action not in READ_EXCEPTIONS and not name.startswith(READ_NAME_PREFIXES):
                problems.append(f"{where}: '{action}' is not a read action")
    for action in sorted(REQUIRED_DENIES - denied):
        problems.append(f"missing explicit deny for '{action}'")
    return problems
