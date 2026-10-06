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
        "lambda:GetLayerVersion",
        "lambda:GetLayerVersionByArn",
        "s3-object-lambda:GetObject",
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
# Action names are compared in lower case, as IAM does.
FORBIDDEN_ALLOW_PREFIXES = ("s3:getobject",)
# An action whose name holds one of these returns a secret, whatever it starts with.
FORBIDDEN_NAME_PARTS = ("credentials", "token", "password", "secretvalue")
# apigateway:GET on any other path can return API key values (/apikeys, /usageplans/*/keys).
API_GATEWAY_PATH_PREFIXES = ("/restapis/", "/apis/", "/domainnames/")
API_GATEWAY_EXACT_PATHS = ("/account",)
ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _lower(names: Any) -> frozenset[str]:
    return frozenset(name.lower() for name in names)


FORBIDDEN_LOWER = _lower(FORBIDDEN_ALLOWS)
READ_EXCEPTIONS_LOWER = _lower(READ_EXCEPTIONS)
READ_PREFIXES_LOWER = tuple(prefix.lower() for prefix in READ_NAME_PREFIXES)
REQUIRED_DENIES_LOWER = _lower(REQUIRED_DENIES)


def _api_gateway_path(resource: str) -> str | None:
    """The lower-case path of an API Gateway ARN, or None when the resource is not one."""
    parts = resource.lower().split(":", 5)
    if len(parts) != 6 or parts[:3] != ["arn", "aws", "apigateway"]:
        return None
    return parts[5]


def _api_gateway_resource_allowed(resource: str) -> bool:
    path = _api_gateway_path(resource)
    return path is not None and (path.startswith(API_GATEWAY_PATH_PREFIXES) or path in API_GATEWAY_EXACT_PATHS)


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
    denied: set[str] = set()  # lower case
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
        if {"Condition", "Principal", "NotPrincipal"} & statement.keys():
            problems.append(f"{where}: conditions are not allowed in this policy")
        effect = statement.get("Effect")
        actions = [str(action) for action in _as_list(statement.get("Action", []))]
        if not actions:
            problems.append(f"{where}: needs at least one Action")
        if effect == "Deny":
            denied.update(action.lower() for action in actions)
            if _as_list(statement.get("Resource")) != ["*"]:
                problems.append(f"{where}: a Deny must apply to every resource")
            continue
        if effect != "Allow":
            problems.append(f"{where}: Effect must be Allow or Deny")
            continue
        resources = [str(resource) for resource in _as_list(statement.get("Resource", []))]
        for action in actions:
            lowered = action.lower()
            service, _, name = action.partition(":")
            if not service or not name:
                problems.append(f"{where}: '{action}' is not a service:Action pair")
            elif "*" in action or "?" in action:
                problems.append(f"{where}: '{action}' uses a wildcard")
            elif (
                lowered in FORBIDDEN_LOWER
                or lowered.startswith(FORBIDDEN_ALLOW_PREFIXES)
                or any(part in name.lower() for part in FORBIDDEN_NAME_PARTS)
            ):
                problems.append(f"{where}: '{action}' must never be granted")
            elif lowered not in READ_EXCEPTIONS_LOWER and not name.lower().startswith(READ_PREFIXES_LOWER):
                problems.append(f"{where}: '{action}' is not a read action")
            elif lowered == "apigateway:get":
                for resource in resources:
                    if not _api_gateway_resource_allowed(resource):
                        problems.append(
                            f"{where}: apigateway:GET on '{resource}' is not allowed; only /restapis/, /apis/, "
                            "/domainnames/, and /account are, because usage plans and API keys expose key values"
                        )
    for action in sorted(REQUIRED_DENIES):
        if action.lower() not in denied:
            problems.append(f"missing explicit deny for '{action}'")
    return problems
