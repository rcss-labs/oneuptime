"""Access collector: an IAM role and its policies, a policy simulation, a KMS key, and a secret's metadata.

The secret value is never requested; the only Secrets Manager call is describe-secret.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.window import format_time

MAX_POLICIES = "20"
RISKY_KEY_STATES = ("Disabled", "PendingDeletion", "PendingReplicaDeletion")


def _when(text: Any) -> str:
    moment = parse_iso(text)
    return format_time(moment) if moment else "unknown"


def _trusted_principals(document: Any) -> list[str]:
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    found: list[str] = []
    for statement in statements:
        principal = statement.get("Principal", {})
        if isinstance(principal, str):
            found.append(principal)
            continue
        for values in principal.values():
            found.extend([values] if isinstance(values, str) else values)
    return found


def _add_role(ctx: CollectContext, name: str) -> str | None:
    """Add the role fact and return the role ARN, or None when the role cannot be read."""
    reply = ctx.aws("iam", "get-role", ["--role-name", name])
    if reply is None:
        return None
    role = reply.get("Role", {})
    used = role.get("RoleLastUsed") or {}
    last_used = (
        f"last used {_when(used['LastUsedDate'])} in {used.get('Region')}" if used.get("LastUsedDate")
        else "has never been used, or not within the period IAM tracks"
    )
    principals = ", ".join(_trusted_principals(role.get("AssumeRolePolicyDocument"))) or "none"
    ctx.evidence.add(
        kind=CURRENT, resource=f"role/{name}", command=ctx.last_command,
        summary=f"Role {name} created {_when(role.get('CreateDate'))}, {last_used}; trusted principals: {principals}",
    )
    return role.get("Arn")


def _add_role_policies(ctx: CollectContext, name: str) -> None:
    attached = ctx.aws("iam", "list-attached-role-policies", ["--role-name", name, "--max-items", MAX_POLICIES])
    command = ctx.last_command
    inline = ctx.aws("iam", "list-role-policies", ["--role-name", name, "--max-items", MAX_POLICIES])
    if attached is None and inline is None:
        return
    attached_names = [p.get("PolicyName", "") for p in (attached or {}).get("AttachedPolicies", [])]
    inline_names = (inline or {}).get("PolicyNames", [])
    ctx.evidence.add(
        kind=CURRENT, resource=f"role/{name}", command=f"{command}; {ctx.last_command}",
        summary=(
            f"Role {name} policies: attached {', '.join(attached_names) or 'none'}; "
            f"inline {', '.join(inline_names) or 'none'}"
        ),
    )


def _statement_text(statement: dict) -> str:
    return f"{statement.get('SourcePolicyId')} ({statement.get('SourcePolicyType')})"


def _add_simulation(ctx: CollectContext, role_arn: str, action: str, resource_arn: str | None) -> None:
    args = ["--policy-source-arn", role_arn, "--action-names", action]
    if resource_arn:
        args += ["--resource-arns", resource_arn]
    reply = ctx.aws("iam", "simulate-principal-policy", args)
    for result in (reply or {}).get("EvaluationResults", []):
        decision = result.get("EvalDecision")
        text = f"Simulation: {result.get('EvalActionName')} on {result.get('EvalResourceName')} is {decision}"
        if decision != "allowed":
            matched = ", ".join(_statement_text(s) for s in result.get("MatchedStatements", []))
            text += f"; denied by {matched}" if matched else "; no statement allows it"
        ctx.evidence.add(kind=DERIVED, resource=role_arn, summary=text, command=ctx.last_command)


def _add_key(ctx: CollectContext, key: str) -> None:
    reply = ctx.aws("kms", "describe-key", ["--key-id", key])
    if reply is None:
        return
    meta = reply.get("KeyMetadata", {})
    resource = f"key/{meta.get('KeyId') or key}"
    deletion = f", deletion date {_when(meta['DeletionDate'])}" if meta.get("DeletionDate") else ""
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Key {meta.get('KeyId')} state {meta.get('KeyState')}, enabled {meta.get('Enabled')}, "
            f"origin {meta.get('Origin')}{deletion}"
        ),
    )
    state = meta.get("KeyState")
    if state == "PendingDeletion" or state == "PendingReplicaDeletion":
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary=f"Key {meta.get('KeyId')} is pending deletion (deletion date {_when(meta.get('DeletionDate'))}); "
                    "calls that use it will fail",
        )
    elif state in RISKY_KEY_STATES or meta.get("Enabled") is False:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary=f"Key {meta.get('KeyId')} is disabled; calls that use it will fail",
        )


def _rotation_overdue(ctx: CollectContext, secret: dict) -> str | None:
    days = (secret.get("RotationRules") or {}).get("AutomaticallyAfterDays")
    rotated = parse_iso(secret.get("LastRotatedDate") if isinstance(secret.get("LastRotatedDate"), str) else None)
    if not secret.get("RotationEnabled") or not days or rotated is None:
        return None
    if ctx.window.end - rotated > timedelta(days=days):
        return f"rotation is overdue: last rotated {_when(secret['LastRotatedDate'])}, interval {days} days"
    return None


def _add_secret(ctx: CollectContext, name: str) -> None:
    secret = ctx.aws("secretsmanager", "describe-secret", ["--secret-id", name])
    if secret is None:
        return
    resource = f"secret/{secret.get('Name') or name}"
    enabled = "enabled" if secret.get("RotationEnabled") else "disabled"
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Secret {secret.get('Name') or name}: rotation {enabled}, last rotated {_when(secret.get('LastRotatedDate'))}, "
            f"last changed {_when(secret.get('LastChangedDate'))}, next rotation {_when(secret.get('NextRotationDate'))}"
        ),
    )
    overdue = _rotation_overdue(ctx, secret)
    if overdue:
        ctx.evidence.add(kind=DERIVED, resource=resource, summary=f"Secret {name}: {overdue}", command=ctx.last_command)
    if in_window(ctx.window, secret.get("LastChangedDate")):
        ctx.evidence.add(
            kind=DERIVED, resource=resource, time=secret["LastChangedDate"], command=ctx.last_command,
            summary=f"Secret {name} changed inside the incident window, at {_when(secret['LastChangedDate'])}",
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    role, key, secret = targets.get("role"), targets.get("kms_key"), targets.get("secret")
    if not (role or key or secret):
        ctx.evidence.add_error("", "MissingTarget", "access needs at least one of role, kms_key, or secret")
        return
    if role:
        role_arn = _add_role(ctx, role)
        _add_role_policies(ctx, role)
        if targets.get("action") and role_arn:
            _add_simulation(ctx, role_arn, targets["action"], targets.get("resource_arn"))
    if key:
        _add_key(ctx, key)
    if secret:
        _add_secret(ctx, secret)


COLLECTOR = Collector(
    name="access",
    description="IAM role trust and policies, a policy simulation, KMS key state, and secret rotation metadata",
    required=(),
    optional=("role", "action", "resource_arn", "kms_key", "secret"),
    run=collect,
)
