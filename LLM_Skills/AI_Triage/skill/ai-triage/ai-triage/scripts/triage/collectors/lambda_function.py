"""Lambda collector: configuration, recent change, concurrency, event source mappings, account limit, metrics.

The module is not named lambda.py because lambda is a Python keyword; the collector name is still "lambda".
"""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_MAPPINGS = "20"
NOT_FOUND = "ResourceNotFoundException"
METRICS = (("Errors", "Sum"), ("Throttles", "Sum"), ("Duration", "Maximum"), ("ConcurrentExecutions", "Maximum"), ("Invocations", "Sum"))


def _get_configuration(ctx: CollectContext, function: str) -> dict | None:
    """The function configuration, or None. A missing function becomes a fact rather than an error."""
    errors_before = len(ctx.evidence.errors)
    reply = ctx.aws("lambda", "get-function-configuration", ["--function-name", function])
    missing = reply is None and len(ctx.evidence.errors) > errors_before and ctx.evidence.errors[-1]["code"] == NOT_FOUND
    if missing or reply == {}:
        if missing:
            ctx.evidence.errors.pop()
        ctx.evidence.add(
            kind=CURRENT, resource=f"function/{function}", command=ctx.last_command,
            summary=f"Function {function} was not found",
        )
        return None
    return reply


def _reason(label: str, reason: str | None) -> str:
    return f" ({label}: {reason})" if reason else ""


def _add_configuration(ctx: CollectContext, resource: str, config: dict) -> None:
    modified = parse_iso(config.get("LastModified"))
    modified_text = format_time(modified) if modified else "unknown"
    if in_window(ctx.window, config.get("LastModified")):
        modified_text += ", modified inside the incident window"
    variables = (config.get("Environment") or {}).get("Variables") or {}
    names = ", ".join(sorted(variables)) or "none"
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Function {config.get('FunctionName')}: runtime {config.get('Runtime')}, memory {config.get('MemorySize')} MB, "
            f"timeout {config.get('Timeout')} s, state {config.get('State')}{_reason('reason', config.get('StateReason'))}, "
            f"last update {config.get('LastUpdateStatus')}{_reason('reason', config.get('LastUpdateStatusReason'))}, "
            f"last modified {modified_text}, environment variables {names}"
        ),
        data={"environment": variables},
    )


def _add_concurrency(ctx: CollectContext, resource: str, function: str) -> None:
    reply = ctx.aws("lambda", "get-function-concurrency", ["--function-name", function])
    if reply is None:
        return
    reserved = reply.get("ReservedConcurrentExecutions")
    text = f"reserved concurrency {reserved}" if reserved is not None else "no reserved concurrency"
    ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=f"Function {function} has {text}")


def _add_mappings(ctx: CollectContext, resource: str, function: str) -> None:
    reply = ctx.aws("lambda", "list-event-source-mappings", ["--function-name", function, "--max-items", MAX_MAPPINGS])
    for mapping in (reply or {}).get("EventSourceMappings", []):
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=(
                f"Event source mapping {mapping.get('UUID')} from {mapping.get('EventSourceArn')} is {mapping.get('State')}; "
                f"last processing result: {mapping.get('LastProcessingResult')}"
            ),
        )


def _add_account_settings(ctx: CollectContext, resource: str) -> None:
    reply = ctx.aws("lambda", "get-account-settings")
    if reply is None:
        return
    limit = reply.get("AccountLimit") or {}
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Account concurrency limit {limit.get('ConcurrentExecutions')}, "
            f"unreserved {limit.get('UnreservedConcurrentExecutions')}"
        ),
        data={key: limit.get(key) for key in ("ConcurrentExecutions", "UnreservedConcurrentExecutions")},
    )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    function = targets["function"]
    resource = f"function/{function}"
    config = _get_configuration(ctx, function)
    if config is None:
        return
    _add_configuration(ctx, resource, config)
    _add_concurrency(ctx, resource, function)
    _add_mappings(ctx, resource, function)
    _add_account_settings(ctx, resource)
    specs = [MetricSpec(metric, "AWS/Lambda", metric, {"FunctionName": function}, stat=stat) for metric, stat in METRICS]
    add_metric_facts(ctx, resource, specs)


COLLECTOR = Collector(
    name="lambda",
    description="Lambda configuration and recent change, concurrency, event source mappings, account limit, errors, throttles, duration",
    required=("function",),
    optional=(),
    run=collect,
)
