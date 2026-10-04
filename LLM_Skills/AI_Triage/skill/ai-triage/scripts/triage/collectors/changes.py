"""Changes collector: what changed just before the incident, and who changed it.

Sources are CloudTrail write events, CloudFormation stack events, CodePipeline executions and stages,
and AWS Config configuration history. Every incident-time summary states the gap to the incident start
when it is known.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, newest_in_window, parse_iso, split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.window import Window, describe_offset, format_time

MAX_RESOURCE_NAMES = 10
MAX_EVENTS_PER_NAME = 40
LOOKUP_ITEMS = "50"
LOOKUP_GRACE_MINUTES = 5
STACK_ITEMS = "50"
PIPELINE_ITEMS = "10"
CONFIG_LIMIT = "10"
NOT_DISCOVERED = "ResourceNotDiscoveredException"
STACK_TYPE = "AWS::CloudFormation::Stack"
STACK_UPDATE_STATUSES = ("UPDATE_IN_PROGRESS", "UPDATE_COMPLETE")


def _gap(incident_start: str | None, when: Any) -> str:
    """Words such as ", 4 minutes before the incident started", or nothing without an incident start."""
    incident, moment = parse_iso(incident_start), parse_iso(when)
    if incident is None or moment is None:
        return ""
    return f", {describe_offset(moment, incident)} the incident started"


def _lookup_end(ctx: CollectContext, incident_start: str | None) -> datetime:
    """Where the cause would be: up to a few minutes after the incident start, else the whole window."""
    incident = parse_iso(incident_start)
    if incident is None:
        return ctx.window.end
    end = min(ctx.window.end, incident + timedelta(minutes=LOOKUP_GRACE_MINUTES))
    return end if end > ctx.window.start else ctx.window.end


def _add_cloudtrail(ctx: CollectContext, lookup: str, name: str, incident_start: str | None) -> None:
    start, end = ctx.window.start, _lookup_end(ctx, incident_start)
    reply = ctx.aws(
        "cloudtrail", "lookup-events",
        ["--lookup-attributes", lookup, "--start-time", format_time(start), "--end-time", format_time(end),
         "--max-items", LOOKUP_ITEMS],
    )
    if reply is None:
        return
    writes = [e for e in reply.get("Events", []) if str(e.get("ReadOnly")).lower() == "false"]
    shown = newest_in_window(Window(start, end), writes, lambda e: e.get("EventTime"), MAX_EVENTS_PER_NAME)
    for item in shown:
        resources = [r.get("ResourceName") for r in item.get("Resources", []) if r.get("ResourceName")]
        resource = ", ".join(resources) or name
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=item.get("EventTime"), command=ctx.last_command,
            summary=(
                f"{item.get('EventName')} ({item.get('EventSource')}) by {item.get('Username') or 'unknown user'} "
                f"on {resource}{_gap(incident_start, item.get('EventTime'))}"
            ),
        )
    returned = len(reply.get("Events", []))
    if reply.get("NextToken"):
        ctx.evidence.add(
            kind=DERIVED, resource=name, command=ctx.last_command,
            summary=(
                f"More change events exist for {name} than the {len(shown)} shown; these are the newest in the period"
                if shown else
                f"No change was found among the {returned} newest events; older events were not read"
            ),
        )
    elif not shown:
        ctx.evidence.add(
            kind=DERIVED, resource=name, command=ctx.last_command,
            summary=f"No change was recorded for {name} between {format_time(start)} and {format_time(end)}",
        )


def _is_stack_event_of_interest(stack: str, event: dict) -> bool:
    status = event.get("ResourceStatus") or ""
    if status.endswith("FAILED") or status.endswith("ROLLBACK_IN_PROGRESS"):
        return True
    is_stack_itself = event.get("ResourceType") == STACK_TYPE and event.get("LogicalResourceId") == stack
    return is_stack_itself and status in STACK_UPDATE_STATUSES


def _add_stack_events(ctx: CollectContext, stack: str, incident_start: str | None) -> None:
    reply = ctx.aws("cloudformation", "describe-stack-events", ["--stack-name", stack, "--max-items", STACK_ITEMS])
    events = [e for e in (reply or {}).get("StackEvents", []) if _is_stack_event_of_interest(stack, e)]
    for event in newest_in_window(ctx.window, events, lambda e: e.get("Timestamp"), len(events)):
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"stack/{stack}", time=event.get("Timestamp"), command=ctx.last_command,
            summary=(
                f"Stack {stack}: {event.get('LogicalResourceId')} ({event.get('ResourceType')}) "
                f"{event.get('ResourceStatus')}{_gap(incident_start, event.get('Timestamp'))}"
            ),
            excerpt=event.get("ResourceStatusReason") or "",
        )


def _execution_time(window, execution: dict) -> str | None:
    """The start time when it is inside the window, else the end time when that is."""
    for key in ("startTime", "lastUpdateTime"):
        if in_window(window, execution.get(key)):
            return execution[key]
    return None


def _add_pipeline_executions(ctx: CollectContext, pipeline: str, incident_start: str | None) -> None:
    reply = ctx.aws(
        "codepipeline", "list-pipeline-executions", ["--pipeline-name", pipeline, "--max-items", PIPELINE_ITEMS],
    )
    for execution in (reply or {}).get("pipelineExecutionSummaries", []):
        when = _execution_time(ctx.window, execution)
        if when is None:
            continue
        trigger = execution.get("trigger") or {}
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"pipeline/{pipeline}", time=when, command=ctx.last_command,
            summary=(
                f"Pipeline {pipeline} execution {execution.get('pipelineExecutionId')} is {execution.get('status')}, "
                f"trigger {trigger.get('triggerType')} {trigger.get('triggerDetail') or ''}".rstrip()
                + _gap(incident_start, when)
            ),
        )


def _add_pipeline_state(ctx: CollectContext, pipeline: str) -> None:
    reply = ctx.aws("codepipeline", "get-pipeline-state", ["--name", pipeline])
    for stage in (reply or {}).get("stageStates", []):
        status = (stage.get("latestExecution") or {}).get("status") or "no execution"
        if status != "Succeeded":
            ctx.evidence.add(
                kind=CURRENT, resource=f"pipeline/{pipeline}", command=ctx.last_command,
                summary=f"Pipeline {pipeline} stage {stage.get('stageName')} is {status}",
            )


def _add_config_history(ctx: CollectContext, config_resource: str, incident_start: str | None) -> None:
    resource_type, _, resource_id = config_resource.partition("/")
    if not resource_type or not resource_id:
        ctx.evidence.add_error(
            "", "InvalidTarget", "config_resource must look like <resource type>/<resource id>",
        )
        return
    reply = ctx.aws(
        "configservice", "get-resource-config-history",
        ["--resource-type", resource_type, "--resource-id", resource_id,
         "--earlier-time", format_time(ctx.window.start), "--later-time", format_time(ctx.window.end),
         "--limit", CONFIG_LIMIT],
        not_found=(NOT_DISCOVERED,),
    )
    if reply is None:
        if was_not_found(ctx, (NOT_DISCOVERED,)):
            ctx.evidence.add(
                kind=DERIVED, resource=config_resource, command=ctx.last_command,
                summary=f"AWS Config does not record {config_resource}, so its configuration history is not available",
            )
        return
    for item in reply.get("configurationItems", []):
        when = item.get("configurationItemCaptureTime")
        if not in_window(ctx.window, when):
            continue
        related = ", ".join(item.get("relatedEvents") or [])
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=config_resource, time=when, command=ctx.last_command,
            summary=(
                f"AWS Config captured a configuration of {config_resource} with status "
                f"{item.get('configurationItemStatus')}{_gap(incident_start, when)}"
            ),
            excerpt=f"related CloudTrail events: {related}" if related else "",
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    incident_start = targets.get("incident_start") or None
    if incident_start and parse_iso(incident_start) is None:
        ctx.evidence.add_error(
            "", "InvalidTarget", "incident_start must be an ISO time with a timezone, for example 2026-10-04T10:50:00Z",
        )
        incident_start = None
    names = split_csv(targets.get("resource_names"))[:MAX_RESOURCE_NAMES]
    if names:
        for name in names:
            _add_cloudtrail(ctx, f"AttributeKey=ResourceName,AttributeValue={name}", name, incident_start)
    else:
        _add_cloudtrail(ctx, "AttributeKey=ReadOnly,AttributeValue=false", "account", incident_start)
    if targets.get("stack"):
        _add_stack_events(ctx, targets["stack"], incident_start)
    if targets.get("pipeline"):
        _add_pipeline_executions(ctx, targets["pipeline"], incident_start)
        _add_pipeline_state(ctx, targets["pipeline"])
    if targets.get("config_resource"):
        _add_config_history(ctx, targets["config_resource"], incident_start)


COLLECTOR = Collector(
    name="changes",
    description="What changed just before the incident: CloudTrail write events, CloudFormation, CodePipeline, AWS Config",
    required=(),
    optional=("resource_names", "stack", "pipeline", "config_resource", "incident_start"),
    run=collect,
)
