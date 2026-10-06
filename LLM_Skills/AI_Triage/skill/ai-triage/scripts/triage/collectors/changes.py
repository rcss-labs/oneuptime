"""Changes collector: what changed just before the incident, and who changed it.

Sources are CloudTrail write events, CloudFormation stack events, CodePipeline executions and stages,
and AWS Config configuration history. Every incident-time summary states the gap to the incident start
when it is known.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, newest_in_window, parse_iso, split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.window import Window, describe_offset, format_time

MAX_RESOURCE_NAMES = 10
MAX_SOURCE_PAGES = 10
MAX_EVENTS_PER_NAME = 40
LOOKUP_ITEMS = "50"
LOOKUP_GRACE_MINUTES = 5
GLOBAL_REGION = "us-east-1"
# One lookup per source (lookup-events takes one attribute per call). sts.amazonaws.com and
# route53domains.amazonaws.com are left out to stay near five calls: STS write events are mostly
# session creation, not changes.
GLOBAL_EVENT_SOURCES = (
    "iam.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com",
    "wafv2.amazonaws.com", "organizations.amazonaws.com",
)
# Event sources of global services, whose CloudTrail events are recorded in us-east-1 only; a lookup by one of
# these sources in any other region finds nothing.
US_EAST_1_SOURCES = frozenset({
    "iam.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com", "route53domains.amazonaws.com",
    "organizations.amazonaws.com", "waf.amazonaws.com",
})
# WAF (v2) records changes to global (CloudFront) web ACLs in us-east-1 and regional web ACLs in their region.
BOTH_REGION_SOURCES = frozenset({"wafv2.amazonaws.com"})
STACK_ITEMS = "50"
PIPELINE_ITEMS = "10"
CONFIG_LIMIT = "10"
NOT_DISCOVERED = "ResourceNotDiscoveredException"
STACK_TYPE = "AWS::CloudFormation::Stack"
STACK_UPDATE_STATUSES = ("UPDATE_IN_PROGRESS", "UPDATE_COMPLETE")


@dataclass(frozen=True)
class _Lookup:
    ok: bool  # the call succeeded
    cut: bool  # the answer had more pages than were read
    found: int  # write events in the period (before removing duplicates)


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
    if incident < ctx.window.start:
        return ctx.window.end
    return min(ctx.window.end, incident + timedelta(minutes=LOOKUP_GRACE_MINUTES))


def _is_write(event: dict) -> bool:
    return str(event.get("ReadOnly")).lower() == "false"


def _add_event_fact(
    ctx: CollectContext, item: dict, fallback: str, recorded: str, incident_start: str | None,
) -> None:
    """One fact from the named fields of a CloudTrail event; the CloudTrailEvent text is never copied."""
    resources = [r.get("ResourceName") for r in item.get("Resources", []) if r.get("ResourceName")]
    resource = ", ".join(resources) or fallback
    ctx.evidence.add(
        kind=INCIDENT_TIME, resource=resource, time=item.get("EventTime"), command=ctx.last_command,
        summary=(
            f"{item.get('EventName')} ({item.get('EventSource')}) by {item.get('Username') or 'unknown user'} "
            f"on {resource}{recorded}{_gap(incident_start, item.get('EventTime'))}"
        ),
    )


def _add_cloudtrail(
    ctx: CollectContext, lookup: str, name: str, incident_start: str | None, label: str | None = None,
    global_source: str | None = None, seen: set[str] | None = None, absence: bool = True,
) -> _Lookup:
    """One CloudTrail lookup. With global_source set it runs in us-east-1 and keeps only that event source.

    seen holds the ids of events already written; with absence False the caller words the "nothing found" fact.
    """
    label = label or name
    seen = set() if seen is None else seen
    region = GLOBAL_REGION if global_source else None
    start, end = ctx.window.start, _lookup_end(ctx, incident_start)
    reply = ctx.aws(
        "cloudtrail", "lookup-events",
        ["--lookup-attributes", lookup, "--start-time", format_time(start), "--end-time", format_time(end),
         "--max-items", LOOKUP_ITEMS],
        region=region,
    )
    if reply is None:
        return _Lookup(ok=False, cut=False, found=0)
    writes = [
        e for e in reply.get("Events", [])
        if _is_write(e) and (global_source is None or e.get("EventSource") == global_source)
    ]
    recorded = f", recorded in {GLOBAL_REGION}" if global_source else ""
    in_period = newest_in_window(Window(start, end), writes, lambda e: e.get("EventTime"), len(writes))
    shown = in_period[:MAX_EVENTS_PER_NAME]
    for item in shown:
        if item.get("EventId") in seen:
            continue
        seen.add(item.get("EventId"))
        _add_event_fact(ctx, item, name, recorded, incident_start)
    returned = len(reply.get("Events", []))
    period = f"between {format_time(start)} and {format_time(end)}"
    cut = bool(reply.get("NextToken"))
    if cut:
        summary = (
            f"More events exist than the {returned} read; they may include changes"
            if shown else
            f"No change was found among the {returned} newest events for {label} {period}; older events were not read"
        )
        ctx.evidence.add(kind=DERIVED, resource=name, command=ctx.last_command, summary=summary)
    elif not shown and not global_source and absence:
        ctx.evidence.add(
            kind=DERIVED, resource=name, command=ctx.last_command,
            summary=f"No change was recorded for {label} {period}",
        )
    elif len(in_period) > len(shown):
        ctx.evidence.add(
            kind=DERIVED, resource=name, command=ctx.last_command,
            summary=f"{len(in_period) - len(shown)} older changes for {label} {period} were not shown",
        )
    return _Lookup(ok=True, cut=cut, found=len(in_period))


def _names_in_record(event: dict, names: list[str]) -> list[str]:
    """The names that appear as whole words in the event's resources or anywhere in its CloudTrail record."""
    text = " ".join([r.get("ResourceName") or "" for r in event.get("Resources", [])] + [event.get("CloudTrailEvent") or ""])
    return [n for n in names if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", text)]


def _source_regions(ctx: CollectContext, source: str) -> list[str]:
    """The regions where CloudTrail records the events of a source."""
    if source in US_EAST_1_SOURCES:
        return [GLOBAL_REGION]
    if source in BOTH_REGION_SOURCES and ctx.region != GLOBAL_REGION:
        return [ctx.region, GLOBAL_REGION]
    return [ctx.region]


def _search_source(
    ctx: CollectContext, source: str, names: list[str], incident_start: str | None, seen: set[str],
    region: str | None = None,
) -> tuple[bool, set[str]]:
    """Read up to MAX_SOURCE_PAGES pages of write events of one source in one region (the collection region
    by default); keep those naming one of names.

    Returns whether the whole period was read, and the names found.
    """
    region = region or ctx.region
    recorded = f", recorded in {region}" if region != ctx.region else ""
    start, end = ctx.window.start, _lookup_end(ctx, incident_start)
    base = ["--lookup-attributes", f"AttributeKey=EventSource,AttributeValue={source}",
            "--start-time", format_time(start), "--end-time", format_time(end), "--max-items", LOOKUP_ITEMS]
    matched: list[tuple[dict, list[str]]] = []
    events_read, token, complete = 0, None, True
    for _ in range(MAX_SOURCE_PAGES):
        reply = ctx.aws(
            "cloudtrail", "lookup-events", base + (["--starting-token", token] if token else []),
            region=None if region == ctx.region else region,
        )
        if reply is None:
            return False, set()
        events_read += len(reply.get("Events", []))
        matched += [(e, hit) for e in reply.get("Events", []) if _is_write(e) and (hit := _names_in_record(e, names))]
        token = reply.get("NextToken")
        if not token:
            break
    else:
        complete = False
    command = ctx.last_command
    period = f"between {format_time(start)} and {format_time(end)}"
    found: set[str] = set()
    pairs = {id(e): hit for e, hit in matched}
    in_period = newest_in_window(Window(start, end), [e for e, _ in matched], lambda e: e.get("EventTime"), len(matched))
    for item in in_period[:MAX_EVENTS_PER_NAME]:
        found.update(pairs[id(item)])
        if item.get("EventId") in seen:
            continue
        seen.add(item.get("EventId"))
        _add_event_fact(ctx, item, ", ".join(pairs[id(item)]), recorded, incident_start)
    for item in in_period[MAX_EVENTS_PER_NAME:]:
        found.update(pairs[id(item)])
    if len(in_period) > MAX_EVENTS_PER_NAME:
        ctx.evidence.add(
            kind=DERIVED, resource=source, command=command,
            summary=f"{len(in_period) - MAX_EVENTS_PER_NAME} older changes by event source {source} {period} were not shown",
        )
    if not complete:
        ctx.evidence.add(
            kind=DERIVED, resource=source, command=command,
            summary=(
                f"Search by event source {source} in {region} stopped after {events_read} events ({MAX_SOURCE_PAGES} pages) {period}; "
                f"absence of changes naming {', '.join(names)} is not established"
            ),
        )
    return complete, found


def _add_named_changes(
    ctx: CollectContext, names: list[str], sources: list[str], incident_start: str | None, seen: set[str],
) -> None:
    """Look up each name exactly, then by event source, and word absence as exactly what was asked."""
    found: dict[str, int] = {}
    complete = True
    for name in names:
        result = _add_cloudtrail(
            ctx, f"AttributeKey=ResourceName,AttributeValue={name}", name, incident_start, seen=seen, absence=False,
        )
        found[name] = result.found
        complete = complete and result.ok and not result.cut
    by_region: dict[str, list[str]] = {ctx.region: []}
    for source in sources:
        for region in _source_regions(ctx, source):
            by_region.setdefault(region, []).append(source)
            source_complete, names_found = _search_source(ctx, source, names, incident_start, seen, region)
            complete = complete and source_complete
            for name in names_found:
                found[name] += 1
    if not complete:
        return
    if sources:
        parts = []
        for region, searched in by_region.items():
            ways = (["by resource name"] if region == ctx.region else []) + (
                [f"by event source {', '.join(searched)}"] if searched else [])
            parts.append(f"in {region} " + " and ".join(ways))
        how = "looked up " + "; ".join(parts)
    else:
        how = f"looked up by resource name only, in {ctx.region}; some services record ARNs or ids instead"
    period = f"between {format_time(ctx.window.start)} and {format_time(_lookup_end(ctx, incident_start))}"
    for name in names:
        if not found[name]:
            ctx.evidence.add(
                kind=DERIVED, resource=name, command=ctx.last_command,
                summary=f"CloudTrail returned no write event naming '{name}' {period} ({how})",
            )


def _add_global_services(ctx: CollectContext, incident_start: str | None, seen: set[str]) -> None:
    """Global services record their events in us-east-1, so look there when the collection is elsewhere."""
    if ctx.region == GLOBAL_REGION:
        return
    for source in GLOBAL_EVENT_SOURCES:
        _add_cloudtrail(
            ctx, f"AttributeKey=EventSource,AttributeValue={source}", source, incident_start,
            label=f"global service {source}", global_source=source, seen=seen,
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
    seen: set[str] = set()  # ids of the CloudTrail events already written, so that no event is written twice
    if names:
        _add_named_changes(ctx, names, split_csv(targets.get("event_sources")), incident_start, seen)
    else:
        _add_cloudtrail(ctx, "AttributeKey=ReadOnly,AttributeValue=false", "account", incident_start,
                        label="any resource", seen=seen)
    _add_global_services(ctx, incident_start, seen)
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
    optional=("resource_names", "event_sources", "stack", "pipeline", "config_resource", "incident_start"),
    run=collect,
)
