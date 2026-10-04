"""RDS collector: instance or cluster state, events, error log lines, metrics, Performance Insights."""
from __future__ import annotations

import json
import re
from datetime import datetime

from triage.collectors import Collector
from triage.collectors.common import newest_in_window, parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_EVENTS = 30
MAX_LOG_LINES = 20
MAX_LOG_FILES = "10"
MAX_EVENT_ITEMS = "50"
MAX_MEMBERS = 6
INSTANCE_NOT_FOUND = ("DBInstanceNotFound", "DBInstanceNotFoundFault")
CLUSTER_NOT_FOUND = ("DBClusterNotFound", "DBClusterNotFoundFault")
LOG_LINES_TO_READ = "200"
TOP_WAIT_EVENTS = 5
PROBLEM_LINE = re.compile(r"ERROR|FATAL|PANIC|(?i:deadlock)")
QUOTED_STRING = re.compile(r"'(?:[^']|'')*'|'[^']*$")
KEY_VALUE_GROUP = re.compile(r"=\([^)]*\)")
LOG_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
METRICS = (
    ("CPUUtilization", "Average"), ("DatabaseConnections", "Maximum"), ("FreeStorageSpace", "Minimum"),
    ("FreeableMemory", "Minimum"), ("ReplicaLag", "Maximum"), ("ReadLatency", "Average"), ("WriteLatency", "Average"),
)


def _describe_instance(ctx: CollectContext, name: str) -> dict | None:
    reply = ctx.aws("rds", "describe-db-instances", ["--db-instance-identifier", name], not_found=INSTANCE_NOT_FOUND)
    instances = (reply or {}).get("DBInstances", [])
    return instances[0] if instances else None


def _pending_text(instance: dict) -> str:
    pending = instance.get("PendingModifiedValues") or {}
    if not pending:
        return "no pending modified values"
    return "pending modified values " + ", ".join(f"{key}={value}" for key, value in sorted(pending.items()))


def _parameter_groups_text(instance: dict) -> str:
    groups = instance.get("DBParameterGroups", [])
    return ", ".join(f"{g.get('DBParameterGroupName')} {g.get('ParameterApplyStatus')}" for g in groups) or "none"


def _add_instance_state(ctx: CollectContext, instance: dict) -> None:
    name = instance.get("DBInstanceIdentifier")
    ctx.evidence.add(
        kind=CURRENT, resource=f"db/{name}", command=ctx.last_command,
        summary=(
            f"Instance {name} is {instance.get('DBInstanceStatus')}: class {instance.get('DBInstanceClass')}, "
            f"engine {instance.get('Engine')} {instance.get('EngineVersion')}, "
            f"multi-AZ {'yes' if instance.get('MultiAZ') else 'no'}, storage {instance.get('AllocatedStorage')} GiB, "
            f"{_pending_text(instance)}, parameter group {_parameter_groups_text(instance)}"
        ),
        data={key: instance.get(key) for key in ("DBInstanceStatus", "PendingModifiedValues")},
    )


def _add_events(ctx: CollectContext, name: str, source_type: str, noun: str) -> None:
    reply = ctx.aws("rds", "describe-events", [
        "--source-identifier", name, "--source-type", source_type,
        "--start-time", format_time(ctx.window.start), "--end-time", format_time(ctx.window.end),
        "--max-items", MAX_EVENT_ITEMS,
    ])
    for event in newest_in_window(ctx.window, (reply or {}).get("Events", []), lambda e: e.get("Date"), MAX_EVENTS):
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"db/{name}", time=event.get("Date"), command=ctx.last_command,
            summary=f"{noun} event on {name}: {event.get('Message')}",
        )


def _mask_values(line: str) -> str:
    """Hide data values in a log line: quoted strings become '?' and =(...) groups become =(?)."""
    return KEY_VALUE_GROUP.sub("=(?)", QUOTED_STRING.sub("'?'", line))


def _error_files(files: list[dict]) -> list[dict]:
    return [f for f in files if "error" in f.get("LogFileName", "").lower()]


def _choose_log_file(files: list[dict], window_end_millis: int) -> dict:
    """The file that was being written when the window ended, else the newest one."""
    active_at_end = [f for f in files if f.get("LastWritten", 0) >= window_end_millis]
    if active_at_end:
        return min(active_at_end, key=lambda f: f.get("LastWritten", 0))
    return max(files, key=lambda f: f.get("LastWritten", 0))


def _line_time(line: str) -> datetime | None:
    match = LOG_TIMESTAMP.search(line)
    return parse_iso(f"{match.group(1)}T{match.group(2)}Z") if match else None


def _add_log_lines(ctx: CollectContext, name: str) -> None:
    window_start_millis, window_end_millis = ctx.window.epoch_millis()
    listing = ctx.aws("rds", "describe-db-log-files", [
        "--db-instance-identifier", name, "--filename-contains", "error",
        "--file-last-written", str(window_start_millis), "--max-items", MAX_LOG_FILES,
    ])
    if listing is None:
        return
    files = _error_files(listing.get("DescribeDBLogFiles", []))
    if not files:
        ctx.evidence.add(
            kind=DERIVED, resource=f"db/{name}", command=ctx.last_command,
            summary=f"No error log of {name} was written in the window",
        )
        return
    file_name = _choose_log_file(files, window_end_millis).get("LogFileName", "")
    portion = ctx.aws("rds", "download-db-log-file-portion", [
        "--db-instance-identifier", name, "--log-file-name", file_name, "--number-of-lines", LOG_LINES_TO_READ,
        "--no-paginate",
    ])
    lines = ((portion or {}).get("LogFileData") or "").splitlines()
    timed = [(_line_time(line), line) for line in lines if PROBLEM_LINE.search(line)]
    inside = [(moment, line) for moment, line in timed if moment is not None and ctx.window.contains(moment)]
    for moment, line in inside[-MAX_LOG_LINES:]:
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"db/{name}", time=moment, command=ctx.last_command,
            summary=f"Database log line in {file_name}", excerpt=_mask_values(line.strip()),
        )


def _add_metrics(ctx: CollectContext, name: str) -> None:
    dimensions = {"DBInstanceIdentifier": name}
    add_metric_facts(ctx, f"db/{name}", [MetricSpec(metric, "AWS/RDS", metric, dimensions, stat) for metric, stat in METRICS])


def _add_wait_events(ctx: CollectContext, name: str, resource_id: str) -> None:
    queries = [{"Metric": "db.load.avg", "GroupBy": {"Group": "db.wait_event", "Limit": TOP_WAIT_EVENTS}}]
    reply = ctx.aws("pi", "get-resource-metrics", [
        "--service-type", "RDS", "--identifier", resource_id, "--metric-queries", json.dumps(queries),
        "--start-time", format_time(ctx.window.start), "--end-time", format_time(ctx.window.end),
        "--period-in-seconds", "300",
    ])
    if reply is None:
        return
    loads = []
    for series in reply.get("MetricList", []):
        dimensions = (series.get("Key") or {}).get("Dimensions") or {}
        values = [point["Value"] for point in series.get("DataPoints", []) if point.get("Value") is not None]
        if dimensions and values:
            label = dimensions.get("db.wait_event.name") or next(iter(dimensions.values()))
            loads.append((sum(values) / len(values), label))
    loads.sort(reverse=True)
    text = ", ".join(f"{label} {load:.2f}" for load, label in loads[:TOP_WAIT_EVENTS]) or "no wait event data was returned"
    ctx.evidence.add(
        kind=DERIVED, resource=f"db/{name}", command=ctx.last_command,
        summary=f"Top wait events by average database load in the window: {text}",
    )


def _collect_instance(ctx: CollectContext, instance: dict) -> None:
    name = instance.get("DBInstanceIdentifier", "")
    _add_instance_state(ctx, instance)
    _add_events(ctx, name, "db-instance", "Instance")
    _add_log_lines(ctx, name)
    _add_metrics(ctx, name)
    if instance.get("PerformanceInsightsEnabled") and instance.get("DbiResourceId"):
        _add_wait_events(ctx, name, instance["DbiResourceId"])


def _collect_cluster(ctx: CollectContext, name: str) -> None:
    reply = ctx.aws("rds", "describe-db-clusters", ["--db-cluster-identifier", name], not_found=CLUSTER_NOT_FOUND)
    clusters = (reply or {}).get("DBClusters", [])
    if not clusters:
        if reply is not None or was_not_found(ctx, CLUSTER_NOT_FOUND):
            ctx.evidence.add(
                kind=CURRENT, resource=f"db/{name}", command=ctx.last_command,
                summary=f"RDS instance or cluster {name} was not found",
            )
        return
    cluster = clusters[0]
    members = cluster.get("DBClusterMembers", [])
    roles = ", ".join(
        f"{m.get('DBInstanceIdentifier')} ({'writer' if m.get('IsClusterWriter') else 'reader'})" for m in members
    )
    ctx.evidence.add(
        kind=CURRENT, resource=f"db/{name}", command=ctx.last_command,
        summary=(
            f"Cluster {name} is {cluster.get('Status')}: engine {cluster.get('Engine')} {cluster.get('EngineVersion')}, "
            f"multi-AZ {'yes' if cluster.get('MultiAZ') else 'no'}, members {roles or 'none'}"
        ),
    )
    _add_events(ctx, name, "db-cluster", "Cluster")
    if len(members) > MAX_MEMBERS:
        ctx.evidence.add(
            kind=DERIVED, resource=f"db/{name}",
            summary=f"The cluster has {len(members)} members; only the first {MAX_MEMBERS} were described",
        )
    for member in members[:MAX_MEMBERS]:
        instance = _describe_instance(ctx, member.get("DBInstanceIdentifier", ""))
        if instance is not None:
            _collect_instance(ctx, instance)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["db"]
    instance = _describe_instance(ctx, name)
    if instance is not None:
        _collect_instance(ctx, instance)
    elif was_not_found(ctx, INSTANCE_NOT_FOUND):
        _collect_cluster(ctx, name)


COLLECTOR = Collector(
    name="rds",
    description="RDS instance or cluster state, events, error log lines, load and storage metrics, Performance Insights wait events",
    required=("db",),
    optional=(),
    run=collect,
)
