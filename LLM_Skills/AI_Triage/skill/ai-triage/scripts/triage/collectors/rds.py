"""RDS collector: instance or cluster state, events, error log lines, metrics, Performance Insights."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from triage.collectors import Collector
from triage.collectors.common import newest_in_window, parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_EVENTS = 30
MAX_LOG_LINES = 20
MAX_LOG_FILES = "10"
LOG_LINES_TO_READ = "200"
TOP_WAIT_EVENTS = 5
PROBLEM_LINE = re.compile(r"ERROR|FATAL|PANIC|(?i:deadlock)")
LOG_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
METRICS = (
    ("CPUUtilization", "Average"), ("DatabaseConnections", "Maximum"), ("FreeStorageSpace", "Minimum"),
    ("FreeableMemory", "Minimum"), ("ReplicaLag", "Maximum"), ("ReadLatency", "Average"), ("WriteLatency", "Average"),
)


def _last_error_code(ctx: CollectContext) -> str:
    return ctx.evidence.errors[-1]["code"] if ctx.evidence.errors else ""


def _describe_instance(ctx: CollectContext, name: str) -> dict | None:
    reply = ctx.aws("rds", "describe-db-instances", ["--db-instance-identifier", name])
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


def _add_events(ctx: CollectContext, name: str) -> None:
    reply = ctx.aws("rds", "describe-events", [
        "--source-identifier", name, "--source-type", "db-instance",
        "--start-time", format_time(ctx.window.start), "--end-time", format_time(ctx.window.end),
    ])
    for event in newest_in_window(ctx.window, (reply or {}).get("Events", []), lambda e: e.get("Date"), MAX_EVENTS):
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"db/{name}", time=event.get("Date"), command=ctx.last_command,
            summary=f"Instance event on {name}: {event.get('Message')}",
        )


def _choose_log_file(files: list[dict]) -> dict | None:
    if not files:
        return None
    errors = [f for f in files if "error" in f.get("LogFileName", "").lower()]
    return max(errors or files, key=lambda f: f.get("LastWritten", 0))


def _line_time(line: str) -> datetime | None:
    match = LOG_TIMESTAMP.search(line)
    return parse_iso(f"{match.group(1)}T{match.group(2)}Z") if match else None


def _add_log_lines(ctx: CollectContext, name: str) -> None:
    window_start_millis = ctx.window.epoch_millis()[0]
    listing = ctx.aws("rds", "describe-db-log-files", [
        "--db-instance-identifier", name, "--file-last-written", str(window_start_millis), "--max-items", MAX_LOG_FILES,
    ])
    chosen = _choose_log_file((listing or {}).get("DescribeDBLogFiles", []))
    if chosen is None:
        return
    file_name = chosen.get("LogFileName", "")
    portion = ctx.aws("rds", "download-db-log-file-portion", [
        "--db-instance-identifier", name, "--log-file-name", file_name, "--number-of-lines", LOG_LINES_TO_READ,
    ])
    lines = ((portion or {}).get("LogFileData") or "").splitlines()
    matching = [line for line in lines if PROBLEM_LINE.search(line)][-MAX_LOG_LINES:]
    for line in matching:
        moment = _line_time(line)
        ctx.evidence.add(
            kind=INCIDENT_TIME if moment else CURRENT, resource=f"db/{name}", time=moment, command=ctx.last_command,
            summary=f"Database log line in {file_name}", excerpt=line.strip(),
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
            loads.append((sum(values) / len(values), next(iter(dimensions.values()))))
    loads.sort(reverse=True)
    text = ", ".join(f"{label} {load:.2f}" for load, label in loads[:TOP_WAIT_EVENTS]) or "no wait event data was returned"
    ctx.evidence.add(
        kind=DERIVED, resource=f"db/{name}", command=ctx.last_command,
        summary=f"Top wait events by average database load in the window: {text}",
    )


def _collect_instance(ctx: CollectContext, instance: dict) -> None:
    name = instance.get("DBInstanceIdentifier", "")
    _add_instance_state(ctx, instance)
    _add_events(ctx, name)
    _add_log_lines(ctx, name)
    _add_metrics(ctx, name)
    if instance.get("PerformanceInsightsEnabled") and instance.get("DbiResourceId"):
        _add_wait_events(ctx, name, instance["DbiResourceId"])


def _collect_cluster(ctx: CollectContext, name: str) -> bool:
    reply = ctx.aws("rds", "describe-db-clusters", ["--db-cluster-identifier", name])
    clusters = (reply or {}).get("DBClusters", [])
    if not clusters:
        return False
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
    for member in members:
        instance = _describe_instance(ctx, member.get("DBInstanceIdentifier", ""))
        if instance is not None:
            _collect_instance(ctx, instance)
    return True


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["db"]
    instance = _describe_instance(ctx, name)
    if instance is not None:
        _collect_instance(ctx, instance)
        return
    if _last_error_code(ctx) not in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
        return
    if _collect_cluster(ctx, name):
        return
    ctx.evidence.add(kind=CURRENT, resource=f"db/{name}", summary=f"No RDS instance or cluster named {name} was not found")


COLLECTOR = Collector(
    name="rds",
    description="RDS instance or cluster state, events, error log lines, load and storage metrics, Performance Insights wait events",
    required=("db",),
    optional=(),
    run=collect,
)
