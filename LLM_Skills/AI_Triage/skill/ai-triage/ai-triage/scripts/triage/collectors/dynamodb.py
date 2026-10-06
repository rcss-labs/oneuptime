"""DynamoDB collector: table state, capacity, indexes, scaling activity, throttling metrics. No item is ever read."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import newest_in_window
from triage.context import CollectContext
from triage.evidence import CURRENT, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts

MAX_ACTIVITIES = 20
METRICS = (
    ("ReadThrottleEvents", "Sum"), ("WriteThrottleEvents", "Sum"), ("ThrottledRequests", "Sum"),
    ("ConsumedReadCapacityUnits", "Sum"), ("ConsumedWriteCapacityUnits", "Sum"), ("SystemErrors", "Sum"),
    ("SuccessfulRequestLatency", "Maximum"),
)


def _table_summary(name: str, table: dict) -> str:
    billing = (table.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED")
    capacity = table.get("ProvisionedThroughput") or {}
    indexes = ", ".join(f"{i.get('IndexName')} {i.get('IndexStatus')}" for i in table.get("GlobalSecondaryIndexes", [])) or "none"
    return (
        f"Table {name} is {table.get('TableStatus')}: billing mode {billing}, "
        f"read capacity {capacity.get('ReadCapacityUnits')}, write capacity {capacity.get('WriteCapacityUnits')}, "
        f"{table.get('ItemCount')} items, global secondary indexes: {indexes}"
    )


def _add_scaling_activities(ctx: CollectContext, name: str, resource: str) -> None:
    reply = ctx.aws("application-autoscaling", "describe-scaling-activities", [
        "--service-namespace", "dynamodb", "--resource-id", f"table/{name}", "--max-items", str(MAX_ACTIVITIES),
    ])
    activities = newest_in_window(ctx.window, (reply or {}).get("ScalingActivities", []), lambda a: a.get("StartTime"), MAX_ACTIVITIES)
    for activity in activities:
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=activity.get("StartTime"), command=ctx.last_command,
            summary=f"Scaling activity {activity.get('StatusCode')}: {activity.get('Description')}",
            excerpt=activity.get("Cause") or "",
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["table"]
    resource = f"table/{name}"
    reply = ctx.aws("dynamodb", "describe-table", ["--table-name", name])
    table = (reply or {}).get("Table")
    if not table:
        if reply is not None or (ctx.evidence.errors and "NotFound" in ctx.evidence.errors[-1]["code"]):
            ctx.evidence.add(kind=CURRENT, resource=resource, summary=f"Table {name} was not found")
        return
    ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=_table_summary(name, table))
    _add_scaling_activities(ctx, name, resource)
    dimensions = {"TableName": name}
    add_metric_facts(ctx, resource, [MetricSpec(metric, "AWS/DynamoDB", metric, dimensions, stat) for metric, stat in METRICS])


COLLECTOR = Collector(
    name="dynamodb",
    description="DynamoDB table state, capacity, indexes, autoscaling activity, throttling and error metrics (no item is read)",
    required=("table",),
    optional=(),
    run=collect,
)
