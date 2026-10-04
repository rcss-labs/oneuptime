"""DynamoDB collector: table state, capacity, indexes, scaling activity, throttling metrics. No item is ever read."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import newest_in_window, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts, fetch

MAX_ACTIVITIES = 20
TABLE_NOT_FOUND = ("ResourceNotFoundException",)
TABLE_METRICS = (
    ("ReadThrottleEvents", "Sum"), ("WriteThrottleEvents", "Sum"),
    ("ConsumedReadCapacityUnits", "Sum"), ("ConsumedWriteCapacityUnits", "Sum"),
)
# CloudWatch publishes these only per operation, so a query with just TableName matches nothing.
OPERATION_METRICS = (("ThrottledRequests", "Sum"), ("SystemErrors", "Sum"), ("SuccessfulRequestLatency", "Maximum"))
OPERATIONS = (
    "GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "Scan",
    "BatchGetItem", "BatchWriteItem", "TransactWriteItems",
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


def _add_operation_metrics(ctx: CollectContext, name: str, resource: str) -> None:
    specs = [
        MetricSpec(f"{metric} {operation}", "AWS/DynamoDB", metric, {"TableName": name, "Operation": operation}, stat)
        for metric, stat in OPERATION_METRICS for operation in OPERATIONS
    ]
    errors_before = len(ctx.evidence.errors)
    summaries = fetch(ctx, specs)
    with_data = [spec for spec, summary in zip(specs, summaries) if summary.datapoints]
    if with_data:
        add_metric_facts(ctx, resource, with_data)
    elif len(ctx.evidence.errors) > errors_before:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary="The per-operation throttling and system error metrics could not be read (see errors)",
        )
    else:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary="No throttling or system error was recorded for any operation in the window (no data for the per-operation metrics)",
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["table"]
    resource = f"table/{name}"
    reply = ctx.aws("dynamodb", "describe-table", ["--table-name", name], not_found=TABLE_NOT_FOUND)
    table = (reply or {}).get("Table")
    if not table:
        if reply is not None or was_not_found(ctx, TABLE_NOT_FOUND):
            ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=f"Table {name} was not found")
        return
    ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=_table_summary(name, table))
    _add_scaling_activities(ctx, name, resource)
    dimensions = {"TableName": name}
    add_metric_facts(ctx, resource, [MetricSpec(metric, "AWS/DynamoDB", metric, dimensions, stat) for metric, stat in TABLE_METRICS])
    _add_operation_metrics(ctx, name, resource)


COLLECTOR = Collector(
    name="dynamodb",
    description="DynamoDB table state, capacity, indexes, autoscaling activity, throttling and error metrics (no item is read)",
    required=("table",),
    optional=(),
    run=collect,
)
