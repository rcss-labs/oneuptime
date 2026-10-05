"""DynamoDB collector: table state, capacity, indexes, scaling activity, throttling metrics. No item is ever read."""
from __future__ import annotations

from dataclasses import asdict

from triage.collectors import Collector
from triage.collectors.common import newest_in_window, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, _fetch, _summary_text, add_metric_facts

MAX_ACTIVITIES = 20
MAX_ARNS = 20
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


def _table_arns(table: dict) -> dict:
    """The table ARN and its global secondary index ARNs (at most MAX_ARNS), as the describe answer gives them."""
    data: dict = {}
    if table.get("TableArn"):
        data["arn"] = table["TableArn"]
    index_arns = [i["IndexArn"] for i in table.get("GlobalSecondaryIndexes", []) if i.get("IndexArn")]
    if index_arns:
        data["index_arns"] = index_arns[:MAX_ARNS]
        if len(index_arns) > MAX_ARNS:
            data["index_arns_omitted"] = len(index_arns) - MAX_ARNS
    return data


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


def _add_operation_metrics(ctx: CollectContext, name: str, resource: str, table_throttled: bool) -> None:
    specs = [
        MetricSpec(f"{metric} {operation}", "AWS/DynamoDB", metric, {"TableName": name, "Operation": operation}, stat)
        for metric, stat in OPERATION_METRICS for operation in OPERATIONS
    ]
    errors_before = len(ctx.evidence.errors)
    summaries, window_command, window_read = _fetch(ctx, specs, 300, None)
    if not window_read:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=window_command,
            summary="The per-operation throttling and system error metrics could not be read (see errors)",
        )
        return
    for summary in summaries:
        if summary.datapoints:
            ctx.evidence.add(
                kind=INCIDENT_TIME, resource=resource, time=summary.peak_time, command=window_command,
                summary=_summary_text(summary), data=asdict(summary),
            )
    if len(ctx.evidence.errors) > errors_before:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary="The one-week baseline for the per-operation metrics could not be read (see errors); the window values are reported without a comparison",
        )
    problems = [
        s for s in summaries
        if s.datapoints and s.label.split()[0] in ("ThrottledRequests", "SystemErrors") and (s.window_max or 0) > 0
    ]
    if not problems and not table_throttled:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=window_command,
            summary=(
                f"No throttling or system error was recorded in the window for any of the {len(OPERATIONS)} operations queried ({', '.join(OPERATIONS)}); "
                "other operations exist and were not queried"
            ),
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
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command, summary=_table_summary(name, table),
        data=_table_arns(table),
    )
    _add_scaling_activities(ctx, name, resource)
    dimensions = {"TableName": name}
    table_summaries = add_metric_facts(
        ctx, resource, [MetricSpec(metric, "AWS/DynamoDB", metric, dimensions, stat) for metric, stat in TABLE_METRICS]
    )
    table_throttled = any(
        s.label in ("ReadThrottleEvents", "WriteThrottleEvents") and s.datapoints and (s.window_max or 0) > 0
        for s in table_summaries
    )
    _add_operation_metrics(ctx, name, resource, table_throttled)


COLLECTOR = Collector(
    name="dynamodb",
    description="DynamoDB table state, capacity, indexes, autoscaling activity, throttling and error metrics (no item is read)",
    required=("table",),
    optional=(),
    run=collect,
)
