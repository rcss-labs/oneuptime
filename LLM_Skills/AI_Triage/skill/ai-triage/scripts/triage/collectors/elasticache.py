"""ElastiCache collector: replication group state, member nodes, events, memory and connection metrics."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import newest_in_window, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_MEMBERS = 10
MAX_EVENTS_PER_MEMBER = 30
MAX_EVENT_ITEMS = "50"
GROUP_NOT_FOUND = ("ReplicationGroupNotFoundFault", "ReplicationGroupNotFound")
CLUSTER_NOT_FOUND = ("CacheClusterNotFound", "CacheClusterNotFoundFault")
METRICS = (
    ("EngineCPUUtilization", "Average"), ("DatabaseMemoryUsagePercentage", "Maximum"), ("Evictions", "Sum"),
    ("CurrConnections", "Maximum"), ("ReplicationLag", "Maximum"), ("SwapUsage", "Maximum"),
)


def _endpoint_text(label: str, endpoint: dict | None) -> str:
    return f"{label} endpoint {endpoint.get('Address')}:{endpoint.get('Port')}" if endpoint else ""


def _group_summary(group: dict) -> str:
    node_groups = group.get("NodeGroups", [])
    endpoints = [
        text for node_group in node_groups
        for text in (_endpoint_text("primary", node_group.get("PrimaryEndpoint")), _endpoint_text("reader", node_group.get("ReaderEndpoint")))
        if text
    ]
    endpoints += [text for text in (_endpoint_text("configuration", group.get("ConfigurationEndpoint")),) if text]
    statuses = ", ".join(f"{n.get('NodeGroupId')} {n.get('Status')}" for n in node_groups) or "none"
    return (
        f"Replication group {group.get('ReplicationGroupId')} is {group.get('Status')}: "
        f"{len(node_groups)} node group(s) ({statuses}), automatic failover {group.get('AutomaticFailover')}, "
        f"multi-AZ {group.get('MultiAZ')}, {'; '.join(endpoints) or 'no endpoints'}"
    )


def _add_member(ctx: CollectContext, name: str) -> None:
    reply = ctx.aws(
        "elasticache", "describe-cache-clusters", ["--cache-cluster-id", name, "--show-cache-node-info"],
        not_found=CLUSTER_NOT_FOUND,
    )
    clusters = (reply or {}).get("CacheClusters", [])
    if not clusters:
        if reply is not None or was_not_found(ctx, CLUSTER_NOT_FOUND):
            ctx.evidence.add(
                kind=CURRENT, resource=f"cache-cluster/{name}", command=ctx.last_command,
                summary=f"Member {name} was not found",
            )
        return
    cluster = clusters[0]
    nodes = ", ".join(f"{n.get('CacheNodeId')} {n.get('CacheNodeStatus')}" for n in cluster.get("CacheNodes", [])) or "none"
    ctx.evidence.add(
        kind=CURRENT, resource=f"cache-cluster/{name}", command=ctx.last_command,
        summary=(
            f"Member {name} is {cluster.get('CacheClusterStatus')}: engine {cluster.get('Engine')} "
            f"{cluster.get('EngineVersion')}, node type {cluster.get('CacheNodeType')}, nodes {nodes}"
        ),
    )


def _add_events(ctx: CollectContext, source: str, source_type: str, resource: str) -> None:
    reply = ctx.aws("elasticache", "describe-events", [
        "--source-identifier", source, "--source-type", source_type,
        "--start-time", format_time(ctx.window.start), "--end-time", format_time(ctx.window.end),
        "--max-items", MAX_EVENT_ITEMS,
    ])
    events = newest_in_window(ctx.window, (reply or {}).get("Events", []), lambda e: e.get("Date"), MAX_EVENTS_PER_MEMBER)
    for event in events:
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=event.get("Date"), command=ctx.last_command,
            summary=f"Event on {source}: {event.get('Message')}",
        )


def _add_metrics(ctx: CollectContext, member: str) -> None:
    dimensions = {"CacheClusterId": member}
    specs = [MetricSpec(metric, "AWS/ElastiCache", metric, dimensions, stat) for metric, stat in METRICS]
    add_metric_facts(ctx, f"cache-cluster/{member}", specs)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["replication_group"]
    resource = f"replication-group/{name}"
    reply = ctx.aws("elasticache", "describe-replication-groups", ["--replication-group-id", name], not_found=GROUP_NOT_FOUND)
    groups = (reply or {}).get("ReplicationGroups", [])
    if not groups:
        if reply is not None or was_not_found(ctx, GROUP_NOT_FOUND):
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=f"Replication group {name} was not found",
            )
        return
    group = groups[0]
    ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=_group_summary(group))
    all_members = group.get("MemberClusters", [])
    members = all_members[:MAX_MEMBERS]
    if len(all_members) > MAX_MEMBERS:
        ctx.evidence.add(
            kind=DERIVED, resource=resource,
            summary=f"The group has {len(all_members)} members; events and metrics cover the first {MAX_MEMBERS}",
        )
    _add_events(ctx, name, "replication-group", resource)
    for member in members:
        _add_member(ctx, member)
        _add_events(ctx, member, "cache-cluster", f"cache-cluster/{member}")
        _add_metrics(ctx, member)


COLLECTOR = Collector(
    name="elasticache",
    description="ElastiCache replication group state, member nodes, events, CPU, memory, evictions, connections, replication lag",
    required=("replication_group",),
    optional=(),
    run=collect,
)
