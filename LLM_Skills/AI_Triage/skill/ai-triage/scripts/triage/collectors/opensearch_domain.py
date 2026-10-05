"""OpenSearch domain collector: domain configuration, cluster health, configuration changes, metrics.

This reads the AWS control plane only; it never queries the domain for documents.
"""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts

IN_PROGRESS = ("PENDING", "PROCESSING")
DOMAIN_NOT_FOUND = ("ResourceNotFoundException",)
METRICS = (
    ("ClusterStatus.red", "Maximum"), ("ClusterStatus.yellow", "Maximum"), ("FreeStorageSpace", "Minimum"),
    ("JVMMemoryPressure", "Maximum"), ("CPUUtilization", "Average"), ("ThreadpoolWriteRejected", "Sum"),
    ("ThreadpoolSearchRejected", "Sum"), ("5xx", "Sum"),
)


def _endpoint(status: dict) -> str:
    endpoints = status.get("Endpoints") or {}
    return status.get("Endpoint") or endpoints.get("vpc") or next(iter(endpoints.values()), None) or "none"


def _domain_summary(name: str, status: dict) -> str:
    cluster, storage = status.get("ClusterConfig", {}), status.get("EBSOptions", {})
    disk = f"{storage.get('VolumeSize')} GiB {storage.get('VolumeType')}" if storage.get("EBSEnabled") else "no EBS storage"
    processing = "processing a change" if status.get("Processing") else "not processing a change"
    return (
        f"Domain {name} runs {status.get('EngineVersion')} on {cluster.get('InstanceCount')} x {cluster.get('InstanceType')}, "
        f"storage {disk}, {processing}, endpoint {_endpoint(status)}"
    )


def _add_health(ctx: CollectContext, resource: str, name: str) -> None:
    health = ctx.aws("opensearch", "describe-domain-health", ["--domain-name", name])
    if not health:
        return
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command, data=health,
        summary=(
            f"Cluster health is {health.get('ClusterHealth')} (domain state {health.get('DomainState')}): "
            f"{health.get('DataNodeCount')} data nodes, {health.get('MasterEligibleNodeCount')} master-eligible nodes, "
            f"{health.get('TotalShards')} shards, {health.get('TotalUnAssignedShards')} unassigned"
        ),
    )


def _add_change_progress(ctx: CollectContext, resource: str, name: str) -> None:
    reply = ctx.aws("opensearch", "describe-domain-change-progress", ["--domain-name", name])
    progress = (reply or {}).get("ChangeProgressStatus")
    if not progress:
        return
    status = progress.get("Status")
    started = progress.get("StartTime")
    updated = progress.get("LastUpdatedTime") or progress.get("LastUpdated")
    if status not in IN_PROGRESS and not (in_window(ctx.window, started) or in_window(ctx.window, updated)):
        return
    ctx.evidence.add(
        kind=INCIDENT_TIME if parse_iso(started) else CURRENT, resource=resource, time=parse_iso(started),
        command=ctx.last_command,
        summary=(
            f"Domain configuration change {progress.get('ChangeId')} is {status} "
            f"(config change status {progress.get('ConfigChangeStatus')}, {progress.get('TotalNumberOfStages')} stages)"
        ),
    )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["domain"]
    resource = f"domain/{name}"
    reply = ctx.aws("opensearch", "describe-domain", ["--domain-name", name], not_found=DOMAIN_NOT_FOUND)
    status = (reply or {}).get("DomainStatus")
    if not status:
        if reply is not None or was_not_found(ctx, DOMAIN_NOT_FOUND):
            ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=f"Domain {name} was not found")
        return
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command, summary=_domain_summary(name, status),
        data={"arn": status["ARN"]} if status.get("ARN") else None,
    )
    _add_health(ctx, resource, name)
    _add_change_progress(ctx, resource, name)
    dimensions = {"DomainName": name, "ClientId": ctx.account.account_id}
    add_metric_facts(ctx, resource, [MetricSpec(metric, "AWS/ES", metric, dimensions, stat) for metric, stat in METRICS])


COLLECTOR = Collector(
    name="opensearch_domain",
    description="OpenSearch domain configuration, cluster health, configuration changes, storage, JVM, CPU, and rejection metrics",
    required=("domain",),
    optional=(),
    run=collect,
)
