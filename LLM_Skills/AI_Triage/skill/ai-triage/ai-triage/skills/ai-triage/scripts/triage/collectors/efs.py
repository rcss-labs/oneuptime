"""EFS collector: file system state, mount targets, NFS reachability, access points, throughput metrics."""
from __future__ import annotations

from triage.collectors import Collector
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.metrics import MetricSpec, add_metric_facts

MAX_ITEMS = 20
NFS_PORT = 2049
METRICS = (
    ("BurstCreditBalance", "Minimum"), ("PercentIOLimit", "Maximum"), ("ClientConnections", "Sum"),
    ("PermittedThroughput", "Minimum"), ("MeteredIOBytes", "Sum"),
)


def _file_system_summary(name: str, file_system: dict) -> str:
    size_bytes = (file_system.get("SizeInBytes") or {}).get("Value", 0)
    throughput = f"throughput mode {file_system.get('ThroughputMode')}"
    if file_system.get("ProvisionedThroughputInMibps") is not None:
        throughput += f" (provisioned {file_system['ProvisionedThroughputInMibps']} MiB/s)"
    return (
        f"File system {name} is {file_system.get('LifeCycleState')}: performance mode {file_system.get('PerformanceMode')}, "
        f"{throughput}, size {size_bytes / 1024**3:.2f} GiB"
    )


def _allows_nfs(group: dict) -> bool:
    for permission in group.get("IpPermissions", []):
        if permission.get("IpProtocol") == "-1":
            return True
        if permission.get("IpProtocol") == "tcp" and permission.get("FromPort", 1) <= NFS_PORT <= permission.get("ToPort", 0):
            return True
    return False


def _add_security_group_verdict(ctx: CollectContext, resource: str, mount_target_ids: list[str]) -> None:
    group_ids: list[str] = []
    for mount_target_id in mount_target_ids:
        reply = ctx.aws("efs", "describe-mount-target-security-groups", ["--mount-target-id", mount_target_id])
        group_ids += [g for g in (reply or {}).get("SecurityGroups", []) if g not in group_ids]
    if not group_ids:
        return
    reply = ctx.aws("ec2", "describe-security-groups", ["--group-ids", *group_ids])
    if reply is None:
        return
    allowing = [g.get("GroupId") for g in reply.get("SecurityGroups", []) if _allows_nfs(g)]
    summary = (
        f"Security groups {', '.join(allowing)} allow inbound TCP {NFS_PORT} on the mount targets"
        if allowing else
        f"No security group on the mount targets ({', '.join(group_ids)}) allows inbound TCP {NFS_PORT}"
    )
    ctx.evidence.add(kind=DERIVED, resource=resource, command=ctx.last_command, summary=summary)


def _add_mount_targets(ctx: CollectContext, name: str, resource: str) -> None:
    reply = ctx.aws("efs", "describe-mount-targets", ["--file-system-id", name, "--max-items", str(MAX_ITEMS)])
    if reply is None:
        return
    targets = reply.get("MountTargets", [])[:MAX_ITEMS]
    if not targets:
        ctx.evidence.add(kind=DERIVED, resource=resource, command=ctx.last_command, summary=f"File system {name} has no mount targets")
        return
    for target in targets:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=(
                f"Mount target {target.get('MountTargetId')} in {target.get('AvailabilityZoneName')}, "
                f"subnet {target.get('SubnetId')}, state {target.get('LifeCycleState')}, address {target.get('IpAddress')}"
            ),
        )
    broken = [f"{t.get('MountTargetId')} ({t.get('LifeCycleState')})" for t in targets if t.get("LifeCycleState") != "available"]
    if broken:
        ctx.evidence.add(kind=DERIVED, resource=resource, summary=f"Mount targets not available: {', '.join(broken)}")
    _add_security_group_verdict(ctx, resource, [t.get("MountTargetId", "") for t in targets])


def _add_access_points(ctx: CollectContext, name: str, resource: str) -> None:
    reply = ctx.aws("efs", "describe-access-points", ["--file-system-id", name, "--max-items", str(MAX_ITEMS)])
    for point in (reply or {}).get("AccessPoints", [])[:MAX_ITEMS]:
        if point.get("LifeCycleState") != "available":
            label = f" ({point['Name']})" if point.get("Name") else ""
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=f"Access point {point.get('AccessPointId')}{label} is {point.get('LifeCycleState')}",
            )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["file_system"]
    resource = f"file-system/{name}"
    reply = ctx.aws("efs", "describe-file-systems", ["--file-system-id", name])
    systems = (reply or {}).get("FileSystems", [])
    if not systems:
        if reply is not None or (ctx.evidence.errors and "NotFound" in ctx.evidence.errors[-1]["code"]):
            ctx.evidence.add(kind=CURRENT, resource=resource, summary=f"File system {name} was not found")
        return
    ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=_file_system_summary(name, systems[0]))
    _add_mount_targets(ctx, name, resource)
    _add_access_points(ctx, name, resource)
    dimensions = {"FileSystemId": name}
    add_metric_facts(ctx, resource, [MetricSpec(metric, "AWS/EFS", metric, dimensions, stat) for metric, stat in METRICS])


COLLECTOR = Collector(
    name="efs",
    description="EFS file system state, mount targets, whether security groups allow NFS, access points, burst and throughput metrics",
    required=("file_system",),
    optional=(),
    run=collect,
)
