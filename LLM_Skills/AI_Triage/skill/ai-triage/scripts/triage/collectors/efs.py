"""EFS collector: file system state, mount targets, NFS reachability, access points, throughput metrics."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.metrics import MetricSpec, add_metric_facts

MAX_ITEMS = 20
NFS_PORT = 2049
FILE_SYSTEM_NOT_FOUND = ("FileSystemNotFound",)
TCP_PROTOCOLS = ("tcp", "6", "-1")
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


def _nfs_sources(groups: list[dict]) -> list[str]:
    """Who the groups allow on TCP 2049: address ranges, prefix lists, and referenced security groups."""
    sources: list[str] = []
    for group in groups:
        for permission in group.get("IpPermissions", []):
            if permission.get("IpProtocol") not in TCP_PROTOCOLS:
                continue
            if permission.get("IpProtocol") != "-1" and not (
                permission.get("FromPort", 1) <= NFS_PORT <= permission.get("ToPort", 0)
            ):
                continue
            found = (
                [r.get("CidrIp") for r in permission.get("IpRanges", [])]
                + [r.get("CidrIpv6") for r in permission.get("Ipv6Ranges", [])]
                + [r.get("PrefixListId") for r in permission.get("PrefixListIds", [])]
                + [r.get("GroupId") for r in permission.get("UserIdGroupPairs", [])]
            )
            sources += [source for source in found if source and source not in sources]
    return sources


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _add_nfs_verdict(
    ctx: CollectContext, resource: str, target: dict, lookups: dict[tuple[str, ...], dict | None]
) -> None:
    label = f"Mount target {target.get('MountTargetId')} in {target.get('AvailabilityZoneName')}"
    reply = ctx.aws("efs", "describe-mount-target-security-groups", ["--mount-target-id", target.get("MountTargetId", "")])
    group_ids = tuple((reply or {}).get("SecurityGroups", []))
    groups = None
    if reply is not None and group_ids:
        if group_ids not in lookups:
            described = ctx.aws("ec2", "describe-security-groups", ["--group-ids", *group_ids])
            lookups[group_ids] = None if described is None else described.get("SecurityGroups", [])
        groups = lookups[group_ids]
    if groups is None:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary=f"{label}: whether it allows NFS (TCP {NFS_PORT}) could not be determined because its security groups could not be read",
        )
        return
    sources = _nfs_sources(groups)
    summary = (
        f"{label} allows NFS from {_join(sources)}" if sources
        else f"{label}: nothing allows TCP {NFS_PORT} in its security groups ({', '.join(group_ids) or 'none attached'})"
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
    lookups: dict[tuple[str, ...], dict | None] = {}
    for target in targets:
        _add_nfs_verdict(ctx, resource, target, lookups)


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
    reply = ctx.aws("efs", "describe-file-systems", ["--file-system-id", name], not_found=FILE_SYSTEM_NOT_FOUND)
    systems = (reply or {}).get("FileSystems", [])
    if not systems:
        if reply is not None or was_not_found(ctx, FILE_SYSTEM_NOT_FOUND):
            ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=f"File system {name} was not found")
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
