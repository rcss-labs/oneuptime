"""VPC collector: security groups, subnets, route tables, network ACLs, NAT gateways, endpoints, NAT metrics."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import split_csv
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.metrics import MetricSpec, add_metric_facts

LOW_ADDRESS_COUNT = 10
MAX_RULES_LISTED = 20
# Rule numbers of the built-in "deny everything else" entries (IPv4, IPv6); nobody added them.
DEFAULT_ACL_RULES = (32767, 32768)
NAT_METRICS = (("ErrorPortAllocation", "Sum"), ("PacketsDropCount", "Sum"), ("ActiveConnectionCount", "Maximum"))
PROTOCOL_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "-1": "all"}
ROUTE_TARGET_KEYS = (
    "GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "EgressOnlyInternetGatewayId",
    "LocalGatewayId", "CarrierGatewayId", "CoreNetworkArn", "InstanceId", "NetworkInterfaceId",
)


def _cidr_words(cidr: str) -> str:
    """Name the open-to-everyone ranges in words, which reads more clearly than 0.0.0.0/0."""
    return {"0.0.0.0/0": "anywhere (IPv4)", "::/0": "anywhere (IPv6)"}.get(cidr, cidr)


def _port_text(permission: dict) -> str:
    protocol = permission.get("IpProtocol")
    if protocol == "-1":
        return "all traffic"
    low, high = permission.get("FromPort"), permission.get("ToPort")
    if protocol in ("icmp", "icmpv6"):
        return f"{protocol} all types" if low == -1 else f"{protocol} type {low}"
    ports = str(low) if low == high else f"{low}-{high}"
    return f"{protocol} {ports}"


def _sources(permission: dict) -> list[str]:
    found = [_cidr_words(r.get("CidrIp", "")) for r in permission.get("IpRanges", [])]
    found += [_cidr_words(r.get("CidrIpv6", "")) for r in permission.get("Ipv6Ranges", [])]
    found += [p.get("GroupId", "") for p in permission.get("UserIdGroupPairs", [])]
    found += [f"prefix list {p.get('PrefixListId')}" for p in permission.get("PrefixListIds", [])]
    return [source for source in found if source]


def _inbound_text(permissions: list[dict]) -> str:
    parts = [f"{_port_text(p)} from {', '.join(_sources(p)) or 'no source'}" for p in permissions[:MAX_RULES_LISTED]]
    if len(permissions) > MAX_RULES_LISTED:
        parts.append(f"and {len(permissions) - MAX_RULES_LISTED} more")
    return "; ".join(parts) or "none"


def _add_not_found(ctx: CollectContext, kind: str, label: str, requested: list[str], found: set[str]) -> None:
    for identifier in requested:
        if identifier not in found:
            ctx.evidence.add(
                kind=CURRENT, resource=f"{kind}/{identifier}", command=ctx.last_command,
                summary=f"{label} {identifier} was not found",
            )


def _add_security_groups(ctx: CollectContext, ids: list[str]) -> None:
    reply = ctx.aws("ec2", "describe-security-groups", ["--filters", f"Name=group-id,Values={','.join(ids)}"])
    if reply is None:
        return
    groups = reply.get("SecurityGroups", [])
    for group in groups:
        inbound, outbound = group.get("IpPermissions", []), group.get("IpPermissionsEgress", [])
        ctx.evidence.add(
            kind=CURRENT, resource=f"security-group/{group.get('GroupId')}", command=ctx.last_command,
            summary=(
                f"Security group {group.get('GroupId')} ({group.get('GroupName')}) has {len(inbound)} inbound rules "
                f"and {len(outbound)} outbound rules; inbound: {_inbound_text(inbound)}"
            ),
        )
    _add_not_found(ctx, "security-group", "Security group", ids, {g.get("GroupId") for g in groups})


def _add_subnets(ctx: CollectContext, ids: list[str]) -> dict[str, str | None]:
    """Add subnet facts; return the VPC id of each subnet that exists (None for every id when the call failed)."""
    reply = ctx.aws("ec2", "describe-subnets", ["--filters", f"Name=subnet-id,Values={','.join(ids)}"])
    if reply is None:
        return {identifier: None for identifier in ids}
    subnets = reply.get("Subnets", [])
    for subnet in subnets:
        free = subnet.get("AvailableIpAddressCount")
        resource = f"subnet/{subnet.get('SubnetId')}"
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Subnet {subnet.get('SubnetId')} in {subnet.get('AvailabilityZone')} has {free} free addresses",
        )
        if isinstance(free, int) and free < LOW_ADDRESS_COUNT:
            ctx.evidence.add(
                kind=DERIVED, resource=resource, command=ctx.last_command,
                summary=f"Subnet {subnet.get('SubnetId')} has only {free} free addresses (fewer than {LOW_ADDRESS_COUNT})",
            )
    _add_not_found(ctx, "subnet", "Subnet", ids, {s.get("SubnetId") for s in subnets})
    return {s.get("SubnetId"): s.get("VpcId") for s in subnets}


def _route_target(route: dict) -> str:
    for key in ROUTE_TARGET_KEYS:
        if route.get(key):
            return route[key]
    return "no target"


def _destination(route: dict) -> str:
    return _cidr_words(
        route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId") or ""
    )


def _route_summary(table: dict, used_by: str) -> str:
    routes = table.get("Routes", [])
    defaults = [
        r for r in routes if r.get("DestinationCidrBlock") == "0.0.0.0/0" or r.get("DestinationIpv6CidrBlock") == "::/0"
    ]
    if len(defaults) == 1:
        default_text = f"default route via {_route_target(defaults[0])}"
    elif defaults:
        default_text = "default route via " + " and ".join(
            f"{_route_target(r)} ({'IPv6' if r.get('DestinationIpv6CidrBlock') else 'IPv4'})" for r in defaults
        )
    else:
        default_text = "no default route"
    holes = [f"{_destination(r)} via {_route_target(r)}" for r in routes if r.get("State") == "blackhole"]
    holes_text = f"; blackhole routes: {', '.join(holes)}" if holes else ""
    return f"Route table {table.get('RouteTableId')}{used_by} has {default_text}{holes_text}"


def _explicit_subnets(table: dict) -> set[str]:
    return {a.get("SubnetId") for a in table.get("Associations", []) if a.get("SubnetId")}


def _add_route_tables(ctx: CollectContext, subnet_vpcs: dict[str, str | None]) -> None:
    subnet_ids = list(subnet_vpcs)
    reply = ctx.aws(
        "ec2", "describe-route-tables", ["--filters", f"Name=association.subnet-id,Values={','.join(subnet_ids)}"],
    )
    if reply is None:
        return
    explicit: set[str] = set()
    for table in reply.get("RouteTables", []):
        explicit |= _explicit_subnets(table)
        ctx.evidence.add(
            kind=CURRENT, resource=f"route-table/{table.get('RouteTableId')}", command=ctx.last_command,
            summary=_route_summary(table, ""),
        )
    implicit = [identifier for identifier in subnet_ids if identifier not in explicit]
    for vpc in sorted({subnet_vpcs[i] for i in implicit if subnet_vpcs[i]}):
        _add_main_route_table(ctx, vpc, [i for i in implicit if subnet_vpcs[i] == vpc])


def _add_main_route_table(ctx: CollectContext, vpc_id: str, subnets: list[str]) -> None:
    """A subnet with no explicit association uses the VPC's main route table."""
    reply = ctx.aws(
        "ec2", "describe-route-tables",
        ["--filters", "Name=association.main,Values=true", f"Name=vpc-id,Values={vpc_id}"],
    )
    for table in (reply or {}).get("RouteTables", []):
        used_by = f" (the main route table of {vpc_id}, used by {', '.join(subnets)} implicitly)"
        ctx.evidence.add(
            kind=CURRENT, resource=f"route-table/{table.get('RouteTableId')}", command=ctx.last_command,
            summary=_route_summary(table, used_by),
        )


def _deny_text(entry: dict) -> str:
    outbound = bool(entry.get("Egress"))
    ports = entry.get("PortRange")
    port_text = f" port {ports.get('From')}-{ports.get('To')}" if ports else ""
    peer = _cidr_words(entry.get("CidrBlock") or entry.get("Ipv6CidrBlock") or "any")
    protocol = PROTOCOL_NAMES.get(str(entry.get("Protocol")), entry.get("Protocol"))
    return (
        f"{'outbound' if outbound else 'inbound'} rule {entry.get('RuleNumber')} deny {protocol}{port_text} "
        f"{'to' if outbound else 'from'} {peer}"
    )


def _add_network_acls(ctx: CollectContext, subnet_ids: list[str]) -> None:
    reply = ctx.aws(
        "ec2", "describe-network-acls", ["--filters", f"Name=association.subnet-id,Values={','.join(subnet_ids)}"],
    )
    for acl in (reply or {}).get("NetworkAcls", []):
        denies = [
            e for e in acl.get("Entries", [])
            if e.get("RuleAction") == "deny" and e.get("RuleNumber") not in DEFAULT_ACL_RULES
        ]
        detail = "; ".join(_deny_text(e) for e in denies) or "no deny entries besides the default rule"
        ctx.evidence.add(
            kind=CURRENT, resource=f"network-acl/{acl.get('NetworkAclId')}", command=ctx.last_command,
            summary=f"Network ACL {acl.get('NetworkAclId')}: {detail}",
        )


def _add_nat_gateways(ctx: CollectContext, vpc_id: str) -> None:
    reply = ctx.aws("ec2", "describe-nat-gateways", ["--filter", f"Name=vpc-id,Values={vpc_id}"])
    gateways = (reply or {}).get("NatGateways", [])
    for gateway in gateways:
        failure = f": {gateway['FailureMessage']}" if gateway.get("FailureMessage") else ""
        ctx.evidence.add(
            kind=CURRENT, resource=f"nat-gateway/{gateway.get('NatGatewayId')}", command=ctx.last_command,
            summary=f"NAT gateway {gateway.get('NatGatewayId')} is {gateway.get('State')}{failure}",
        )
    specs = [
        MetricSpec(f"{metric} {gateway.get('NatGatewayId')}", "AWS/NATGateway", metric,
                   {"NatGatewayId": gateway.get("NatGatewayId", "")}, stat)
        for gateway in gateways for metric, stat in NAT_METRICS
    ]
    if specs:
        add_metric_facts(ctx, f"vpc/{vpc_id}", specs)


def _add_endpoints(ctx: CollectContext, vpc_id: str) -> None:
    reply = ctx.aws("ec2", "describe-vpc-endpoints", ["--filters", f"Name=vpc-id,Values={vpc_id}"])
    for endpoint in (reply or {}).get("VpcEndpoints", []):
        if str(endpoint.get("State")).lower() == "available":
            continue
        ctx.evidence.add(
            kind=CURRENT, resource=f"vpc-endpoint/{endpoint.get('VpcEndpointId')}", command=ctx.last_command,
            summary=f"VPC endpoint {endpoint.get('VpcEndpointId')} ({endpoint.get('ServiceName')}) is {endpoint.get('State')}",
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    group_ids = split_csv(targets.get("security_group_ids"))
    subnet_ids = split_csv(targets.get("subnet_ids"))
    vpc_id = targets.get("vpc_id") or None
    if group_ids:
        _add_security_groups(ctx, group_ids)
    if subnet_ids:
        subnet_vpcs = _add_subnets(ctx, subnet_ids)
        vpc_id = vpc_id or next((v for v in subnet_vpcs.values() if v), None)
        if subnet_vpcs:
            _add_route_tables(ctx, subnet_vpcs)
            _add_network_acls(ctx, list(subnet_vpcs))
    if vpc_id:
        _add_nat_gateways(ctx, vpc_id)
        _add_endpoints(ctx, vpc_id)


COLLECTOR = Collector(
    name="vpc",
    description="Security group rules, subnet free addresses, route tables, network ACL denies, NAT gateways, endpoints",
    required=(),
    optional=("security_group_ids", "subnet_ids", "vpc_id"),
    run=collect,
    one_of=("security_group_ids", "subnet_ids", "vpc_id"),
)
