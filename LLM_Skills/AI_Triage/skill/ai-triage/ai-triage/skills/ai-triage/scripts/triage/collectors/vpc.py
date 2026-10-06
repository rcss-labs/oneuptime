"""VPC collector: security groups, subnets, route tables, network ACLs, NAT gateways, endpoints, NAT metrics."""
from __future__ import annotations

from triage.collectors import Collector
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.metrics import MetricSpec, add_metric_facts

LOW_ADDRESS_COUNT = 10
DEFAULT_ACL_RULE = 32767
NAT_METRICS = (("ErrorPortAllocation", "Sum"), ("PacketsDropCount", "Sum"), ("ActiveConnectionCount", "Maximum"))


def _split(text: str | None) -> list[str]:
    return [part.strip() for part in (text or "").split(",") if part.strip()]


def _cidr_words(cidr: str) -> str:
    """Name the open-to-everyone ranges in words; the redactor would otherwise replace 0.0.0.0 with a placeholder."""
    return {"0.0.0.0/0": "anywhere (IPv4)", "::/0": "anywhere (IPv6)"}.get(cidr, cidr)


def _port_text(permission: dict) -> str:
    protocol = permission.get("IpProtocol")
    if protocol == "-1":
        return "all traffic"
    low, high = permission.get("FromPort"), permission.get("ToPort")
    ports = str(low) if low == high else f"{low}-{high}"
    return f"{protocol} {ports}"


def _sources(permission: dict) -> list[str]:
    found = [_cidr_words(r.get("CidrIp", "")) for r in permission.get("IpRanges", [])]
    found += [_cidr_words(r.get("CidrIpv6", "")) for r in permission.get("Ipv6Ranges", [])]
    found += [p.get("GroupId", "") for p in permission.get("UserIdGroupPairs", [])]
    found += [p.get("PrefixListId", "") for p in permission.get("PrefixListIds", [])]
    return [source for source in found if source]


def _inbound_text(permissions: list[dict]) -> str:
    parts = [f"{_port_text(p)} from {', '.join(_sources(p)) or 'no source'}" for p in permissions]
    return "; ".join(parts) or "none"


def _add_security_groups(ctx: CollectContext, ids: list[str]) -> None:
    reply = ctx.aws("ec2", "describe-security-groups", ["--group-ids", *ids])
    if reply is None:
        return
    groups = reply.get("SecurityGroups", [])
    if not groups:
        ctx.evidence.add(
            kind=CURRENT, resource="security-group", command=ctx.last_command,
            summary=f"No security group was found for {', '.join(ids)}",
        )
    for group in groups:
        inbound, outbound = group.get("IpPermissions", []), group.get("IpPermissionsEgress", [])
        ctx.evidence.add(
            kind=CURRENT, resource=f"security-group/{group.get('GroupId')}", command=ctx.last_command,
            summary=(
                f"Security group {group.get('GroupId')} ({group.get('GroupName')}) has {len(inbound)} inbound rules "
                f"and {len(outbound)} outbound rules; inbound: {_inbound_text(inbound)}"
            ),
        )


def _add_subnets(ctx: CollectContext, ids: list[str]) -> tuple[str | None, bool]:
    """Add subnet facts; return the VPC id of the first subnet and whether any subnet was found."""
    reply = ctx.aws("ec2", "describe-subnets", ["--subnet-ids", *ids])
    if reply is None:
        return None, True
    subnets = reply.get("Subnets", [])
    if not subnets:
        ctx.evidence.add(
            kind=CURRENT, resource="subnet", command=ctx.last_command,
            summary=f"No subnet was found for {', '.join(ids)}",
        )
        return None, False
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
    return subnets[0].get("VpcId"), True


def _route_target(route: dict) -> str:
    for key in ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "NetworkInterfaceId"):
        if route.get(key):
            return route[key]
    return "no target"


def _add_route_tables(ctx: CollectContext, subnet_ids: list[str]) -> None:
    reply = ctx.aws(
        "ec2", "describe-route-tables", ["--filters", f"Name=association.subnet-id,Values={','.join(subnet_ids)}"],
    )
    for table in (reply or {}).get("RouteTables", []):
        routes = table.get("Routes", [])
        default = next((r for r in routes if r.get("DestinationCidrBlock") == "0.0.0.0/0"), None)
        default_text = f"default route via {_route_target(default)}" if default else "no default route"
        holes = [
            f"{_cidr_words(r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock') or '')} via {_route_target(r)}"
            for r in routes if r.get("State") == "blackhole"
        ]
        holes_text = f"; blackhole routes: {', '.join(holes)}" if holes else ""
        ctx.evidence.add(
            kind=CURRENT, resource=f"route-table/{table.get('RouteTableId')}", command=ctx.last_command,
            summary=f"Route table {table.get('RouteTableId')} has {default_text}{holes_text}",
        )


def _deny_text(entry: dict) -> str:
    direction = "outbound" if entry.get("Egress") else "inbound"
    ports = entry.get("PortRange")
    port_text = f" port {ports.get('From')}-{ports.get('To')}" if ports else ""
    source = _cidr_words(entry.get("CidrBlock") or entry.get("Ipv6CidrBlock") or "any")
    return f"{direction} rule {entry.get('RuleNumber')} deny {entry.get('Protocol')}{port_text} from {source}"


def _add_network_acls(ctx: CollectContext, subnet_ids: list[str]) -> None:
    reply = ctx.aws(
        "ec2", "describe-network-acls", ["--filters", f"Name=association.subnet-id,Values={','.join(subnet_ids)}"],
    )
    for acl in (reply or {}).get("NetworkAcls", []):
        denies = [
            e for e in acl.get("Entries", [])
            if e.get("RuleAction") == "deny" and e.get("RuleNumber") != DEFAULT_ACL_RULE
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
    for gateway in gateways:
        identifier = gateway.get("NatGatewayId", "")
        specs = [
            MetricSpec(f"{metric} {identifier}", "AWS/NATGateway", metric, {"NatGatewayId": identifier}, stat)
            for metric, stat in NAT_METRICS
        ]
        add_metric_facts(ctx, f"nat-gateway/{identifier}", specs)


def _add_endpoints(ctx: CollectContext, vpc_id: str) -> None:
    reply = ctx.aws("ec2", "describe-vpc-endpoints", ["--filters", f"Name=vpc-id,Values={vpc_id}"])
    for endpoint in (reply or {}).get("VpcEndpoints", []):
        if endpoint.get("State") == "available":
            continue
        ctx.evidence.add(
            kind=CURRENT, resource=f"vpc-endpoint/{endpoint.get('VpcEndpointId')}", command=ctx.last_command,
            summary=f"VPC endpoint {endpoint.get('VpcEndpointId')} ({endpoint.get('ServiceName')}) is {endpoint.get('State')}",
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    group_ids = _split(targets.get("security_group_ids"))
    subnet_ids = _split(targets.get("subnet_ids"))
    vpc_id = targets.get("vpc_id") or None
    if not (group_ids or subnet_ids or vpc_id):
        ctx.evidence.add_error(
            "", "MissingTarget", "vpc needs at least one of security_group_ids, subnet_ids, or vpc_id",
        )
        return
    if group_ids:
        _add_security_groups(ctx, group_ids)
    if subnet_ids:
        subnet_vpc, found = _add_subnets(ctx, subnet_ids)
        vpc_id = vpc_id or subnet_vpc
        if found:
            _add_route_tables(ctx, subnet_ids)
            _add_network_acls(ctx, subnet_ids)
    if vpc_id:
        _add_nat_gateways(ctx, vpc_id)
        _add_endpoints(ctx, vpc_id)


COLLECTOR = Collector(
    name="vpc",
    description="Security group rules, subnet free addresses, route tables, network ACL denies, NAT gateways, endpoints",
    required=(),
    optional=("security_group_ids", "subnet_ids", "vpc_id"),
    run=collect,
)
