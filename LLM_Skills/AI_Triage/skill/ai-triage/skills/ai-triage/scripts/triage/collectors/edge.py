"""Edge collector: load balancer, listeners, rules, target health, certificates, DNS record, metrics."""
from __future__ import annotations

from datetime import timedelta

from triage.collectors import Collector
from triage.collectors.common import parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import describe_offset, format_time

MAX_LISTENERS = 5
MAX_TARGET_GROUPS = 10
CERTIFICATE_WARNING = timedelta(days=30)
LOAD_BALANCER_METRICS = (
    ("HTTPCode_ELB_5XX_Count", "Sum"),
    ("HTTPCode_Target_5XX_Count", "Sum"),
    ("TargetResponseTime", "Maximum"),
    ("RequestCount", "Sum"),
    ("RejectedConnectionCount", "Sum"),
    ("TargetConnectionErrorCount", "Sum"),
)
HOST_COUNT_METRICS = (("UnHealthyHostCount", "Maximum"), ("HealthyHostCount", "Minimum"))


def _last_segment(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _describe_load_balancer(ctx: CollectContext, name: str) -> dict | None:
    reply = ctx.aws("elbv2", "describe-load-balancers", ["--names", name])
    if reply is None:
        return None
    balancers = reply.get("LoadBalancers", [])
    if not balancers:
        ctx.evidence.add(
            kind=CURRENT, resource=f"loadbalancer/{name}", command=ctx.last_command,
            summary=f"Load balancer {name} was not found",
        )
        return None
    return balancers[0]


def _add_load_balancer(ctx: CollectContext, resource: str, balancer: dict) -> None:
    zones = ", ".join(zone.get("ZoneName", "") for zone in balancer.get("AvailabilityZones", [])) or "none"
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Load balancer {balancer.get('LoadBalancerName')} is {balancer.get('State', {}).get('Code')}: "
            f"{balancer.get('Scheme')} {balancer.get('Type')}, zones {zones}, DNS name {balancer.get('DNSName')}"
        ),
    )


def _listener_text(listener: dict) -> str:
    return f"Listener {listener.get('Protocol')} {listener.get('Port')}"


def _add_listeners(ctx: CollectContext, resource: str, balancer_arn: str, group_names: dict[str, str]) -> list[str]:
    """Add listener and rule facts; return the ARNs of the certificates the listeners use."""
    reply = ctx.aws("elbv2", "describe-listeners", ["--load-balancer-arn", balancer_arn])
    certificates: list[str] = []
    for listener in (reply or {}).get("Listeners", []):
        arns = [c.get("CertificateArn", "") for c in listener.get("Certificates", [])]
        certificates += [arn for arn in arns if arn and arn not in certificates]
        shown = ", ".join(_last_segment(arn) for arn in arns) or "none"
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"{_listener_text(listener)}, certificate {shown}",
        )
    for listener in (reply or {}).get("Listeners", [])[:MAX_LISTENERS]:
        _add_rules(ctx, resource, listener, group_names)
    return certificates


def _forwarded_groups(rule: dict) -> list[str]:
    arns: list[str] = []
    for action in rule.get("Actions", []):
        arns.append(action.get("TargetGroupArn", ""))
        arns += [g.get("TargetGroupArn", "") for g in action.get("ForwardConfig", {}).get("TargetGroups", [])]
    return [arn for arn in arns if arn]


def _add_rules(ctx: CollectContext, resource: str, listener: dict, group_names: dict[str, str]) -> None:
    reply = ctx.aws("elbv2", "describe-rules", ["--listener-arn", listener.get("ListenerArn", "")])
    if reply is None:
        return
    rules = reply.get("Rules", [])
    names: list[str] = []
    for rule in rules:
        for arn in _forwarded_groups(rule):
            name = group_names.get(arn) or arn.split("/")[1] if "/" in arn else arn
            if name not in names:
                names.append(name)
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=f"{_listener_text(listener)} has {len(rules)} rules forwarding to {', '.join(names) or 'no target group'}",
    )


def _describe_target_groups(ctx: CollectContext, balancer_arn: str) -> list[dict]:
    reply = ctx.aws("elbv2", "describe-target-groups", ["--load-balancer-arn", balancer_arn])
    return (reply or {}).get("TargetGroups", [])


def _add_target_group(ctx: CollectContext, resource: str, group: dict) -> None:
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Target group {group.get('TargetGroupName')} health check path {group.get('HealthCheckPath')} "
            f"on port {group.get('HealthCheckPort')} every {group.get('HealthCheckIntervalSeconds')} seconds, "
            f"healthy threshold {group.get('HealthyThresholdCount')}, unhealthy threshold {group.get('UnhealthyThresholdCount')}"
        ),
    )


def _add_target_health(ctx: CollectContext, resource: str, group: dict) -> None:
    reply = ctx.aws("elbv2", "describe-target-health", ["--target-group-arn", group.get("TargetGroupArn", "")])
    if reply is None:
        return
    descriptions = reply.get("TargetHealthDescriptions", [])
    counts: dict[str, int] = {}
    for description in descriptions:
        state = description.get("TargetHealth", {}).get("State", "unknown")
        counts[state] = counts.get(state, 0) + 1
    shown = ", ".join(f"{count} {state}" for state, count in sorted(counts.items())) or "no registered"
    name = group.get("TargetGroupName")
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command, data={"states": counts},
        summary=f"Target group {name} has {shown} targets",
    )
    for description in descriptions:
        health = description.get("TargetHealth", {})
        if health.get("State") == "healthy":
            continue
        target = description.get("Target", {})
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=(
                f"Target {target.get('Id')}:{target.get('Port')} in target group {name} is {health.get('State')} "
                f"({health.get('Reason')}): {health.get('Description')}"
            ),
        )


def _add_group_attributes(ctx: CollectContext, resource: str, group: dict) -> None:
    reply = ctx.aws("elbv2", "describe-target-group-attributes", ["--target-group-arn", group.get("TargetGroupArn", "")])
    if reply is None:
        return
    values = {a.get("Key"): a.get("Value") for a in reply.get("Attributes", [])}
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Target group {group.get('TargetGroupName')} deregistration delay "
            f"{values.get('deregistration_delay.timeout_seconds')} seconds, "
            f"slow start {values.get('slow_start.duration_seconds')} seconds"
        ),
    )


def _add_certificate(ctx: CollectContext, resource: str, arn: str) -> None:
    reply = ctx.aws("acm", "describe-certificate", ["--certificate-arn", arn])
    certificate = (reply or {}).get("Certificate")
    if not certificate:
        return
    name = f"{_last_segment(arn)}"
    not_after = parse_iso(certificate.get("NotAfter"))
    until = f", valid until {format_time(not_after)}" if not_after else ""
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=f"Certificate {name} ({certificate.get('DomainName') or 'no domain'}) is {certificate.get('Status')}{until}",
    )
    if not_after is None:
        return
    end = ctx.window.end
    offset = describe_offset(not_after, end)
    if not_after <= end:
        text = f"Certificate {name} expired {offset} the window end"
    elif not_after - end <= CERTIFICATE_WARNING:
        text = f"Certificate {name} expires {offset} the window end"
    else:
        return
    ctx.evidence.add(kind=DERIVED, resource=resource, command=ctx.last_command, summary=text)


def _normal_name(name: str) -> str:
    cleaned = name.strip().rstrip(".").lower()
    return cleaned[len("dualstack."):] if cleaned.startswith("dualstack.") else cleaned


def _find_zone(ctx: CollectContext, hostname: str) -> str | None:
    reply = ctx.aws("route53", "list-hosted-zones", ["--max-items", "100"])
    best: tuple[int, str] | None = None
    for zone in (reply or {}).get("HostedZones", []):
        name = _normal_name(zone.get("Name", ""))
        if hostname == name or hostname.endswith("." + name):
            if best is None or len(name) > best[0]:
                best = (len(name), zone.get("Id", "").rsplit("/", 1)[-1])
    if best is None and reply is not None:
        ctx.evidence.add(
            kind=CURRENT, resource=f"dns/{hostname}", command=ctx.last_command,
            summary=f"No hosted zone matches {hostname}",
        )
    return best[1] if best else None


def _record_targets(record: dict) -> list[str]:
    alias = record.get("AliasTarget", {}).get("DNSName")
    if alias:
        return [alias]
    return [r.get("Value", "") for r in record.get("ResourceRecords", [])]


def _add_dns_record(ctx: CollectContext, hostname: str, dns_name: str) -> None:
    zone_id = _find_zone(ctx, hostname)
    if zone_id is None:
        return
    reply = ctx.aws(
        "route53", "list-resource-record-sets",
        ["--hosted-zone-id", zone_id, "--start-record-name", hostname, "--max-items", "5"],
    )
    if reply is None:
        return
    resource = f"dns/{hostname}"
    records = [r for r in reply.get("ResourceRecordSets", []) if _normal_name(r.get("Name", "")) == hostname]
    if not records:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"No record named {hostname} exists in hosted zone {zone_id}",
        )
        return
    for record in records:
        targets = _record_targets(record)
        shown = ", ".join(targets) or "no value"
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"{hostname} is a {record.get('Type')} record pointing at {shown}",
        )
        if not any(_normal_name(target) == _normal_name(dns_name) for target in targets):
            ctx.evidence.add(
                kind=DERIVED, resource=resource, command=ctx.last_command,
                summary=f"{hostname} does not point at this load balancer ({dns_name}); it points at {shown}",
            )


def _add_metrics(ctx: CollectContext, resource: str, balancer: dict, groups: list[dict]) -> None:
    arn = balancer.get("LoadBalancerArn", "")
    suffix = arn.split("loadbalancer/", 1)[-1]
    network = balancer.get("Type") == "network"
    namespace = "AWS/NetworkELB" if network else "AWS/ApplicationELB"
    specs = [] if network else [
        MetricSpec(metric, namespace, metric, {"LoadBalancer": suffix}, stat) for metric, stat in LOAD_BALANCER_METRICS
    ]
    for group in groups[:MAX_TARGET_GROUPS]:
        dimensions = {"TargetGroup": group.get("TargetGroupArn", "").split(":")[-1], "LoadBalancer": suffix}
        specs += [
            MetricSpec(f"{metric} {group.get('TargetGroupName')}", namespace, metric, dimensions, stat)
            for metric, stat in HOST_COUNT_METRICS
        ]
    add_metric_facts(ctx, resource, specs)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["load_balancer"]
    resource = f"loadbalancer/{name}"
    balancer = _describe_load_balancer(ctx, name)
    if balancer is None:
        return
    arn = balancer.get("LoadBalancerArn", "")
    _add_load_balancer(ctx, resource, balancer)
    groups = _describe_target_groups(ctx, arn)
    group_names = {g.get("TargetGroupArn", ""): g.get("TargetGroupName", "") for g in groups}
    certificates = _add_listeners(ctx, resource, arn, group_names)
    for group in groups:
        _add_target_group(ctx, resource, group)
    for group in groups[:MAX_TARGET_GROUPS]:
        _add_target_health(ctx, resource, group)
        _add_group_attributes(ctx, resource, group)
    for certificate in certificates:
        _add_certificate(ctx, resource, certificate)
    if targets.get("hostname"):
        _add_dns_record(ctx, _normal_name(targets["hostname"]), balancer.get("DNSName", ""))
    _add_metrics(ctx, resource, balancer, groups)


COLLECTOR = Collector(
    name="edge",
    description="Load balancer state, listeners, rules, target health, certificate expiry, DNS record, and load balancer metrics",
    required=("load_balancer",),
    optional=("hostname",),
    run=collect,
)
