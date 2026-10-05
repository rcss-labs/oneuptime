"""Edge collector: load balancer, listeners, rules, target health, certificates, DNS record, metrics."""
from __future__ import annotations

from datetime import timedelta

from triage.collectors import Collector
from triage.collectors.common import parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import describe_offset, format_time

MAX_LISTENERS = 5
MAX_LISTENER_FACTS = 20
MAX_CERTIFICATES = 20
MAX_TARGET_GROUPS = 10
MAX_UNHEALTHY_FACTS = 20
LOAD_BALANCER_NOT_FOUND = ("LoadBalancerNotFound",)
ADDRESS_RECORD_TYPES = ("A", "AAAA", "CNAME")
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
    reply = ctx.aws("elbv2", "describe-load-balancers", ["--names", name], not_found=LOAD_BALANCER_NOT_FOUND)
    if reply is None and not was_not_found(ctx, LOAD_BALANCER_NOT_FOUND):
        return None
    balancers = (reply or {}).get("LoadBalancers", [])
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


def _add_listeners(
    ctx: CollectContext, resource: str, balancer_arn: str, group_names: dict[str, str]
) -> tuple[list[str], str]:
    """Add listener and rule facts; return the ACM certificate ARNs the listeners use and the listing command."""
    reply = ctx.aws("elbv2", "describe-listeners", ["--load-balancer-arn", balancer_arn])
    command = ctx.last_command
    listeners = (reply or {}).get("Listeners", [])
    certificates: list[str] = []
    for listener in listeners:
        arns = [c.get("CertificateArn", "") for c in listener.get("Certificates", [])]
        # IAM server certificates are not ACM certificates and acm describe-certificate rejects them.
        certificates += [arn for arn in arns if ":acm:" in arn and arn not in certificates]
    for listener in listeners[:MAX_LISTENER_FACTS]:
        arns = [c.get("CertificateArn", "") for c in listener.get("Certificates", [])]
        shown = ", ".join(_last_segment(arn) for arn in arns) or "none"
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=command,
            summary=f"{_listener_text(listener)}, certificate {shown}",
        )
    if len(listeners) > MAX_LISTENER_FACTS:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=command,
            summary=f"{len(listeners) - MAX_LISTENER_FACTS} listeners were not listed ({len(listeners)} exist)",
        )
    for listener in listeners[:MAX_LISTENERS]:
        _add_rules(ctx, resource, listener, group_names)
    return certificates, command


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
            name = (group_names.get(arn) or arn.split("/")[1]) if "/" in arn else arn
            if name not in names:
                names.append(name)
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=f"{_listener_text(listener)} has {len(rules)} rules forwarding to {', '.join(names) or 'no target group'}",
    )


def _describe_target_groups(ctx: CollectContext, balancer_arn: str) -> list[dict]:
    reply = ctx.aws("elbv2", "describe-target-groups", ["--load-balancer-arn", balancer_arn])
    return (reply or {}).get("TargetGroups", [])


def _add_target_group(ctx: CollectContext, resource: str, group: dict, command: str) -> None:
    pieces = []
    if group.get("HealthCheckPath"):
        pieces.append(f"path {group['HealthCheckPath']}")
    if group.get("HealthCheckPort"):
        pieces.append(f"on port {group['HealthCheckPort']}")
    if group.get("HealthCheckIntervalSeconds") is not None:
        pieces.append(f"every {group['HealthCheckIntervalSeconds']} seconds")
    thresholds = [
        f"{label} threshold {group[key]}"
        for label, key in (("healthy", "HealthyThresholdCount"), ("unhealthy", "UnhealthyThresholdCount"))
        if group.get(key) is not None
    ]
    detail = ", ".join(part for part in (" ".join(pieces), ", ".join(thresholds)) if part)
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=command,
        summary=f"Target group {group.get('TargetGroupName')} health check {detail or 'settings are not reported'}",
    )


def _add_target_health(
    ctx: CollectContext, resource: str, group: dict, unhealthy: list[tuple[str, str]]
) -> None:
    """Add the count fact; collect the unhealthy targets as (summary, command) so the caller can cap them."""
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
        unhealthy.append((
            f"Target {target.get('Id')}:{target.get('Port')} in target group {name} is {health.get('State')} "
            f"({health.get('Reason')}): {health.get('Description')}",
            ctx.last_command,
        ))


def _add_unhealthy_targets(ctx: CollectContext, resource: str, unhealthy: list[tuple[str, str]]) -> None:
    for summary, command in unhealthy[:MAX_UNHEALTHY_FACTS]:
        ctx.evidence.add(kind=CURRENT, resource=resource, command=command, summary=summary)
    if len(unhealthy) > MAX_UNHEALTHY_FACTS:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=unhealthy[0][1],
            summary=(
                f"{len(unhealthy)} targets are unhealthy in total; "
                f"only the first {MAX_UNHEALTHY_FACTS} are listed"
            ),
        )


def _add_group_attributes(ctx: CollectContext, resource: str, group: dict) -> None:
    reply = ctx.aws("elbv2", "describe-target-group-attributes", ["--target-group-arn", group.get("TargetGroupArn", "")])
    if reply is None:
        return
    values = {a.get("Key"): a.get("Value") for a in reply.get("Attributes", [])}
    pieces = [
        f"{label} {values[key]} seconds"
        for label, key in (
            ("deregistration delay", "deregistration_delay.timeout_seconds"),
            ("slow start", "slow_start.duration_seconds"),
        )
        if values.get(key) is not None
    ]
    if not pieces:
        return
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=f"Target group {group.get('TargetGroupName')} {', '.join(pieces)}",
    )


def _soonest_first(ctx: CollectContext, certificates: list[str]) -> list[str]:
    """Order the certificates by expiry using one list call; certificates it does not know about go last."""
    reply = ctx.aws("acm", "list-certificates", ["--max-items", "1000"])
    if reply is None:
        return certificates
    expiry = {
        c.get("CertificateArn"): parse_iso(c.get("NotAfter")) for c in reply.get("CertificateSummaryList", [])
    }
    known = [arn for arn in certificates if expiry.get(arn) is not None]
    unknown = [arn for arn in certificates if expiry.get(arn) is None]
    return sorted(known, key=lambda arn: expiry[arn]) + unknown


def _add_certificate(ctx: CollectContext, resource: str, arn: str) -> None:
    reply = ctx.aws("acm", "describe-certificate", ["--certificate-arn", arn])
    certificate = (reply or {}).get("Certificate")
    if not certificate:
        return
    name = f"{_last_segment(arn)}"
    not_after = parse_iso(certificate.get("NotAfter"))
    until = f", valid until {format_time(not_after)}" if not_after else ""
    # The status is read now but names the expiry time; the expiry fact below is an incident fact when it
    # falls inside the window.
    kind = INCIDENT_TIME if not_after and ctx.window.contains(not_after) else CURRENT
    ctx.evidence.add(
        kind=CURRENT, resource=resource, time=not_after, command=ctx.last_command,
        summary=f"Certificate {name} ({certificate.get('DomainName') or 'no domain'}) is {certificate.get('Status')}{until}",
    )
    if not_after is None:
        return
    when = f"{format_time(not_after)}, {describe_offset(not_after, ctx.window.start)} the window start"
    if ctx.window.contains(not_after):
        text = f"Certificate {name} expired at {format_time(not_after)}, inside the incident window, " \
               f"{describe_offset(not_after, ctx.window.start)} the window start"
    elif not_after <= ctx.window.end:
        text = f"Certificate {name} expired at {when}"
    elif not_after - ctx.window.end <= CERTIFICATE_WARNING:
        text = f"Certificate {name} expires at {when}"
    else:
        return
    ctx.evidence.add(kind=kind, resource=resource, time=not_after, command=ctx.last_command, summary=text)


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
    records = [
        r for r in reply.get("ResourceRecordSets", [])
        if _normal_name(r.get("Name", "")) == hostname and r.get("Type") in ADDRESS_RECORD_TYPES
    ]
    if not records:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=(
                f"No A, AAAA, or CNAME record named {hostname} exists in hosted zone {zone_id} "
                "(a wildcard record may apply)"
            ),
        )
        return
    for record in records:
        if any(_normal_name(target) == _normal_name(dns_name) for target in _record_targets(record)):
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=(
                    f"{hostname} has {'a' if record.get('Type') == 'CNAME' else 'an'} {record.get('Type')} record "
                    f"pointing at {dns_name}, this load balancer"
                ),
            )
            return
    shown = "; ".join(f"{r.get('Type')} record to {', '.join(_record_targets(r)) or 'no value'}" for r in records)
    ctx.evidence.add(
        kind=DERIVED, resource=resource, command=ctx.last_command,
        summary=f"{hostname} does not point at this load balancer ({dns_name}); its records point at: {shown}",
    )


def _add_metrics(ctx: CollectContext, resource: str, balancer: dict, groups: list[dict]) -> None:
    arn = balancer.get("LoadBalancerArn", "")
    suffix = arn.split("loadbalancer/", 1)[-1]
    kind = balancer.get("Type")
    namespace = {"network": "AWS/NetworkELB", "gateway": "AWS/GatewayELB"}.get(kind, "AWS/ApplicationELB")
    specs = [] if kind in ("network", "gateway") else [
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
    groups_command = ctx.last_command
    group_names = {g.get("TargetGroupArn", ""): g.get("TargetGroupName", "") for g in groups}
    certificates, listeners_command = _add_listeners(ctx, resource, arn, group_names)
    listed = groups[:MAX_TARGET_GROUPS]
    for group in listed:
        _add_target_group(ctx, resource, group, groups_command)
    if len(groups) > len(listed):
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=groups_command,
            summary=f"{len(groups)} target groups exist; only the first {MAX_TARGET_GROUPS} were read",
        )
    unhealthy: list[tuple[str, str]] = []
    for group in listed:
        _add_target_health(ctx, resource, group, unhealthy)
        _add_group_attributes(ctx, resource, group)
    _add_unhealthy_targets(ctx, resource, unhealthy)
    if len(certificates) > MAX_CERTIFICATES:
        certificates = _soonest_first(ctx, certificates)
    for certificate in certificates[:MAX_CERTIFICATES]:
        _add_certificate(ctx, resource, certificate)
    if len(certificates) > MAX_CERTIFICATES:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=listeners_command,
            summary=f"{len(certificates) - MAX_CERTIFICATES} certificates were not checked ({len(certificates)} are in use)",
        )
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
