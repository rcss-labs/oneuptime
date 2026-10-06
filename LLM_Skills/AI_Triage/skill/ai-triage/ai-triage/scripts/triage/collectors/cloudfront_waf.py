"""CloudFront and WAF collector: distribution state, edge metrics, web ACL rules, blocked sampled requests."""
from __future__ import annotations

from dataclasses import replace

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

GLOBAL_REGION = "us-east-1"
NOT_FOUND = "NoSuchDistribution"
MAX_SAMPLES = "20"
DISTRIBUTION_METRICS = (
    ("5xxErrorRate", "Average"), ("4xxErrorRate", "Average"), ("Requests", "Sum"), ("OriginLatency", "Maximum"),
)


def _add_distribution(ctx: CollectContext, distribution_id: str) -> None:
    resource = f"cloudfront/{distribution_id}"
    errors_before = len(ctx.evidence.errors)
    reply = ctx.aws("cloudfront", "get-distribution", ["--id", distribution_id], region=GLOBAL_REGION)
    if reply is None:
        if len(ctx.evidence.errors) > errors_before and ctx.evidence.errors[-1]["code"] == NOT_FOUND:
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=f"Distribution {distribution_id} was not found",
            )
        return
    found = reply.get("Distribution", {})
    config = found.get("DistributionConfig", {})
    domains = [found.get("DomainName", "")] + config.get("Aliases", {}).get("Items", [])
    origins = ", ".join(
        f"{o.get('Id')} ({o.get('DomainName')})" for o in config.get("Origins", {}).get("Items", [])
    ) or "none"
    modified = parse_iso(found.get("LastModifiedTime"))
    when = f", last modified {format_time(modified)}" if modified else ""
    inside = " and was modified inside the window" if in_window(ctx.window, found.get("LastModifiedTime")) else ""
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Distribution {distribution_id} is {found.get('Status')}{when}{inside}; "
            f"domain names {', '.join(d for d in domains if d)}; origins {origins}; "
            f"default cache behavior sends requests to origin {config.get('DefaultCacheBehavior', {}).get('TargetOriginId')}"
        ),
    )
    _add_metrics(ctx, resource, distribution_id)


def _add_metrics(ctx: CollectContext, resource: str, distribution_id: str) -> None:
    """CloudFront publishes its metrics in us-east-1 only; the helper takes the region from the context."""
    edge_ctx = replace(ctx, region=GLOBAL_REGION)
    dimensions = {"DistributionId": distribution_id, "Region": "Global"}
    specs = [MetricSpec(metric, "AWS/CloudFront", metric, dimensions, stat) for metric, stat in DISTRIBUTION_METRICS]
    add_metric_facts(edge_ctx, resource, specs)
    ctx.last_command = edge_ctx.last_command


def _acl_parts(arn: str) -> tuple[str, str, str] | None:
    """Return (name, id, scope) from a web ACL ARN, or None when it is malformed."""
    parts = arn.split(":", 5)[-1].split("/")
    if len(parts) < 4 or parts[1] != "webacl":
        return None
    return parts[2], parts[3], "CLOUDFRONT" if ":global/" in arn else "REGIONAL"


def _action_text(rule: dict) -> str:
    if rule.get("Action"):
        return f"action {next(iter(rule['Action'])).lower()}"
    if rule.get("OverrideAction"):
        return f"override action {next(iter(rule['OverrideAction'])).lower()} (rule group)"
    return "no action"


def _add_web_acl(ctx: CollectContext, arn: str) -> None:
    parts = _acl_parts(arn)
    if parts is None:
        ctx.evidence.add_error("", "BadTarget", "the web ACL ARN could not be read")
        return
    name, acl_id, scope = parts
    region = GLOBAL_REGION if scope == "CLOUDFRONT" else ctx.region
    reply = ctx.aws("wafv2", "get-web-acl", ["--name", name, "--scope", scope, "--id", acl_id], region=region)
    acl = (reply or {}).get("WebACL")
    if not acl:
        return
    resource = f"web-acl/{name}"
    default = next(iter(acl.get("DefaultAction", {})), "unknown").lower()
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=f"Web ACL {name} ({scope}) default action {default}, {len(acl.get('Rules', []))} rules",
    )
    for rule in acl.get("Rules", []):
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Rule {rule.get('Name')} priority {rule.get('Priority')} {_action_text(rule)}",
        )
    metric = acl.get("VisibilityConfig", {}).get("MetricName")
    if metric:
        _add_blocked_requests(ctx, resource, arn, scope, region, metric)


def _add_blocked_requests(ctx: CollectContext, resource: str, arn: str, scope: str, region: str, metric: str) -> None:
    window = f"StartTime={format_time(ctx.window.start)},EndTime={format_time(ctx.window.end)}"
    reply = ctx.aws(
        "wafv2", "get-sampled-requests",
        ["--web-acl-arn", arn, "--rule-metric-name", metric, "--scope", scope,
         "--time-window", window, "--max-items", MAX_SAMPLES],
        region=region,
    )
    blocked = [s for s in (reply or {}).get("SampledRequests", []) if s.get("Action") == "BLOCK"]
    for sampled in blocked[: int(MAX_SAMPLES)]:
        request = sampled.get("Request", {})
        # Only the path, country, and rule are read; headers and the client address are never copied.
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=sampled.get("Timestamp"), command=ctx.last_command,
            summary=(
                f"Request blocked by rule {sampled.get('RuleNameWithinRuleGroup') or 'default action'}: "
                f"{request.get('URI')} from country {request.get('Country')}"
            ),
        )


def _acl_arns(ctx: CollectContext, targets: dict[str, str]) -> list[str]:
    arns = [targets["web_acl_arn"]] if targets.get("web_acl_arn") else []
    resource_arn = targets.get("resource_arn")
    if resource_arn:
        reply = ctx.aws("wafv2", "get-web-acl-for-resource", ["--resource-arn", resource_arn])
        if reply is not None:
            found = (reply.get("WebACL") or {}).get("ARN")
            if found:
                arns.append(found)
            else:
                ctx.evidence.add(
                    kind=CURRENT, resource=f"web-acl-for/{resource_arn}", command=ctx.last_command,
                    summary=f"No web ACL is associated with {resource_arn}",
                )
    return list(dict.fromkeys(arns))


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    if not any(targets.get(key) for key in ("distribution_id", "web_acl_arn", "resource_arn")):
        ctx.evidence.add_error(
            "", "MissingTarget", "cloudfront_waf needs at least one of distribution_id, web_acl_arn, or resource_arn",
        )
        return
    if targets.get("distribution_id"):
        _add_distribution(ctx, targets["distribution_id"])
    for arn in _acl_arns(ctx, targets):
        _add_web_acl(ctx, arn)


COLLECTOR = Collector(
    name="cloudfront_waf",
    description="CloudFront distribution state and edge errors, plus WAF web ACL rules and blocked sampled requests",
    required=(),
    optional=("distribution_id", "web_acl_arn", "resource_arn"),
    run=collect,
)
