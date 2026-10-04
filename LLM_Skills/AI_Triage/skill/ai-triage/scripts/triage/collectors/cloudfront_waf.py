"""CloudFront and WAF collector: distribution state, edge metrics, web ACL rules, blocked sampled requests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

GLOBAL_REGION = "us-east-1"
NOT_FOUND = ("NoSuchDistribution",)
MAX_SAMPLES = "20"
MAX_BLOCKING_RULES = 5
SAMPLING_HORIZON = timedelta(hours=3)
DISTRIBUTION_METRICS = (
    ("5xxErrorRate", "Average"), ("4xxErrorRate", "Average"), ("Requests", "Sum"), ("OriginLatency", "Maximum"),
)


def _add_distribution(ctx: CollectContext, distribution_id: str) -> str | None:
    """Add the distribution facts; return the ARN of its WAFv2 web ACL, if it has one."""
    resource = f"cloudfront/{distribution_id}"
    reply = ctx.aws("cloudfront", "get-distribution", ["--id", distribution_id], region=GLOBAL_REGION, not_found=NOT_FOUND)
    if reply is None:
        if was_not_found(ctx, NOT_FOUND):
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=f"Distribution {distribution_id} was not found",
            )
        return None
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
    # WebACLId holds a WAFv2 ARN, or the id of a classic WAF web ACL, which this collector does not read.
    acl = config.get("WebACLId") or ""
    return acl if acl.startswith("arn:") and ":wafv2:" in acl else None


def _add_metrics(ctx: CollectContext, resource: str, distribution_id: str) -> None:
    dimensions = {"DistributionId": distribution_id, "Region": "Global"}
    specs = [MetricSpec(metric, "AWS/CloudFront", metric, dimensions, stat) for metric, stat in DISTRIBUTION_METRICS]
    add_metric_facts(ctx, resource, specs, region=GLOBAL_REGION)


def _acl_parts(arn: str) -> tuple[str, str, str, str] | None:
    """Return (name, id, scope, region) from a web ACL ARN, or None when it is malformed."""
    fields = arn.split(":", 5)
    parts = fields[-1].split("/")
    if len(fields) < 6 or len(parts) < 4 or parts[1] != "webacl":
        return None
    scope = "CLOUDFRONT" if ":global/" in arn else "REGIONAL"
    return parts[2], parts[3], scope, GLOBAL_REGION if scope == "CLOUDFRONT" else fields[3]


def _action_text(rule: dict) -> str:
    if rule.get("Action"):
        return f"action {next(iter(rule['Action'])).lower()}"
    if rule.get("OverrideAction"):
        return f"override action {next(iter(rule['OverrideAction'])).lower()} (rule group)"
    return "no action"


def _add_web_acl(ctx: CollectContext, arn: str, now: datetime) -> None:
    parts = _acl_parts(arn)
    if parts is None:
        ctx.evidence.add_error("", "BadTarget", "the web ACL ARN could not be read")
        return
    name, acl_id, scope, region = parts
    reply = ctx.aws("wafv2", "get-web-acl", ["--name", name, "--scope", scope, "--id", acl_id], region=region)
    acl = (reply or {}).get("WebACL")
    if not acl:
        return
    resource = f"web-acl/{name}"
    default = next(iter(acl.get("DefaultAction", {})), "unknown").lower()
    rules = acl.get("Rules", [])
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=f"Web ACL {name} ({scope}) default action {default}, {len(rules)} rules",
    )
    for rule in rules:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Rule {rule.get('Name')} priority {rule.get('Priority')} {_action_text(rule)}",
        )
    # Sampling by a rule's own metric name is the only way to know which rule blocked a request.
    targets = [
        (f"rule {r.get('Name')}", r.get("VisibilityConfig", {}).get("MetricName"))
        for r in rules if "Block" in (r.get("Action") or {})
    ][:MAX_BLOCKING_RULES]
    if default == "block":
        targets.append(("the default action", acl.get("VisibilityConfig", {}).get("MetricName")))
    targets = [(label, metric) for label, metric in targets if metric]
    if not targets:
        return
    if now - ctx.window.end > SAMPLING_HORIZON:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary=(
                f"Blocked requests of web ACL {name} were not sampled: WAF keeps sampled requests for "
                "only the last three hours, and the window ended before that"
            ),
        )
        return
    for label, metric in targets:
        _add_blocked_requests(ctx, resource, arn, scope, region, metric, label)


def _add_blocked_requests(
    ctx: CollectContext, resource: str, arn: str, scope: str, region: str, metric: str, label: str
) -> None:
    window = f"StartTime={format_time(ctx.window.start)},EndTime={format_time(ctx.window.end)}"
    reply = ctx.aws(
        "wafv2", "get-sampled-requests",
        ["--web-acl-arn", arn, "--rule-metric-name", metric, "--scope", scope,
         "--time-window", window, "--max-items", MAX_SAMPLES],
        region=region,
    )
    if reply is None:
        return
    covered = reply.get("TimeWindow") or {}
    start, end = parse_iso(covered.get("StartTime")), parse_iso(covered.get("EndTime"))
    period = f"{format_time(start)} to {format_time(end)}" if start and end else "an unreported period"
    ctx.evidence.add(
        kind=DERIVED, resource=resource, command=ctx.last_command,
        summary=(
            f"Sampling for {label} covered {period} and saw {reply.get('PopulationSize')} requests; "
            "WAF samples only the first 5,000 requests of the period"
        ),
    )
    blocked = [s for s in reply.get("SampledRequests", []) if s.get("Action") == "BLOCK"]
    for sampled in blocked[: int(MAX_SAMPLES)]:
        request = sampled.get("Request", {})
        # Only the path and country are read; headers and the client address are never copied.
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=sampled.get("Timestamp"), command=ctx.last_command,
            summary=f"Request blocked by {label}: {request.get('URI')} from country {request.get('Country')}",
        )


def _resource_acl(ctx: CollectContext, resource_arn: str) -> str | None:
    region = resource_arn.split(":")[3] or ctx.region
    reply = ctx.aws("wafv2", "get-web-acl-for-resource", ["--resource-arn", resource_arn], region=region)
    if reply is None:
        return None
    found = (reply.get("WebACL") or {}).get("ARN")
    if not found:
        ctx.evidence.add(
            kind=CURRENT, resource=f"web-acl-for/{resource_arn}", command=ctx.last_command,
            summary=f"No web ACL is associated with {resource_arn}",
        )
    return found


def _distribution_ids(targets: dict[str, str]) -> list[str]:
    ids = [targets["distribution_id"]] if targets.get("distribution_id") else []
    resource_arn = targets.get("resource_arn") or ""
    if ":cloudfront:" in resource_arn:
        ids.append(resource_arn.rsplit("/", 1)[-1])
    return list(dict.fromkeys(ids))


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    now = getattr(ctx, "now", None) or datetime.now(timezone.utc)
    arns = [targets["web_acl_arn"]] if targets.get("web_acl_arn") else []
    for distribution_id in _distribution_ids(targets):
        arns.append(_add_distribution(ctx, distribution_id))
    resource_arn = targets.get("resource_arn") or ""
    if resource_arn and ":cloudfront:" not in resource_arn:
        arns.append(_resource_acl(ctx, resource_arn))
    for arn in dict.fromkeys(a for a in arns if a):
        _add_web_acl(ctx, arn, now)


COLLECTOR = Collector(
    name="cloudfront_waf",
    description="CloudFront distribution state and edge errors, plus WAF web ACL rules and blocked sampled requests",
    required=(),
    optional=("distribution_id", "web_acl_arn", "resource_arn"),
    run=collect,
    one_of=("distribution_id", "web_acl_arn", "resource_arn"),
)
