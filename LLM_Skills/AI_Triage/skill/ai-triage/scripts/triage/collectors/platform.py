"""Platform collector: AWS Health events for this region, and service quota limits with their peak usage."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import parse_iso, split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, MetricSummary, fetch

DEFAULT_SERVICE_CODES = "ecs,lambda,ec2,rds,elasticloadbalancing"
HEALTH_REGION = "us-east-1"
HEALTH_ITEMS = "100"
MAX_HEALTH_FACTS = 30
QUOTA_ITEMS = "50"
MAX_QUOTAS_LISTED = 10
NEAR_LIMIT_SHARE = 0.8
SUMMARY_BUDGET = 440  # evidence summaries are cut at 500 characters
DEFAULT_STATISTIC = "Maximum"
SUBSCRIPTION_REQUIRED = "SubscriptionRequiredException"


def _overlaps_window(ctx: CollectContext, event: dict) -> bool:
    """Started before the window end, and either still open or ended after the window start."""
    started = parse_iso(event.get("startTime"))
    if started is None or started > ctx.window.end:
        return False
    if event.get("statusCode") == "open":
        return True
    ended = parse_iso(event.get("endTime"))
    return ended is not None and ended >= ctx.window.start


def _is_for_region(ctx: CollectContext, event: dict) -> bool:
    """The event is in the collection's region or is global."""
    return (event.get("region") or "global") in (ctx.region, "global")


def _add_health(ctx: CollectContext) -> None:
    reply = ctx.aws(
        "health", "describe-events",
        ["--filter", "eventStatusCodes=open,closed,upcoming", "--max-items", HEALTH_ITEMS],
        region=HEALTH_REGION, not_found=(SUBSCRIPTION_REQUIRED,),
    )
    if reply is None:
        if was_not_found(ctx, (SUBSCRIPTION_REQUIRED,)):
            ctx.evidence.add(
                kind=DERIVED, resource="aws-health", command=ctx.last_command,
                summary="AWS Health events are not available: AWS Health needs a Business or Enterprise support plan",
            )
        return
    overlapping = [e for e in reply.get("events", []) if _overlaps_window(ctx, e)]
    here = [e for e in overlapping if _is_for_region(ctx, e)]
    if len(here) < len(overlapping):
        ctx.evidence.add(
            kind=DERIVED, resource="aws-health", command=ctx.last_command,
            summary=f"{len(overlapping) - len(here)} events in other regions were left out",
        )
    for event in here[:MAX_HEALTH_FACTS]:
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"health/{event.get('service')}", time=event.get("startTime"),
            command=ctx.last_command,
            summary=(
                f"AWS Health event for {event.get('service')} in {event.get('region')}: "
                f"{event.get('eventTypeCode')}, category {event.get('eventTypeCategory')}, status {event.get('statusCode')}"
            ),
        )


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.3g}"


def _usage_spec(quota: dict) -> MetricSpec:
    usage = quota["UsageMetric"]
    return MetricSpec(
        quota.get("QuotaName", ""), usage.get("MetricNamespace", ""), usage.get("MetricName", ""),
        dict(usage.get("MetricDimensions") or {}), usage.get("MetricStatisticRecommendation") or DEFAULT_STATISTIC,
    )


def _quota_text(quota: dict, summary: MetricSummary) -> str:
    limit = quota.get("Value")
    head = f"{quota.get('QuotaName')}: limit {_number(limit)}"
    if summary.window_max is None:
        return f"{head}, usage could not be read"
    if not limit:
        return f"{head}, peak {_number(summary.window_max)}"
    return f"{head}, peak {_number(summary.window_max)} ({_number(summary.window_max / limit * 100)}% of the limit)"


def _share(quota: dict, summary: MetricSummary) -> float:
    """Peak usage as a share of the limit; -1 when it cannot be computed, so those sort last."""
    limit = quota.get("Value")
    if summary.window_max is None or not limit:
        return -1.0
    return summary.window_max / limit


def _add_near_limit(ctx: CollectContext, service_code: str, quota: dict, summary: MetricSummary) -> None:
    limit = quota.get("Value")
    if summary.window_max is None or not limit or summary.window_max / limit < NEAR_LIMIT_SHARE:
        return
    ctx.evidence.add(
        kind=INCIDENT_TIME, resource=f"quotas/{service_code}", time=summary.peak_time, command=ctx.last_command,
        summary=(
            f"Quota {quota.get('QuotaName')} of service {service_code} reached "
            f"{_number(summary.window_max / limit * 100)}% of its limit: peak {_number(summary.window_max)} "
            f"of {_number(limit)} at {summary.peak_time}"
        ),
    )


def _add_quotas(ctx: CollectContext, service_code: str) -> None:
    reply = ctx.aws("service-quotas", "list-service-quotas", ["--service-code", service_code, "--max-items", QUOTA_ITEMS])
    command = ctx.last_command
    tracked = [q for q in (reply or {}).get("Quotas", []) if q.get("UsageMetric")]
    if not tracked:
        return
    read = tracked[:MAX_QUOTAS_LISTED]
    summaries = fetch(ctx, [_usage_spec(q) for q in read])
    pairs = sorted(zip(read, summaries), key=lambda pair: -_share(*pair))
    skipped = len(tracked) - len(read)
    head = f"Service {service_code} has {len(tracked)} quotas with usage tracking"
    head += f"; {skipped} more tracked quotas were not read. " if skipped else ". "
    texts, used = [], len(head)
    for quota, summary in pairs:
        text = _quota_text(quota, summary)
        if used + len(text) + 2 > SUMMARY_BUDGET:
            texts.append(f"{len(pairs) - len(texts)} more are in the data")
            break
        texts.append(text)
        used += len(text) + 2
    ctx.evidence.add(
        kind=CURRENT, resource=f"quotas/{service_code}", command=command,
        summary=head + "; ".join(texts),
        data={"quotas": [
            {"name": q.get("QuotaName"), "limit": q.get("Value"), "peak": m.window_max, "peak_time": m.peak_time}
            for q, m in pairs
        ]},
    )
    for quota, summary in zip(read, summaries):
        _add_near_limit(ctx, service_code, quota, summary)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    _add_health(ctx)
    codes = split_csv(targets.get("service_codes") or DEFAULT_SERVICE_CODES)
    for code in codes:
        _add_quotas(ctx, code)


COLLECTOR = Collector(
    name="platform",
    description="AWS Health events and the service quotas that have usage tracking",
    required=(),
    optional=("service_codes",),
    run=collect,
)
