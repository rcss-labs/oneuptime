"""Platform collector: AWS Health events and which service quotas have usage tracking."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import parse_iso, split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME

DEFAULT_SERVICE_CODES = "ecs,lambda,ec2,rds,elasticloadbalancing"
HEALTH_REGION = "us-east-1"
HEALTH_ITEMS = "100"
MAX_HEALTH_FACTS = 30
QUOTA_ITEMS = "50"
MAX_QUOTAS_LISTED = 10
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


def _add_quotas(ctx: CollectContext, service_code: str) -> None:
    reply = ctx.aws("service-quotas", "list-service-quotas", ["--service-code", service_code, "--max-items", QUOTA_ITEMS])
    tracked = [q for q in (reply or {}).get("Quotas", []) if q.get("UsageMetric")]
    if not tracked:
        return
    listed = ", ".join(f"{q.get('QuotaName')} = {q.get('Value')}" for q in tracked[:MAX_QUOTAS_LISTED])
    ctx.evidence.add(
        kind=CURRENT, resource=f"quotas/{service_code}", command=ctx.last_command,
        summary=f"Service {service_code} has {len(tracked)} quotas with usage tracking, for example: {listed}",
    )


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
