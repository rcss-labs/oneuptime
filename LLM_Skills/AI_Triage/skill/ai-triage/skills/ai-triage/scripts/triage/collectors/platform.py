"""Platform collector: AWS Health events and which service quotas have usage tracking."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import in_window
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME

DEFAULT_SERVICE_CODES = "ecs,lambda,ec2,rds,elasticloadbalancing"
HEALTH_REGION = "us-east-1"
HEALTH_ITEMS = "30"
QUOTA_ITEMS = "50"
MAX_QUOTAS_LISTED = 10
SUBSCRIPTION_REQUIRED = "SubscriptionRequiredException"


def _add_health(ctx: CollectContext) -> None:
    reply = ctx.aws(
        "health", "describe-events",
        ["--filter", "eventStatusCodes=open,closed,upcoming", "--max-items", HEALTH_ITEMS],
        region=HEALTH_REGION,
    )
    if reply is None:
        if ctx.evidence.errors and ctx.evidence.errors[-1]["code"] == SUBSCRIPTION_REQUIRED:
            ctx.evidence.errors.pop()
            ctx.evidence.add(
                kind=DERIVED, resource="aws-health", command=ctx.last_command,
                summary="AWS Health events are not available: AWS Health needs a Business or Enterprise support plan",
            )
        return
    for event in reply.get("events", []):
        if not (in_window(ctx.window, event.get("startTime")) or event.get("statusCode") == "open"):
            continue
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
    codes = [c.strip() for c in (targets.get("service_codes") or DEFAULT_SERVICE_CODES).split(",") if c.strip()]
    for code in codes:
        _add_quotas(ctx, code)


COLLECTOR = Collector(
    name="platform",
    description="AWS Health events and the service quotas that have usage tracking",
    required=(),
    optional=("service_codes",),
    run=collect,
)
