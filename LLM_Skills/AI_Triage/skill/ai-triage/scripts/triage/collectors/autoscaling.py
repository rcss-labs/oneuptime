"""EC2 Auto Scaling collector: group state, scaling activities, instance refreshes, and ECS service scaling."""
from __future__ import annotations

from triage.collectors import Collector
from triage.collectors.common import in_window, newest_in_window, parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, INCIDENT_TIME

MAX_ACTIVITIES = "30"
MAX_REFRESHES = "5"
ACTIVE_REFRESH_STATES = frozenset({"Pending", "InProgress", "Cancelling", "RollbackInProgress"})


def _add_group_state(ctx: CollectContext, resource: str, group: dict) -> None:
    instances = group.get("Instances", [])
    not_ok = [
        i for i in instances
        if i.get("HealthStatus") != "Healthy" or i.get("LifecycleState") != "InService"
    ]
    health = f"; {len(not_ok)} of {len(instances)} instances are not healthy and in service" if not_ok else ""
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Group {group.get('AutoScalingGroupName')}: min {group.get('MinSize')}, max {group.get('MaxSize')}, "
            f"desired {group.get('DesiredCapacity')}, {len(instances)} instances, "
            f"health check {group.get('HealthCheckType')}, grace period {group.get('HealthCheckGracePeriod')} s{health}"
        ),
        data={key: group.get(key) for key in ("MinSize", "MaxSize", "DesiredCapacity")},
    )


def _add_activities(ctx: CollectContext, resource: str, name: str) -> None:
    reply = ctx.aws("autoscaling", "describe-scaling-activities", ["--auto-scaling-group-name", name, "--max-items", MAX_ACTIVITIES])
    activities = newest_in_window(ctx.window, (reply or {}).get("Activities", []), lambda a: a.get("StartTime"), int(MAX_ACTIVITIES))
    for activity in activities:
        code = activity.get("StatusCode")
        if code == "Failed":
            message = f"; status message: {activity['StatusMessage']}" if activity.get("StatusMessage") else ""
            summary = f"FAILED scaling activity: {activity.get('Description')}{message}"
        else:
            summary = f"Scaling activity {code}: {activity.get('Description')}"
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=activity.get("StartTime"), command=ctx.last_command,
            summary=summary, excerpt=activity.get("Cause") or "",
        )


def _add_refreshes(ctx: CollectContext, resource: str, name: str) -> None:
    # describe-instance-refreshes is not paginated by the CLI, so the limit is --max-records.
    reply = ctx.aws("autoscaling", "describe-instance-refreshes", ["--auto-scaling-group-name", name, "--max-records", MAX_REFRESHES])
    for refresh in (reply or {}).get("InstanceRefreshes", []):
        started = parse_iso(refresh.get("StartTime"))
        ended = parse_iso(refresh.get("EndTime"))
        active = refresh.get("Status") in ACTIVE_REFRESH_STATES
        # Report a refresh whose period [start, end or still running] overlaps the window.
        if started is None or started > ctx.window.end or (not active and ended is not None and ended < ctx.window.start):
            continue
        status_note = " (status now)" if active else ""
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=refresh.get("StartTime"), command=ctx.last_command,
            summary=(
                f"Instance refresh {refresh.get('InstanceRefreshId')} {refresh.get('Status')}{status_note}, "
                f"{refresh.get('PercentageComplete')}% complete, {refresh.get('InstancesToUpdate')} instances to update"
            ),
            excerpt=refresh.get("StatusReason") or "",
        )


def _suspended_text(state: dict) -> str:
    parts = [
        label for key, label in (
            ("DynamicScalingInSuspended", "scale-in suspended"),
            ("DynamicScalingOutSuspended", "scale-out suspended"),
            ("ScheduledScalingSuspended", "scheduled scaling suspended"),
        ) if state.get(key)
    ]
    return f"; {', '.join(parts)}" if parts else ""


def _policy_text(policy: dict) -> str:
    tracking = policy.get("TargetTrackingScalingPolicyConfiguration") or {}
    if not tracking:
        return ""
    metric = (tracking.get("PredefinedMetricSpecification") or {}).get("PredefinedMetricType") \
        or (tracking.get("CustomizedMetricSpecification") or {}).get("MetricName")
    return f"; target {tracking.get('TargetValue')} on {metric}"


def _add_ecs_scaling(ctx: CollectContext, cluster: str, service: str) -> None:
    resource_id = f"service/{cluster}/{service}"
    targets = ctx.aws(
        "application-autoscaling", "describe-scalable-targets",
        ["--service-namespace", "ecs", "--resource-ids", resource_id],
    )
    for target in (targets or {}).get("ScalableTargets", []):
        ctx.evidence.add(
            kind=CURRENT, resource=resource_id, command=ctx.last_command,
            summary=(
                f"Scalable target {target.get('ResourceId')}: min {target.get('MinCapacity')}, "
                f"max {target.get('MaxCapacity')}{_suspended_text(target.get('SuspendedState') or {})}"
            ),
        )
    policies = ctx.aws(
        "application-autoscaling", "describe-scaling-policies",
        ["--service-namespace", "ecs", "--resource-id", resource_id],
    )
    for policy in (policies or {}).get("ScalingPolicies", []):
        ctx.evidence.add(
            kind=CURRENT, resource=resource_id, command=ctx.last_command,
            summary=f"Scaling policy {policy.get('PolicyName')} ({policy.get('PolicyType')}){_policy_text(policy)}",
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["group"]
    resource = f"autoscaling-group/{name}"
    reply = ctx.aws("autoscaling", "describe-auto-scaling-groups", ["--auto-scaling-group-names", name])
    if reply is None:
        return
    groups = reply.get("AutoScalingGroups", [])
    if not groups:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Auto Scaling group {name} was not found",
        )
        return
    _add_group_state(ctx, resource, groups[0])
    _add_activities(ctx, resource, name)
    _add_refreshes(ctx, resource, name)
    if targets.get("ecs_cluster") and targets.get("ecs_service"):
        _add_ecs_scaling(ctx, targets["ecs_cluster"], targets["ecs_service"])


COLLECTOR = Collector(
    name="autoscaling",
    description="EC2 Auto Scaling group capacity, scaling activities and failures, instance refreshes, and ECS service scaling policies",
    required=("group",),
    optional=("ecs_cluster", "ecs_service"),
    run=collect,
)
