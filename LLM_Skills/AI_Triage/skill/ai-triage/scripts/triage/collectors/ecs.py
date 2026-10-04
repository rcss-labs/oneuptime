"""ECS collector: service state, deployments, events, stopped tasks, task definition, scaling, metrics."""
from __future__ import annotations

from typing import Any

from triage.collectors import Collector
from triage.collectors.common import env_changes, env_summary, in_window, newest_in_window
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts

MAX_EVENTS = 30
MAX_ITEMS = "20"
TASK_LEVEL_FIELDS = ("cpu", "memory")


def _short_name(arn: str) -> str:
    """checkout-api:42 from a task definition ARN; other ARNs keep their last segment."""
    return arn.rsplit("/", 1)[-1]


def _describe_service(ctx: CollectContext, cluster: str, name: str) -> dict | None:
    reply = ctx.aws("ecs", "describe-services", ["--cluster", cluster, "--services", name])
    if reply is None:
        return None
    services = reply.get("services", [])
    if not services:
        ctx.evidence.add(
            kind=CURRENT, resource=f"service/{cluster}/{name}", command=ctx.last_command,
            summary=f"Service {name} was not found in cluster {cluster}",
        )
        return None
    return services[0]


def _add_service_state(ctx: CollectContext, resource: str, service: dict) -> None:
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Service {service.get('serviceName')} is {service.get('status')}: desired {service.get('desiredCount')}, "
            f"running {service.get('runningCount')}, pending {service.get('pendingCount')}, "
            f"task definition {_short_name(service.get('taskDefinition', ''))}"
        ),
        data={key: service.get(key) for key in ("status", "desiredCount", "runningCount", "pendingCount")},
    )


def _add_deployments(ctx: CollectContext, resource: str, service: dict) -> None:
    for deployment in service.get("deployments", []):
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=deployment.get("createdAt"), command=ctx.last_command,
            summary=(
                f"Deployment of {_short_name(deployment.get('taskDefinition', ''))} was created; "
                f"state read now: {deployment.get('rolloutState')}, "
                f"{deployment.get('runningCount')} of {deployment.get('desiredCount')} tasks running"
            ),
            excerpt=deployment.get("rolloutStateReason") or "",
        )


def _add_events(ctx: CollectContext, resource: str, service: dict) -> None:
    for event in newest_in_window(ctx.window, service.get("events", []), lambda e: e.get("createdAt"), MAX_EVENTS):
        message = event.get("message", "")
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=event.get("createdAt"), command=ctx.last_command,
            summary="Service event", excerpt=message,
        )


def _container_text(container: dict) -> str:
    code = container.get("exitCode")
    exit_text = f" exit code {code}" if code is not None else ""
    reason = f" ({container['reason']})" if container.get("reason") else ""
    return f"{container.get('name')}{exit_text}{reason}"


def _add_stopped_tasks(ctx: CollectContext, cluster: str, name: str, resource: str) -> None:
    listed = ctx.aws(
        "ecs", "list-tasks",
        ["--cluster", cluster, "--service-name", name, "--desired-status", "STOPPED", "--max-items", MAX_ITEMS],
    )
    arns = (listed or {}).get("taskArns", [])
    if listed is not None and not arns:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary=(
                f"No stopped tasks were found for service {name} "
                "(ECS keeps stopped tasks visible for only about an hour)"
            ),
        )
    if not arns:
        return
    described = ctx.aws("ecs", "describe-tasks", ["--cluster", cluster, "--tasks", *arns])
    if described is None:
        return
    for task in newest_in_window(ctx.window, described.get("tasks", []), lambda t: t.get("stoppedAt"), int(MAX_ITEMS)):
        containers = "; ".join(_container_text(c) for c in task.get("containers", []))
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=task.get("stoppedAt"), command=ctx.last_command,
            summary=(
                f"Task {task.get('taskArn', '').rsplit('/', 1)[-1]} stopped ({task.get('stopCode')}): "
                f"{task.get('stoppedReason')}; containers: {containers}"
            ),
        )


def _describe_task_definition(ctx: CollectContext, reference: str) -> dict | None:
    reply = ctx.aws("ecs", "describe-task-definition", ["--task-definition", reference])
    return reply.get("taskDefinition") if reply else None


def _add_task_definition(ctx: CollectContext, resource: str, reference: str, definition: dict) -> None:
    task_level = "".join(
        f", task {field} {definition[field]}" for field in TASK_LEVEL_FIELDS if definition.get(field) is not None
    )
    for container in definition.get("containerDefinitions", []):
        environment = env_summary(_environment(container).items())
        names = ", ".join(environment) or "none"
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=(
                f"Task definition {reference} container {container.get('name')}: image {container.get('image')}, "
                f"cpu {container.get('cpu')}, memory {container.get('memory')}{task_level}, environment variables {names}"
            ),
            data={"container": container.get("name"), "environment": environment},
        )


def _containers_by_name(definition: dict) -> dict[str, dict]:
    return {c.get("name", ""): c for c in definition.get("containerDefinitions", [])}


def _environment(container: dict) -> dict[str, Any]:
    return {entry.get("name", ""): entry.get("value") for entry in container.get("environment", [])}


def _container_changes(name: str, old: dict, new: dict) -> list[str]:
    changes = []
    for field in ("image", "cpu", "memory"):
        if old.get(field) != new.get(field):
            changes.append(f"container {name} {field} {old.get(field)} -> {new.get(field)}")
    old_env, new_env = _environment(old), _environment(new)
    raw_changed = {key for key in old_env.keys() & new_env.keys() if old_env[key] != new_env[key]}
    for sentence in env_changes(env_summary(old_env.items()), env_summary(new_env.items()), raw_changed):
        changes.append(f"container {name}: {sentence}")
    return changes


def _previous_reference(service: dict, reference: str) -> str | None:
    """The task definition of a non-primary deployment, else the revision one below the current one."""
    for deployment in service.get("deployments", []):
        other = _short_name(deployment.get("taskDefinition", ""))
        if deployment.get("status") != "PRIMARY" and other and other != reference:
            return other
    family, _, revision = reference.rpartition(":")
    if revision.isdigit() and int(revision) > 1:
        return f"{family}:{int(revision) - 1}"
    return None


def _add_definition_diff(ctx: CollectContext, resource: str, reference: str, current: dict, service: dict) -> None:
    previous_reference = _previous_reference(service, reference)
    if previous_reference is None:
        return
    previous = _describe_task_definition(ctx, previous_reference)
    if previous is None:
        return
    old, new = _containers_by_name(previous), _containers_by_name(current)
    changes = [
        f"task {field} {previous.get(field)} -> {current.get(field)}"
        for field in TASK_LEVEL_FIELDS
        if previous.get(field) != current.get(field)
    ]
    for name in sorted(old.keys() | new.keys()):
        if name not in old or name not in new:
            changes.append(f"container {name} {'added' if name in new else 'removed'}")
        else:
            changes += _container_changes(name, old[name], new[name])
    detail = "; ".join(changes) or "no difference in image, cpu, memory, or environment variables"
    ctx.evidence.add(
        kind=DERIVED, resource=resource, command=ctx.last_command,
        summary=f"Task definition {reference} compared with {previous_reference}: {detail}",
    )


def _add_scaling_activities(ctx: CollectContext, cluster: str, name: str, resource: str) -> None:
    reply = ctx.aws(
        "application-autoscaling", "describe-scaling-activities",
        ["--service-namespace", "ecs", "--resource-id", f"service/{cluster}/{name}", "--max-items", MAX_ITEMS],
    )
    for activity in (reply or {}).get("ScalingActivities", []):
        if in_window(ctx.window, activity.get("StartTime")):
            ctx.evidence.add(
                kind=INCIDENT_TIME, resource=resource, time=activity.get("StartTime"), command=ctx.last_command,
                summary=f"Scaling activity {activity.get('StatusCode')}: {activity.get('Description')}",
                excerpt=activity.get("Cause") or "",
            )


def _add_metrics(ctx: CollectContext, cluster: str, name: str, resource: str) -> None:
    dimensions = {"ClusterName": cluster, "ServiceName": name}
    specs = [MetricSpec(metric, "AWS/ECS", metric, dimensions) for metric in ("CPUUtilization", "MemoryUtilization")]
    add_metric_facts(ctx, resource, specs)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    cluster, name = targets["cluster"], targets["service"]
    resource = f"service/{cluster}/{name}"
    service = _describe_service(ctx, cluster, name)
    if service is None:
        return
    _add_service_state(ctx, resource, service)
    _add_deployments(ctx, resource, service)
    _add_events(ctx, resource, service)
    _add_stopped_tasks(ctx, cluster, name, resource)
    reference = _short_name(service.get("taskDefinition", ""))
    definition = _describe_task_definition(ctx, reference)
    if definition is not None:
        _add_task_definition(ctx, resource, reference, definition)
        _add_definition_diff(ctx, resource, reference, definition, service)
    _add_scaling_activities(ctx, cluster, name, resource)
    _add_metrics(ctx, cluster, name, resource)


COLLECTOR = Collector(
    name="ecs",
    description="ECS service state, deployments, events, stopped tasks, task definition changes, scaling, CPU and memory",
    required=("cluster", "service"),
    optional=(),
    run=collect,
)
