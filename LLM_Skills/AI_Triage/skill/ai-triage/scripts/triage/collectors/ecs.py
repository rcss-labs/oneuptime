"""ECS collector: service state, deployments, events, stopped tasks, task definition, scaling, metrics."""
from __future__ import annotations

from typing import Any

from triage.collectors import Collector
from triage.collectors.common import env_changes, env_summary, in_window, newest_in_window
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, MAX_DATA_STRING, SUMMARY_CUT_MARKER
from triage.metrics import MetricSpec, add_metric_facts

MAX_EVENTS = 30
MAX_ITEMS = "20"
TASK_LEVEL_FIELDS = ("cpu", "memory")
MAX_CHANGES = 50
MAX_CHANGE_LENGTH = 300
CHANGE_CUT_MARKER = "… [change cut]"
IMAGE = "image"
MAX_EVENT_SUMMARY = 200
MIN_IMAGE_PART = 100
MAX_RELATED_ARNS = 20


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
        data={**{key: service.get(key) for key in ("status", "desiredCount", "runningCount", "pendingCount")},
              **_service_arns(service)},
    )


def _service_arns(service: dict) -> dict[str, Any]:
    """The ARNs the describe-services answer returns for the service and what an action could target.
    Capacity providers are named, not given by ARN, in that answer."""
    arns: dict[str, Any] = {}
    for key, field in (("arn", "serviceArn"), ("cluster_arn", "clusterArn"), ("task_definition_arn", "taskDefinition")):
        if service.get(field):
            arns[key] = service[field]
    current = service.get("taskDefinition")
    previous = next((d.get("taskDefinition") for d in service.get("deployments", [])
                     if d.get("status") != "PRIMARY" and d.get("taskDefinition") and d.get("taskDefinition") != current), None)
    if previous:
        arns["previous_task_definition_arn"] = previous
    groups = list(dict.fromkeys(lb["targetGroupArn"] for lb in service.get("loadBalancers", []) if lb.get("targetGroupArn")))
    if groups:
        arns["target_group_arns"] = groups[:MAX_RELATED_ARNS]
        if len(groups) > MAX_RELATED_ARNS:
            arns["target_group_arns_omitted"] = len(groups) - MAX_RELATED_ARNS
    providers = [entry["capacityProvider"] for entry in service.get("capacityProviderStrategy", []) if entry.get("capacityProvider")]
    if providers:
        arns["capacity_providers"] = providers[:MAX_RELATED_ARNS]
    return arns


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


def _event_summary(message: str) -> str:
    """The event message itself, cut at MAX_EVENT_SUMMARY characters with the usual cut marker."""
    if len(message) <= MAX_EVENT_SUMMARY:
        return message or "Service event with no message"
    return message[: MAX_EVENT_SUMMARY - len(SUMMARY_CUT_MARKER)] + SUMMARY_CUT_MARKER


def _add_events(ctx: CollectContext, resource: str, service: dict) -> None:
    for event in newest_in_window(ctx.window, service.get("events", []), lambda e: e.get("createdAt"), MAX_EVENTS):
        message = event.get("message", "")
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=event.get("createdAt"), command=ctx.last_command,
            summary=_event_summary(message), excerpt=message,
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
            data={"container": container.get("name"), "environment": environment,
                  **({"task_definition_arn": definition["taskDefinitionArn"]} if definition.get("taskDefinitionArn") else {})},
        )


def _containers_by_name(definition: dict) -> dict[str, dict]:
    return {c.get("name", ""): c for c in definition.get("containerDefinitions", [])}


def _environment(container: dict) -> dict[str, Any]:
    return {entry.get("name", ""): entry.get("value") for entry in container.get("environment", [])}


Change = tuple[str, str]  # (kind, sentence)


def _container_changes(name: str, old: dict, new: dict) -> list[Change]:
    changes: list[Change] = []
    for field in ("image", "cpu", "memory"):
        if old.get(field) != new.get(field):
            changes.append((field, f"container {name} {field} {old.get(field)} -> {new.get(field)}"))
    old_env, new_env = _environment(old), _environment(new)
    raw_changed = {key for key in old_env.keys() & new_env.keys() if old_env[key] != new_env[key]}
    for sentence in env_changes(env_summary(old_env.items()), env_summary(new_env.items()), raw_changed):
        changes.append(("environment value", f"container {name}: {sentence}"))
    return changes


def _image_parts(reference: str, length: int) -> list[str]:
    """A reference cut into parts of at most length characters, each ending at a / : or @ where one falls
    in the second half of the part. Joined in order, the parts give the reference back."""
    parts = []
    while len(reference) > length:
        cut = max(reference[:length].rfind(mark) for mark in "/:@") + 1
        if cut <= length // 2:
            cut = length
        parts.append(reference[:cut])
        reference = reference[cut:]
    return parts + [reference]


def _image_lines(prefix: str, label: str, reference: str) -> list[str]:
    """One line for a reference, or numbered parts when that line would pass the evidence string cap."""
    line = f"{prefix} image {label} {reference}"
    if len(line) <= MAX_DATA_STRING:
        return [line]
    header_length = len(f"{prefix} image {label}, part 99 of 99: ")
    parts = _image_parts(reference, max(MIN_IMAGE_PART, MAX_DATA_STRING - header_length))
    return [f"{prefix} image {label}, part {n} of {len(parts)}: {part}" for n, part in enumerate(parts, 1)]


def _change_lines(change: Change) -> list[str]:
    """The data lines of one change. An image change is never cut: when one line would be longer than the
    evidence layer keeps a string, each reference gets its own lines, split into numbered parts when needed."""
    kind, text = change
    if kind == IMAGE:
        if len(text) <= MAX_DATA_STRING:
            return [text]
        head, _, new = text.partition(" -> ")
        prefix, _, old = head.rpartition(" image ")
        return _image_lines(prefix, "was", old) + _image_lines(prefix, "is now", new)
    if len(text) <= MAX_CHANGE_LENGTH:
        return [text]
    return [text[: MAX_CHANGE_LENGTH - len(CHANGE_CUT_MARKER)] + CHANGE_CUT_MARKER]


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
    changes: list[Change] = [
        (f"task {field}", f"task {field} {previous.get(field)} -> {current.get(field)}")
        for field in TASK_LEVEL_FIELDS
        if previous.get(field) != current.get(field)
    ]
    for name in sorted(old.keys() | new.keys()):
        if name not in old or name not in new:
            changes.append(("container", f"container {name} {'added' if name in new else 'removed'}"))
        else:
            changes += _container_changes(name, old[name], new[name])
    before, after = _revision(previous_reference), _revision(reference)
    lines = [line for change in changes for line in _change_lines(change)]
    data: dict[str, Any] = {"changes": lines[:MAX_CHANGES]}
    if len(lines) > MAX_CHANGES:
        data["changes_omitted"] = len(lines) - MAX_CHANGES
    for key, definition in (("task_definition_arn", current), ("previous_task_definition_arn", previous)):
        if definition.get("taskDefinitionArn"):
            data[key] = definition["taskDefinitionArn"]
    ctx.evidence.add(
        kind=DERIVED, resource=resource, command=ctx.last_command, data=data,
        summary=_diff_summary(before, after, changes),
    )


def _revision(reference: str) -> str:
    return reference.rpartition(":")[2]


def _diff_summary(before: str, after: str, changes: list[Change]) -> str:
    if not changes:
        return (
            f"The task definition did not change between revision {before} and {after} "
            "(image, cpu, memory, and environment values were compared)"
        )
    counts: dict[str, int] = {}
    for kind, _ in changes:
        counts[kind] = counts.get(kind, 0) + 1
    parts = []
    for kind, count in counts.items():
        if kind == "environment value":
            parts.append(f"{count} environment value{'s' if count > 1 else ''}")
        else:
            parts.append(kind if count == 1 else f"{count} {kind}s")
    plural = "change" if len(changes) == 1 else "changes"
    return f"The task definition changed between revision {before} and {after}: {len(changes)} {plural} ({', '.join(parts)})"


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
