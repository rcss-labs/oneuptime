"""EKS collector: cluster, nodegroup, add-on and update state from AWS; pods, events, workloads and logs from Kubernetes."""
from __future__ import annotations

import re
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso, split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, MAX_EXCERPT
from triage.window import format_time

MAX_NODEGROUPS = 10
MAX_ADDONS = 20
MAX_UPDATES = "20"
MAX_WORKLOADS = 10
MAX_CONTAINERS_PER_POD = 2
LOG_HEAD_LINES = 20
LOG_ERROR_LINES = 30
LOG_LINE_CHARS = 300
_ERROR_LOOKING = re.compile(
    r"\b(error|fatal|critical|panic|warn|warning)\b|exception|traceback|panic|killed|refused|timeout|denied|failed",
    re.IGNORECASE,
)
LOG_BYTES = 200000
MAX_PODS = 30
MAX_EVENTS = 40
MAX_LOG_PODS = 3
NOT_FOUND = "ResourceNotFoundException"
WORKLOAD = re.compile(r"^(deployment|statefulset|daemonset)/[A-Za-z0-9][A-Za-z0-9.-]*$")


def _issues_text(health: dict | None) -> str:
    issues = (health or {}).get("issues") or []
    if not issues:
        return "no health issues"
    return "health issues: " + "; ".join(f"{i.get('code')}: {i.get('message')}" for i in issues)


def _describe_cluster(ctx: CollectContext, name: str, region: str) -> dict | None:
    reply = ctx.aws("eks", "describe-cluster", ["--name", name], region=region, not_found=(NOT_FOUND,))
    if was_not_found(ctx, (NOT_FOUND,)) or (reply is not None and not reply.get("cluster")):
        ctx.evidence.add(
            kind=CURRENT, resource=f"cluster/{name}", command=ctx.last_command,
            summary=f"EKS cluster {name} was not found in region {region}",
        )
        return None
    return reply["cluster"] if reply else None


def _add_cluster(ctx: CollectContext, name: str, cluster: dict) -> None:
    vpc = cluster.get("resourcesVpcConfig") or {}
    ctx.evidence.add(
        kind=CURRENT, resource=f"cluster/{name}", command=ctx.last_command,
        summary=(
            f"Cluster {name} is {cluster.get('status')}: Kubernetes {cluster.get('version')}, "
            f"public access {str(bool(vpc.get('endpointPublicAccess'))).lower()}, "
            f"private access {str(bool(vpc.get('endpointPrivateAccess'))).lower()}, {_issues_text(cluster.get('health'))}"
        ),
    )


def _add_nodegroups(ctx: CollectContext, name: str, region: str) -> None:
    listed = ctx.aws("eks", "list-nodegroups", ["--cluster-name", name, "--max-items", "50"], region=region)
    names = (listed or {}).get("nodegroups", [])
    if len(names) > MAX_NODEGROUPS:
        ctx.evidence.add(
            kind=DERIVED, resource=f"cluster/{name}",
            summary=f"The cluster has {len(names)} nodegroups; only the first {MAX_NODEGROUPS} were described",
        )
    for group_name in names[:MAX_NODEGROUPS]:
        reply = ctx.aws("eks", "describe-nodegroup", ["--cluster-name", name, "--nodegroup-name", group_name], region=region)
        group = (reply or {}).get("nodegroup")
        if not group:
            continue
        scaling = group.get("scalingConfig") or {}
        ctx.evidence.add(
            kind=CURRENT, resource=f"nodegroup/{name}/{group_name}", command=ctx.last_command,
            summary=(
                f"Nodegroup {group_name} is {group.get('status')}: min {scaling.get('minSize')}, "
                f"max {scaling.get('maxSize')}, desired {scaling.get('desiredSize')}, {_issues_text(group.get('health'))}"
            ),
        )


def _add_addons(ctx: CollectContext, name: str, region: str) -> None:
    listed = ctx.aws("eks", "list-addons", ["--cluster-name", name, "--max-items", str(MAX_ADDONS)], region=region)
    for addon_name in (listed or {}).get("addons", [])[:MAX_ADDONS]:
        reply = ctx.aws("eks", "describe-addon", ["--cluster-name", name, "--addon-name", addon_name], region=region)
        addon = (reply or {}).get("addon")
        if not addon or addon.get("status") == "ACTIVE":
            continue
        ctx.evidence.add(
            kind=CURRENT, resource=f"addon/{name}/{addon_name}", command=ctx.last_command,
            summary=f"Add-on {addon_name} is {addon.get('status')}: {_issues_text(addon.get('health'))}",
        )


def _add_updates(ctx: CollectContext, name: str, region: str) -> None:
    listed = ctx.aws("eks", "list-updates", ["--name", name, "--max-items", MAX_UPDATES], region=region)
    for update_id in (listed or {}).get("updateIds", []):
        reply = ctx.aws("eks", "describe-update", ["--name", name, "--update-id", update_id], region=region)
        update = (reply or {}).get("update")
        if not update or not in_window(ctx.window, update.get("createdAt")):
            continue
        errors = "; ".join(f"{e.get('errorCode')}: {e.get('errorMessage')}" for e in update.get("errors") or [])
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"cluster/{name}", time=update.get("createdAt"), command=ctx.last_command,
            summary=(
                f"Update {update.get('id')} ({update.get('type')}) is {update.get('status')}"
                + (f"; errors: {errors}" if errors else "")
            ),
        )


def _container_problems(status: dict, prefix: str = "") -> tuple[list[str], list[str]]:
    """Short phrases for the summary and longer messages for the excerpt."""
    phrases: list[str] = []
    messages: list[str] = []
    container = f"{prefix}{status.get('name')}"
    for label, state in (("", status.get("state") or {}), ("last ", status.get("lastState") or {})):
        for kind in ("waiting", "terminated"):
            detail = state.get(kind)
            if not detail:
                continue
            code = f" exit code {detail['exitCode']}" if detail.get("exitCode") is not None else ""
            phrases.append(f"container {container} {label}{kind} {detail.get('reason')}{code}")
            if detail.get("message"):
                messages.append(f"{container}: {detail['message']}")
    return phrases, messages


def _container_statuses(pod: dict) -> list[dict]:
    return (pod.get("status") or {}).get("containerStatuses") or []


def _init_statuses(pod: dict) -> list[dict]:
    return (pod.get("status") or {}).get("initContainerStatuses") or []


def _pod_is_healthy(pod: dict) -> bool:
    status = pod.get("status") or {}
    if status.get("phase") == "Succeeded":
        return True
    containers = _container_statuses(pod)
    return status.get("phase") == "Running" and bool(containers) and all(c.get("ready") for c in containers)


def _restarts(pod: dict) -> int:
    return sum(c.get("restartCount", 0) for c in _container_statuses(pod) + _init_statuses(pod))


def _pod_fact(ctx: CollectContext, namespace: str, pod: dict) -> None:
    name = pod["metadata"]["name"]
    status = pod.get("status") or {}
    phrases: list[str] = []
    messages: list[str] = []
    for container, prefix in [(c, "") for c in _container_statuses(pod)] + [(c, "init ") for c in _init_statuses(pod)]:
        more_phrases, more_messages = _container_problems(container, prefix)
        phrases += more_phrases
        messages += more_messages
    for condition in status.get("conditions") or []:
        if condition.get("status") == "False" and condition.get("message"):
            phrases.append(f"condition {condition.get('type')} false ({condition.get('reason')})")
            messages.append(condition["message"])
    detail = f"; {'; '.join(phrases)}" if phrases else ""
    ctx.evidence.add(
        kind=CURRENT, resource=f"pod/{namespace}/{name}", command=ctx.last_command,
        summary=f"Pod {name} is {status.get('phase')} and not ready, {_restarts(pod)} restarts{detail}",
        excerpt="; ".join(messages),
    )


def _add_pods(ctx: CollectContext, cluster: str, namespace: str) -> list[dict]:
    reply = ctx.kubectl_json(cluster, ["get", "pods"], namespace=namespace)
    unhealthy = [p for p in (reply or {}).get("items", []) if not _pod_is_healthy(p)]
    unhealthy.sort(key=lambda p: (-_restarts(p), p["metadata"]["name"]))
    for pod in unhealthy[:MAX_PODS]:
        _pod_fact(ctx, namespace, pod)
    if len(unhealthy) > MAX_PODS:
        ctx.evidence.add(
            kind=DERIVED, resource=f"namespace/{namespace}",
            summary=f"{len(unhealthy) - MAX_PODS} more pods are not running and ready; only {MAX_PODS} are listed",
        )
    return unhealthy


def _event_period(event: dict) -> tuple[Any, Any]:
    """First and last occurrence of an event, as parsed times (None when unknown)."""
    last = parse_iso(event.get("lastTimestamp")) or parse_iso((event.get("series") or {}).get("lastObservedTime"))
    first = parse_iso(event.get("firstTimestamp")) or parse_iso(event.get("eventTime"))
    return first or last, last or first


def _times_text(event: dict) -> str:
    count = (event.get("series") or {}).get("count") or event.get("count") or 1
    return "once" if count == 1 else f"{count} times"


def _add_events(ctx: CollectContext, cluster: str, namespace: str) -> None:
    reply = ctx.kubectl_json(cluster, ["get", "events"], namespace=namespace)
    window = ctx.window
    overlapping = []
    for event in (reply or {}).get("items", []):
        first, last = _event_period(event)
        if event.get("type") == "Warning" and first and last and first <= window.end and last >= window.start:
            overlapping.append((last, first, event))
    overlapping.sort(key=lambda entry: entry[0], reverse=True)
    for last, first, event in overlapping[:MAX_EVENTS]:
        involved = event.get("involvedObject") or {}
        # The first occurrence inside the window is not known for a recurring event; use the best bound we have.
        moment = first if window.contains(first) else last if window.contains(last) else window.start
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"{involved.get('kind')}/{involved.get('name')}", time=moment,
            command=ctx.last_command,
            summary=(
                f"Warning event {event.get('reason')} on {involved.get('kind')}/{involved.get('name')} "
                f"({_times_text(event)}, first seen {format_time(first)}, last seen {format_time(last)})"
            ),
            excerpt=event.get("message") or "",
        )


def _conditions_text(conditions: list[dict]) -> str:
    parts = [f"{c.get('type')}={c.get('status')}" + (f" ({c['reason']})" if c.get("reason") else "") for c in conditions]
    return ", ".join(parts) or "none"


def _add_workload(ctx: CollectContext, cluster: str, namespace: str, workload: str) -> None:
    reply = ctx.kubectl_json(cluster, ["get", workload], namespace=namespace)
    if reply:
        spec, status = reply.get("spec") or {}, reply.get("status") or {}
        desired = spec.get("replicas", status.get("desiredNumberScheduled", 0))
        ready = status.get("readyReplicas", status.get("numberReady", 0))
        updated = status.get("updatedReplicas", status.get("updatedNumberScheduled", 0))
        ctx.evidence.add(
            kind=CURRENT, resource=f"{workload}", command=ctx.last_command,
            summary=(
                f"Workload {workload}: desired {desired}, ready {ready}, updated {updated}; "
                f"conditions {_conditions_text(status.get('conditions') or [])}"
            ),
            data={"desired": desired, "ready": ready, "updated": updated},
        )
    history = ctx.kubectl(cluster, ["rollout", "history", workload], namespace=namespace)
    if history:
        revisions = [int(m.group(1)) for m in re.finditer(r"^(\d+)\s", history, re.MULTILINE)]
        latest = f", latest revision {max(revisions)}" if revisions else ""
        ctx.evidence.add(
            kind=CURRENT, resource=workload, command=ctx.last_command,
            summary=f"Rollout history of {workload}: {len(revisions)} revisions{latest}",
            excerpt=history[-MAX_EXCERPT:],
        )


_LOG_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z(?: |$)")


def _line_time(line: str):
    """The time kubectl --timestamps put at the start of a line (nanoseconds are cut to microseconds)."""
    match = _LOG_TIME.match(line)
    if not match:
        return None
    fraction = f".{match.group(2)[:6]}" if match.group(2) else ""
    return parse_iso(f"{match.group(1)}{fraction}Z")


def _containers_to_read(pod: dict) -> list[dict]:
    """Containers that are not ready or have restarted, and that have run (so they have logs), at most two."""
    chosen = [c for c in _container_statuses(pod) if not c.get("ready") or c.get("restartCount", 0) > 0]
    return chosen[:MAX_CONTAINERS_PER_POD]


def _fetch_logs(ctx: CollectContext, cluster: str, namespace: str, pod_name: str, container: str, previous: bool) -> None:
    # No --tail: the answer is the first LOG_BYTES bytes from the window start, so the onset is always read.
    args = [
        "logs", pod_name, "-c", container, f"--since-time={format_time(ctx.window.start)}",
        "--timestamps", f"--limit-bytes={LOG_BYTES}",
    ]
    if previous:
        args.append("--previous")
    output = ctx.kubectl(cluster, args, namespace=namespace)
    if output is None:
        return
    which = "previous container instance" if previous else "container"
    resource = f"pod/{namespace}/{pod_name}"
    inside = []
    for line in output.splitlines():
        moment = _line_time(line)
        if moment is not None and ctx.window.contains(moment):
            inside.append((moment, line))
    cut = len(output.encode("utf-8")) >= LOG_BYTES
    if cut:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary=(
                f"The log of {which} {container} in pod {pod_name} was cut {LOG_BYTES} bytes after the window start; "
                "later lines were not read"
            ),
        )
    if not inside:
        if not cut:
            ctx.evidence.add(
                kind=DERIVED, resource=resource, command=ctx.last_command,
                summary=f"No log line of {which} {container} in pod {pod_name} falls inside the incident window",
            )
        return
    errors = [index for index, (_, line) in enumerate(inside) if _ERROR_LOOKING.search(line)]
    wanted = sorted(set(range(min(LOG_HEAD_LINES, len(inside)))) | set(errors[:LOG_ERROR_LINES]))
    # Redact each line before it is cut or quoted, so no secret survives at a cut boundary.
    kept = [(inside[i][0], _shorten(ctx.evidence.redactor.text(inside[i][1]))) for i in wanted]
    first_error = _shorten(ctx.evidence.redactor.text(inside[errors[0]][1])) if errors else None
    shown = first_error or kept[0][1]
    error_text = f"; first error-looking line: {first_error}" if first_error else ""
    ctx.evidence.add(
        kind=INCIDENT_TIME, resource=resource, time=kept[0][0], command=ctx.last_command,
        summary=(
            f"Log lines of {which} {container} in pod {pod_name} from {format_time(kept[0][0])} "
            f"to {format_time(kept[-1][0])}: {len(output.splitlines())} lines read, {len(inside)} inside the window, "
            f"{len(errors)} error-looking, {len(kept)} kept (the first {LOG_HEAD_LINES} and the error-looking lines)"
            f"{error_text}"
        ),
        data={"lines": [line for _, line in kept]},
        excerpt=shown,
    )


def _shorten(line: str) -> str:
    return line if len(line) <= LOG_LINE_CHARS else line[: LOG_LINE_CHARS - 1] + "…"


def _add_logs(ctx: CollectContext, cluster: str, namespace: str, pod: dict) -> None:
    name = pod["metadata"]["name"]
    for container in _containers_to_read(pod):
        state = container.get("state") or {}
        if "running" in state or "terminated" in state:
            _fetch_logs(ctx, cluster, namespace, name, container["name"], previous=False)
        if container.get("restartCount", 0) > 0:
            _fetch_logs(ctx, cluster, namespace, name, container["name"], previous=True)


def _add_kubernetes(ctx: CollectContext, cluster: str, namespace: str, workloads: list[str]) -> None:
    unhealthy = _add_pods(ctx, cluster, namespace)
    _add_events(ctx, cluster, namespace)
    if len(workloads) > MAX_WORKLOADS:
        ctx.evidence.add(
            kind=DERIVED, resource=f"namespace/{namespace}",
            summary=f"{len(workloads)} workloads were given; only the first {MAX_WORKLOADS} were examined",
        )
    for workload in workloads[:MAX_WORKLOADS]:
        if not WORKLOAD.match(workload):
            ctx.evidence.add_error(
                "", "InvalidTarget",
                f"workload '{workload}' is not deployment/<name>, statefulset/<name>, or daemonset/<name>",
            )
            continue
        _add_workload(ctx, cluster, namespace, workload)
    for pod in unhealthy[:MAX_LOG_PODS]:
        _add_logs(ctx, cluster, namespace, pod)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["cluster"]
    cluster = ctx.config.eks_clusters.get(name)
    if cluster is None:
        ctx.evidence.add_error("", "UnknownCluster", f"{name} is not in eks_clusters in the triage config")
        return
    if cluster.account != ctx.account.alias:
        ctx.evidence.add(
            kind=DERIVED, resource=f"cluster/{name}",
            summary=(
                f"Cluster {name} belongs to account {cluster.account}, but this run uses account "
                f"{ctx.account.alias}; nothing was collected"
            ),
        )
        return
    described = _describe_cluster(ctx, name, cluster.region)
    if described is None:
        return
    _add_cluster(ctx, name, described)
    _add_nodegroups(ctx, name, cluster.region)
    _add_addons(ctx, name, cluster.region)
    _add_updates(ctx, name, cluster.region)
    namespace = targets.get("namespace")
    if namespace:
        workloads = split_csv(targets.get("workloads"))
        _add_kubernetes(ctx, name, namespace, workloads)


COLLECTOR = Collector(
    name="eks",
    description="EKS cluster, nodegroup, add-on and update state, plus pods, warning events, workloads and logs for a namespace",
    required=("cluster",),
    optional=("namespace", "workloads"),
    run=collect,
)
