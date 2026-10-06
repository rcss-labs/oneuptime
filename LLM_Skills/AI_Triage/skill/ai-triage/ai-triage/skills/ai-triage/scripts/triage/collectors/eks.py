"""EKS collector: cluster, nodegroup, add-on and update state from AWS; pods, events, workloads and logs from Kubernetes."""
from __future__ import annotations

import re
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, newest_in_window
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, MAX_EXCERPT

MAX_NODEGROUPS = 10
MAX_ADDONS = 20
MAX_UPDATES = "5"
MAX_PODS = 30
MAX_EVENTS = 40
MAX_LOG_PODS = 3
LOG_TAIL = "50"
NOT_FOUND = "ResourceNotFoundException"
WORKLOAD = re.compile(r"^(deployment|statefulset|daemonset)/[A-Za-z0-9][A-Za-z0-9.-]*$")


def _issues_text(health: dict | None) -> str:
    issues = (health or {}).get("issues") or []
    if not issues:
        return "no health issues"
    return "health issues: " + "; ".join(f"{i.get('code')}: {i.get('message')}" for i in issues)


def _describe_cluster(ctx: CollectContext, name: str, region: str) -> dict | None:
    errors_before = len(ctx.evidence.errors)
    reply = ctx.aws("eks", "describe-cluster", ["--name", name], region=region)
    missing = reply is None and len(ctx.evidence.errors) > errors_before and ctx.evidence.errors[-1]["code"] == NOT_FOUND
    if missing or (reply is not None and not reply.get("cluster")):
        if missing:
            ctx.evidence.errors.pop()
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


def _container_problems(status: dict) -> tuple[list[str], list[str]]:
    """Short phrases for the summary and longer messages for the excerpt."""
    phrases: list[str] = []
    messages: list[str] = []
    container = status.get("name")
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


def _pod_is_healthy(pod: dict) -> bool:
    status = pod.get("status") or {}
    if status.get("phase") == "Succeeded":
        return True
    containers = status.get("containerStatuses") or []
    return status.get("phase") == "Running" and bool(containers) and all(c.get("ready") for c in containers)


def _restarts(pod: dict) -> int:
    return sum(c.get("restartCount", 0) for c in (pod.get("status") or {}).get("containerStatuses") or [])


def _pod_fact(ctx: CollectContext, namespace: str, pod: dict) -> None:
    name = pod["metadata"]["name"]
    status = pod.get("status") or {}
    phrases: list[str] = []
    messages: list[str] = []
    for container in status.get("containerStatuses") or []:
        more_phrases, more_messages = _container_problems(container)
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


def _event_time(event: dict) -> Any:
    return event.get("lastTimestamp") or (event.get("series") or {}).get("lastObservedTime") \
        or event.get("eventTime") or event.get("firstTimestamp")


def _add_events(ctx: CollectContext, cluster: str, namespace: str) -> None:
    reply = ctx.kubectl_json(cluster, ["get", "events", "--sort-by=.lastTimestamp"], namespace=namespace)
    warnings = [e for e in (reply or {}).get("items", []) if e.get("type") == "Warning"]
    for event in newest_in_window(ctx.window, warnings, _event_time, MAX_EVENTS):
        involved = event.get("involvedObject") or {}
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"{involved.get('kind')}/{involved.get('name')}", time=_event_time(event),
            command=ctx.last_command,
            summary=(
                f"Warning event {event.get('reason')} on {involved.get('kind')}/{involved.get('name')} "
                f"({event.get('count', 1)} times)"
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


def _add_logs(ctx: CollectContext, cluster: str, namespace: str, pod: dict) -> None:
    name = pod["metadata"]["name"]
    minutes = max(1, int(ctx.window.duration().total_seconds() // 60))
    base = ["logs", name, "--tail", LOG_TAIL, "--since", f"{minutes}m"]
    calls = [(base, f"Last log lines of pod {name}")]
    if _restarts(pod) > 0:
        calls.append(([*base, "--previous"], f"Last log lines of pod {name} before its previous restart (previous container)"))
    for args, summary in calls:
        output = ctx.kubectl(cluster, args, namespace=namespace)
        if not output:
            continue
        # Redact the whole text first so a secret cut by the tail boundary cannot leave a fragment.
        text = ctx.evidence.redactor.text(output)
        ctx.evidence.add(
            kind=CURRENT, resource=f"pod/{namespace}/{name}", command=ctx.last_command,
            summary=summary, excerpt=text[-MAX_EXCERPT:],
        )


def _add_kubernetes(ctx: CollectContext, cluster: str, namespace: str, workloads: list[str]) -> None:
    unhealthy = _add_pods(ctx, cluster, namespace)
    _add_events(ctx, cluster, namespace)
    for workload in workloads:
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
        ctx.evidence.add_error(
            "", "AccountMismatch",
            f"cluster {name} belongs to account {cluster.account}, but this run uses account {ctx.account.alias}",
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
        workloads = [w.strip() for w in targets.get("workloads", "").split(",") if w.strip()]
        _add_kubernetes(ctx, name, namespace, workloads)


COLLECTOR = Collector(
    name="eks",
    description="EKS cluster, nodegroup, add-on and update state, plus pods, warning events, workloads and logs for a namespace",
    required=("cluster",),
    optional=("namespace", "workloads"),
    run=collect,
)
