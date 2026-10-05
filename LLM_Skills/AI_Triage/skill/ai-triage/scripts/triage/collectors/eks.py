"""EKS collector: cluster, nodegroup, add-on and update state from AWS; pods, events, workloads and logs from Kubernetes."""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso, split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, MAX_EXCERPT
from triage.window import describe_offset, format_time

MAX_NODEGROUPS = 10
MAX_ADDONS = 20
MAX_UPDATES = "20"
MAX_UPDATE_NODEGROUPS = 5
MAX_NODEGROUP_UPDATES = 3
UPDATE_LOOKBACK = timedelta(hours=24)
MAX_WORKLOADS = 10
MAX_RESOURCE_CONTAINERS = 3
MAX_CONTAINERS_PER_POD = 2
LOG_HEAD_LINES = 20
LOG_ERROR_LINES = 30
LOG_LINE_CHARS = 300
_STRONG_LINE = re.compile(r"\b(error|fatal|critical|oom)\b|panic|exception|traceback|killed|out of memory", re.IGNORECASE)
_SOFT_LINE = re.compile(r"\b(warn|warning)\b|timeout|refused|denied|failed", re.IGNORECASE)
_DIGITS = re.compile(r"\d+")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{8,}(?![0-9A-Za-z])")
REPLACEMENT = "\ufffd"
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
        data={"arn": cluster["arn"]} if cluster.get("arn") else {},
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
            data={"arn": group["nodegroupArn"]} if group.get("nodegroupArn") else {},
        )
    _add_nodegroup_updates(ctx, name, region, names)


def _add_nodegroup_updates(ctx: CollectContext, cluster: str, region: str, names: list[str]) -> None:
    """Updates of each nodegroup (AMI or version rollouts) created in the window or the day before it."""
    if len(names) > MAX_UPDATE_NODEGROUPS:
        ctx.evidence.add(
            kind=DERIVED, resource=f"cluster/{cluster}",
            summary=(
                f"The cluster has {len(names)} nodegroups; updates were checked for only the first "
                f"{MAX_UPDATE_NODEGROUPS} nodegroups"
            ),
        )
    earliest = ctx.window.start - UPDATE_LOOKBACK
    for group_name in names[:MAX_UPDATE_NODEGROUPS]:
        listed = ctx.aws(
            "eks", "list-updates", ["--name", cluster, "--nodegroup-name", group_name, "--max-items", MAX_UPDATES],
            region=region,
        )
        ids = (listed or {}).get("updateIds", [])
        if len(ids) > MAX_NODEGROUP_UPDATES:
            ctx.evidence.add(
                kind=DERIVED, resource=f"nodegroup/{cluster}/{group_name}",
                summary=(
                    f"Nodegroup {group_name} has {len(ids)} or more updates; only {MAX_NODEGROUP_UPDATES} were "
                    "described and older ones may not be shown"
                ),
            )
        for update_id in ids[:MAX_NODEGROUP_UPDATES]:
            reply = ctx.aws(
                "eks", "describe-update", ["--name", cluster, "--nodegroup-name", group_name, "--update-id", update_id],
                region=region,
            )
            update = (reply or {}).get("update")
            created = parse_iso((update or {}).get("createdAt"))
            if created is None or not earliest <= created <= ctx.window.end:
                continue
            errors = "; ".join(f"{e.get('errorCode')}: {e.get('errorMessage')}" for e in update.get("errors") or [])
            ctx.evidence.add(
                kind=INCIDENT_TIME, resource=f"nodegroup/{cluster}/{group_name}", time=created, command=ctx.last_command,
                summary=(
                    f"Nodegroup {group_name} update {update.get('id')} ({update.get('type')}) is {update.get('status')}, "
                    f"created {format_time(created)}, {describe_offset(created, ctx.window.start)} the window start"
                    + (f"; errors: {errors}" if errors else "")
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
            data={"arn": addon["addonArn"]} if addon.get("addonArn") else {},
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


def _resources(container: dict) -> dict:
    """Requests and limits of one container from its spec; an absent value is stated as "none"."""
    resources = container.get("resources") or {}
    limits, requests = resources.get("limits") or {}, resources.get("requests") or {}
    return {
        "name": container.get("name"),
        "memory_limit": limits.get("memory", "none"), "memory_request": requests.get("memory", "none"),
        "cpu_limit": limits.get("cpu", "none"), "cpu_request": requests.get("cpu", "none"),
    }


def _resources_text(entries: list[dict]) -> str:
    return "; ".join(
        f"container {e['name']}: memory limit {e['memory_limit']}, request {e['memory_request']}; "
        f"cpu limit {e['cpu_limit']}, request {e['cpu_request']}"
        for e in entries[:MAX_RESOURCE_CONTAINERS]
    )


def _was_killed_or_restarted(pod: dict) -> bool:
    if _restarts(pod) > 0:
        return True
    return any(
        "terminated" in (c.get("state") or {}) or "terminated" in (c.get("lastState") or {})
        for c in _container_statuses(pod)
    )


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
    data: dict = {}
    if _was_killed_or_restarted(pod):
        # The limit goes in the same fact as the termination reason, so an OOMKilled container and its limit are together.
        failing = {c.get("name") for c in _container_statuses(pod) if c.get("restartCount") or "terminated" in (c.get("lastState") or {})}
        entries = [_resources(c) for c in (pod.get("spec") or {}).get("containers") or []]
        entries.sort(key=lambda e: e["name"] not in failing)
        if entries:
            phrases.append(f"resources: {_resources_text(entries)}")
            data["containers"] = entries
    detail = f"; {'; '.join(phrases)}" if phrases else ""
    ctx.evidence.add(
        kind=CURRENT, resource=f"pod/{namespace}/{name}", command=ctx.last_command,
        summary=f"Pod {name} is {status.get('phase')} and not ready, {_restarts(pod)} restarts{detail}",
        data=data,
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
        entries = [_resources(c) for c in ((spec.get("template") or {}).get("spec") or {}).get("containers") or []]
        resources = f"; resources: {_resources_text(entries)}" if entries else ""
        ctx.evidence.add(
            kind=CURRENT, resource=f"{workload}", command=ctx.last_command,
            summary=(
                f"Workload {workload}: desired {desired}, ready {ready}, updated {updated}; "
                f"conditions {_conditions_text(status.get('conditions') or [])}{resources}"
            ),
            # Kubernetes objects have no ARN; kind, name and namespace identify the owner to act on.
            data={
                "desired": desired, "ready": ready, "updated": updated, "containers": entries,
                "workload": {
                    "kind": reply.get("kind") or workload.split("/", 1)[0].capitalize(),
                    "name": workload.split("/", 1)[1], "namespace": namespace,
                },
            },
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
    cut = _reached_byte_limit(output)
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
    error_count = sum(1 for _, line in inside if _is_error_looking(line))
    chosen, group_count = _error_lines_to_keep(inside)
    not_kept = group_count - len(chosen)
    wanted = sorted(set(range(min(LOG_HEAD_LINES, len(inside)))) | set(chosen))
    # Redact each line before it is cut or quoted, so no secret survives at a cut boundary.
    kept = [(inside[i][0], _shorten(ctx.evidence.redactor.text(inside[i][1])) + _repeat_note(chosen.get(i, 1))) for i in wanted]
    strong = [i for i in chosen if _STRONG_LINE.search(inside[i][1])]
    first_index = min(strong or chosen, default=None)
    first_error = _shorten(ctx.evidence.redactor.text(inside[first_index][1])) if first_index is not None else None
    shown = first_error or kept[0][1]
    label = "first strong error-looking line" if strong else "first error-looking line"
    error_text = f"; {label}: {first_error}" if first_error else ""
    left_out = f"; first {LOG_ERROR_LINES} of {group_count} distinct error-looking lines; {not_kept} not kept" if not_kept else ""
    ctx.evidence.add(
        kind=INCIDENT_TIME, resource=resource, time=kept[0][0], command=ctx.last_command,
        summary=(
            f"Log lines of {which} {container} in pod {pod_name} from {format_time(kept[0][0])} "
            f"to {format_time(kept[-1][0])}: {len(output.splitlines())} lines read, {len(inside)} inside the window, "
            f"{error_count} error-looking, {len(kept)} kept (the first {LOG_HEAD_LINES} lines and the error-looking "
            f"lines, strong before soft, repeats kept once){left_out}{error_text}"
        ),
        data={"lines": [line for _, line in kept]},
        excerpt=shown,
    )


def _reached_byte_limit(output: str) -> bool:
    """Whether kubectl cut the answer at LOG_BYTES, judged on the bytes it sent rather than on the decoded text.

    The runner decodes with errors="replace" (one U+FFFD per invalid byte, and one for a character cut at the end,
    which was up to 3 bytes) and turns CRLF into LF. A cut answer almost always ends inside a line, so the CRLF
    allowance is only made for an answer without a final newline.
    """
    sent = len(output.encode("utf-8")) - 2 * output.count(REPLACEMENT)
    if output.endswith(REPLACEMENT):
        sent += 2
    if sent >= LOG_BYTES:
        return True
    return not output.endswith("\n") and sent + output.count("\n") >= LOG_BYTES


def _is_error_looking(line: str) -> bool:
    return bool(_STRONG_LINE.search(line) or _SOFT_LINE.search(line))


def _group_key(line: str) -> str:
    """The line with UUIDs, hex runs of 8 or more characters, and digits ignored."""
    return _DIGITS.sub("#", _HEX_RUN.sub("<hex>", _UUID.sub("<uuid>", line)))


def _error_lines_to_keep(inside: list[tuple]) -> tuple[dict[int, int], int]:
    """Index of the first line of each kept group of error-looking lines (same text once ids and digits are ignored)
    with its count, strong groups before soft ones, at most LOG_ERROR_LINES groups; and how many groups there were."""
    groups: dict[str, list[int]] = {}
    for index, (_, line) in enumerate(inside):
        if _is_error_looking(line):
            groups.setdefault(_group_key(line), []).append(index)
    ranked = sorted(groups.values(), key=lambda members: (not _STRONG_LINE.search(inside[members[0]][1]), members[0]))
    return {members[0]: len(members) for members in ranked[:LOG_ERROR_LINES]}, len(ranked)


def _repeat_note(count: int) -> str:
    return f" (repeated {count} times)" if count > 1 else ""


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
