"""The queries of the OpenSearch tool. Each one sends requests through the client and records bounded facts.

Every search body comes from search_body, so a query can only ask for shapes the read policy allows.

The state-only queries (health, nodes, indices, shards, allocation-explain, mapping) read the current state.
Their evidence window is only the minute before the run; it is not a query range.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from triage.config import OpenSearchCluster
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, Evidence
from triage.opensearch.client import OpenSearchClient, OpenSearchError
from triage.redact import Redactor
from triage.opensearch.policy import Request, search_body
from triage.window import Window, WindowError, format_time, parse_time

MAX_INDEX_FACTS = 50
MAX_SHARD_FACTS = 50
MAX_BUCKET_FACTS = 100
MAX_MAPPING_FIELDS = 200
MAX_TOP_MESSAGES = 20
MAX_DECIDERS = 5
MAX_SUMMARY_MESSAGE = 300
MAX_DATA_MESSAGE = 500
NO_MESSAGE = "(no message field)"
NO_UNASSIGNED_TEXT = "unable to find any unassigned shards"
SHARD_COLUMNS = "index,shard,prirep,state,unassigned.reason,node"
HISTOGRAM_NAME = "by_time"
TOP_MESSAGES_NAME = "top_messages"
HEALTH_ORDER = {"green": 0, "yellow": 1, "red": 2}

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_ID_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{8,}(?![0-9A-Za-z])")
_DIGITS_RE = re.compile(r"\d+")


@dataclass
class QueryContext:
    client: OpenSearchClient
    cluster: OpenSearchCluster
    limits: dict[str, int]
    window: Window
    evidence: Evidence
    invocation: str = ""  # the tool command line that is running; it becomes each fact's command


def _command(ctx: QueryContext, request: Request) -> str:
    return ctx.invocation or f"opensearch {ctx.cluster.name} {request.method} {request.path}"


def _send(ctx: QueryContext, request: Request) -> tuple[Any, str]:
    return ctx.client.request(request), _command(ctx, request)


def _window_text(ctx: QueryContext) -> str:
    return f"between {format_time(ctx.window.start)} and {format_time(ctx.window.end)}"


def _percent(part: float, whole: float) -> float | None:
    return round(part / whole * 100, 1) if whole else None


def _lookup(source: dict, path: str) -> Any:
    """Read a field by its flat name first, then by walking dotted parts."""
    if path in source:
        return source[path]
    node: Any = source
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else json.dumps(value)


def _hit_moment(value: Any) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 100_000_000_000 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            return parse_time(value)
        except WindowError:
            return None
    return None


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _asked(
    ctx: QueryContext, index: str, query: str | None, filters: dict[str, str] | None, **extra: Any
) -> dict:
    """What a windowed fact was queried with, kept in one place: data["asked"].

    Summaries and excerpts never repeat these values, so that quoting the tool's own query is not evidence.
    """
    return {"index": index, "query": query, "filters": dict(filters or {}), "window": ctx.window.iso(), **extra}


def _flag_partial(ctx: QueryContext, answer: dict, index: str, command: str) -> None:
    reasons = []
    if answer.get("timed_out"):
        reasons.append("the search timed out")
    if answer.get("terminated_early"):
        reasons.append("the search terminated early at the per-shard document limit")
    shard_info = answer.get("_shards") or {}
    if shard_info.get("failed"):
        reasons.append(f"{shard_info['failed']} of {shard_info.get('total', '?')} shards failed")
    if reasons:
        ctx.evidence.truncated = True
        ctx.evidence.add(
            kind=DERIVED, resource=index, command=command,
            summary=f"Results are partial, counts are lower bounds: {'; '.join(reasons)}",
            data={"partial": reasons},
        )


def _total_hits(response: dict) -> int:
    total = (response.get("hits") or {}).get("total", 0)
    return int(total.get("value", 0) if isinstance(total, dict) else total)


def _add_empty_fact(ctx: QueryContext, index: str, command: str, asked: dict) -> None:
    ctx.evidence.add(
        kind=DERIVED, resource=index, command=command,
        summary=f"No documents matched in the window {_window_text(ctx)} (index, query and filters are recorded under asked)",
        data={"asked": asked},
    )


def _query_body(ctx: QueryContext, query: str | None, filters: dict[str, str] | None, **options: Any) -> dict:
    return search_body(ctx.cluster, ctx.window, ctx.limits, query_string=query, filters=filters, **options)


# Cluster state

def health(ctx: QueryContext) -> None:
    answer, command = _send(ctx, Request("GET", "_cluster/health"))
    data = {
        "status": answer.get("status"),
        "node_count": answer.get("number_of_nodes"),
        "active_shards": answer.get("active_shards"),
        "unassigned_shards": answer.get("unassigned_shards"),
        "pending_tasks": answer.get("number_of_pending_tasks"),
    }
    ctx.evidence.add(
        kind=CURRENT, resource=f"cluster/{ctx.cluster.name}", command=command, data=data,
        summary=(
            f"Cluster {ctx.cluster.name} is {data['status']}: {data['node_count']} nodes, "
            f"{data['active_shards']} active shards, {data['unassigned_shards']} unassigned shards, "
            f"{data['pending_tasks']} pending tasks"
        ),
    )


def nodes(ctx: QueryContext) -> None:
    answer, command = _send(ctx, Request("GET", "_nodes/stats/jvm,fs,os,thread_pool"))
    for node_id, node in (answer.get("nodes") or {}).items():
        name = node.get("name") or node_id
        heap = _lookup(node, "jvm.mem.heap_used_percent")
        disk = node.get("fs", {}).get("total", {})
        disk_free = _percent(disk.get("available_in_bytes", 0), disk.get("total_in_bytes", 0))
        cpu = _lookup(node, "os.cpu.percent")
        rejections = {
            pool: stats["rejected"]
            for pool, stats in (node.get("thread_pool") or {}).items()
            if stats.get("rejected")
        }
        rejected_text = (
            "thread pool rejections since node start: " + ", ".join(f"{pool}={n}" for pool, n in rejections.items())
            if rejections else "no thread pool rejections since node start"
        )
        disk_text = f"{disk_free}% free" if disk_free is not None else "unknown"
        ctx.evidence.add(
            kind=CURRENT, resource=f"node/{name}", command=command,
            summary=(
                f"Node {name}: heap {heap if heap is not None else 'unknown'}% used, disk {disk_text}, "
                f"CPU {cpu if cpu is not None else 'unknown'}%, {rejected_text}"
            ),
            data={"heap_used_percent": heap, "disk_free_percent": disk_free, "cpu_percent": cpu,
                  "rejections_since_node_start": rejections},
        )


def indices(ctx: QueryContext, index: str | None = None) -> None:
    path = f"_cat/indices/{index}" if index else "_cat/indices"
    rows, command = _send(ctx, Request("GET", path, {"format": "json"}))
    counts = Counter(row.get("health") or "unknown" for row in rows)
    ordered = sorted(counts, key=lambda name: HEALTH_ORDER.get(name, 3))
    counts_text = ", ".join(f"{name}={counts[name]}" for name in ordered)
    ctx.evidence.add(
        kind=CURRENT, resource=f"cluster/{ctx.cluster.name}", command=command,
        summary=f"{len(rows)} indices" + (f": {counts_text}" if counts_text else ""),
        data={"counts": {name: counts[name] for name in ordered}, **({"asked": {"index": index}} if index else {})},
    )
    unhealthy = sorted(
        (row for row in rows if row.get("health") != "green"),
        key=lambda row: -HEALTH_ORDER.get(row.get("health"), 3),
    )
    if len(unhealthy) > MAX_INDEX_FACTS:
        ctx.evidence.truncated = True
    for row in unhealthy[:MAX_INDEX_FACTS]:
        ctx.evidence.add(
            kind=CURRENT, resource=f"index/{row.get('index')}", command=command,
            summary=(
                f"Index {row.get('index')} is {row.get('health')} ({row.get('status')}, "
                f"{row.get('pri')} primary, {row.get('rep')} replicas, {row.get('docs.count')} documents)"
            ),
            data={key: row.get(key) for key in ("health", "status", "pri", "rep", "docs.count", "store.size")},
        )


def shards(ctx: QueryContext) -> None:
    rows, command = _send(ctx, Request("GET", "_cat/shards", {"format": "json", "h": SHARD_COLUMNS}))
    unstarted = [row for row in rows if row.get("state") != "STARTED"]
    ctx.evidence.add(
        kind=CURRENT, resource=f"cluster/{ctx.cluster.name}", command=command,
        summary=f"{len(rows)} shards, {len(unstarted)} not STARTED",
        data={"shards": len(rows), "not_started": len(unstarted)},
    )
    if len(unstarted) > MAX_SHARD_FACTS:
        ctx.evidence.truncated = True
    for row in unstarted[:MAX_SHARD_FACTS]:
        role = "primary" if row.get("prirep") == "p" else "replica"
        text = f"Shard {row.get('shard')} ({role}) of {row.get('index')} is {row.get('state')}"
        if row.get("node"):
            text += f" on {row['node']}"
        if row.get("unassigned.reason"):
            text += f" (reason {row['unassigned.reason']})"
        ctx.evidence.add(
            kind=CURRENT, resource=f"index/{row.get('index')}", command=command, summary=text,
            data={key: row.get(key) for key in ("index", "shard", "prirep", "state", "node", "unassigned.reason")},
        )


def allocation_explain(ctx: QueryContext) -> None:
    request = Request("GET", "_cluster/allocation/explain")
    try:
        answer, command = _send(ctx, request)
    except OpenSearchError as error:
        if error.status != 400 or NO_UNASSIGNED_TEXT not in str(error):
            raise
        ctx.evidence.add(
            kind=CURRENT, resource=f"cluster/{ctx.cluster.name}", command=_command(ctx, request),
            summary="No shard is unassigned, so there is nothing to explain",
        )
        return
    role = "primary" if answer.get("primary") else "replica"
    reason = (answer.get("unassigned_info") or {}).get("reason")
    summary = f"Shard {answer.get('shard')} ({role}) of {answer.get('index')} is {answer.get('current_state')}"
    if reason:
        summary += f", reason {reason}"
    blockers = [
        f"{node.get('node_name')}: {decider.get('decider')}: {decider.get('explanation')}"
        for node in answer.get("node_allocation_decisions") or []
        for decider in node.get("deciders") or []
        if decider.get("decision") == "NO"
    ][:MAX_DECIDERS]
    ctx.evidence.add(
        kind=CURRENT, resource=f"index/{answer.get('index')}", command=command, summary=summary,
        excerpt=answer.get("allocate_explanation") or "",
        data={"index": answer.get("index"), "shard": answer.get("shard"), "primary": answer.get("primary"),
              "current_state": answer.get("current_state"), "reason": reason, "blocking_deciders": blockers},
    )


def _flatten_properties(properties: dict, prefix: str, fields: dict[str, str]) -> None:
    for name, spec in properties.items():
        path = f"{prefix}{name}"
        if "type" in spec:
            fields.setdefault(path, spec["type"])
        _flatten_properties(spec.get("fields") or {}, f"{path}.", fields)
        _flatten_properties(spec.get("properties") or {}, f"{path}.", fields)


def mapping(ctx: QueryContext, index: str) -> None:
    answer, command = _send(ctx, Request("GET", f"{index}/_mapping"))
    fields: dict[str, str] = {}
    for body in answer.values():
        _flatten_properties((body.get("mappings") or {}).get("properties") or {}, "", fields)
    listed = dict(list(fields.items())[:MAX_MAPPING_FIELDS])
    summary = f"The index has {len(fields)} fields"
    if len(fields) > len(listed):
        summary += f", {len(listed)} listed"
        ctx.evidence.truncated = True
    ctx.evidence.add(
        kind=CURRENT, resource=index, command=command, summary=summary,
        data={"fields": listed, "asked": {"index": index}},
        excerpt=", ".join(f"{name}:{kind}" for name, kind in listed.items()),
    )


# Queries over a time window

def count(ctx: QueryContext, index: str, query: str | None = None, filters: dict[str, str] | None = None) -> None:
    body = {"query": _query_body(ctx, query, filters)["query"]}
    answer, command = _send(ctx, Request("POST", f"{index}/_count", body=body))
    number = answer.get("count", 0)
    ctx.evidence.add(
        kind=DERIVED, resource=index, command=command,
        summary=f"{number} documents matched in the window (query and filters are recorded under asked)",
        data={"count": number, "asked": _asked(ctx, index, query, filters)},
    )


def histogram(
    ctx: QueryContext, index: str, interval: str = "5m", query: str | None = None,
    filters: dict[str, str] | None = None,
) -> None:
    aggs = {HISTOGRAM_NAME: {"date_histogram": {"field": ctx.cluster.time_field, "fixed_interval": interval,
                                                 "min_doc_count": 1}}}
    body = _query_body(ctx, query, filters, size=0, aggs=aggs)
    answer, command = _send(ctx, Request("POST", f"{index}/_search", body=body))
    found = [b for b in answer["aggregations"][HISTOGRAM_NAME]["buckets"] if b["doc_count"] > 0]
    asked = _asked(ctx, index, query, filters, interval=interval)
    _flag_partial(ctx, answer, index, command)
    if not found:
        _add_empty_fact(ctx, index, command, asked)
        return
    kept = found
    if len(found) > MAX_BUCKET_FACTS:
        ctx.evidence.truncated = True
        kept = sorted(sorted(found, key=lambda b: -b["doc_count"])[:MAX_BUCKET_FACTS], key=lambda b: b["key"])
    for bucket in kept:
        start = format_time(datetime.fromtimestamp(bucket["key"] / 1000, tz=timezone.utc))
        ctx.evidence.add(
            kind=INCIDENT_TIME, time=start, resource=index, command=command,
            summary=f"{bucket['doc_count']} documents in the {interval} bucket starting {start}",
            data={"count": bucket["doc_count"], "asked": asked},
        )
    peak = max(found, key=lambda bucket: bucket["doc_count"])
    peak_start = format_time(datetime.fromtimestamp(peak["key"] / 1000, tz=timezone.utc))
    total = sum(bucket["doc_count"] for bucket in found)
    ctx.evidence.add(
        kind=DERIVED, resource=index, command=command,
        summary=f"Peak: {peak['doc_count']} documents in the {interval} bucket starting {peak_start}, {total} documents in all",
        data={"count": peak["doc_count"], "bucket_start": peak_start, "total": total, "asked": asked},
    )


def normalise_message(message: str) -> str:
    """Replace ids and numbers with # so that messages that differ only in those group together."""
    message = _UUID_RE.sub("#", message)
    message = _HEX_ID_RE.sub("#", message)
    return _DIGITS_RE.sub("#", message)


def top_messages(
    ctx: QueryContext, index: str, query: str | None = None, filters: dict[str, str] | None = None,
    field: str | None = None,
) -> None:
    field = field or ctx.cluster.message_field
    keyword_field = field if field.endswith(".keyword") else f"{field}.keyword"
    aggs = {TOP_MESSAGES_NAME: {"terms": {"field": keyword_field, "size": MAX_TOP_MESSAGES}}}
    body = _query_body(ctx, query, filters, size=0, aggs=aggs)
    request = Request("POST", f"{index}/_search", body=body)
    try:
        answer, command = _send(ctx, request)
    except OpenSearchError as error:
        if error.status is None:
            raise
        _top_messages_from_hits(ctx, index, query, filters, field)
        return
    found = answer.get("aggregations", {}).get(TOP_MESSAGES_NAME, {}).get("buckets", [])
    if not found and _total_hits(answer) > 0:
        # The fallback flags its own answer; flagging here too would add a second identical fact.
        _top_messages_from_hits(ctx, index, query, filters, field)
        return
    _flag_partial(ctx, answer, index, command)
    asked = _asked(ctx, index, query, filters, method="terms aggregation")
    if not found:
        _add_empty_fact(ctx, index, command, asked)
        return
    for bucket in found[:MAX_TOP_MESSAGES]:
        message = ctx.evidence.redactor.text(_as_text(bucket["key"]))
        ctx.evidence.add(
            kind=DERIVED, resource=index, command=command, excerpt=message,
            summary=f"{bucket['doc_count']} occurrences of: {_shorten(message, MAX_SUMMARY_MESSAGE)}",
            data={"message": _shorten(message, MAX_DATA_MESSAGE), "count": bucket["doc_count"], "asked": asked},
        )


def _group_key(redactor: Redactor, hit: dict, field: str) -> str:
    text = _as_text(_lookup(hit.get("_source") or {}, field))
    return normalise_message(redactor.text(text)) if text else NO_MESSAGE


def _top_messages_from_hits(
    ctx: QueryContext, index: str, query: str | None, filters: dict[str, str] | None, field: str
) -> None:
    body = _query_body(ctx, query, filters, size=ctx.limits["opensearch_max_hits"])
    answer, command = _send(ctx, Request("POST", f"{index}/_search", body=body))
    _flag_partial(ctx, answer, index, command)
    hits = answer.get("hits", {}).get("hits", [])
    asked = _asked(ctx, index, query, filters, method=f"grouped sample of {len(hits)} hits")
    if not hits:
        _add_empty_fact(ctx, index, command, asked)
        return
    if _total_hits(answer) > len(hits):
        ctx.evidence.truncated = True
    redactor = ctx.evidence.redactor
    # Redact first: normalising first would break the patterns that recognise keys and tokens.
    groups = Counter(_group_key(redactor, hit, field) for hit in hits)
    for message, number in groups.most_common(MAX_TOP_MESSAGES):
        ctx.evidence.add(
            kind=DERIVED, resource=index, command=command, excerpt=message,
            summary=f"{number} of {len(hits)} sampled hits: {_shorten(message, MAX_SUMMARY_MESSAGE)}",
            data={"message": _shorten(message, MAX_DATA_MESSAGE), "count": number, "asked": asked},
        )


def search(
    ctx: QueryContext, index: str, query: str | None = None, filters: dict[str, str] | None = None,
    size: int | None = None, order: str = "asc",
) -> None:
    max_hits = ctx.limits["opensearch_max_hits"]
    size = max_hits if size is None else max(0, min(size, max_hits))
    body = _query_body(ctx, query, filters, size=size, sort_order=order)
    answer, command = _send(ctx, Request("POST", f"{index}/_search", body=body))
    _flag_partial(ctx, answer, index, command)
    hits = answer.get("hits", {}).get("hits", [])
    asked = _asked(ctx, index, query, filters)
    if not hits:
        _add_empty_fact(ctx, index, command, asked)
        return
    if _total_hits(answer) > len(hits):
        ctx.evidence.truncated = True
    cluster = ctx.cluster
    for hit in hits:
        source = hit.get("_source") or {}
        raw_time = _lookup(source, cluster.time_field)
        moment = _hit_moment(raw_time)
        data = {cluster.time_field: raw_time}
        level = _lookup(source, cluster.level_field)
        if level is not None:
            data[cluster.level_field] = level
        for name in filters or {}:
            value = _lookup(source, name)
            if value is not None:
                data[name] = value
        where = hit.get("_index") or index  # the resource name; the summary uses only what the hit reports
        reported = hit.get("_index")
        ctx.evidence.add(
            kind=INCIDENT_TIME if moment else DERIVED, time=moment, resource=where, command=command,
            summary=(f"{level} log line" if level is not None else "Log line") + (f" in {reported}" if reported else ""),
            data={**data, "asked": asked}, excerpt=_as_text(_lookup(source, cluster.message_field)),
        )
