"""The only gate between the skill and an OpenSearch cluster that has no login.

check_request refuses everything that is not listed here. When in doubt, it refuses.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from triage.config import OpenSearchCluster
from triage.window import Window, format_time

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
READ_METHODS = frozenset({"GET", "HEAD"})
POST_SUFFIXES = frozenset({"_search", "_count"})
EXPLAIN_PATH = "_cluster/allocation/explain"
CLUSTER_PATHS = frozenset(
    {"_cluster/health", "_cluster/stats", "_cluster/settings", EXPLAIN_PATH, "_nodes", "_nodes/stats", "_tasks"}
)
INDEX_SUFFIXES = frozenset({"_mapping", "_settings", "_count", "_search"})
ALLOWED_PARAMS = frozenset(
    {"format", "h", "s", "v", "bytes", "level", "filter_path", "flat_settings", "include_defaults", "pretty"}
)
FORBIDDEN_BODY_KEYS = frozenset({"script", "script_fields", "scripted_metric", "runtime_mappings", "scroll", "pit"})
FORBIDDEN_PATH_PARTS = ("..", "%", "?", "#", "\\")
MAX_TERMINATE_AFTER = 100000
MAX_TRACK_TOTAL_HITS = 10000

METRICS_RE = re.compile(r"^[a-z_]+(,[a-z_]+)*$")
CAT_NAME_RE = re.compile(r"^[a-z_]+$")
INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._*-]*$")
BROAD_INDEX_EXPRESSIONS = frozenset({"*", "_all"})


class Refused(Exception):
    """Raised with the reason a request is not allowed."""


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    params: dict[str, str] = field(default_factory=dict)
    body: dict | None = None


def normalise_path(path: str) -> str:
    return path.strip("/")


def _check_path_characters(path: str) -> None:
    if any(part in path for part in FORBIDDEN_PATH_PARTS):
        raise Refused(f"path '{path}' contains a forbidden sequence")
    if any(not 0x21 <= ord(char) <= 0x7E for char in path.replace("/", "")):
        raise Refused(f"path '{path}' contains whitespace or a character outside printable ASCII")


def _check_index(expression: str, cluster: OpenSearchCluster) -> None:
    if (
        expression in BROAD_INDEX_EXPRESSIONS
        or "," in expression
        or not INDEX_RE.match(expression)
        or not any(fnmatch.fnmatchcase(expression, allowed) for allowed in cluster.allowed_index_patterns)
    ):
        raise Refused(f"index '{expression}' is not an allowed index expression for this cluster")


def _route(segments: list[str], cluster: OpenSearchCluster) -> str:
    """Return the last path segment that decides the body rules, or '' for a plain read."""
    path = "/".join(segments)
    if path in CLUSTER_PATHS:
        return path if path == EXPLAIN_PATH else ""
    if len(segments) == 3 and segments[:2] == ["_nodes", "stats"] and METRICS_RE.match(segments[2]):
        return ""
    if segments[0] == "_cat" and len(segments) in (2, 3) and CAT_NAME_RE.match(segments[1]):
        if len(segments) == 3:
            _check_index(segments[2], cluster)
        return ""
    if len(segments) == 2 and segments[1] in INDEX_SUFFIXES:
        _check_index(segments[0], cluster)
        return segments[1]
    raise Refused(f"path '{path}' is not allowed")


def _check_method(method: str, route: str) -> None:
    if method in READ_METHODS:
        return
    if method == "POST" and (route in POST_SUFFIXES or route == EXPLAIN_PATH):
        return
    raise Refused(f"method {method!r} is not allowed here")


def _check_params(params: dict[str, str]) -> None:
    if not isinstance(params, dict):
        raise Refused("parameters must be a mapping")
    for key, value in params.items():
        if key not in ALLOWED_PARAMS:
            raise Refused(f"parameter '{key}' is not allowed")
        if not isinstance(value, str):
            raise Refused(f"parameter '{key}' must be a string")


def _check_forbidden_keys(body: Any) -> None:
    """Walk the body without recursion so that a deeply nested body cannot crash the check."""
    pending = [(body, 0)]
    while pending:
        node, depth = pending.pop()
        if depth > 100:
            raise Refused("body is nested too deeply")
        if isinstance(node, dict):
            for key, value in node.items():
                if key in FORBIDDEN_BODY_KEYS:
                    raise Refused(f"body key '{key}' is not allowed")
                pending.append((value, depth + 1))
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)


def _parse_time(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise Refused(f"time range '{name}' must be a YYYY-MM-DDTHH:MM:SSZ string")
    try:
        moment = datetime.strptime(value, TIME_FORMAT)
    except ValueError:
        raise Refused(f"time range '{name}' must be a YYYY-MM-DDTHH:MM:SSZ string") from None
    if moment.strftime(TIME_FORMAT) != value:
        raise Refused(f"time range '{name}' must be a YYYY-MM-DDTHH:MM:SSZ string")
    return moment


def _check_time_range(body: dict, cluster: OpenSearchCluster, limits: dict[str, int]) -> None:
    query = body.get("query")
    bool_query = query.get("bool") if isinstance(query, dict) and set(query) == {"bool"} else None
    filters = bool_query.get("filter") if isinstance(bool_query, dict) else None
    if not isinstance(filters, list):
        raise Refused("query must be a bool query with a filter list holding the time range")
    for clause in filters:
        if not (isinstance(clause, dict) and set(clause) == {"range"}):
            continue
        range_clause = clause["range"]
        bounds = range_clause.get(cluster.time_field) if isinstance(range_clause, dict) else None
        if isinstance(range_clause, dict) and set(range_clause) == {cluster.time_field} and isinstance(bounds, dict):
            if set(bounds) != {"gte", "lte"}:
                raise Refused("time range must have exactly gte and lte")
            start = _parse_time(bounds["gte"], "gte")
            end = _parse_time(bounds["lte"], "lte")
            if end <= start:
                raise Refused("time range lte must be after gte")
            if (end - start).total_seconds() > limits["max_window_hours"] * 3600:
                raise Refused(f"time range is longer than {limits['max_window_hours']} hours")
            return
    raise Refused(f"query has no time range filter on '{cluster.time_field}'")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_search_limits(body: dict, limits: dict[str, int]) -> None:
    size = body.get("size")
    if not _is_int(size) or not 0 <= size <= limits["opensearch_max_hits"]:
        raise Refused(f"size must be a whole number from 0 to {limits['opensearch_max_hits']}")
    timeout = body.get("timeout")
    if not isinstance(timeout, str) or not timeout:
        raise Refused("timeout must be present")
    terminate_after = body.get("terminate_after")
    if not _is_int(terminate_after) or not 1 <= terminate_after <= MAX_TERMINATE_AFTER:
        raise Refused(f"terminate_after must be present and from 1 to {MAX_TERMINATE_AFTER}")
    if "track_total_hits" in body:
        hits = body["track_total_hits"]
        if hits is not False and not (_is_int(hits) and 0 <= hits <= MAX_TRACK_TOTAL_HITS):
            raise Refused(f"track_total_hits must be false or a whole number up to {MAX_TRACK_TOTAL_HITS}")


def _check_body(request: Request, route: str, cluster: OpenSearchCluster, limits: dict[str, int]) -> None:
    body = request.body
    takes_body = route in POST_SUFFIXES or route == EXPLAIN_PATH
    if body is None:
        if route in POST_SUFFIXES:
            raise Refused("body is required for search and count")
        return
    if not takes_body:
        raise Refused("a body is not allowed on this path")
    if not isinstance(body, dict):
        raise Refused("body must be a JSON object")
    _check_forbidden_keys(body)
    if route in POST_SUFFIXES:
        _check_time_range(body, cluster, limits)
        if route == "_search":
            _check_search_limits(body, limits)


def check_request(request: Request, cluster: OpenSearchCluster, limits: dict[str, int]) -> None:
    """Raise Refused unless the request is on the read-only allow-list."""
    path = normalise_path(request.path)
    _check_path_characters(path)
    segments = path.split("/")
    if not path or "" in segments:
        raise Refused(f"path '{request.path}' is not allowed")
    route = _route(segments, cluster)
    _check_method(request.method, route)
    _check_params(request.params)
    _check_body(request, route, cluster, limits)


def search_body(
    cluster: OpenSearchCluster,
    window: Window,
    limits: dict[str, int],
    *,
    query_string: str | None = None,
    filters: dict[str, str] | None = None,
    size: int = 0,
    aggs: dict | None = None,
    sort_order: str = "asc",
) -> dict:
    """Build the one search shape the tool sends; it always passes check_request."""
    if sort_order not in ("asc", "desc"):
        raise ValueError(f"sort_order must be 'asc' or 'desc', not {sort_order!r}")
    time_range = {"range": {cluster.time_field: {"gte": format_time(window.start), "lte": format_time(window.end)}}}
    bool_query: dict[str, Any] = {"filter": [time_range] + [{"term": {key: value}} for key, value in (filters or {}).items()]}
    if query_string:
        bool_query["must"] = [
            {"query_string": {"query": query_string, "allow_leading_wildcard": False, "lenient": True}}
        ]
    body: dict[str, Any] = {
        "query": {"bool": bool_query},
        "size": min(size, limits["opensearch_max_hits"]),
        "timeout": f"{limits['opensearch_timeout_seconds']}s",
        "terminate_after": MAX_TERMINATE_AFTER,
        "track_total_hits": MAX_TRACK_TOTAL_HITS,
        "sort": [{cluster.time_field: {"order": sort_order}}],
    }
    if aggs:
        body["aggs"] = aggs
    return body
