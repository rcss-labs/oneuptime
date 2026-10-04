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
SEARCH_KEYS = frozenset({"query", "size", "timeout", "terminate_after", "track_total_hits", "sort", "aggs", "_source"})
COUNT_KEYS = frozenset({"query"})
EXPLAIN_KEYS = frozenset({"index", "shard", "primary"})
QUERY_STRING_KEYS = frozenset({"query", "default_field", "allow_leading_wildcard", "lenient", "default_operator"})
HISTOGRAM_INTERVALS = frozenset({"1m", "5m", "15m", "1h"})
TIMEOUT_RE = re.compile(r"([0-9]+)(ms|s)")
MAX_QUERY_STRING_CHARS = 500
MAX_SOURCE_FIELDS = 20
MAX_AGGREGATIONS = 3
MAX_TERMS_SIZE = 50
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


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_keys(node: Any, allowed: frozenset[str], where: str) -> dict:
    """Require a dict whose keys are all in the allowed set; refuse the first other key by name."""
    if not isinstance(node, dict):
        raise Refused(f"{where} must be an object")
    for key in node:
        if key not in allowed:
            raise Refused(f"{where} key '{key}' is not allowed")
    return node


def _check_range(clause: dict, cluster: OpenSearchCluster, limits: dict[str, int]) -> None:
    ranges = _check_keys(clause["range"], frozenset({cluster.time_field}), "range")
    bounds = ranges.get(cluster.time_field)
    if not isinstance(bounds, dict):
        raise Refused(f"range must be on the time field '{cluster.time_field}'")
    _check_keys(bounds, frozenset({"gte", "lte", "format"}), "range")
    if "gte" not in bounds or "lte" not in bounds:
        raise Refused("time range must have gte and lte")
    if "format" in bounds and not isinstance(bounds["format"], str):
        raise Refused("range format must be a string")
    start = _parse_time(bounds["gte"], "gte")
    end = _parse_time(bounds["lte"], "lte")
    if end <= start:
        raise Refused("time range lte must be after gte")
    if (end - start).total_seconds() > limits["max_window_hours"] * 3600:
        raise Refused(f"time range is longer than {limits['max_window_hours']} hours")


def _check_term(clause: dict) -> None:
    term = clause["term"]
    if not isinstance(term, dict) or len(term) != 1:
        raise Refused("term must name exactly one field")
    field_name, value = next(iter(term.items()))
    if not isinstance(field_name, str) or not isinstance(value, (str, int, float, bool)):
        raise Refused("term value must be a string, number, or boolean")


def _check_exists(clause: dict) -> None:
    exists = _check_keys(clause["exists"], frozenset({"field"}), "exists")
    if not isinstance(exists.get("field"), str):
        raise Refused("exists field must be a string")


def _check_filters(filters: Any, cluster: OpenSearchCluster, limits: dict[str, int]) -> None:
    if not isinstance(filters, list):
        raise Refused("bool filter must be a list holding the time range")
    ranges = 0
    for clause in filters:
        kind = next(iter(clause)) if isinstance(clause, dict) and len(clause) == 1 else None
        if kind == "range":
            ranges += 1
            _check_range(clause, cluster, limits)
        elif kind == "term":
            _check_term(clause)
        elif kind == "exists":
            _check_exists(clause)
        else:
            raise Refused(f"filter clause {kind or clause!r} is not allowed; use range, term, or exists")
    if ranges != 1:
        raise Refused(f"query needs exactly one time range filter on '{cluster.time_field}', found {ranges}")


def _check_query_string(must: Any) -> None:
    if not isinstance(must, list) or len(must) > 1:
        raise Refused("bool must holds at most one query_string clause")
    for clause in must:
        if not (isinstance(clause, dict) and set(clause) == {"query_string"}):
            raise Refused("bool must clause must be a query_string")
        spec = _check_keys(clause["query_string"], QUERY_STRING_KEYS, "query_string")
        if spec.get("allow_leading_wildcard") is not False:
            raise Refused("query_string allow_leading_wildcard must be present and false")
        text = spec.get("query")
        if not isinstance(text, str) or len(text) > MAX_QUERY_STRING_CHARS:
            raise Refused(f"query_string query must be a string of at most {MAX_QUERY_STRING_CHARS} characters")


def _check_query(body: dict, cluster: OpenSearchCluster, limits: dict[str, int]) -> None:
    query = body.get("query")
    if not isinstance(query, dict) or set(query) != {"bool"}:
        raise Refused("query must be a bool query with a time range filter")
    bool_query = _check_keys(query["bool"], frozenset({"filter", "must"}), "bool")
    _check_filters(bool_query.get("filter"), cluster, limits)
    if "must" in bool_query:
        _check_query_string(bool_query["must"])


def _check_timeout(body: dict, limits: dict[str, int]) -> None:
    timeout = body.get("timeout")
    match = TIMEOUT_RE.fullmatch(timeout) if isinstance(timeout, str) else None
    if not match:
        raise Refused("timeout must be present, written like 10s or 500ms")
    millis = int(match.group(1)) * (1 if match.group(2) == "ms" else 1000)
    if not 0 < millis <= limits["opensearch_timeout_seconds"] * 1000:
        raise Refused(f"timeout must be above zero and at most {limits['opensearch_timeout_seconds']}s")


def _check_sort(body: dict, cluster: OpenSearchCluster) -> None:
    sort = body.get("sort")
    if not isinstance(sort, list) or len(sort) != 1 or not isinstance(sort[0], dict) or set(sort[0]) != {cluster.time_field}:
        raise Refused(f"sort must be a list with one entry on '{cluster.time_field}'")
    spec = sort[0][cluster.time_field]
    if not isinstance(spec, dict) or set(spec) != {"order"} or spec["order"] not in ("asc", "desc"):
        raise Refused("sort order must be asc or desc")


def _check_source(source: Any) -> None:
    if source is False:
        return
    if not (isinstance(source, list) and len(source) <= MAX_SOURCE_FIELDS and all(isinstance(f, str) for f in source)):
        raise Refused(f"_source must be false or a list of at most {MAX_SOURCE_FIELDS} field names")


def _check_aggregation(spec: Any, cluster: OpenSearchCluster) -> None:
    if not isinstance(spec, dict) or len(spec) != 1:
        raise Refused("each aggs entry must hold exactly one date_histogram or terms aggregation")
    kind, options = next(iter(spec.items()))
    if kind == "date_histogram":
        _check_keys(options, frozenset({"field", "fixed_interval", "min_doc_count"}), "date_histogram")
        if options.get("field") != cluster.time_field:
            raise Refused(f"date_histogram field must be '{cluster.time_field}'")
        if options.get("fixed_interval") not in HISTOGRAM_INTERVALS:
            raise Refused(f"date_histogram interval must be one of {', '.join(sorted(HISTOGRAM_INTERVALS))}")
        count = options.get("min_doc_count", 0)
        if not _is_int(count) or count < 0:
            raise Refused("date_histogram min_doc_count must be a whole number")
    elif kind == "terms":
        _check_keys(options, frozenset({"field", "size"}), "terms")
        if not isinstance(options.get("field"), str) or not options["field"]:
            raise Refused("terms field must be a string")
        size = options.get("size")
        if not _is_int(size) or not 1 <= size <= MAX_TERMS_SIZE:
            raise Refused(f"terms size must be a whole number from 1 to {MAX_TERMS_SIZE}")
    elif kind == "aggs" or kind == "aggregations":
        raise Refused("nested aggregations are not allowed")
    else:
        raise Refused(f"aggregation type '{kind}' is not allowed; use date_histogram or terms")


def _check_aggs(aggs: Any, cluster: OpenSearchCluster) -> None:
    if not isinstance(aggs, dict) or len(aggs) > MAX_AGGREGATIONS:
        raise Refused(f"aggs must be an object with at most {MAX_AGGREGATIONS} named aggregations")
    for spec in aggs.values():
        if isinstance(spec, dict) and ("aggs" in spec or "aggregations" in spec):
            raise Refused("nested aggregations are not allowed")
        _check_aggregation(spec, cluster)


def _check_search_limits(body: dict, limits: dict[str, int]) -> None:
    size = body.get("size")
    if not _is_int(size) or not 0 <= size <= limits["opensearch_max_hits"]:
        raise Refused(f"size must be a whole number from 0 to {limits['opensearch_max_hits']}")
    _check_timeout(body, limits)
    terminate_after = body.get("terminate_after")
    if not _is_int(terminate_after) or not 1 <= terminate_after <= MAX_TERMINATE_AFTER:
        raise Refused(f"terminate_after must be present and from 1 to {MAX_TERMINATE_AFTER}")
    if "track_total_hits" in body:
        hits = body["track_total_hits"]
        if hits is not False and not (_is_int(hits) and 0 <= hits <= MAX_TRACK_TOTAL_HITS):
            raise Refused(f"track_total_hits must be false or a whole number up to {MAX_TRACK_TOTAL_HITS}")


def _check_search_body(body: dict, cluster: OpenSearchCluster, limits: dict[str, int]) -> None:
    _check_keys(body, SEARCH_KEYS, "body")
    _check_query(body, cluster, limits)
    _check_search_limits(body, limits)
    if "sort" in body:
        _check_sort(body, cluster)
    if "_source" in body:
        _check_source(body["_source"])
    if "aggs" in body:
        _check_aggs(body["aggs"], cluster)


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
    if route == "_search":
        _check_search_body(body, cluster, limits)
    elif route == "_count":
        _check_keys(body, COUNT_KEYS, "body")
        _check_query(body, cluster, limits)
    else:
        _check_keys(body, EXPLAIN_KEYS, "body")


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
    """Build the one search shape the tool sends; it raises Refused rather than build a body that check_request would refuse."""
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
    _check_search_body(body, cluster, limits)
    return body
