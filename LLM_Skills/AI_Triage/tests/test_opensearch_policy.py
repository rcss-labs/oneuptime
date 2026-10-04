import copy
from datetime import datetime, timezone

import pytest

from triage.config import parse_config
from triage.opensearch.policy import Refused, Request, check_request, search_body
from triage.window import Window

INDEX = "app-logs-2026.10.04"
START = "2026-10-04T10:00:00Z"
END = "2026-10-04T12:00:00Z"
LIMITS = {"max_window_hours": 6, "opensearch_max_hits": 50, "opensearch_timeout_seconds": 10}


@pytest.fixture
def cluster(config_data):
    return parse_config(config_data).opensearch_clusters["logs-prod"]


def valid_body(**overrides):
    body = {
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": START, "lte": END}}}]}},
        "size": 10,
        "timeout": "10s",
        "terminate_after": 100000,
        "track_total_hits": 10000,
    }
    body.update(overrides)
    return body


def count_body():
    return {"query": valid_body()["query"]}


def with_range(**range_parts):
    body = valid_body()
    body["query"] = {"bool": {"filter": [{"range": {"@timestamp": range_parts}}]}}
    return body


ALLOWED = [
    ("GET", "_cluster/health", {}, None),
    ("HEAD", "_cluster/health", {}, None),
    ("GET", "/_cluster/stats/", {}, None),
    ("GET", "_cluster/settings", {"flat_settings": "true", "include_defaults": "true"}, None),
    ("GET", "_cluster/allocation/explain", {}, None),
    ("POST", "_cluster/allocation/explain", {}, {"index": INDEX, "shard": 0, "primary": True}),
    ("GET", "_nodes", {}, None),
    ("GET", "_nodes/stats", {"level": "shards"}, None),
    ("GET", "_nodes/stats/jvm,os,fs", {"filter_path": "nodes.*.name"}, None),
    ("GET", "_tasks", {}, None),
    ("GET", "_cat/indices", {"format": "json", "h": "index,health", "s": "index", "v": "true", "bytes": "mb"}, None),
    ("GET", "_cat/thread_pool", {"pretty": "true"}, None),
    ("GET", f"_cat/shards/{INDEX}", {}, None),
    ("GET", f"_cat/indices/{INDEX}", {}, None),
    ("GET", f"{INDEX}/_mapping", {}, None),
    ("HEAD", f"{INDEX}/_settings", {}, None),
    ("GET", "app-logs-*/_settings", {}, None),
    ("GET", f"{INDEX}/_count", {}, count_body()),
    ("POST", f"{INDEX}/_count", {}, count_body()),
    ("GET", f"{INDEX}/_search", {}, valid_body()),
    ("POST", f"/{INDEX}/_search/", {}, valid_body()),
    ("POST", "app-logs-*/_search", {}, valid_body(track_total_hits=False)),
]


@pytest.mark.parametrize("method,path,params,body", ALLOWED)
def test_allowed_requests_pass(cluster, method, path, params, body):
    check_request(Request(method, path, params, body), cluster, LIMITS)


REFUSED = [
    ("PUT", f"{INDEX}/_search", {}, valid_body(), "method"),
    ("DELETE", f"{INDEX}/_mapping", {}, None, "method"),
    ("PATCH", f"{INDEX}/_settings", {}, None, "method"),
    ("get", "_cluster/health", {}, None, "method"),
    ("POST", "_cat/indices", {}, None, "method"),
    ("POST", "_cluster/health", {}, None, "method"),
    ("POST", f"{INDEX}/_mapping", {}, None, "method"),
    ("POST", "_bulk", {}, {}, "path"),
    ("POST", f"{INDEX}/_bulk", {}, {}, "path"),
    ("POST", f"{INDEX}/_delete_by_query", {}, valid_body(), "path"),
    ("POST", f"{INDEX}/_update_by_query", {}, valid_body(), "path"),
    ("POST", "_reindex", {}, {}, "path"),
    ("GET", "_snapshot", {}, None, "path"),
    ("GET", "_scripts/anything", {}, None, "path"),
    ("GET", f"{INDEX}/_doc/1", {}, None, "path"),
    ("GET", INDEX, {}, None, "path"),
    ("GET", "_cat", {}, None, "path"),
    ("GET", "_cat/Indices", {}, None, "path"),
    ("GET", "_nodes/stats/JVM", {}, None, "path"),
    ("GET", "_cluster//health", {}, None, "path"),
    ("GET", "", {}, None, "path"),
    ("POST", "_all/_search", {}, valid_body(), "index"),
    ("POST", "*/_search", {}, valid_body(), "index"),
    ("POST", "other-index/_search", {}, valid_body(), "index"),
    ("POST", "app-*/_search", {}, valid_body(), "index"),
    ("POST", "app-logs-1,app-logs-2/_search", {}, valid_body(), "index"),
    ("POST", ".app-logs-1/_search", {}, valid_body(), "index"),
    ("POST", "-app-logs-1/_search", {}, valid_body(), "index"),
    ("POST", "_app-logs-1/_search", {}, valid_body(), "index"),
    ("POST", "remote:app-logs-1/_search", {}, valid_body(), "index"),
    ("GET", "_cat/indices/_all", {}, None, "index"),
    ("GET", "_cat/indices/*", {}, None, "index"),
    ("GET", "../_cluster/health", {}, None, "path"),
    ("GET", f"{INDEX}/../_cluster/health", {}, None, "path"),
    ("GET", "_cluster/%2e%2e/_cluster/health", {}, None, "path"),
    ("GET", f"{INDEX}%2f_search", {}, None, "path"),
    ("GET", "_cluster/health?pretty", {}, None, "path"),
    ("GET", "_cluster/health#x", {}, None, "path"),
    ("GET", "_cluster/health ", {}, None, "path"),
    ("GET", "_cluster/he alth", {}, None, "path"),
    ("GET", "_cluster\\health", {}, None, "path"),
    ("GET", "_cluster/healthé", {}, None, "path"),
    ("POST", f"{INDEX}/_search", {"q": "error"}, valid_body(), "parameter"),
    ("POST", f"{INDEX}/_search", {"scroll": "1m"}, valid_body(), "parameter"),
    ("POST", f"{INDEX}/_search", {"size": "1000"}, valid_body(), "parameter"),
    ("GET", "_cluster/health", {"timeout": "1s"}, None, "parameter"),
    ("GET", "_cluster/health", {"format": 1}, None, "parameter"),
    ("GET", "_cat/indices", {}, {}, "body"),
    ("GET", "_cluster/health", {}, {"a": 1}, "body"),
    ("GET", f"{INDEX}/_mapping", {}, {"a": 1}, "body"),
    ("POST", f"{INDEX}/_search", {}, None, "body"),
    ("POST", f"{INDEX}/_count", {}, None, "body"),
    ("POST", f"{INDEX}/_search", {}, [valid_body()], "body"),
    ("POST", "_cluster/allocation/explain", {}, {"script": {}}, "script"),
]


@pytest.mark.parametrize("method,path,params,body,fragment", REFUSED)
def test_refused_requests(cluster, method, path, params, body, fragment):
    with pytest.raises(Refused) as caught:
        check_request(Request(method, path, params, body), cluster, LIMITS)
    assert fragment in str(caught.value).lower()


def without(body, key):
    trimmed = copy.deepcopy(body)
    del trimmed[key]
    return trimmed


BODY_REFUSALS = [
    ("no query", without(valid_body(), "query"), "time range"),
    ("query not a dict", valid_body(query="error"), "time range"),
    ("match_all query", valid_body(query={"match_all": {}}), "time range"),
    ("bool without filter", valid_body(query={"bool": {"must": []}}), "time range"),
    ("filter not a list", valid_body(query={"bool": {"filter": {"range": {}}}}), "time range"),
    ("range on another field",
     valid_body(query={"bool": {"filter": [{"range": {"timestamp": {"gte": START, "lte": END}}}]}}), "time range"),
    ("missing lte", with_range(gte=START), "time range"),
    ("missing gte", with_range(lte=END), "time range"),
    ("extra range key", with_range(gte=START, lte=END, time_zone="+05:00"), "time range"),
    ("lt instead of lte", with_range(gte=START, lt=END), "time range"),
    ("relative time", with_range(gte="now-1h", lte="now"), "time"),
    ("no Z suffix", with_range(gte="2026-10-04T10:00:00", lte="2026-10-04T12:00:00"), "time"),
    ("offset instead of Z", with_range(gte="2026-10-04T10:00:00+00:00", lte=END), "time"),
    ("unpadded time", with_range(gte="2026-10-4T10:00:00Z", lte=END), "time"),
    ("time is a number", with_range(gte=1, lte=2), "time"),
    ("range longer than the limit", with_range(gte="2026-10-04T00:00:00Z", lte="2026-10-04T06:00:01Z"), "hours"),
    ("lte before gte", with_range(gte=END, lte=START), "after"),
    ("lte equals gte", with_range(gte=START, lte=START), "after"),
    ("missing size", without(valid_body(), "size"), "size"),
    ("size over the limit", valid_body(size=51), "size"),
    ("negative size", valid_body(size=-1), "size"),
    ("size is a string", valid_body(size="10"), "size"),
    ("size is a bool", valid_body(size=True), "size"),
    ("missing timeout", without(valid_body(), "timeout"), "timeout"),
    ("missing terminate_after", without(valid_body(), "terminate_after"), "terminate_after"),
    ("terminate_after too large", valid_body(terminate_after=100001), "terminate_after"),
    ("terminate_after zero", valid_body(terminate_after=0), "terminate_after"),
    ("track_total_hits true", valid_body(track_total_hits=True), "track_total_hits"),
    ("track_total_hits too large", valid_body(track_total_hits=10001), "track_total_hits"),
    ("track_total_hits string", valid_body(track_total_hits="true"), "track_total_hits"),
]


@pytest.mark.parametrize("label,body,fragment", BODY_REFUSALS, ids=[row[0] for row in BODY_REFUSALS])
def test_search_body_refusals(cluster, label, body, fragment):
    with pytest.raises(Refused) as caught:
        check_request(Request("POST", f"{INDEX}/_search", {}, body), cluster, LIMITS)
    assert fragment in str(caught.value).lower()


def test_search_body_at_exactly_the_limits_is_allowed(cluster):
    body = valid_body(size=50, terminate_after=100000, track_total_hits=10000)
    body["query"] = {"bool": {"filter": [{"range": {"@timestamp": {"gte": "2026-10-04T00:00:00Z", "lte": "2026-10-04T06:00:00Z"}}}]}}
    check_request(Request("POST", f"{INDEX}/_search", {}, body), cluster, LIMITS)


def test_count_does_not_need_size_or_timeout(cluster):
    check_request(Request("POST", f"{INDEX}/_count", {}, count_body()), cluster, LIMITS)


def test_count_still_needs_the_time_range(cluster):
    with pytest.raises(Refused):
        check_request(Request("POST", f"{INDEX}/_count", {}, {"query": {"match_all": {}}}), cluster, LIMITS)


def test_extra_filters_next_to_the_time_range_are_allowed(cluster):
    body = valid_body()
    body["query"]["bool"]["filter"].append({"term": {"level": "error"}})
    body["query"]["bool"]["must"] = [{"query_string": {"query": "timeout"}}]
    check_request(Request("POST", f"{INDEX}/_search", {}, body), cluster, LIMITS)


FORBIDDEN_KEYS = ["script", "script_fields", "scripted_metric", "runtime_mappings", "scroll", "pit"]


@pytest.mark.parametrize("key", FORBIDDEN_KEYS)
def test_forbidden_key_is_refused_at_the_top_level(cluster, key):
    with pytest.raises(Refused) as caught:
        check_request(Request("POST", f"{INDEX}/_search", {}, valid_body(**{key: {}})), cluster, LIMITS)
    assert key in str(caught.value)


@pytest.mark.parametrize("key", FORBIDDEN_KEYS)
def test_forbidden_key_is_refused_inside_an_aggregation(cluster, key):
    aggs = {"by_host": {"terms": {"field": "host"}, "aggs": {"inner": {key: {"source": "x"}}}}}
    for path in (f"{INDEX}/_search", f"{INDEX}/_count"):
        with pytest.raises(Refused) as caught:
            check_request(Request("POST", path, {}, valid_body(aggs=aggs)), cluster, LIMITS)
        assert key in str(caught.value)


def test_forbidden_key_is_refused_inside_a_list(cluster):
    body = valid_body()
    body["query"]["bool"]["filter"].append({"bool": {"should": [{"script": {"script": "1"}}]}})
    with pytest.raises(Refused):
        check_request(Request("POST", f"{INDEX}/_search", {}, body), cluster, LIMITS)


def test_deeply_nested_body_is_refused_not_crashed(cluster):
    nested: dict = {}
    cursor = nested
    for _ in range(5000):
        cursor["a"] = {}
        cursor = cursor["a"]
    with pytest.raises(Refused):
        check_request(Request("POST", f"{INDEX}/_search", {}, valid_body(aggs=nested)), cluster, LIMITS)


def test_limits_are_read_from_the_limits_argument(cluster):
    tight = dict(LIMITS, opensearch_max_hits=5)
    with pytest.raises(Refused):
        check_request(Request("POST", f"{INDEX}/_search", {}, valid_body(size=10)), cluster, tight)


def test_index_must_match_the_cluster_patterns(config_data):
    config_data["opensearch_clusters"]["logs-prod"]["allowed_index_patterns"] = ["other-*"]
    other = parse_config(config_data).opensearch_clusters["logs-prod"]
    with pytest.raises(Refused):
        check_request(Request("GET", f"{INDEX}/_mapping"), other, LIMITS)
    check_request(Request("GET", "other-1/_mapping"), other, LIMITS)


def test_the_time_field_comes_from_the_cluster(config_data):
    config_data["opensearch_clusters"]["logs-prod"]["time_field"] = "event_time"
    other = parse_config(config_data).opensearch_clusters["logs-prod"]
    with pytest.raises(Refused):
        check_request(Request("POST", f"{INDEX}/_search", {}, valid_body()), other, LIMITS)


WINDOW = Window(
    datetime(2026, 10, 4, 10, 0, tzinfo=timezone.utc), datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
)


def passes_check(cluster, body):
    check_request(Request("POST", f"{INDEX}/_search", {}, body), cluster, LIMITS)
    check_request(Request("POST", f"{INDEX}/_count", {}, {"query": body["query"]}), cluster, LIMITS)


def test_search_body_with_no_filters_has_the_documented_shape(cluster):
    body = search_body(cluster, WINDOW, LIMITS)
    assert body == {
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": START, "lte": END}}}]}},
        "size": 0,
        "timeout": "10s",
        "terminate_after": 100000,
        "track_total_hits": 10000,
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    passes_check(cluster, body)


def test_search_body_adds_one_term_filter_per_entry(cluster):
    body = search_body(cluster, WINDOW, LIMITS, filters={"kubernetes.namespace": "checkout", "level": "error"})
    assert body["query"]["bool"]["filter"][1:] == [
        {"term": {"kubernetes.namespace": "checkout"}},
        {"term": {"level": "error"}},
    ]
    passes_check(cluster, body)


def test_search_body_puts_the_query_string_in_must(cluster):
    body = search_body(cluster, WINDOW, LIMITS, query_string="timeout AND checkout", size=20)
    assert body["query"]["bool"]["must"] == [
        {"query_string": {"query": "timeout AND checkout", "allow_leading_wildcard": False, "lenient": True}}
    ]
    assert body["size"] == 20
    passes_check(cluster, body)


def test_search_body_without_a_query_string_has_no_must(cluster):
    assert "must" not in search_body(cluster, WINDOW, LIMITS)["query"]["bool"]


def test_search_body_includes_aggregations(cluster):
    aggs = {"by_level": {"terms": {"field": "level", "size": 5}}}
    body = search_body(cluster, WINDOW, LIMITS, aggs=aggs)
    assert body["aggs"] == aggs
    passes_check(cluster, body)


def test_search_body_clamps_size_to_the_limit(cluster):
    body = search_body(cluster, WINDOW, LIMITS, size=5000)
    assert body["size"] == 50
    passes_check(cluster, body)


def test_search_body_sort_order_and_timeout_follow_the_arguments(cluster):
    body = search_body(cluster, WINDOW, dict(LIMITS, opensearch_timeout_seconds=20), sort_order="desc")
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert body["timeout"] == "20s"


def test_search_body_rejects_an_unknown_sort_order(cluster):
    with pytest.raises(ValueError):
        search_body(cluster, WINDOW, LIMITS, sort_order="sideways")


def test_search_body_uses_the_cluster_time_field(config_data):
    config_data["opensearch_clusters"]["logs-prod"]["time_field"] = "event_time"
    other = parse_config(config_data).opensearch_clusters["logs-prod"]
    body = search_body(other, WINDOW, LIMITS)
    assert body["sort"] == [{"event_time": {"order": "asc"}}]
    passes_check(other, body)


def test_search_body_cannot_be_used_to_smuggle_a_forbidden_key(cluster):
    body = search_body(cluster, WINDOW, LIMITS, aggs={"x": {"scripted_metric": {}}})
    with pytest.raises(Refused):
        passes_check(cluster, body)
