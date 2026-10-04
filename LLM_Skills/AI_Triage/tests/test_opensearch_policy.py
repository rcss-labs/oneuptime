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
     valid_body(query={"bool": {"filter": [{"range": {"timestamp": {"gte": START, "lte": END}}}]}}), "range"),
    ("missing lte", with_range(gte=START), "time range"),
    ("missing gte", with_range(lte=END), "time range"),
    ("extra range key", with_range(gte=START, lte=END, time_zone="+05:00"), "range"),
    ("lt instead of lte", with_range(gte=START, lt=END), "range"),
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
    body["query"]["bool"]["must"] = [{"query_string": {"query": "timeout", "allow_leading_wildcard": False}}]
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
    with pytest.raises(Refused):
        search_body(cluster, WINDOW, LIMITS, aggs={"x": {"scripted_metric": {}}})


# ---- the body check is an allow-list ----

TERMS = {"by_level": {"terms": {"field": "level", "size": 5}}}
HISTOGRAM = {"over_time": {"date_histogram": {"field": "@timestamp", "fixed_interval": "5m", "min_doc_count": 1}}}


def query_with(*filters, must=None):
    bool_query = {"filter": [{"range": {"@timestamp": {"gte": START, "lte": END}}}, *filters]}
    if must is not None:
        bool_query["must"] = must
    return {"query": {"bool": bool_query}}


def search_refusal(cluster, body):
    with pytest.raises(Refused) as caught:
        check_request(Request("POST", f"{INDEX}/_search", {}, body), cluster, LIMITS)
    return str(caught.value).lower()


ALLOW_LIST_REFUSALS = [
    ("global aggregation", valid_body(aggs={"all": {"global": {}}}), "global"),
    ("significant_terms", valid_body(aggs={"s": {"significant_terms": {"field": "a"}}}), "significant_terms"),
    ("cardinality aggregation", valid_body(aggs={"c": {"cardinality": {"field": "a"}}}), "cardinality"),
    ("suggest", valid_body(suggest={"s": {"text": "x"}}), "suggest"),
    ("from", valid_body(**{"from": 10000}), "from"),
    ("collapse", valid_body(collapse={"field": "host"}), "collapse"),
    ("highlight", valid_body(highlight={"fields": {"*": {}}}), "highlight"),
    ("profile", valid_body(profile=True), "profile"),
    ("search_after", valid_body(search_after=[1]), "search_after"),
    ("timeout -1", valid_body(timeout="-1"), "timeout"),
    ("timeout 1000d", valid_body(timeout="1000d"), "timeout"),
    ("timeout above the limit", valid_body(timeout="11s"), "timeout"),
    ("timeout in ms above the limit", valid_body(timeout="10001ms"), "timeout"),
    ("timeout zero", valid_body(timeout="0s"), "timeout"),
    ("timeout with trailing text", valid_body(timeout="5s;x"), "timeout"),
    ("timeout not a string", valid_body(timeout=5), "timeout"),
    ("minimum_should_match_script", valid_body(query={"bool": {"filter": valid_body()["query"]["bool"]["filter"], "minimum_should_match_script": {}}}), "minimum_should_match_script"),
    ("should clause", valid_body(query={"bool": {"filter": valid_body()["query"]["bool"]["filter"], "should": [{"term": {"a": "b"}}]}}), "should"),
    ("must_not clause", valid_body(query={"bool": {"filter": valid_body()["query"]["bool"]["filter"], "must_not": []}}), "must_not"),
    ("regexp in filter", valid_body(**query_with({"regexp": {"msg": ".*a.*b.*"}})), "regexp"),
    ("wildcard in filter", valid_body(**query_with({"wildcard": {"msg": "*foo*"}})), "wildcard"),
    ("prefix in filter", valid_body(**query_with({"prefix": {"msg": "a"}})), "prefix"),
    ("terms in filter", valid_body(**query_with({"terms": {"msg": ["a"]}})), "terms"),
    ("second range", valid_body(**query_with({"range": {"@timestamp": {"gte": START, "lte": END}}})), "range"),
    ("range on another field as the extra range", valid_body(**query_with({"range": {"bytes": {"gte": 1}}})), "range"),
    ("term with a list value", valid_body(**query_with({"term": {"a": ["x"]}})), "term"),
    ("term with two fields", valid_body(**query_with({"term": {"a": "x", "b": "y"}})), "term"),
    ("exists with extra key", valid_body(**query_with({"exists": {"field": "a", "boost": 2}})), "exists"),
    ("two must clauses", valid_body(**query_with(must=[{"query_string": {"query": "a", "allow_leading_wildcard": False}}] * 2)), "must"),
    ("must is not query_string", valid_body(**query_with(must=[{"match_all": {}}])), "must"),
    ("query_string with leading wildcards allowed", valid_body(**query_with(must=[{"query_string": {"query": "*a", "allow_leading_wildcard": True}}])), "allow_leading_wildcard"),
    ("query_string without allow_leading_wildcard", valid_body(**query_with(must=[{"query_string": {"query": "a"}}])), "allow_leading_wildcard"),
    ("query_string with an extra key", valid_body(**query_with(must=[{"query_string": {"query": "a", "allow_leading_wildcard": False, "fuzziness": 5}}])), "fuzziness"),
    ("query_string too long", valid_body(**query_with(must=[{"query_string": {"query": "a" * 501, "allow_leading_wildcard": False}}])), "500"),
    ("query_string not a string", valid_body(**query_with(must=[{"query_string": {"query": 1, "allow_leading_wildcard": False}}])), "query"),
    ("range with an extra key", with_range(gte=START, lte=END, boost=2), "range"),
    ("sort on another field", valid_body(sort=[{"host": {"order": "asc"}}]), "sort"),
    ("sort with two entries", valid_body(sort=[{"@timestamp": {"order": "asc"}}] * 2), "sort"),
    ("sort with a bad order", valid_body(sort=[{"@timestamp": {"order": "sideways"}}]), "sort"),
    ("sort script", valid_body(sort=[{"_script": {"type": "number"}}]), "sort"),
    ("_source true", valid_body(_source=True), "_source"),
    ("_source with 21 fields", valid_body(_source=[f"f{n}" for n in range(21)]), "_source"),
    ("_source with a non-string", valid_body(_source=["a", 1]), "_source"),
    ("aggs not a dict", valid_body(aggs=[TERMS]), "aggs"),
    ("a fourth aggregation", valid_body(aggs={f"a{n}": {"terms": {"field": "f", "size": 5}} for n in range(4)}), "aggs"),
    ("terms size over 50", valid_body(aggs={"t": {"terms": {"field": "f", "size": 51}}}), "size"),
    ("terms size zero", valid_body(aggs={"t": {"terms": {"field": "f", "size": 0}}}), "size"),
    ("terms without size", valid_body(aggs={"t": {"terms": {"field": "f"}}}), "size"),
    ("terms with an extra key", valid_body(aggs={"t": {"terms": {"field": "f", "size": 5, "include": ".*"}}}), "include"),
    ("terms with a non-string field", valid_body(aggs={"t": {"terms": {"field": 1, "size": 5}}}), "field"),
    ("nested aggregation", valid_body(aggs={"t": {"terms": {"field": "f", "size": 5}, "aggs": {"u": {"terms": {"field": "g", "size": 5}}}}}), "nested"),
    ("two aggregation types in one", valid_body(aggs={"t": {"terms": {"field": "f", "size": 5}, "date_histogram": {}}}), "aggs"),
    ("histogram interval 1s", valid_body(aggs={"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1s"}}}), "interval"),
    ("histogram without an interval", valid_body(aggs={"h": {"date_histogram": {"field": "@timestamp"}}}), "interval"),
    ("histogram calendar interval", valid_body(aggs={"h": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}}}), "calendar_interval"),
    ("histogram on another field", valid_body(aggs={"h": {"date_histogram": {"field": "other", "fixed_interval": "5m"}}}), "field"),
    ("histogram min_doc_count negative", valid_body(aggs={"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "5m", "min_doc_count": -1}}}), "min_doc_count"),
    ("histogram extra bounds", valid_body(aggs={"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "5m", "extended_bounds": {}}}}), "extended_bounds"),
]


@pytest.mark.parametrize("label,body,fragment", ALLOW_LIST_REFUSALS, ids=[row[0] for row in ALLOW_LIST_REFUSALS])
def test_allow_list_refusals(cluster, label, body, fragment):
    assert fragment.lower() in search_refusal(cluster, body)


def test_count_accepts_only_a_query(cluster):
    for extra in ({"size": 1}, {"aggs": TERMS}, {"timeout": "5s"}, {"sort": []}):
        body = dict(count_body(), **extra)
        with pytest.raises(Refused) as caught:
            check_request(Request("POST", f"{INDEX}/_count", {}, body), cluster, LIMITS)
        assert next(iter(extra)) in str(caught.value)


def test_explain_accepts_only_index_shard_and_primary(cluster):
    with pytest.raises(Refused) as caught:
        check_request(
            Request("POST", "_cluster/allocation/explain", {}, {"index": INDEX, "current_node": "n1"}), cluster, LIMITS
        )
    assert "current_node" in str(caught.value)


ALLOW_LIST_ACCEPTED = [
    ("term, exists and query_string", valid_body(**query_with(
        {"term": {"level": "error"}}, {"term": {"status": 500}}, {"term": {"ok": False}}, {"exists": {"field": "trace.id"}},
        must=[{"query_string": {"query": "a" * 500, "default_field": "message", "allow_leading_wildcard": False,
                                "lenient": True, "default_operator": "AND"}}]))),
    ("range with format", with_range(gte=START, lte=END, format="strict_date_time_no_millis")),
    ("terms aggregation", valid_body(aggs=TERMS)),
    ("histogram aggregation", valid_body(aggs=HISTOGRAM)),
    ("histogram without min_doc_count", valid_body(aggs={"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}})),
    ("three aggregations", valid_body(aggs={**TERMS, **HISTOGRAM, "c": {"terms": {"field": "host", "size": 50}}})),
    ("_source false", valid_body(_source=False)),
    ("_source list", valid_body(_source=[f"f{n}" for n in range(20)])),
    ("sort desc", valid_body(sort=[{"@timestamp": {"order": "desc"}}])),
    ("timeout in ms", valid_body(timeout="10000ms")),
]


@pytest.mark.parametrize("label,body", ALLOW_LIST_ACCEPTED, ids=[row[0] for row in ALLOW_LIST_ACCEPTED])
def test_allow_list_accepts_what_the_tool_builds(cluster, label, body):
    check_request(Request("POST", f"{INDEX}/_search", {}, body), cluster, LIMITS)


def test_search_body_with_every_allowed_option_passes_the_check(cluster):
    body = search_body(
        cluster, WINDOW, LIMITS, query_string="timeout", filters={"level": "error"}, size=50, aggs={**TERMS, **HISTOGRAM}
    )
    passes_check(cluster, body)


def test_search_body_refuses_a_window_longer_than_the_limit(cluster):
    long_window = Window(WINDOW.start, datetime(2026, 10, 4, 17, 0, tzinfo=timezone.utc))
    with pytest.raises(Refused, match="hours"):
        search_body(cluster, long_window, LIMITS)


@pytest.mark.parametrize(
    "aggs",
    [
        {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "10s"}}},
        {"t": {"terms": {"field": "f", "size": 500}}},
        {"g": {"global": {}}},
        {"t": {"terms": {"field": "f", "size": 5}, "aggs": {"u": {"terms": {"field": "g", "size": 5}}}}},
    ],
)
def test_search_body_refuses_aggregations_outside_the_two_shapes(cluster, aggs):
    with pytest.raises(Refused):
        search_body(cluster, WINDOW, LIMITS, aggs=aggs)


def test_search_body_refuses_an_overlong_query_string(cluster):
    with pytest.raises(Refused, match="500"):
        search_body(cluster, WINDOW, LIMITS, query_string="a" * 501)
