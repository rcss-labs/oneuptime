import json
from urllib.parse import parse_qsl, urlsplit

import pytest

from triage import config as config_module
from triage.evidence import Evidence
from triage.opensearch import queries
from triage.opensearch.client import OpenSearchClient, OpenSearchError
from triage.opensearch.policy import Refused, Request, check_request
from triage.window import make_window

INDEX = "app-logs-*"
START = "2026-10-04T10:00:00Z"
END = "2026-10-04T11:00:00Z"
LIMITS = {"max_window_hours": 6, "opensearch_max_hits": 50, "opensearch_timeout_seconds": 10}
ENDPOINT = "https://opensearch.internal.example.com/"


@pytest.fixture
def cluster(config_data):
    return config_module.parse_config(config_data).opensearch_clusters["logs-prod"]


class Sequence(list):
    """Answers for consecutive calls to the same path."""


class FakeTransport:
    """Answers by path; every call is recorded as a Request so that tests can check the policy."""

    def __init__(self, answers):
        self.answers = answers
        self.requests = []

    def __call__(self, method, url, body, timeout_seconds, verify_tls, ca_bundle):
        parts = urlsplit(url)
        path = parts.path.strip("/")
        self.requests.append(
            Request(method, path, dict(parse_qsl(parts.query)), json.loads(body) if body else None)
        )
        answer = self.answers[path] if path in self.answers else self.answers[(method, path)]
        if isinstance(answer, Sequence):
            answer = answer.pop(0)
        status, payload = answer if isinstance(answer, tuple) else (200, answer)
        return status, json.dumps(payload)


def make_context(cluster, answers):
    transport = FakeTransport(answers)
    window = make_window(START, END, 6)
    evidence = Evidence("opensearch", cluster.account, cluster.name, window)
    client = OpenSearchClient(cluster, LIMITS, transport=transport)
    return queries.QueryContext(client, cluster, LIMITS, window, evidence), transport


def assert_all_pass_policy(transport, cluster):
    assert transport.requests
    for request in transport.requests:
        check_request(request, cluster, LIMITS)


def range_filter():
    return {"range": {"@timestamp": {"gte": START, "lte": END}}}


# health

def test_health_reads_cluster_health_and_states_the_numbers(cluster):
    health = {"status": "yellow", "number_of_nodes": 3, "active_shards": 120, "unassigned_shards": 4,
              "number_of_pending_tasks": 2}
    ctx, transport = make_context(cluster, {"_cluster/health": health})
    queries.health(ctx)
    assert transport.requests == [Request("GET", "_cluster/health")]
    (fact,) = ctx.evidence.facts
    assert fact.kind == "current"
    assert fact.summary == "Cluster logs-prod is yellow: 3 nodes, 120 active shards, 4 unassigned shards, 2 pending tasks"
    assert fact.data["status"] == "yellow"
    assert ctx.evidence.account == "prod-main" and ctx.evidence.region == "logs-prod"
    assert_all_pass_policy(transport, cluster)


# nodes

NODES = {"nodes": {
    "n1": {"name": "data-1", "jvm": {"mem": {"heap_used_percent": 91}},
           "fs": {"total": {"total_in_bytes": 1000, "available_in_bytes": 123}},
           "os": {"cpu": {"percent": 40}},
           "thread_pool": {"write": {"rejected": 12}, "search": {"rejected": 0}}},
    "n2": {"name": "data-2", "jvm": {"mem": {"heap_used_percent": 50}},
           "fs": {"total": {"total_in_bytes": 1000, "available_in_bytes": 500}},
           "os": {"cpu": {"percent": 10}}, "thread_pool": {"write": {"rejected": 0}}},
}}


def test_nodes_one_fact_per_node_with_computed_percentages(cluster):
    ctx, transport = make_context(cluster, {"_nodes/stats/jvm,fs,os,thread_pool": NODES})
    queries.nodes(ctx)
    assert transport.requests == [Request("GET", "_nodes/stats/jvm,fs,os,thread_pool")]
    first, second = ctx.evidence.facts
    assert first.kind == "current" and first.resource == "node/data-1"
    assert first.summary == "Node data-1: heap 91% used, disk 12.3% free, CPU 40%, rejections: write=12"
    assert first.data == {"heap_used_percent": 91, "disk_free_percent": 12.3, "cpu_percent": 40,
                          "rejections": {"write": 12}}
    assert second.summary == "Node data-2: heap 50% used, disk 50.0% free, CPU 10%, no thread pool rejections"
    assert_all_pass_policy(transport, cluster)


# indices

def test_indices_lists_non_green_and_summarises_all(cluster):
    rows = [
        {"health": "green", "index": "app-logs-1", "status": "open", "pri": "1", "rep": "1", "docs.count": "5"},
        {"health": "yellow", "index": "app-logs-2", "status": "open", "pri": "1", "rep": "1", "docs.count": "7"},
        {"health": "red", "index": "app-logs-3", "status": "open", "pri": "1", "rep": "1", "docs.count": "9"},
    ]
    ctx, transport = make_context(cluster, {"_cat/indices": rows})
    queries.indices(ctx)
    assert transport.requests == [Request("GET", "_cat/indices", {"format": "json"})]
    summary, red, yellow = ctx.evidence.facts
    assert summary.summary == "3 indices: green=1, yellow=1, red=1"
    assert summary.data["counts"] == {"green": 1, "yellow": 1, "red": 1}
    assert red.resource == "index/app-logs-3" and "red" in red.summary
    assert yellow.resource == "index/app-logs-2"
    assert all(fact.kind == "current" for fact in ctx.evidence.facts)
    assert_all_pass_policy(transport, cluster)


def test_indices_with_a_pattern_uses_the_pattern_path(cluster):
    ctx, transport = make_context(cluster, {"_cat/indices/app-logs-*": []})
    queries.indices(ctx, "app-logs-*")
    assert transport.requests[0].path == "_cat/indices/app-logs-*"
    assert ctx.evidence.facts[0].summary == "0 indices"
    assert_all_pass_policy(transport, cluster)


def test_indices_caps_at_fifty_and_marks_truncation(cluster):
    rows = [{"health": "yellow", "index": f"app-logs-{n:03}", "status": "open"} for n in range(80)]
    ctx, transport = make_context(cluster, {"_cat/indices": rows})
    queries.indices(ctx)
    assert len(ctx.evidence.facts) == 51
    assert ctx.evidence.truncated is True
    assert ctx.evidence.facts[0].data["counts"] == {"yellow": 80}


# shards

def test_shards_lists_only_shards_that_are_not_started(cluster):
    rows = [
        {"index": "app-logs-1", "shard": "0", "prirep": "p", "state": "STARTED", "node": "data-1"},
        {"index": "app-logs-2", "shard": "1", "prirep": "r", "state": "UNASSIGNED", "node": None,
         "unassigned.reason": "NODE_LEFT"},
    ]
    ctx, transport = make_context(cluster, {"_cat/shards": rows})
    queries.shards(ctx)
    assert transport.requests == [Request("GET", "_cat/shards", {"format": "json"})]
    summary, shard = ctx.evidence.facts
    assert summary.summary == "2 shards, 1 not STARTED"
    assert shard.kind == "current"
    assert shard.summary == "Shard 1 (replica) of app-logs-2 is UNASSIGNED (reason NODE_LEFT)"
    assert_all_pass_policy(transport, cluster)


def test_shards_caps_at_fifty(cluster):
    rows = [{"index": "app-logs-1", "shard": str(n), "prirep": "r", "state": "INITIALIZING", "node": "n"} for n in range(70)]
    ctx, _ = make_context(cluster, {"_cat/shards": rows})
    queries.shards(ctx)
    assert len(ctx.evidence.facts) == 51
    assert ctx.evidence.truncated is True


# allocation explain

def test_allocation_explain_states_index_shard_and_reason(cluster):
    answer = {"index": "app-logs-2", "shard": 1, "primary": False, "current_state": "unassigned",
              "unassigned_info": {"reason": "NODE_LEFT"},
              "allocate_explanation": "cannot allocate because allocation is not permitted to any of the nodes",
              "node_allocation_decisions": [
                  {"node_name": "data-1", "deciders": [
                      {"decider": "disk_threshold", "decision": "NO", "explanation": "the node is above the high watermark"},
                      {"decider": "same_shard", "decision": "YES", "explanation": "fine"}]}]}
    ctx, transport = make_context(cluster, {"_cluster/allocation/explain": answer})
    queries.allocation_explain(ctx)
    assert transport.requests == [Request("GET", "_cluster/allocation/explain")]
    (fact,) = ctx.evidence.facts
    assert fact.kind == "current"
    assert fact.resource == "index/app-logs-2"
    assert fact.summary.startswith("Shard 1 (replica) of app-logs-2 is unassigned")
    assert fact.data["blocking_deciders"] == ["data-1: disk_threshold: the node is above the high watermark"]
    assert "cannot allocate" in fact.excerpt
    assert_all_pass_policy(transport, cluster)


def test_allocation_explain_400_means_nothing_is_unassigned(cluster):
    body = {"error": {"reason": "unable to find any unassigned shards to explain"}}
    ctx, _ = make_context(cluster, {"_cluster/allocation/explain": (400, body)})
    queries.allocation_explain(ctx)
    (fact,) = ctx.evidence.facts
    assert fact.summary == "No shard is unassigned, so there is nothing to explain"


def test_allocation_explain_other_errors_propagate(cluster):
    ctx, _ = make_context(cluster, {"_cluster/allocation/explain": (503, {})})
    with pytest.raises(OpenSearchError):
        queries.allocation_explain(ctx)


# mapping

def test_mapping_flattens_fields_and_types(cluster):
    answer = {"app-logs-1": {"mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "message": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "kubernetes": {"properties": {"pod": {"type": "keyword"}}},
    }}}}
    ctx, transport = make_context(cluster, {"app-logs-*/_mapping": answer})
    queries.mapping(ctx, INDEX)
    assert transport.requests == [Request("GET", "app-logs-*/_mapping")]
    (fact,) = ctx.evidence.facts
    assert fact.kind == "current"
    assert fact.data["fields"] == {"@timestamp": "date", "message": "text", "message.keyword": "keyword",
                                   "kubernetes.pod": "keyword"}
    assert fact.summary == "app-logs-* has 4 fields"
    assert "kubernetes.pod:keyword" in fact.excerpt
    assert_all_pass_policy(transport, cluster)


def test_mapping_caps_at_two_hundred_fields(cluster):
    properties = {f"field_{n:03}": {"type": "keyword"} for n in range(250)}
    answer = {"app-logs-1": {"mappings": {"properties": properties}}}
    ctx, _ = make_context(cluster, {"app-logs-*/_mapping": answer})
    queries.mapping(ctx, INDEX)
    (fact,) = ctx.evidence.facts
    assert len(fact.data["fields"]) == 200
    assert fact.summary == "app-logs-* has 250 fields, 200 listed"
    assert ctx.evidence.truncated is True


# count

def test_count_sends_only_a_query_and_states_the_number(cluster):
    ctx, transport = make_context(cluster, {"app-logs-*/_count": {"count": 1234}})
    queries.count(ctx, INDEX, query="level:ERROR", filters={"service": "checkout"})
    (request,) = transport.requests
    assert request.method == "POST" and request.path == "app-logs-*/_count"
    assert request.body == {"query": {"bool": {
        "filter": [range_filter(), {"term": {"service": "checkout"}}],
        "must": [{"query_string": {"query": "level:ERROR", "allow_leading_wildcard": False, "lenient": True}}]}}}
    (fact,) = ctx.evidence.facts
    assert fact.kind == "derived"
    assert fact.summary == (
        "1234 documents in app-logs-* between 2026-10-04T10:00:00Z and 2026-10-04T11:00:00Z "
        "matching level:ERROR with service=checkout"
    )
    assert fact.data["count"] == 1234
    assert_all_pass_policy(transport, cluster)


def test_count_without_filters_says_all_documents(cluster):
    ctx, _ = make_context(cluster, {"app-logs-*/_count": {"count": 0}})
    queries.count(ctx, INDEX)
    assert ctx.evidence.facts[0].summary.endswith("2026-10-04T11:00:00Z")


# histogram

def buckets(*pairs):
    return {"aggregations": {"by_time": {"buckets": [
        {"key": key, "key_as_string": "x", "doc_count": count} for key, count in pairs]}}}


MS_10_00 = 1791108000000  # 2026-10-04T10:00:00Z


def test_histogram_request_and_facts(cluster):
    answer = buckets((MS_10_00, 3), (MS_10_00 + 300000, 40), (MS_10_00 + 600000, 0), (MS_10_00 + 900000, 7))
    ctx, transport = make_context(cluster, {"app-logs-*/_search": answer})
    queries.histogram(ctx, INDEX, interval="5m", query="level:ERROR")
    (request,) = transport.requests
    assert request.body["size"] == 0
    assert request.body["aggs"] == {"by_time": {"date_histogram": {
        "field": "@timestamp", "fixed_interval": "5m", "min_doc_count": 1}}}
    assert request.body["query"]["bool"]["must"][0]["query_string"]["query"] == "level:ERROR"
    *timed, peak = ctx.evidence.facts
    assert [f.kind for f in timed] == ["incident_time"] * 3
    assert timed[0].time == "2026-10-04T10:00:00Z"
    assert timed[1].summary == "40 documents in the 5m bucket starting 2026-10-04T10:05:00Z"
    assert peak.kind == "derived"
    assert peak.summary == "Peak: 40 documents in the 5m bucket starting 2026-10-04T10:05:00Z, 50 documents in all"
    assert_all_pass_policy(transport, cluster)


def test_histogram_caps_at_one_hundred_buckets_keeping_the_largest(cluster):
    pairs = [(MS_10_00 + n * 60000, n + 1) for n in range(150)]
    ctx, _ = make_context(cluster, {"app-logs-*/_search": buckets(*pairs)})
    queries.histogram(ctx, INDEX, interval="1m")
    *timed, peak = ctx.evidence.facts
    assert len(timed) == 100
    assert ctx.evidence.truncated is True
    assert min(f.data["count"] for f in timed) == 51
    assert [f.time for f in timed] == sorted(f.time for f in timed)
    assert peak.data["count"] == 150


def test_histogram_with_no_documents_says_so(cluster):
    ctx, _ = make_context(cluster, {"app-logs-*/_search": buckets()})
    queries.histogram(ctx, INDEX)
    (fact,) = ctx.evidence.facts
    assert fact.kind == "derived" and fact.summary.startswith("No documents")


def test_histogram_rejects_an_interval_the_policy_does_not_allow(cluster):
    ctx, transport = make_context(cluster, {})
    with pytest.raises(Refused):
        queries.histogram(ctx, INDEX, interval="10m")
    assert transport.requests == []


# top messages

def terms(*pairs, total=100):
    return {"hits": {"total": {"value": total}},
            "aggregations": {"top_messages": {"buckets": [{"key": k, "doc_count": c} for k, c in pairs]}}}


def test_top_messages_uses_a_keyword_terms_aggregation(cluster):
    ctx, transport = make_context(cluster, {"app-logs-*/_search": terms(("db timeout", 30), ("oom", 5))})
    queries.top_messages(ctx, INDEX)
    (request,) = transport.requests
    assert request.body["size"] == 0
    assert request.body["aggs"] == {"top_messages": {"terms": {"field": "message.keyword", "size": 20}}}
    first, second = ctx.evidence.facts
    assert first.kind == "derived"
    assert first.summary == "30 occurrences of: db timeout"
    assert first.data == {"message": "db timeout", "count": 30, "method": "terms aggregation"}
    assert second.data["count"] == 5
    assert_all_pass_policy(transport, cluster)


def test_top_messages_custom_field(cluster):
    ctx, transport = make_context(cluster, {"app-logs-*/_search": terms(("a", 1))})
    queries.top_messages(ctx, INDEX, field="log")
    assert transport.requests[0].body["aggs"]["top_messages"]["terms"]["field"] == "log.keyword"


def hit(message, time="2026-10-04T10:01:00Z", **extra):
    return {"_index": "app-logs-1", "_source": {"@timestamp": time, "message": message, **extra}}


def test_top_messages_falls_back_to_grouping_hits_when_the_cluster_errors(cluster):
    hits = {"hits": {"total": {"value": 3}, "hits": [
        hit("timeout after 3000 ms for request 7f3a9c21e8b4"),
        hit("timeout after 250 ms for request 00aa11bb22cc"),
        hit("disk full on node 7"),
    ]}}
    ctx, transport = make_context(cluster, {"app-logs-*/_search": Sequence([(400, {"error": "no keyword"}), hits])})
    queries.top_messages(ctx, INDEX)
    assert len(transport.requests) == 2
    assert "aggs" not in transport.requests[1].body
    assert transport.requests[1].body["size"] == 50
    first, second = ctx.evidence.facts
    assert first.data == {"message": "timeout after # ms for request #", "count": 2,
                          "method": "grouped sample of 3 hits"}
    assert first.summary == "2 of 3 sampled hits: timeout after # ms for request #"
    assert second.data["message"] == "disk full on node #"
    assert_all_pass_policy(transport, cluster)


def test_top_messages_falls_back_when_the_keyword_field_matches_nothing(cluster):
    empty = terms(total=2)
    hits = {"hits": {"total": {"value": 2}, "hits": [hit("a 1"), hit("a 2")]}}
    ctx, transport = make_context(cluster, {"app-logs-*/_search": Sequence([empty, hits])})
    queries.top_messages(ctx, INDEX)
    assert len(transport.requests) == 2
    assert ctx.evidence.facts[0].data["count"] == 2


def test_top_messages_network_errors_are_not_masked_by_the_fallback(cluster):
    ctx, _ = make_context(cluster, {})

    def broken(*args):
        raise OSError("down")

    ctx.client._transport = broken
    with pytest.raises(OpenSearchError):
        queries.top_messages(ctx, INDEX)


@pytest.mark.parametrize("message, expected", [
    ("retry 3 of 10", "retry # of #"),
    ("request 7f3a9c21e8b4 failed", "request # failed"),
    ("trace 3f2b8c1a-9d1e-4b6a-8c3d-0123456789ab done", "trace # done"),
    ("short ab12cd34 id", "short # id"),
    ("abc1234 stays partly", "abc# stays partly"),
    ("deployment checkout-api ready", "deployment checkout-api ready"),
])
def test_normalise_message(message, expected):
    assert queries.normalise_message(message) == expected


def test_top_messages_fallback_keeps_at_most_twenty_groups(cluster):
    hits = {"hits": {"total": {"value": 30}, "hits": [hit(f"kind{chr(97 + n)} happened") for n in range(26)]}}
    ctx, _ = make_context(cluster, {"app-logs-*/_search": Sequence([(400, {}), hits])})
    queries.top_messages(ctx, INDEX)
    assert len(ctx.evidence.facts) == 20


# search

def test_search_one_fact_per_hit_with_only_the_allowed_fields(cluster):
    hits = {"hits": {"total": {"value": 2}, "hits": [
        hit("db timeout", level="ERROR", service="checkout", secret_blob="drop me", other="x"),
        hit("recovered", time="2026-10-04T10:02:30Z", service="checkout"),
    ]}}
    ctx, transport = make_context(cluster, {"app-logs-*/_search": hits})
    queries.search(ctx, INDEX, filters={"service": "checkout"}, size=10)
    (request,) = transport.requests
    assert request.body["size"] == 10
    assert request.body["sort"] == [{"@timestamp": {"order": "asc"}}]
    first, second = ctx.evidence.facts
    assert first.kind == "incident_time" and first.time == "2026-10-04T10:01:00Z"
    assert first.excerpt == "db timeout"
    assert first.resource == "app-logs-1"
    assert first.data == {"@timestamp": "2026-10-04T10:01:00Z", "level": "ERROR", "service": "checkout"}
    assert second.data == {"@timestamp": "2026-10-04T10:02:30Z", "service": "checkout"}
    assert ctx.evidence.truncated is False
    assert_all_pass_policy(transport, cluster)


def test_search_size_is_clamped_to_the_limit(cluster):
    ctx, transport = make_context(cluster, {"app-logs-*/_search": {"hits": {"total": {"value": 0}, "hits": []}}})
    queries.search(ctx, INDEX, size=5000)
    assert transport.requests[0].body["size"] == 50
    assert ctx.evidence.facts[0].summary.startswith("No documents")


def test_search_marks_truncation_when_more_documents_match(cluster):
    hits = {"hits": {"total": {"value": 900}, "hits": [hit("a")]}}
    ctx, _ = make_context(cluster, {"app-logs-*/_search": hits})
    queries.search(ctx, INDEX, size=1)
    assert ctx.evidence.truncated is True


def test_search_redacts_secret_looking_text_in_a_hit(cluster):
    secret = "AKIA" + "B" * 16
    hits = {"hits": {"total": {"value": 1}, "hits": [hit(f"login with key {secret} failed", token_value="x")]}}
    ctx, _ = make_context(cluster, {"app-logs-*/_search": hits})
    queries.search(ctx, INDEX)
    output = ctx.evidence.to_json()
    assert secret not in output
    assert "<SECRET-1>" in ctx.evidence.facts[0].excerpt


def test_top_messages_redacts_secret_looking_text(cluster):
    secret = "AKIA" + "C" * 16
    ctx, _ = make_context(cluster, {"app-logs-*/_search": terms((f"key {secret} rejected", 4))})
    queries.top_messages(ctx, INDEX)
    assert secret not in ctx.evidence.to_json()


def test_search_handles_epoch_millis_and_dotted_message_field(config_data):
    config_data["opensearch_clusters"]["logs-prod"]["message_field"] = "log.message"
    cluster = config_module.parse_config(config_data).opensearch_clusters["logs-prod"]
    hits = {"hits": {"total": {"value": 1}, "hits": [
        {"_index": "app-logs-1", "_source": {"@timestamp": MS_10_00, "log": {"message": "nested"}}}]}}
    ctx, _ = make_context(cluster, {"app-logs-*/_search": hits})
    queries.search(ctx, INDEX)
    fact = ctx.evidence.facts[0]
    assert fact.excerpt == "nested" and fact.time == "2026-10-04T10:00:00Z"
