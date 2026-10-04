import json
import ssl
import urllib.request

import pytest

from triage.config import parse_config
from triage.opensearch import client as client_module
from triage.opensearch.client import (
    OpenSearchClient,
    OpenSearchError,
    SameHostRedirects,
    build_ssl_context,
)
from triage.opensearch.policy import Request

INDEX = "app-logs-2026.10.04"
LIMITS = {"max_window_hours": 6, "opensearch_max_hits": 50, "opensearch_timeout_seconds": 10}


@pytest.fixture
def cluster(config_data):
    return parse_config(config_data).opensearch_clusters["logs-prod"]


class RecordingTransport:
    def __init__(self, status=200, text="{}", error=None):
        self.calls = []
        self.status = status
        self.text = text
        self.error = error

    def __call__(self, method, url, body, timeout_seconds, verify_tls, ca_bundle):
        self.calls.append((method, url, body, timeout_seconds, verify_tls, ca_bundle))
        if self.error:
            raise self.error
        return self.status, self.text


def forbidden_transport(*args):
    pytest.fail("a refused request reached the transport")


def search_request():
    body = {
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "2026-10-04T10:00:00Z", "lte": "2026-10-04T11:00:00Z"}}}]}},
        "size": 5,
        "timeout": "10s",
        "terminate_after": 100000,
    }
    return Request("POST", f"{INDEX}/_search", {"filter_path": "hits.hits"}, body)


def test_a_refused_request_never_reaches_the_transport(cluster):
    client = OpenSearchClient(cluster, LIMITS, transport=forbidden_transport)
    for request in (
        Request("DELETE", f"{INDEX}/_search"),
        Request("POST", "_bulk", body={}),
        Request("GET", "_cluster/health", {"q": "x"}),
        Request("GET", "_cluster/../_cat/indices"),
    ):
        with pytest.raises(Exception) as caught:
            client.request(request)
        assert caught.type.__name__ == "Refused"


def test_url_and_body_are_built_from_the_cluster_endpoint(cluster):
    transport = RecordingTransport(text='{"hits": {"hits": []}}')
    client = OpenSearchClient(cluster, LIMITS, transport=transport)
    result = client.request(search_request())
    method, url, body, _, _, _ = transport.calls[0]
    assert method == "POST"
    assert url == f"https://opensearch.internal.example.com/{INDEX}/_search?filter_path=hits.hits"
    assert json.loads(body) == search_request().body
    assert result == {"hits": {"hits": []}}


def test_the_path_is_normalised_and_no_query_string_is_added_without_params(cluster):
    transport = RecordingTransport()
    OpenSearchClient(cluster, LIMITS, transport=transport).request(Request("GET", "/_cluster/health/"))
    method, url, body, *_ = transport.calls[0]
    assert (method, url, body) == ("GET", "https://opensearch.internal.example.com/_cluster/health", None)


def test_an_endpoint_with_a_trailing_slash_is_joined_cleanly(config_data):
    config_data["opensearch_clusters"]["logs-prod"]["endpoint"] = "https://opensearch.internal.example.com/"
    cluster = parse_config(config_data).opensearch_clusters["logs-prod"]
    transport = RecordingTransport()
    OpenSearchClient(cluster, LIMITS, transport=transport).request(Request("GET", "_nodes"))
    assert transport.calls[0][1] == "https://opensearch.internal.example.com/_nodes"


def test_params_are_url_encoded(cluster):
    transport = RecordingTransport()
    OpenSearchClient(cluster, LIMITS, transport=transport).request(
        Request("GET", "_cat/indices", {"h": "index,docs.count", "format": "json"})
    )
    assert transport.calls[0][1].endswith("/_cat/indices?h=index%2Cdocs.count&format=json")


def test_a_text_response_is_returned_as_text(cluster):
    transport = RecordingTransport(text="green open app-logs-1\n")
    result = OpenSearchClient(cluster, LIMITS, transport=transport).request(Request("GET", "_cat/indices"))
    assert result == "green open app-logs-1\n"


def test_the_timeout_is_the_limit_plus_five_seconds(cluster):
    transport = RecordingTransport()
    OpenSearchClient(cluster, dict(LIMITS, opensearch_timeout_seconds=20), transport=transport).request(
        Request("GET", "_nodes")
    )
    assert transport.calls[0][3] == 25


def test_tls_settings_default_to_verifying(cluster):
    transport = RecordingTransport()
    OpenSearchClient(cluster, LIMITS, transport=transport).request(Request("GET", "_nodes"))
    assert transport.calls[0][4:] == (True, None)


def test_tls_settings_are_passed_through(cluster):
    class Custom:
        endpoint = cluster.endpoint
        allowed_index_patterns = cluster.allowed_index_patterns
        time_field = cluster.time_field
        verify_tls = False
        ca_bundle = "/etc/ssl/example-ca.pem"

    transport = RecordingTransport()
    OpenSearchClient(Custom(), LIMITS, transport=transport).request(Request("GET", "_nodes"))
    assert transport.calls[0][4:] == (False, "/etc/ssl/example-ca.pem")


def test_an_http_error_raises_with_status_and_a_short_message(cluster):
    transport = RecordingTransport(status=503, text="x" * 1000)
    with pytest.raises(OpenSearchError) as caught:
        OpenSearchClient(cluster, LIMITS, transport=transport).request(Request("GET", "_nodes"))
    assert caught.value.status == 503
    assert "x" * 300 in str(caught.value)
    assert "x" * 301 not in str(caught.value)


def test_status_399_is_not_an_error(cluster):
    transport = RecordingTransport(status=399, text="{}")
    assert OpenSearchClient(cluster, LIMITS, transport=transport).request(Request("GET", "_nodes")) == {}


def test_a_network_failure_raises_with_no_status(cluster):
    transport = RecordingTransport(error=ConnectionRefusedError("connection refused"))
    with pytest.raises(OpenSearchError) as caught:
        OpenSearchClient(cluster, LIMITS, transport=transport).request(Request("GET", "_nodes"))
    assert caught.value.status is None
    assert "connection refused" in str(caught.value)


def test_ssl_context_verifies_by_default():
    context = build_ssl_context(True, None)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_ssl_context_can_skip_verification():
    context = build_ssl_context(False, None)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_ssl_context_loads_the_given_ca_bundle(monkeypatch):
    loaded = []
    real = ssl.create_default_context

    def fake_create(*, cafile=None, **kwargs):
        loaded.append(cafile)
        return real(**kwargs)

    monkeypatch.setattr(client_module.ssl, "create_default_context", fake_create)
    build_ssl_context(True, "/etc/ssl/example-ca.pem")
    assert loaded == ["/etc/ssl/example-ca.pem"]


def redirect(handler, target):
    request = urllib.request.Request("https://opensearch.internal.example.com/_nodes")
    return handler.redirect_request(request, None, 302, "Found", {}, target)


def test_a_redirect_to_another_host_is_refused():
    with pytest.raises(OpenSearchError) as caught:
        redirect(SameHostRedirects(), "https://elsewhere.example.com/_nodes")
    assert caught.value.status is None
    assert "redirect" in str(caught.value).lower()


@pytest.mark.parametrize(
    "target",
    ["http://opensearch.internal.example.com/_nodes", "https://opensearch.internal.example.com:9200/_nodes"],
)
def test_a_redirect_that_changes_scheme_or_port_is_refused(target):
    with pytest.raises(OpenSearchError):
        redirect(SameHostRedirects(), target)


def test_a_redirect_on_the_same_host_is_followed():
    followed = redirect(SameHostRedirects(), "https://opensearch.internal.example.com/_cluster/health")
    assert followed.full_url == "https://opensearch.internal.example.com/_cluster/health"
