import json
from urllib.parse import parse_qsl, urlsplit

import pytest
import yaml

import opensearch_query
from triage.config import parse_config
from triage.opensearch.policy import Request, check_request

START = "2026-10-04T10:00:00Z"
END = "2026-10-04T11:00:00Z"
LIMITS = {"max_window_hours": 6, "opensearch_max_hits": 50, "opensearch_timeout_seconds": 10}

ANSWERS = {
    "_cluster/health": {"status": "green", "number_of_nodes": 3, "active_shards": 9,
                        "unassigned_shards": 0, "number_of_pending_tasks": 0},
    "_nodes/stats/jvm,fs,os,thread_pool": {"nodes": {"n1": {"name": "data-1"}}},
    "_cat/indices": [{"health": "green", "index": "app-logs-1"}],
    "_cat/shards": [{"index": "app-logs-1", "shard": "0", "prirep": "p", "state": "STARTED"}],
    "_cluster/allocation/explain": (400, {"error": "none"}),
    "app-logs-*/_mapping": {"app-logs-1": {"mappings": {"properties": {"message": {"type": "text"}}}}},
    "app-logs-*/_count": {"count": 7},
    "app-logs-*/_search": {
        "hits": {"total": {"value": 1}, "hits": [
            {"_index": "app-logs-1", "_source": {"@timestamp": START, "message": "boom"}}]},
        "aggregations": {
            "by_time": {"buckets": [{"key": 1791108000000, "doc_count": 4}]},
            "top_messages": {"buckets": [{"key": "boom", "doc_count": 4}]},
        },
    },
}


class FakeTransport:
    def __init__(self, answers=None, error=None):
        self.answers = ANSWERS if answers is None else answers
        self.error = error
        self.requests = []

    def __call__(self, method, url, body, timeout_seconds, verify_tls, ca_bundle):
        parts = urlsplit(url)
        self.requests.append(Request(method, parts.path.strip("/"), dict(parse_qsl(parts.query)),
                                     json.loads(body) if body else None))
        if self.error:
            raise self.error
        answer = self.answers[parts.path.strip("/")]
        status, payload = answer if isinstance(answer, tuple) else (200, answer)
        return status, json.dumps(payload)


@pytest.fixture
def skill_dir(tmp_path, config_data):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return tmp_path


def run(skill_dir, *argv, cluster="logs-prod", transport=None):
    transport = transport or FakeTransport()
    code = opensearch_query.main(
        [argv[0], "--cluster", cluster, *argv[1:], "--skill-dir", str(skill_dir)], transport=transport
    )
    return code, transport


WINDOWED = ["--index", "app-logs-*", "--start", START, "--end", END]
SUBCOMMANDS = [
    ("health", []),
    ("nodes", []),
    ("indices", []),
    ("shards", []),
    ("allocation-explain", []),
    ("mapping", ["--index", "app-logs-*"]),
    ("count", WINDOWED),
    ("histogram", WINDOWED + ["--interval", "15m"]),
    ("top-messages", WINDOWED),
    ("search", WINDOWED + ["--size", "5"]),
]


@pytest.mark.parametrize("name, extra", SUBCOMMANDS, ids=[name for name, _ in SUBCOMMANDS])
def test_each_subcommand_exits_0_with_an_opensearch_document(skill_dir, capsys, name, extra):
    code, transport = run(skill_dir, name, *extra)
    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["collector"] == "opensearch"
    assert document["account"] == "prod-main"
    assert document["region"] == "logs-prod"
    assert document["facts"]
    config = parse_config(yaml.safe_load((skill_dir / "config" / "triage-config.yaml").read_text()))
    cluster = config.opensearch_clusters["logs-prod"]
    assert transport.requests
    for request in transport.requests:
        check_request(request, cluster, LIMITS)


def test_the_window_is_reported_for_windowed_subcommands(skill_dir, capsys):
    run(skill_dir, "count", *WINDOWED)
    assert json.loads(capsys.readouterr().out)["window"] == {"start": START, "end": END}


def test_search_filters_and_query_reach_the_body(skill_dir, capsys):
    _, transport = run(skill_dir, "search", *WINDOWED, "--query", "level:ERROR",
                       "--filter", "service=checkout", "--filter", "env=prod", "--size", "5000")
    body = transport.requests[0].body
    assert body["size"] == 50
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"service": "checkout"}} in filters and {"term": {"env": "prod"}} in filters
    assert body["query"]["bool"]["must"][0]["query_string"]["query"] == "level:ERROR"


def test_top_messages_field_option(skill_dir, capsys):
    _, transport = run(skill_dir, "top-messages", *WINDOWED, "--field", "log")
    assert transport.requests[0].body["aggs"]["top_messages"]["terms"]["field"] == "log.keyword"


def test_indices_option_selects_the_pattern_path(skill_dir, capsys):
    transport = FakeTransport({"_cat/indices/app-logs-*": []})
    run(skill_dir, "indices", "--index", "app-logs-*", transport=transport)
    assert transport.requests[0].path == "_cat/indices/app-logs-*"


def test_an_index_outside_the_allowed_patterns_exits_5_and_sends_nothing(skill_dir, capsys):
    code, transport = run(skill_dir, "count", "--index", "secret-*", "--start", START, "--end", END)
    captured = capsys.readouterr()
    assert code == 5
    assert transport.requests == []
    assert "secret-*" in captured.err and captured.out == ""


@pytest.mark.parametrize("index", ["*", "_all", "app-logs-1,other-1"])
def test_broad_index_expressions_exit_5(skill_dir, index):
    code, transport = run(skill_dir, "mapping", "--index", index)
    assert code == 5 and transport.requests == []


def test_a_cluster_error_exits_6(skill_dir, capsys):
    transport = FakeTransport({"_cluster/health": (503, {"error": "down"})})
    code, _ = run(skill_dir, "health", transport=transport)
    assert code == 6
    assert "HTTP 503" in capsys.readouterr().err


def test_an_unreachable_cluster_exits_6(skill_dir, capsys):
    code, _ = run(skill_dir, "health", transport=FakeTransport(error=OSError("connection refused")))
    assert code == 6
    assert "connection refused" in capsys.readouterr().err


def test_an_unknown_cluster_exits_2(skill_dir, capsys):
    code, transport = run(skill_dir, "health", cluster="nope")
    assert code == 2 and transport.requests == []
    assert "logs-prod" in capsys.readouterr().err


def test_a_missing_config_exits_2(tmp_path, capsys):
    code, transport = run(tmp_path, "health")
    assert code == 2 and transport.requests == []


def test_a_window_longer_than_the_limit_exits_2(skill_dir, capsys):
    code, transport = run(skill_dir, "count", "--index", "app-logs-*", "--start", START,
                          "--end", "2026-10-04T20:00:00Z")
    assert code == 2 and transport.requests == []


def test_a_bad_time_exits_2(skill_dir):
    code, _ = run(skill_dir, "count", "--index", "app-logs-*", "--start", "yesterday", "--end", END)
    assert code == 2


def test_a_bad_filter_exits_2(skill_dir):
    transport = FakeTransport()
    with pytest.raises(SystemExit) as caught:
        run(skill_dir, "search", *WINDOWED, "--filter", "novalue", transport=transport)
    assert caught.value.code == 2 and transport.requests == []


@pytest.mark.parametrize("argv", [
    ["count", "--cluster", "logs-prod", "--start", START, "--end", END],
    ["count", "--cluster", "logs-prod", "--index", "app-logs-*"],
    ["mapping", "--cluster", "logs-prod"],
    ["histogram", "--cluster", "logs-prod", *WINDOWED, "--interval", "10m"],
    ["search", "--cluster", "logs-prod", *WINDOWED, "--size", "0"],
    ["delete", "--cluster", "logs-prod"],
    ["health"],
])
def test_usage_errors_exit_2(skill_dir, argv):
    with pytest.raises(SystemExit) as caught:
        opensearch_query.main(argv + ["--skill-dir", str(skill_dir)], transport=FakeTransport())
    assert caught.value.code == 2


def test_there_is_no_way_to_pass_a_raw_path_or_body(skill_dir):
    for option in ("--path", "--body", "--url", "--method"):
        with pytest.raises(SystemExit) as caught:
            opensearch_query.main(["health", "--cluster", "logs-prod", option, "x", "--skill-dir", str(skill_dir)],
                                  transport=FakeTransport())
        assert caught.value.code == 2


def test_case_dir_writes_the_evidence_file(skill_dir, tmp_path, capsys):
    case_dir = tmp_path / "case"
    code, _ = run(skill_dir, "count", *WINDOWED, "--case-dir", str(case_dir), "--suffix", "errors")
    path = case_dir / "evidence" / "opensearch-prod-main-logs-prod-errors.json"
    assert code == 0 and path.is_file()
    assert json.loads(path.read_text())["facts"][0]["data"]["count"] == 7
    assert "facts=1" in capsys.readouterr().out


def test_secret_looking_text_in_hits_is_redacted_in_the_output(skill_dir, capsys):
    secret = "AKIA" + "D" * 16
    answers = dict(ANSWERS)
    answers["app-logs-*/_search"] = {"hits": {"total": {"value": 1}, "hits": [
        {"_index": "app-logs-1", "_source": {"@timestamp": START, "message": f"key {secret} used"}}]}}
    code, _ = run(skill_dir, "search", *WINDOWED, transport=FakeTransport(answers))
    out = capsys.readouterr().out
    assert code == 0 and secret not in out and "<SECRET-1>" in out


# replay mode

def real_call_fails(*args, **kwargs):
    raise AssertionError("a real network call was made in replay mode")


def test_replay_mode_answers_from_fixtures_and_prints_the_banner_once(skill_dir, tmp_path, monkeypatch, capsys):
    replay = tmp_path / "replay"
    replay.mkdir()
    (replay / "opensearch.json").write_text(json.dumps([
        {"method": "GET", "path_contains": "_cluster/health", "status": 200, "body": ANSWERS["_cluster/health"]},
    ]))
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(replay))
    monkeypatch.setattr("urllib.request.OpenerDirector.open", real_call_fails)
    code = opensearch_query.main(["health", "--cluster", "logs-prod", "--skill-dir", str(skill_dir)])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["facts"]
    assert captured.err.count("REPLAY MODE") == 1
    assert f"REPLAY MODE: answers come from {replay}; nothing is called." in captured.err


def test_an_injected_transport_wins_over_the_environment(skill_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(tmp_path))
    code, transport = run(skill_dir, "health")
    assert code == 0
    assert transport.requests
    assert "REPLAY MODE" not in capsys.readouterr().err


def test_a_bad_fixture_directory_exits_2(skill_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(tmp_path / "nowhere"))
    monkeypatch.setattr("urllib.request.OpenerDirector.open", real_call_fails)
    code = opensearch_query.main(["health", "--cluster", "logs-prod", "--skill-dir", str(skill_dir)])
    assert code == 2
    assert "not a directory" in capsys.readouterr().err
