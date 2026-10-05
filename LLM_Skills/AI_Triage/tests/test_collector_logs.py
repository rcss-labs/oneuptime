import pytest

from helpers import assert_read_only, fact_summaries, make_context
from triage.collectors.logs import COLLECTOR, run_query

GROUPS = ["/aws/ecs/checkout", "/aws/ecs/payments"]
DEFAULT_PATTERN = "(?i)(error|exception|fatal|panic|timed? ?out|refused|denied|oom|killed)"


def row(**fields):
    return [{"field": name, "value": value} for name, value in fields.items()] + [{"field": "@ptr", "value": "p1"}]


def complete(*rows):
    return {"status": "Complete", "results": list(rows)}


class QueryAws:
    """Wraps FakeAws: start-query hands out ids q1, q2, ...; get-query-results answers by the id."""

    def __init__(self, fake, by_marker):
        self.fake, self.by_marker, self.queries = fake, by_marker, {}

    def __call__(self, argv, timeout):
        if argv[1:3] == ["logs", "start-query"]:
            text = argv[argv.index("--query-string") + 1]
            query_id = f"q{len(self.queries) + 1}"
            self.queries[query_id] = text
            self.fake.calls.append(argv)
            import json
            return 0, json.dumps({"queryId": query_id}), ""
        if argv[1:3] == ["logs", "get-query-results"]:
            text = self.queries[argv[argv.index("--query-id") + 1]]
            for marker, reply in self.by_marker.items():
                if marker in text:
                    self.fake.calls.append(argv)
                    import json
                    return 0, json.dumps(reply), ""
        return self.fake(argv, timeout)


def make(config_data, tmp_path, by_marker, extra=None):
    ctx, fake, kube = make_context(config_data, tmp_path, dict(extra or {}), collector="logs")
    ctx.runner = QueryAws(fake, by_marker)
    return ctx, fake, kube


def standard(buckets=None, patterns=None, lines=None):
    return {
        "stats count": complete(*(buckets if buckets is not None else [
            row(**{"bin(5m)": "2026-10-04 10:35:00.000", "matches": "3"}),
            row(**{"bin(5m)": "2026-10-04 10:40:00.000", "matches": "40"}),
            row(**{"bin(5m)": "2026-10-04 10:45:00.000", "matches": "7"}),
        ])),
        "| pattern @message": complete(*(patterns if patterns is not None else [
            row(**{"@pattern": "connection to <*> refused", "@sampleCount": "37"}),
        ])),
        "fields @timestamp": complete(*(lines if lines is not None else [
            row(**{"@timestamp": "2026-10-04 10:41:02.500", "@logStream": "app/1", "@message": "ERROR connection refused"}),
        ])),
    }


def run(config_data, tmp_path, by_marker, targets=None):
    ctx, fake, kube = make(config_data, tmp_path, by_marker)
    COLLECTOR.run(ctx, targets or {"log_groups": ",".join(GROUPS)})
    return ctx, fake, kube


# ---- run_query ----

class Sleeper:
    def __init__(self, on_sleep=None):
        self.calls, self.on_sleep = [], on_sleep

    def __call__(self, seconds):
        self.calls.append(seconds)
        if self.on_sleep:
            self.on_sleep(len(self.calls))


def query_context(config_data, tmp_path, status_answers):
    return make_context(config_data, tmp_path, {
        "logs start-query": {"queryId": "q-1"},
        "logs get-query-results": status_answers,
        "logs stop-query": {"success": True},
    }, collector="logs")


def test_run_query_polls_until_complete_and_drops_ptr(config_data, tmp_path):
    ctx, fake, _ = query_context(config_data, tmp_path, {"status": "Running", "results": []})
    sleeper = Sleeper(lambda n: fake.answers.update({"logs get-query-results": complete(row(a="1", b="2"))}))
    result = run_query(ctx, GROUPS, "fields @message", sleep=sleeper)
    assert result == [{"a": "1", "b": "2"}]
    assert sleeper.calls == [1]
    assert len(fake.called("logs", "get-query-results")) == 2
    assert not fake.called("logs", "stop-query")
    assert_read_only(ctx, fake)


def test_run_query_sends_groups_epoch_times_and_query(config_data, tmp_path):
    ctx, fake, _ = query_context(config_data, tmp_path, complete())
    run_query(ctx, GROUPS, "fields @message", sleep=Sleeper())
    argv = fake.called("logs", "start-query")[0]
    assert argv[argv.index("--log-group-names") + 1: argv.index("--log-group-names") + 3] == GROUPS
    start, end = ctx.window.epoch_seconds()
    assert argv[argv.index("--start-time") + 1] == str(start)
    assert argv[argv.index("--end-time") + 1] == str(end)
    assert argv[argv.index("--query-string") + 1] == "fields @message"


def test_run_query_failed_status_records_error(config_data, tmp_path):
    ctx, fake, _ = query_context(config_data, tmp_path, {"status": "Failed", "results": []})
    assert run_query(ctx, GROUPS, "q", sleep=Sleeper()) is None
    assert ctx.evidence.errors and "Failed" in ctx.evidence.errors[0]["message"]
    assert not fake.called("logs", "stop-query")


def test_run_query_gives_up_after_max_wait_and_stops_query(config_data, tmp_path):
    ctx, fake, _ = query_context(config_data, tmp_path, {"status": "Running", "results": []})
    sleeper = Sleeper()
    assert run_query(ctx, GROUPS, "q", sleep=sleeper, max_wait_seconds=3) is None
    assert sleeper.calls == [1, 1, 1]
    assert len(fake.called("logs", "stop-query")) == 1
    assert ctx.evidence.errors
    assert_read_only(ctx, fake)


def test_run_query_timeout_status_is_an_error_without_stop(config_data, tmp_path):
    ctx, fake, _ = query_context(config_data, tmp_path, {"status": "Timeout", "results": []})
    assert run_query(ctx, GROUPS, "q", sleep=Sleeper()) is None
    assert ctx.evidence.errors
    assert not fake.called("logs", "stop-query")


def test_run_query_start_failure_returns_none(config_data, tmp_path):
    ctx, fake, _ = make_context(config_data, tmp_path, {"logs start-query": (254, "An error occurred (AccessDeniedException) when calling the StartQuery operation: no")}, collector="logs")
    assert run_query(ctx, GROUPS, "q", sleep=Sleeper()) is None
    assert ctx.evidence.errors[0]["code"] == "AccessDeniedException"


# ---- collector ----

def test_declares_its_targets():
    assert COLLECTOR.name == "logs"
    assert COLLECTOR.required == ("log_groups",)
    assert COLLECTOR.optional == ("pattern",)


def test_sends_three_queries_with_the_default_pattern(config_data, tmp_path):
    ctx, fake, _ = run(config_data, tmp_path, standard())
    queries = [a[a.index("--query-string") + 1] for a in fake.called("logs", "start-query")]
    assert len(queries) == 3
    assert all(q.startswith(f"filter @message like /{DEFAULT_PATTERN}/ | ") for q in queries)
    assert "| stats count(*) as matches by bin(5m)" in queries[0]
    assert "| pattern @message | sort @sampleCount desc | limit 15" in queries[1]
    assert "| fields @timestamp, @logStream, @message | sort @timestamp asc | limit 20" in queries[2]
    assert_read_only(ctx, fake)


def test_custom_pattern_is_used(config_data, tmp_path):
    ctx, fake, _ = run(config_data, tmp_path, standard(), {"log_groups": GROUPS[0], "pattern": "boom"})
    queries = [a[a.index("--query-string") + 1] for a in fake.called("logs", "start-query")]
    assert all(q.startswith("filter @message like /boom/ | ") for q in queries)


def test_slash_in_pattern_is_escaped(config_data, tmp_path):
    ctx, fake, _ = run(config_data, tmp_path, standard(), {"log_groups": GROUPS[0], "pattern": "GET /health failed"})
    query = fake.called("logs", "start-query")[0]
    text = query[query.index("--query-string") + 1]
    assert text.startswith("filter @message like /GET \\/health failed/ | ")


def test_bucket_facts_and_peak_and_first_bucket(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, standard())
    summaries = fact_summaries(ctx)
    buckets = [f for f in ctx.evidence.facts if f.kind == "incident_time" and "matching log lines" in f.summary]
    assert [f.time for f in buckets] == ["2026-10-04T10:35:00Z", "2026-10-04T10:40:00Z", "2026-10-04T10:45:00Z"]
    assert "40 matching log lines" in buckets[1].summary
    derived = [s for s in summaries if "Peak" in s]
    assert len(derived) == 1
    assert "2026-10-04T10:40:00Z" in derived[0] and "40" in derived[0]
    assert "first" in derived[0] and "2026-10-04T10:35:00Z" in derived[0]


def test_pattern_and_line_facts(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, standard())
    pattern = [f for f in ctx.evidence.facts if f.kind == "derived" and f.excerpt == "connection to <*> refused"]
    assert pattern and "37" in pattern[0].summary
    line = [f for f in ctx.evidence.facts if f.excerpt == "ERROR connection refused"]
    assert line[0].kind == "incident_time" and line[0].time == "2026-10-04T10:41:02Z"
    assert "app/1" in line[0].summary


def test_too_many_log_groups_uses_first_allowed(config_data, tmp_path):
    limit = make_context(config_data, tmp_path, {})[0].config.limits["logs_insights_max_log_groups"]
    groups = [f"/aws/app/g{i}" for i in range(limit + 2)]
    ctx, fake, _ = run(config_data, tmp_path, standard(), {"log_groups": ",".join(groups)})
    argv = fake.called("logs", "start-query")[0]
    sent = argv[argv.index("--log-group-names") + 1: argv.index("--start-time")]
    assert sent == groups[:limit]
    refusal = [f for f in ctx.evidence.facts if f.kind == "derived" and "limit" in f.summary]
    assert refusal and str(limit) in refusal[0].summary
    assert groups[-1] in refusal[0].summary and groups[0] not in refusal[0].summary


def test_empty_result_says_nothing_matched(config_data, tmp_path):
    ctx, fake, _ = run(config_data, tmp_path, standard(buckets=[], patterns=[], lines=[]))
    assert any("No log lines matched" in s for s in fact_summaries(ctx))
    assert not any("Peak" in s for s in fact_summaries(ctx))


def test_secret_looking_log_text_is_redacted(config_data, tmp_path):
    key = "AKIA" + "A" * 16
    password = "hunter" + "2" * 6
    lines = [row(**{"@timestamp": "2026-10-04 10:41:02.500", "@logStream": "s",
                    "@message": f"ERROR login failed password={password} key {key}"})]
    ctx, _, _ = run(config_data, tmp_path, standard(lines=lines))
    text = ctx.evidence.to_json()
    assert password not in text and key not in text
    assert "login failed" in text


def test_failed_query_is_recorded_and_others_continue(config_data, tmp_path):
    by_marker = standard()
    by_marker["stats count"] = {"status": "Failed", "results": []}
    ctx, _, _ = run(config_data, tmp_path, by_marker)
    assert ctx.evidence.errors
    assert any(f.excerpt == "ERROR connection refused" for f in ctx.evidence.facts)


def sent_query(fake):
    call = fake.called("logs", "start-query")[0]
    return call[call.index("--query-string") + 1]


def test_already_escaped_slash_is_not_escaped_again(config_data, tmp_path):
    ctx, fake, _ = run(config_data, tmp_path, standard(), {"log_groups": GROUPS[0], "pattern": "a\\/b c/d"})
    assert sent_query(fake).startswith("filter @message like /a\\/b c\\/d/ | ")


def test_escaped_backslash_before_slash_still_escapes_the_slash(config_data, tmp_path):
    pattern = "a\\\\/ | fields @message #"
    ctx, fake, _ = run(config_data, tmp_path, standard(), {"log_groups": GROUPS[0], "pattern": pattern})
    assert sent_query(fake).startswith("filter @message like /a\\\\\\/ | fields @message #/ | ")


def test_pattern_ending_in_a_backslash_is_refused_without_a_query(config_data, tmp_path):
    ctx, fake, _ = run(config_data, tmp_path, standard(), {"log_groups": GROUPS[0], "pattern": "C:\\"})
    assert not fake.called("logs", "start-query")
    facts = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert len(facts) == 1 and "not usable" in facts[0].summary


def test_pattern_ending_in_an_even_number_of_backslashes_is_allowed(config_data, tmp_path):
    ctx, fake, _ = run(config_data, tmp_path, standard(), {"log_groups": GROUPS[0], "pattern": "C:\\\\"})
    assert sent_query(fake).startswith("filter @message like /C:\\\\/ | ")


def test_bucket_facts_are_capped_at_sixty_keeping_the_highest_counts(config_data, tmp_path):
    rows = [row(**{"bin(5m)": f"2026-10-04 {10 + i // 12:02d}:{i % 12 * 5:02d}:00.000", "matches": str(i + 1)})
            for i in range(70)]
    ctx, _, _ = run(config_data, tmp_path, standard(buckets=rows))
    buckets = [f for f in ctx.evidence.facts if "matching log lines in the 5 minutes" in f.summary]
    assert len(buckets) == 60
    assert [f.time for f in buckets] == sorted(f.time for f in buckets)
    counts = [f.data["matches"] for f in buckets]
    assert 1 in counts and 11 not in counts and 12 in counts and max(counts) == 70
    derived = [f.summary for f in ctx.evidence.facts if "Peak" in f.summary]
    assert len(derived) == 1
    assert "10 other buckets were left out" in derived[0] and "lowest" not in derived[0]
    assert "with 70" in derived[0] and "first bucket with matches starts 2026-10-04T10:00:00Z" in derived[0]


def test_onset_and_peak_buckets_are_kept_when_the_cap_applies(config_data, tmp_path):
    rows = [row(**{"bin(5m)": f"2026-10-04 {10 + i // 12:02d}:{i % 12 * 5:02d}:00.000",
                   "matches": str(1 if i == 0 else 500 + i)}) for i in range(70)]
    peak_row = rows[10]
    peak_row[1]["value"] = "9999"
    ctx, _, _ = run(config_data, tmp_path, standard(buckets=rows))
    buckets = [f for f in ctx.evidence.facts if "matching log lines in the 5 minutes" in f.summary]
    assert len(buckets) == 60
    times = [f.time for f in buckets]
    assert times == sorted(times)
    assert "2026-10-04T10:00:00Z" in times
    assert "2026-10-04T10:50:00Z" in times


def test_unparseable_line_time_gives_a_derived_fact_without_time(config_data, tmp_path):
    lines = [row(**{"@timestamp": "not a time", "@logStream": "s1", "@message": "ERROR boom"}),
             row(**{"@timestamp": "2026-10-04 10:41:02.500", "@logStream": "s2", "@message": "ERROR fine"})]
    ctx, _, _ = run(config_data, tmp_path, standard(lines=lines))
    bad = [f for f in ctx.evidence.facts if f.excerpt == "ERROR boom"][0]
    assert bad.kind == "derived" and bad.time is None
    assert "could not be read" in bad.summary
    good = [f for f in ctx.evidence.facts if f.excerpt == "ERROR fine"][0]
    assert good.kind == "incident_time"


# Fix round 4

@pytest.mark.parametrize("answer", [{}, {"queryId": ""}, {"queryId": None}, []])
def test_start_query_answer_without_a_query_id_is_an_evidence_error(config_data, tmp_path, answer):
    ctx, fake, _ = make_context(config_data, tmp_path, {"logs start-query": answer}, collector="logs")
    assert run_query(ctx, GROUPS, "q", sleep=Sleeper()) is None
    assert [error["code"] for error in ctx.evidence.errors] == ["QueryNotStarted"]
    assert "queryId" in ctx.evidence.errors[0]["message"]
    assert not fake.called("logs", "get-query-results")
