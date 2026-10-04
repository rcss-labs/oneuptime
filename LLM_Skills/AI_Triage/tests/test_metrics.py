import json

from fakes import FakeAws
from triage.config import parse_config
from triage.context import CollectContext
from triage.evidence import DERIVED, INCIDENT_TIME, Evidence
from triage.metrics import MetricSpec, add_metric_facts, fetch
from triage.window import make_window

CPU = MetricSpec("CPUUtilization", "AWS/ECS", "CPUUtilization", {"ClusterName": "checkout"})
MEM = MetricSpec("MemoryUtilization", "AWS/ECS", "MemoryUtilization", {"ClusterName": "checkout"}, stat="Maximum")


def make_ctx(tmp_path, config_data, answers):
    config = parse_config(config_data)
    window = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", 6)
    evidence = Evidence("ecs", "prod-main", "eu-west-1", window)
    runner = FakeAws(answers)
    ctx = CollectContext(config, config.accounts["prod-main"], "eu-west-1", window, evidence, tmp_path, runner=runner)
    return ctx, runner


def series(index, times, values):
    return {"Id": f"m{index}", "Timestamps": times, "Values": values}


def reply(*results):
    return {"MetricDataResults": list(results)}


class Sequenced(FakeAws):
    """Answers the first get-metric-data call with the window and the second with the baseline."""

    def __init__(self, window_reply, baseline_reply):
        super().__init__({})
        self.replies = [window_reply, baseline_reply]

    def __call__(self, argv, timeout):
        self.answers["cloudwatch get-metric-data"] = self.replies[len(self.called("cloudwatch", "get-metric-data"))]
        return super().__call__(argv, timeout)


def ctx_with(tmp_path, config_data, window_reply, baseline_reply):
    ctx, _ = make_ctx(tmp_path, config_data, {})
    ctx.runner = Sequenced(window_reply, baseline_reply)
    return ctx


def arg(argv, name):
    return argv[argv.index(name) + 1]


def test_two_calls_with_window_and_week_earlier(tmp_path, config_data):
    ctx = ctx_with(tmp_path, config_data, reply(), reply())
    fetch(ctx, [CPU, MEM], period=60)
    first, second = ctx.runner.called("cloudwatch", "get-metric-data")
    assert arg(first, "--start-time") == "2026-10-04T10:00:00Z"
    assert arg(first, "--end-time") == "2026-10-04T12:00:00Z"
    assert arg(second, "--start-time") == "2026-09-27T10:00:00Z"
    assert arg(second, "--end-time") == "2026-09-27T12:00:00Z"
    queries = json.loads(arg(first, "--metric-data-queries"))
    assert [q["Id"] for q in queries] == ["m0", "m1"]
    assert queries[0]["MetricStat"]["Period"] == 60
    assert queries[0]["MetricStat"]["Stat"] == "Average"
    assert queries[1]["MetricStat"]["Stat"] == "Maximum"
    assert queries[0]["MetricStat"]["Metric"] == {
        "Namespace": "AWS/ECS",
        "MetricName": "CPUUtilization",
        "Dimensions": [{"Name": "ClusterName", "Value": "checkout"}],
    }


def test_rising_metric(tmp_path, config_data):
    times = ["2026-10-04T10:35:00+00:00", "2026-10-04T10:40:00+00:00", "2026-10-04T10:45:00+00:00"]
    base = ["2026-09-27T10:35:00+00:00", "2026-09-27T10:40:00+00:00"]
    ctx = ctx_with(tmp_path, config_data, reply(series(0, times, [20.0, 96.0, 40.0])), reply(series(0, base, [30.0, 40.0])))
    (summary,) = fetch(ctx, [CPU])
    assert summary.window_avg == 52.0
    assert summary.window_max == 96.0
    assert summary.window_min == 20.0
    assert summary.peak_time == "2026-10-04T10:40:00Z"
    assert summary.baseline_avg == 35.0
    assert summary.baseline_max == 40.0
    assert summary.datapoints == 3
    assert round(summary.change_ratio, 3) == round(52 / 35, 3)


def test_missing_baseline(tmp_path, config_data):
    ctx = ctx_with(tmp_path, config_data, reply(series(0, ["2026-10-04T10:35:00Z"], [5.0])), reply())
    (summary,) = fetch(ctx, [CPU])
    assert summary.baseline_avg is None
    assert summary.change_ratio is None


def test_zero_baseline_gives_no_ratio(tmp_path, config_data):
    ctx = ctx_with(
        tmp_path, config_data,
        reply(series(0, ["2026-10-04T10:35:00Z"], [5.0])), reply(series(0, ["2026-09-27T10:35:00Z"], [0.0])),
    )
    (summary,) = fetch(ctx, [CPU])
    assert summary.baseline_avg == 0.0
    assert summary.change_ratio is None


def test_no_datapoints(tmp_path, config_data):
    ctx = ctx_with(tmp_path, config_data, reply(series(0, [], [])), reply())
    (summary,) = fetch(ctx, [CPU])
    assert summary.datapoints == 0
    assert summary.window_avg is None
    assert summary.window_max is None
    assert summary.peak_time is None


def test_failed_call_gives_empty_summaries_and_one_error(tmp_path, config_data):
    ctx, _ = make_ctx(tmp_path, config_data, {"cloudwatch get-metric-data": (254, "An error occurred (AccessDeniedException) x")})
    (summary,) = fetch(ctx, [CPU])
    assert summary.datapoints == 0
    assert len(ctx.evidence.errors) == 2


def facts_for(tmp_path, config_data, window_values, baseline_values):
    wt = [f"2026-10-04T10:{40 + i}:00+00:00" for i in range(len(window_values))]
    bt = [f"2026-09-27T10:{40 + i}:00+00:00" for i in range(len(baseline_values))]
    ctx = ctx_with(tmp_path, config_data, reply(series(0, wt, window_values)), reply(series(0, bt, baseline_values)))
    summaries = add_metric_facts(ctx, "service/checkout", [CPU])
    return ctx.evidence.facts, summaries


def test_summary_wording_higher(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [46.0, 96.2], [23.5])
    assert facts[0].summary == (
        "CPUUtilization (Average): peak 96.2 at 2026-10-04T10:41:00Z; "
        "window average 71.1 against 23.5 one week earlier (3.0 times higher)"
    )
    assert facts[0].kind == INCIDENT_TIME
    assert facts[0].time == "2026-10-04T10:41:00Z"
    assert facts[0].resource == "service/checkout"
    assert facts[0].data["window_max"] == 96.2


def test_summary_wording_about_the_same(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [50.0], [48.0])
    assert "(about the same)" in facts[0].summary


def test_summary_wording_lower(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [10.0], [40.0])
    assert "(4.0 times lower)" in facts[0].summary


def test_summary_wording_no_baseline(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [10.0], [])
    assert "no comparable baseline" in facts[0].summary
    assert "one week earlier" not in facts[0].summary
    assert "no baseline" not in facts[0].summary.replace("no comparable baseline", "")


def test_no_data_adds_a_derived_fact(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [], [])
    assert len(facts) == 1
    assert facts[0].kind == DERIVED
    assert "no data" in facts[0].summary.lower()


def test_one_fact_per_metric(tmp_path, config_data):
    t = ["2026-10-04T10:40:00Z"]
    ctx = ctx_with(
        tmp_path, config_data,
        reply(series(0, t, [1.0]), series(1, t, [2.0])), reply(),
    )
    summaries = add_metric_facts(ctx, "service/checkout", [CPU, MEM])
    assert len(summaries) == 2
    assert len(ctx.evidence.facts) == 2


def test_window_average_zero_with_baseline_does_not_crash(tmp_path, config_data):
    facts, summaries = facts_for(tmp_path, config_data, [0.0, 0.0], [5.0])
    assert summaries[0].change_ratio == 0.0
    assert "down to zero" in facts[0].summary
    assert "against 5.0 one week earlier" in facts[0].summary


def test_zero_baseline_with_activity(tmp_path, config_data):
    facts, summaries = facts_for(tmp_path, config_data, [7.0], [0.0])
    assert summaries[0].change_ratio is None
    assert "no comparable baseline" in facts[0].summary
    assert "no baseline data" not in facts[0].summary
    assert "from zero" in facts[0].summary or "zero one week earlier" in facts[0].summary


def test_zero_in_both_periods(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [0.0], [0.0])
    assert "zero in both periods" in facts[0].summary


def test_fact_command_is_the_window_call(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [1.0], [1.0])
    assert "2026-10-04T10:00:00Z" in facts[0].command
    assert "2026-09-27" not in facts[0].command


def test_region_is_passed_through(tmp_path, config_data):
    ctx = ctx_with(tmp_path, config_data, reply(), reply())
    add_metric_facts(ctx, "distribution/x", [CPU], region="us-east-1")
    calls = ctx.runner.called("cloudwatch", "get-metric-data")
    assert len(calls) == 2
    for call in calls:
        assert call[call.index("--region") + 1] == "us-east-1"


def test_fetch_region_is_passed_through(tmp_path, config_data):
    ctx = ctx_with(tmp_path, config_data, reply(), reply())
    fetch(ctx, [CPU], region="us-east-1")
    for call in ctx.runner.called("cloudwatch", "get-metric-data"):
        assert call[call.index("--region") + 1] == "us-east-1"


def test_failed_read_says_so(tmp_path, config_data):
    ctx, _ = make_ctx(tmp_path, config_data, {"cloudwatch get-metric-data": (254, "An error occurred (AccessDeniedException) x")})
    add_metric_facts(ctx, "service/x", [CPU])
    assert "could not be read" in ctx.evidence.facts[0].summary
