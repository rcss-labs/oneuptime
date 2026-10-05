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
        "CPUUtilization (Average): lowest 46 at 2026-10-04T10:40:00Z, highest 96.2 at 2026-10-04T10:41:00Z; "
        "71.1 during the incident against 23.5 in the same hours one week earlier; "
        "rose above the range of one week earlier at 2026-10-04T10:40:00Z"
    )
    assert facts[0].kind == INCIDENT_TIME
    assert facts[0].time == "2026-10-04T10:40:00Z"
    assert facts[0].resource == "service/checkout"
    assert facts[0].data["maximum"] == 96.2 and facts[0].data["direction"] == "rose"


def test_summary_wording_about_the_same(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [50.0], [48.0])
    assert facts[0].summary.endswith("; about the same as one week earlier")
    assert facts[0].data["direction"] == "unchanged" and facts[0].data["notable"] is False


def test_summary_wording_lower(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [10.0], [40.0])
    assert "fell below the range of one week earlier at 2026-10-04T10:40:00Z" in facts[0].summary


def test_summary_wording_no_baseline(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [10.0], [])
    assert facts[0].summary.endswith("10 during the incident; no comparable baseline")
    assert "one week earlier" not in facts[0].summary


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
    assert "lowest 0 from 2026-10-04T10:40:00Z to 2026-10-04T10:41:00Z" in facts[0].summary
    assert "0 during the incident against 5 in the same hours one week earlier" in facts[0].summary
    assert "fell below" in facts[0].summary


def test_zero_baseline_with_activity(tmp_path, config_data):
    facts, summaries = facts_for(tmp_path, config_data, [7.0], [0.0])
    assert summaries[0].change_ratio is None
    assert "against 0 in the same hours one week earlier" in facts[0].summary
    assert "rose above the range of one week earlier" in facts[0].summary


def test_zero_in_both_periods(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [0.0], [0.0])
    assert facts[0].summary.endswith("; zero in both periods")
    assert facts[0].data["notable"] is False


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


def test_numbers_have_three_significant_figures(tmp_path, config_data):
    facts, _ = facts_for(tmp_path, config_data, [0.000000001], [5.0])
    assert "1e-09 during the incident" in facts[0].summary
    assert "5000000000" not in facts[0].summary
    facts, _ = facts_for(tmp_path, config_data, [12345.6], [100.0])
    assert "highest 12300 at" in facts[0].summary
    assert "e+" not in facts[0].summary


def test_odd_numbers_read_sensibly(tmp_path, config_data):
    from triage.metrics import _num
    assert _num(-0.0) == "0"
    assert _num(float("nan")) == "not a number"
    assert _num(float("inf")) == "not a number"
    assert _num(float("-inf")) == "not a number"
    assert _num(1e300) == "1e+300"
    assert _num(-1e-9) == "-1e-09"
    assert _num(17.0) == "17"
    assert _num(999.5) == "1000"
    assert _num(0) == "0"


# Metric peak order: the AWS CLI returns points newest first, fixtures often oldest first.

TIES_TIMES = ["2026-10-04T10:00:00+00:00", "2026-10-04T10:05:00+00:00", "2026-10-04T10:10:00+00:00", "2026-10-04T10:15:00+00:00"]


def _peak_fact(tmp_path, config_data, times, values, name):
    case = tmp_path / name
    case.mkdir()
    ctx = ctx_with(case, config_data, reply(series(0, times, values)), reply())
    add_metric_facts(ctx, "service/checkout", [CPU])
    return ctx.evidence.facts[0]


def test_the_same_points_in_either_order_give_the_same_fact(tmp_path, config_data):
    values = [40.0, 85.0, 60.0, 85.0]
    oldest_first = _peak_fact(tmp_path, config_data, TIES_TIMES, values, "a")
    newest_first = _peak_fact(tmp_path, config_data, TIES_TIMES[::-1], values[::-1], "b")
    assert oldest_first.summary == newest_first.summary
    assert oldest_first.time == newest_first.time == "2026-10-04T10:05:00Z"
    assert "highest 85 at 2026-10-04T10:05:00Z" in oldest_first.summary


def test_a_peak_held_over_three_points_says_from_and_to(tmp_path, config_data):
    values = [40.0, 85.0, 85.0, 85.0]
    for name, times, ordered in (("a", TIES_TIMES, values), ("b", TIES_TIMES[::-1], values[::-1])):
        fact = _peak_fact(tmp_path, config_data, times, ordered, name)
        assert "highest 85 from 2026-10-04T10:05:00Z to 2026-10-04T10:15:00Z" in fact.summary
        assert fact.data["maximum_time"] == "2026-10-04T10:05:00Z"
        assert fact.data["peak_time"] == "2026-10-04T10:05:00Z"
        assert fact.data["peak_end"] == "2026-10-04T10:15:00Z"


def test_a_flat_series_holds_its_peak_for_the_whole_window(tmp_path, config_data):
    fact = _peak_fact(tmp_path, config_data, TIES_TIMES[::-1], [12.0] * 4, "a")
    assert "highest 12 from 2026-10-04T10:00:00Z to 2026-10-04T10:15:00Z" in fact.summary
    assert "lowest 12 from 2026-10-04T10:00:00Z to 2026-10-04T10:15:00Z" in fact.summary


def test_a_single_point_peak_has_no_end(tmp_path, config_data):
    fact = _peak_fact(tmp_path, config_data, TIES_TIMES[::-1], [1.0, 2.0, 9.0, 3.0], "a")
    assert "highest 9 at 2026-10-04T10:05:00Z" in fact.summary
    assert fact.data["peak_end"] is None


# notable: whether a metric fact is worth a line on a timeline

BASE_TIMES = ["2026-09-27T10:00:00+00:00", "2026-09-27T10:05:00+00:00"]


def _fact_for(tmp_path, config_data, name, window_values, baseline_values):
    case = tmp_path / name
    case.mkdir()
    window = reply(series(0, TIES_TIMES[: len(window_values)], window_values)) if window_values else reply()
    baseline = reply(series(0, BASE_TIMES[: len(baseline_values)], baseline_values)) if baseline_values else reply()
    ctx = ctx_with(case, config_data, window, baseline)
    add_metric_facts(ctx, "service/checkout", [CPU])
    return ctx.evidence.facts[0]


def test_notable_follows_the_direction(tmp_path, config_data):
    cases = {
        "higher": ([80.0, 90.0], [20.0, 20.0], "rose above", True),
        "lower": ([5.0, 5.0], [40.0, 40.0], "fell below", True),
        "to-zero": ([0.0, 0.0], [40.0, 40.0], "fell below", True),
        "same": ([20.0, 22.0], [20.0, 21.0], "about the same", False),
        "zero": ([0.0, 0.0], [0.0, 0.0], "zero in both periods", False),
    }
    for name, (window_values, baseline_values, words, notable) in cases.items():
        fact = _fact_for(tmp_path, config_data, name, window_values, baseline_values)
        assert words in fact.summary, name
        assert fact.data["notable"] is notable, name


def test_without_a_baseline_only_a_moving_series_is_notable(tmp_path, config_data):
    moving = _fact_for(tmp_path, config_data, "moving", [10.0, 70.0], [])
    flat = _fact_for(tmp_path, config_data, "flat", [30.0, 30.0], [])
    assert "no comparable baseline" in moving.summary and moving.data["notable"] is True
    assert "no comparable baseline" in flat.summary and flat.data["notable"] is False


def test_a_fact_with_no_data_is_not_notable(tmp_path, config_data):
    fact = _fact_for(tmp_path, config_data, "empty", [], [20.0])
    assert "no data was returned" in fact.summary
    assert fact.data["notable"] is False


def test_data_carries_the_contract_keys(tmp_path, config_data):
    fact = _fact_for(tmp_path, config_data, "keys", [80.0, 90.0], [20.0, 20.0])
    for key in ("minimum", "minimum_time", "maximum", "maximum_time", "incident_average", "baseline_average",
                "first_departure_time", "direction", "notable"):
        assert key in fact.data, key


# Final review I-1: the reviewer's three cases

def _window_ctx(tmp_path, config_data, start, end, window_reply, baseline_reply):
    config = parse_config(config_data)
    window = make_window(start, end, 12)
    evidence = Evidence("ecs", "prod-main", "eu-west-1", window)
    ctx = CollectContext(config, config.accounts["prod-main"], "eu-west-1", window, evidence, tmp_path, runner=FakeAws({}))
    ctx.runner = Sequenced(window_reply, baseline_reply)
    return ctx


def _every(start_hour, start_minute, count, step_minutes, week_earlier=False):
    from datetime import datetime, timedelta, timezone
    first = datetime(2026, 10, 4, start_hour, start_minute, tzinfo=timezone.utc) - timedelta(days=7 if week_earlier else 0)
    return [(first + timedelta(minutes=step_minutes * n)).strftime("%Y-%m-%dT%H:%M:%SZ") for n in range(count)]


def test_a_short_rise_before_the_incident_is_notable_and_says_when(tmp_path, config_data):
    times = _every(10, 0, 18, 5)  # a 90-minute window; the incident starts at 11:00
    values = [4000.0] * 18
    values[10] = values[11] = 8300.0  # 10:50 and 10:55
    spec = MetricSpec("RequestCount", "AWS/ApplicationELB", "RequestCount", {"LoadBalancer": "app/x/1"}, stat="Sum")
    ctx = _window_ctx(tmp_path, config_data, "2026-10-04T10:00:00Z", "2026-10-04T11:30:00Z",
                      reply(series(0, times, values)), reply(series(0, _every(10, 0, 18, 5, week_earlier=True), [4000.0] * 18)))
    add_metric_facts(ctx, "lb/x", [spec])
    fact = ctx.evidence.facts[0]
    assert fact.data["notable"] is True and fact.data["direction"] == "rose"
    assert fact.data["first_departure_time"] == "2026-10-04T10:50:00Z"
    assert fact.time == "2026-10-04T10:50:00Z"
    assert "highest 8300 from 2026-10-04T10:50:00Z to 2026-10-04T10:55:00Z" in fact.summary
    assert "rose above the range of one week earlier at 2026-10-04T10:50:00Z" in fact.summary
    assert "about the same" not in fact.summary


def test_free_storage_falling_to_zero_states_zero_and_its_time(tmp_path, config_data):
    times = _every(10, 0, 24, 5)
    values = [21.5e9 - n * 1.0e9 for n in range(22)] + [0.0, 0.0]
    spec = MetricSpec("FreeStorageSpace", "AWS/RDS", "FreeStorageSpace", {"DBInstanceIdentifier": "db"}, stat="Minimum")
    ctx = _window_ctx(tmp_path, config_data, "2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z",
                      reply(series(0, times, values)), reply(series(0, _every(10, 0, 24, 5, week_earlier=True), [22.5e9] * 24)))
    add_metric_facts(ctx, "db/db", [spec])
    fact = ctx.evidence.facts[0]
    assert "lowest 0 from 2026-10-04T11:50:00Z to 2026-10-04T11:55:00Z" in fact.summary
    assert fact.data["minimum"] == 0.0 and fact.data["minimum_time"] == "2026-10-04T11:50:00Z"
    assert fact.data["direction"] == "fell" and fact.data["notable"] is True
    assert "fell below the range of one week earlier at" in fact.summary


def test_a_one_period_cpu_spike_in_six_hours_is_notable(tmp_path, config_data):
    times = _every(6, 0, 72, 5)  # 06:00 to 11:55
    values = [25.0] * 72
    values[40] = 100.0  # 09:20
    ctx = _window_ctx(tmp_path, config_data, "2026-10-04T06:00:00Z", "2026-10-04T12:00:00Z",
                      reply(series(0, times, values)), reply(series(0, _every(6, 0, 72, 5, week_earlier=True), [24.0, 26.0] * 36)))
    add_metric_facts(ctx, "service/checkout", [CPU])
    fact = ctx.evidence.facts[0]
    assert fact.data["notable"] is True
    assert fact.data["first_departure_time"] == "2026-10-04T09:20:00Z"
    assert "highest 100 at 2026-10-04T09:20:00Z" in fact.summary


def test_an_unchanged_metric_is_still_written_and_not_notable(tmp_path, config_data):
    times = _every(10, 0, 24, 5)
    ctx = _window_ctx(tmp_path, config_data, "2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z",
                      reply(series(0, times, [24.0, 26.0] * 12)), reply(series(0, _every(10, 0, 24, 5, week_earlier=True), [25.0] * 24)))
    add_metric_facts(ctx, "service/checkout", [CPU])
    fact = ctx.evidence.facts[0]
    assert fact.data["notable"] is False and fact.data["direction"] == "unchanged"
    assert fact.data["first_departure_time"] is None
    assert fact.summary.endswith("about the same as one week earlier")


def test_the_incident_part_is_compared_with_the_same_hours_one_week_earlier(tmp_path, config_data):
    times = _every(10, 0, 24, 5)  # incident part: 11:00 onwards
    window_values = [10.0] * 12 + [30.0] * 12
    baseline_values = [10.0] * 12 + [20.0] * 12
    ctx = _window_ctx(tmp_path, config_data, "2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z",
                      reply(series(0, times, window_values)), reply(series(0, _every(10, 0, 24, 5, week_earlier=True), baseline_values)))
    add_metric_facts(ctx, "service/checkout", [CPU])
    fact = ctx.evidence.facts[0]
    assert fact.data["incident_average"] == 30.0 and fact.data["baseline_average"] == 20.0
    assert "30 during the incident against 20 in the same hours one week earlier" in fact.summary
