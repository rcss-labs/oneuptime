import json

from helpers import assert_read_only, fact_summaries, make_context
from triage.collectors.alarms import COLLECTOR

IN_WINDOW = "2026-10-04T10:42:10.123000+00:00"
LATER = "2026-10-04T11:10:00+00:00"
OUTSIDE = "2026-10-04T07:00:00+00:00"


def alarm(name, state="ALARM"):
    return {
        "AlarmName": name, "StateValue": state, "StateReason": "Threshold Crossed: 3 datapoints were greater than 80",
        "MetricName": "CPUUtilization", "Namespace": "AWS/ECS", "Threshold": 80.0,
        "ComparisonOperator": "GreaterThanThreshold",
    }


def history(timestamp, old, new):
    data = {"oldState": {"stateValue": old}, "newState": {"stateValue": new}}
    return {"AlarmName": "x", "Timestamp": timestamp, "HistoryItemType": "StateUpdate",
            "HistorySummary": f"Alarm updated from {old} to {new}", "HistoryData": json.dumps(data)}


def run(config_data, tmp_path, answers, targets):
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="alarms")
    COLLECTOR.run(ctx, targets)
    return ctx, aws


def test_declares_its_targets():
    assert COLLECTOR.name == "alarms"
    assert COLLECTOR.required == ()
    assert COLLECTOR.optional == ("alarm_names", "name_prefix")
    assert COLLECTOR.one_of == ("alarm_names", "name_prefix")


def test_alarm_names_give_current_facts(config_data, tmp_path):
    answers = {
        "cloudwatch describe-alarms": {"MetricAlarms": [alarm("cpu-high"), alarm("mem-high", "OK")]},
        "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []},
    }
    ctx, aws = run(config_data, tmp_path, answers, {"alarm_names": "cpu-high,mem-high"})
    call = aws.called("cloudwatch", "describe-alarms")[0]
    assert call[call.index("--alarm-names") + 1: call.index("--alarm-names") + 3] == ["cpu-high", "mem-high"]
    current = [f for f in ctx.evidence.facts if f.kind == "current"]
    assert len(current) == 2
    text = current[0].summary
    for part in ("cpu-high", "ALARM", "CPUUtilization", "80", "GreaterThanThreshold"):
        assert part in text
    assert "Threshold Crossed" in current[0].summary + current[0].excerpt
    assert_read_only(ctx, aws)


def test_name_prefix_is_used_with_a_cap(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("checkout-cpu")]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}
    ctx, aws = run(config_data, tmp_path, answers, {"name_prefix": "checkout-"})
    call = aws.called("cloudwatch", "describe-alarms")[0]
    assert call[call.index("--alarm-name-prefix") + 1] == "checkout-"
    assert call[call.index("--max-items") + 1] == "50"
    assert "--alarm-names" not in call
    assert_read_only(ctx, aws)


def test_history_inside_window_only_and_first_alarm_fact(config_data, tmp_path):
    answers = {
        "cloudwatch describe-alarms": {"MetricAlarms": [alarm("cpu-high")]},
        "cloudwatch describe-alarm-history": {"AlarmHistoryItems": [
            history(LATER, "OK", "ALARM"),
            history(IN_WINDOW, "INSUFFICIENT_DATA", "OK"),
            history(OUTSIDE, "OK", "ALARM"),
        ]},
    }
    ctx, aws = run(config_data, tmp_path, answers, {"alarm_names": "cpu-high"})
    changes = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert [f.time for f in changes] == ["2026-10-04T10:42:10Z", "2026-10-04T11:10:00Z"]
    assert any("OK to ALARM" in f.summary for f in changes)
    first = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert len(first) == 1
    assert "cpu-high" in first[0].summary and "2026-10-04T11:10:00Z" in first[0].summary
    call = aws.called("cloudwatch", "describe-alarm-history")[0]
    assert call[call.index("--alarm-name") + 1] == "cpu-high"
    assert call[call.index("--history-item-type") + 1] == "StateUpdate"
    assert call[call.index("--start-date") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-date") + 1] == "2026-10-04T12:00:00Z"
    assert call[call.index("--max-items") + 1] == "20"
    assert_read_only(ctx, aws)


def test_first_alarm_is_the_earliest_across_alarms(config_data, tmp_path):
    answers = {
        "cloudwatch describe-alarms": {"MetricAlarms": [alarm("a-late"), alarm("b-early")]},
        "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []},
    }
    ctx, aws = make_context(config_data, tmp_path, answers, collector="alarms")[:2]
    original = aws.__call__

    def per_alarm(argv, timeout):
        if argv[1:3] == ["cloudwatch", "describe-alarm-history"]:
            name = argv[argv.index("--alarm-name") + 1]
            when = LATER if name == "a-late" else IN_WINDOW
            aws.calls.append(argv)
            return 0, json.dumps({"AlarmHistoryItems": [history(when, "OK", "ALARM")]}), ""
        return original(argv, timeout)

    ctx.runner = per_alarm
    COLLECTOR.run(ctx, {"alarm_names": "a-late,b-early"})
    first = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert "b-early" in first[0].summary and "2026-10-04T10:42:10Z" in first[0].summary


def test_history_limited_to_twenty_alarms(config_data, tmp_path):
    names = [f"alarm-{i}" for i in range(25)]
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm(n) for n in names]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}
    ctx, aws = run(config_data, tmp_path, answers, {"name_prefix": "alarm-"})
    assert len(aws.called("cloudwatch", "describe-alarm-history")) == 20
    assert len([f for f in ctx.evidence.facts if f.kind == "current"]) == 25


def test_no_alarms_found(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, {"cloudwatch describe-alarms": {"MetricAlarms": []}}, {"name_prefix": "nope-"})
    assert any("No alarms" in s for s in fact_summaries(ctx))
    assert not aws.called("cloudwatch", "describe-alarm-history")
    assert_read_only(ctx, aws)


def test_history_failure_is_recorded_and_collection_continues(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("cpu-high")]},
               "cloudwatch describe-alarm-history": (254, "An error occurred (AccessDeniedException) when calling the DescribeAlarmHistory operation: no")}
    ctx, _ = run(config_data, tmp_path, answers, {"alarm_names": "cpu-high"})
    assert ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert len([f for f in ctx.evidence.facts if f.kind == "current"]) == 1


def composite(name, state="ALARM"):
    return {"AlarmName": name, "StateValue": state, "StateReason": "child alarms in ALARM",
            "AlarmRule": "ALARM(cpu-high) AND ALARM(mem-high)"}


def test_composite_alarm_by_name_asks_for_both_types_and_reads_composites(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [], "CompositeAlarms": [composite("service-down")]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}
    ctx, aws = run(config_data, tmp_path, answers, {"alarm_names": "service-down"})
    call = aws.called("cloudwatch", "describe-alarms")[0]
    at = call.index("--alarm-types")
    assert call[at + 1: at + 3] == ["CompositeAlarm", "MetricAlarm"]
    current = [f for f in ctx.evidence.facts if f.kind == "current"]
    assert len(current) == 1
    assert "service-down" in current[0].summary and "ALARM" in current[0].summary
    assert "ALARM(cpu-high) AND ALARM(mem-high)" in current[0].summary
    assert "child alarms in ALARM" in current[0].excerpt
    assert "threshold" not in current[0].summary
    assert_read_only(ctx, aws)


def test_composite_alarm_by_prefix(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("svc-cpu")], "CompositeAlarms": [composite("svc-down")]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}
    ctx, aws = run(config_data, tmp_path, answers, {"name_prefix": "svc-"})
    call = aws.called("cloudwatch", "describe-alarms")[0]
    assert "--alarm-types" in call and "CompositeAlarm" in call and "MetricAlarm" in call
    assert len([f for f in ctx.evidence.facts if f.kind == "current"]) == 2


def test_history_is_requested_newest_first(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("cpu-high")]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": [history(IN_WINDOW, "OK", "ALARM")]}}
    ctx, aws = run(config_data, tmp_path, answers, {"alarm_names": "cpu-high"})
    call = aws.called("cloudwatch", "describe-alarm-history")[0]
    assert call[call.index("--scan-by") + 1] == "TimestampDescending"
    assert "CompositeAlarm" in call
    first = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert "cpu-high" in first[0].summary and "2026-10-04T10:42:10Z" in first[0].summary
    assert_read_only(ctx, aws)


def test_history_in_any_order_gives_earliest_alarm_time(config_data, tmp_path):
    items = [history("2026-10-04T10:30:00+00:00", "OK", "ALARM"), history("2026-10-04T10:31:00+00:00", "ALARM", "OK"),
             history("2026-10-04T10:50:00+00:00", "OK", "ALARM")]
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("cpu-high")]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": items}}
    ctx, _ = run(config_data, tmp_path, answers, {"alarm_names": "cpu-high"})
    first = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert "2026-10-04T10:30:00Z" in first[0].summary


def test_more_than_fifty_prefix_matches_is_said(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("svc-cpu")], "NextToken": "abc"},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}
    ctx, _ = run(config_data, tmp_path, answers, {"name_prefix": "svc-"})
    notes = [f for f in ctx.evidence.facts if f.kind == "derived" and "more alarms match" in f.summary.lower()]
    assert len(notes) == 1 and "50" in notes[0].summary


def test_no_next_token_means_no_note(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("svc-cpu")]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}
    ctx, _ = run(config_data, tmp_path, answers, {"name_prefix": "svc-"})
    assert not [f for f in ctx.evidence.facts if "more alarms match" in f.summary.lower()]


def history_by_alarm(config_data, tmp_path, alarms_reply, when_by_name, targets):
    ctx, aws, _ = make_context(config_data, tmp_path, {"cloudwatch describe-alarms": alarms_reply}, collector="alarms")
    original = aws.__call__

    def per_alarm(argv, timeout):
        if argv[1:3] == ["cloudwatch", "describe-alarm-history"]:
            aws.calls.append(argv)
            when = when_by_name.get(argv[argv.index("--alarm-name") + 1])
            items = [history(when, "OK", "ALARM")] if when else []
            return 0, json.dumps({"AlarmHistoryItems": items}), ""
        return original(argv, timeout)

    ctx.runner = per_alarm
    COLLECTOR.run(ctx, targets)
    return ctx, aws


def test_first_alarm_is_a_metric_alarm_and_a_tied_composite_is_named_second(config_data, tmp_path):
    reply = {"MetricAlarms": [alarm("m1")], "CompositeAlarms": [composite("c1")]}
    ctx, _ = history_by_alarm(config_data, tmp_path, reply, {"m1": IN_WINDOW, "c1": IN_WINDOW}, {"alarm_names": "m1,c1"})
    first = [f for f in ctx.evidence.facts if f.summary.startswith("The first alarm")]
    assert len(first) == 1
    assert "was m1 at 2026-10-04T10:42:10Z" in first[0].summary
    assert "c1" in first[0].summary and "composite" in first[0].summary


def test_composite_that_changed_later_is_not_mentioned(config_data, tmp_path):
    reply = {"MetricAlarms": [alarm("m1")], "CompositeAlarms": [composite("c1")]}
    ctx, _ = history_by_alarm(config_data, tmp_path, reply, {"m1": IN_WINDOW, "c1": LATER}, {"alarm_names": "m1,c1"})
    first = [f for f in ctx.evidence.facts if f.summary.startswith("The first alarm")]
    assert "c1" not in first[0].summary


def test_metric_alarms_get_history_before_composites_and_left_out_alarms_are_said(config_data, tmp_path):
    reply = {"CompositeAlarms": [composite(f"c{i}") for i in range(5)],
             "MetricAlarms": [alarm(f"m{i}") for i in range(18)]}
    ctx, aws = history_by_alarm(config_data, tmp_path, reply, {}, {"name_prefix": "x"})
    asked = [c[c.index("--alarm-name") + 1] for c in aws.called("cloudwatch", "describe-alarm-history")]
    assert len(asked) == 20
    assert all(f"m{i}" in asked for i in range(18))
    note = [f for f in ctx.evidence.facts if f.kind == "derived" and "history" in f.summary and "left out" in f.summary]
    assert len(note) == 1 and "3" in note[0].summary


def test_blank_prefix_beside_names_is_rejected_not_queried(config_data, tmp_path):
    answers = {"cloudwatch describe-alarms": {"MetricAlarms": [alarm("cpu-high")]},
               "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}
    ctx, aws = run(config_data, tmp_path, answers, {"alarm_names": "cpu-high", "name_prefix": "  "})
    assert all("--alarm-name-prefix" not in call for call in aws.called("cloudwatch", "describe-alarms"))
    assert ctx.evidence.errors and ctx.evidence.errors[0]["code"] == "InvalidTarget"


def test_names_with_only_commas_make_no_query(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, {}, {"alarm_names": " , ,"})
    assert not aws.calls
    assert ctx.evidence.errors and ctx.evidence.errors[0]["code"] == "InvalidTarget"


def stamp(step):
    """Step n is 50 seconds after 10:00:00 UTC, so 130 steps still fit inside the two hour window."""
    seconds = step * 50
    return f"2026-10-04T{10 + seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}+00:00"


def zulu(step):
    return stamp(step).replace("+00:00", "Z")


def paged_history(config_data, tmp_path, alarms_reply, changes_by_name, targets):
    """changes_by_name: alarm -> list of (minute, old, new). The fake pages newest first by --max-items
    and --starting-token, like the CLI."""
    ctx, aws, _ = make_context(config_data, tmp_path, {"cloudwatch describe-alarms": alarms_reply}, collector="alarms")
    original = aws.__call__

    def pager(argv, timeout):
        if argv[1:3] != ["cloudwatch", "describe-alarm-history"]:
            return original(argv, timeout)
        aws.calls.append(argv)
        name = argv[argv.index("--alarm-name") + 1]
        size = int(argv[argv.index("--max-items") + 1])
        begin = int(argv[argv.index("--starting-token") + 1]) if "--starting-token" in argv else 0
        ordered = sorted(changes_by_name.get(name, []), reverse=True)
        page = [history(stamp(m), old, new) for m, old, new in ordered[begin:begin + size]]
        reply = {"AlarmHistoryItems": page}
        if begin + size < len(ordered):
            reply["NextToken"] = str(begin + size)
        return 0, json.dumps(reply), ""

    ctx.runner = pager
    COLLECTOR.run(ctx, targets)
    return ctx, aws


def flapping(count, first_minute=1):
    """count changes, one per minute, alternating OK->ALARM and ALARM->OK, starting with ALARM."""
    return [(first_minute + i, "OK", "ALARM") if i % 2 == 0 else (first_minute + i, "ALARM", "OK") for i in range(count)]


def derived_texts(ctx):
    return [f.summary for f in ctx.evidence.facts if f.kind == "derived"]


def test_busy_alarm_shows_newest_changes_finds_the_earliest_alarm_and_says_what_was_cut(config_data, tmp_path):
    changes = flapping(60)
    ctx, aws = paged_history(config_data, tmp_path, {"MetricAlarms": [alarm("busy")]}, {"busy": changes}, {"alarm_names": "busy"})
    calls = aws.called("cloudwatch", "describe-alarm-history")
    assert len(calls) == 3
    assert [c[c.index("--starting-token") + 1] for c in calls[1:]] == ["20", "40"]
    shown = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    times = [f.time for f in shown]
    assert zulu(60) in times  # the newest change
    assert zulu(1) in times  # the earliest change into ALARM is kept
    assert zulu(5) not in times
    assert len(shown) == 21
    first = [t for t in derived_texts(ctx) if t.startswith("The first alarm")]
    assert len(first) == 1 and "busy" in first[0] and zulu(1) in first[0]
    note = [t for t in derived_texts(ctx) if "pages" in t]
    assert len(note) == 1 and "3 pages" in note[0] and "60" in note[0]
    assert "older changes exist" not in note[0]


def test_the_busy_alarm_that_fired_first_is_named_over_a_quiet_one(config_data, tmp_path):
    reply = {"MetricAlarms": [alarm("quiet"), alarm("busy")]}
    changes = {"busy": flapping(60, first_minute=2), "quiet": [(30, "OK", "ALARM")]}
    ctx, _ = paged_history(config_data, tmp_path, reply, changes, {"alarm_names": "quiet,busy"})
    first = [t for t in derived_texts(ctx) if t.startswith("The first alarm")]
    assert len(first) == 1 and f"was busy at {zulu(2)}" in first[0]


def test_history_still_cut_after_five_pages_does_not_name_the_first_alarm(config_data, tmp_path):
    reply = {"MetricAlarms": [alarm("endless"), alarm("calm")]}
    changes = {"endless": flapping(130), "calm": [(30, "OK", "ALARM")]}
    ctx, aws = paged_history(config_data, tmp_path, reply, changes, {"alarm_names": "endless,calm"})
    calls = [c for c in aws.called("cloudwatch", "describe-alarm-history") if "endless" in c]
    assert len(calls) == 5
    texts = derived_texts(ctx)
    note = [t for t in texts if "endless" in t and "5 pages" in t]
    assert len(note) == 1 and "older changes exist" in note[0]
    assert not [t for t in texts if t.startswith("The first alarm to go into ALARM in the window was")]
    cut = [t for t in texts if "cannot be named" in t]
    assert len(cut) == 1 and "endless" in cut[0] and "calm" not in cut[0].split("cut")[-1]
