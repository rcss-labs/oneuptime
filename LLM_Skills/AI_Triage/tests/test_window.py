from datetime import datetime, timedelta, timezone

import pytest

from triage.window import (
    Window,
    WindowError,
    describe_offset,
    format_time,
    make_window,
    parse_time,
    window_around,
)

UTC = timezone.utc


def at(hour: int, minute: int = 0, second: int = 0, day: int = 4) -> datetime:
    return datetime(2026, 10, day, hour, minute, second, tzinfo=UTC)


def test_parse_time_accepts_z_suffix():
    assert parse_time("2026-10-04T10:00:00Z") == at(10)


def test_parse_time_converts_numeric_offset_to_utc():
    parsed = parse_time("2026-10-04T12:30:00+02:00")
    assert parsed == at(10, 30)
    assert parsed.utcoffset() == timedelta(0)


def test_parse_time_accepts_fractional_seconds():
    assert parse_time("2026-10-04T10:00:00.5Z") == at(10) + timedelta(milliseconds=500)
    assert parse_time("2026-10-04T10:00:00.123456789Z").microsecond == 123456


@pytest.mark.parametrize("text", ["2026-10-04T10:00:00", "2026-10-04 10:00:00"])
def test_parse_time_rejects_naive_time(text):
    with pytest.raises(WindowError, match="time must include a timezone: " + text):
        parse_time(text)


@pytest.mark.parametrize("text", ["", "yesterday", "2026-13-45T00:00:00Z"])
def test_parse_time_rejects_garbage(text):
    with pytest.raises(WindowError):
        parse_time(text)


def test_format_time_drops_subseconds_and_round_trips():
    moment = at(10, 5, 9) + timedelta(microseconds=900000)
    assert format_time(moment) == "2026-10-04T10:05:09Z"
    assert parse_time(format_time(at(10, 5, 9))) == at(10, 5, 9)


def test_format_time_converts_to_utc():
    local = datetime(2026, 10, 4, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    assert format_time(local) == "2026-10-04T10:00:00Z"


def test_make_window_parses_both_ends():
    window = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", max_hours=6)
    assert window == Window(at(10), at(12))


def test_make_window_rejects_end_not_after_start():
    with pytest.raises(WindowError):
        make_window("2026-10-04T10:00:00Z", "2026-10-04T10:00:00Z", max_hours=6)
    with pytest.raises(WindowError):
        make_window("2026-10-04T10:00:00Z", "2026-10-04T09:00:00Z", max_hours=6)


def test_make_window_enforces_max_hours_inclusive():
    make_window("2026-10-04T10:00:00Z", "2026-10-04T16:00:00Z", max_hours=6)
    with pytest.raises(WindowError, match="6"):
        make_window("2026-10-04T10:00:00Z", "2026-10-04T16:00:01Z", max_hours=6)


def test_window_methods():
    window = Window(at(10), at(12))
    assert window.duration() == timedelta(hours=2)
    assert window.shifted(timedelta(hours=-1)) == Window(at(9), at(11))
    assert window.iso() == {"start": "2026-10-04T10:00:00Z", "end": "2026-10-04T12:00:00Z"}
    assert window.contains(at(10))
    assert window.contains(at(12))
    assert window.contains(at(11, 30))
    assert not window.contains(at(9, 59, 59))
    assert not window.contains(at(12, 0, 1))


def test_window_epoch_conversions():
    window = Window(at(10), at(12))
    start_seconds = int(at(10).timestamp())
    end_seconds = int(at(12).timestamp())
    assert window.epoch_seconds() == (start_seconds, end_seconds)
    assert window.epoch_millis() == (start_seconds * 1000, end_seconds * 1000)


def test_window_around_closed_incident():
    window = window_around(
        "2026-10-04T10:00:00Z", "2026-10-04T10:30:00Z", now=at(18), max_hours=6
    )
    assert window == Window(at(9), at(10, 45))


def test_window_around_open_incident_ends_at_now():
    window = window_around("2026-10-04T10:00:00Z", None, now=at(11), max_hours=6)
    assert window == Window(at(9), at(11))


def test_window_around_never_ends_after_now():
    window = window_around(
        "2026-10-04T10:00:00Z", "2026-10-04T10:30:00Z", now=at(10, 35), max_hours=6
    )
    assert window.end == at(10, 35)


def test_window_around_cuts_end_and_keeps_start():
    window = window_around(
        "2026-10-04T10:00:00Z", "2026-10-04T20:00:00Z", now=at(23), max_hours=6
    )
    assert window == Window(at(9), at(15))


def test_window_around_custom_lead_and_tail():
    window = window_around(
        "2026-10-04T10:00:00Z",
        "2026-10-04T10:30:00Z",
        now=at(18),
        max_hours=6,
        lead_minutes=10,
        tail_minutes=5,
    )
    assert window == Window(at(9, 50), at(10, 35))


def test_window_around_rejects_incident_in_the_future():
    with pytest.raises(WindowError):
        window_around("2026-10-04T20:00:00Z", None, now=at(10), max_hours=6)


@pytest.mark.parametrize(
    "event_offset, expected",
    [
        (timedelta(seconds=0), "at the same time as"),
        (timedelta(seconds=-29), "at the same time as"),
        (timedelta(seconds=29), "at the same time as"),
        (timedelta(seconds=-30), "30 seconds before"),
        (timedelta(seconds=45), "45 seconds after"),
        (timedelta(seconds=-60), "1 minute before"),
        (timedelta(seconds=119), "1 minute after"),
        (timedelta(minutes=-12), "12 minutes before"),
        (timedelta(minutes=59, seconds=59), "59 minutes after"),
        (timedelta(hours=-1), "1 hour before"),
        (timedelta(hours=-1, minutes=-1), "1 hour 1 minute before"),
        (timedelta(hours=2, minutes=15), "2 hours 15 minutes after"),
        (timedelta(hours=-5, minutes=-30), "5 hours 30 minutes before"),
        (timedelta(days=1), "1 day after"),
        (timedelta(days=-1, hours=-1), "1 day 1 hour before"),
        (timedelta(days=3, hours=4), "3 days 4 hours after"),
    ],
)
def test_describe_offset(event_offset, expected):
    reference = at(12)
    assert describe_offset(reference + event_offset, reference) == expected


def test_window_around_rejects_incident_end_before_start():
    with pytest.raises(WindowError):
        window_around("2026-10-04T10:00:00Z", "2026-10-04T09:00:00Z", now=at(12), max_hours=6)


def test_window_around_rejects_naive_now():
    with pytest.raises(WindowError):
        window_around("2026-10-04T10:00:00Z", None, now=datetime(2026, 10, 4, 12), max_hours=6)


@pytest.mark.parametrize("max_hours", [0, -1])
def test_max_hours_below_one_is_rejected(max_hours):
    with pytest.raises(WindowError):
        window_around("2026-10-04T10:00:00Z", None, now=at(12), max_hours=max_hours)
    with pytest.raises(WindowError):
        make_window("2026-10-04T10:00:00Z", "2026-10-04T11:00:00Z", max_hours=max_hours)


def test_format_time_rejects_naive_datetime():
    with pytest.raises(WindowError):
        format_time(datetime(2026, 10, 4, 10))
