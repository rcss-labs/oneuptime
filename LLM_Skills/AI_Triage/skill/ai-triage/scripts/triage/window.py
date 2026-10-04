"""Time window arithmetic for evidence collection. All times are aware UTC."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SAME_TIME_SECONDS = 30
_TIME_RE = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})[T ](?P<hour>[0-9]{2}):(?P<minute>[0-9]{2})"
    r"(?::(?P<second>[0-9]{2})(?:\.(?P<fraction>[0-9]{1,9}))?)?"
    r"(?P<zone>[Zz]|[+-][0-9]{2}(?::?[0-9]{2})?)?$"
)


class WindowError(ValueError):
    """Raised for an unparseable time or an invalid window."""


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime

    def duration(self) -> timedelta:
        return self.end - self.start

    def shifted(self, delta: timedelta) -> "Window":
        return Window(self.start + delta, self.end + delta)

    def iso(self) -> dict[str, str]:
        return {"start": format_time(self.start), "end": format_time(self.end)}

    def epoch_seconds(self) -> tuple[int, int]:
        return int(self.start.timestamp()), int(self.end.timestamp())

    def epoch_millis(self) -> tuple[int, int]:
        start, end = self.epoch_seconds()
        return start * 1000, end * 1000

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment <= self.end


def parse_time(text: str) -> datetime:
    """Parse ISO 8601 with Z or a numeric offset into an aware UTC datetime.

    Parsed by hand so the result does not depend on the Python version's fromisoformat.
    """
    if not isinstance(text, str) or not text.strip():
        raise WindowError(f"cannot parse time: {text!r}")
    match = _TIME_RE.match(text.strip())
    if not match:
        raise WindowError(f"cannot parse time: {text}")
    if match.group("zone") is None:
        raise WindowError(f"time must include a timezone: {text}")
    year, month, day, hour, minute = (int(match.group(name)) for name in ("year", "month", "day", "hour", "minute"))
    second = int(match.group("second") or 0)
    microsecond = int((match.group("fraction") or "").ljust(6, "0")[:6] or 0)
    try:
        moment = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=_zone(match.group("zone")))
        return moment.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError) as error:  # includes times that do not fit in UTC
        raise WindowError(f"cannot parse time: {text}") from error


def _zone(zone: str) -> timezone:
    if zone in ("Z", "z"):
        return timezone.utc
    sign = -1 if zone[0] == "-" else 1
    digits = zone[1:].replace(":", "")
    minutes = int(digits[2:4] or 0)
    if minutes > 59:
        raise ValueError("offset minutes must be at most 59")
    offset = timedelta(hours=int(digits[:2]), minutes=minutes)
    return timezone(sign * offset)


def _require_aware(moment: datetime, label: str) -> None:
    if moment.tzinfo is None:
        raise WindowError(f"{label} must include a timezone: {moment.isoformat()}")


def format_time(moment: datetime) -> str:
    _require_aware(moment, "time")
    try:
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError) as error:
        raise WindowError(f"cannot format time: {moment!r}") from error


def _check_max_hours(max_hours: int) -> None:
    if max_hours < 1:
        raise WindowError(f"max_hours must be at least 1, got {max_hours}")


def _check_length(window: Window, max_hours: int) -> None:
    if window.duration() > timedelta(hours=max_hours):
        raise WindowError(f"window is longer than the {max_hours} hour limit")


def make_window(start: str, end: str, max_hours: int) -> Window:
    _check_max_hours(max_hours)
    window = Window(parse_time(start), parse_time(end))
    if window.end <= window.start:
        raise WindowError("window end must be after its start")
    _check_length(window, max_hours)
    return window


def window_around(
    incident_start: str,
    incident_end: str | None,
    now: datetime,
    max_hours: int,
    lead_minutes: int = 60,
    tail_minutes: int = 15,
) -> Window:
    """Window from before the incident start to after its end (or now), cut to max_hours."""
    _check_max_hours(max_hours)
    _require_aware(now, "now")
    incident_begin = parse_time(incident_start)
    try:
        start = incident_begin - timedelta(minutes=lead_minutes)
    except OverflowError as error:
        raise WindowError(f"incident start is too close to the calendar edge: {incident_start}") from error
    if incident_end is None:
        end = now
    else:
        incident_finish = parse_time(incident_end)
        if incident_finish < incident_begin:
            raise WindowError("incident end is before its start")
        try:
            end = min(incident_finish + timedelta(minutes=tail_minutes), now)
        except OverflowError:
            end = now  # an end at the calendar edge: the window simply ends now
    if end <= start:
        raise WindowError("window end must be after its start")
    try:
        end = min(end, start + timedelta(hours=max_hours))
    except OverflowError:
        pass  # start is so late that the cap cannot be added: keep the end as it is
    return Window(start, end)


def _unit(count: int, name: str) -> str:
    return f"{count} {name}" if count == 1 else f"{count} {name}s"


def describe_offset(event: datetime, reference: datetime) -> str:
    """Say in words how event relates to reference, e.g. "12 minutes before"."""
    gap = reference - event
    seconds = int(abs(gap).total_seconds())
    if seconds < SAME_TIME_SECONDS:
        return "at the same time as"
    direction = "before" if gap > timedelta(0) else "after"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        parts = [(days, "day"), (hours, "hour")]
    elif hours:
        parts = [(hours, "hour"), (minutes, "minute")]
    elif minutes:
        parts = [(minutes, "minute")]
    else:
        parts = [(secs, "second")]
    words = " ".join(_unit(count, name) for count, name in parts if count)
    return f"{words} {direction}"
