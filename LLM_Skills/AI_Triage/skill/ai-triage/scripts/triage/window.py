"""Time window arithmetic for evidence collection. All times are aware UTC."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SAME_TIME_SECONDS = 30
_FRACTION_RE = re.compile(r"\.(\d+)")


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
    """Parse ISO 8601 with Z or a numeric offset into an aware UTC datetime."""
    if not isinstance(text, str) or not text.strip():
        raise WindowError(f"cannot parse time: {text!r}")
    cleaned = text.strip()
    if cleaned[-1] in "zZ":
        cleaned = cleaned[:-1] + "+00:00"
    # fromisoformat only takes 3 or 6 fractional digits on older Pythons.
    cleaned = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), cleaned, count=1)
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as error:
        raise WindowError(f"cannot parse time: {text}") from error
    if parsed.tzinfo is None:
        raise WindowError(f"time must include a timezone: {text}")
    return parsed.astimezone(timezone.utc)


def format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_length(window: Window, max_hours: int) -> None:
    if window.duration() > timedelta(hours=max_hours):
        raise WindowError(f"window is longer than the {max_hours} hour limit")


def make_window(start: str, end: str, max_hours: int) -> Window:
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
    start = parse_time(incident_start) - timedelta(minutes=lead_minutes)
    if incident_end is None:
        end = now
    else:
        end = min(parse_time(incident_end) + timedelta(minutes=tail_minutes), now)
    if end <= start:
        raise WindowError("window end must be after its start")
    end = min(end, start + timedelta(hours=max_hours))
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
