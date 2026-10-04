"""Small helpers shared by collectors. This module has no COLLECTOR, so the registry skips it."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Iterable

from triage.window import Window, WindowError, parse_time


def parse_iso(text: Any) -> datetime | None:
    """Parse an ISO time string from an API reply, or None when it is missing or unreadable."""
    if not isinstance(text, str):
        return None
    try:
        return parse_time(text)
    except WindowError:
        return None


def in_window(window: Window, text: Any) -> bool:
    moment = parse_iso(text)
    return moment is not None and window.contains(moment)


def newest_in_window(
    window: Window,
    items: Iterable[dict],
    time_of: Callable[[dict], Any],
    limit: int,
) -> list[dict]:
    """The items whose time falls inside the window, newest first, at most limit of them."""
    timed = [(parse_iso(time_of(item)), item) for item in items]
    inside = [(moment, item) for moment, item in timed if moment is not None and window.contains(moment)]
    inside.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _, item in inside[:limit]]
