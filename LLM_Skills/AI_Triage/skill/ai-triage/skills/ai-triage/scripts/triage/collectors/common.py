"""Small helpers shared by collectors. This module has no COLLECTOR, so the registry skips it."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import urlsplit

from triage.context import CollectContext
from triage.redact import looks_secret_key
from triage.window import Window, WindowError, parse_time

_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
_HOST_RE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?")
_SETTING_RE = re.compile(r"[a-z][a-z0-9_.-]{0,39}")
_HIDDEN_PREFIX = "<hidden:"


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


def _hidden(value: Any) -> str:
    return f"<hidden: {len(value if isinstance(value, str) else str(value))} characters>"


def _origin(text: str) -> str | None:
    """scheme://host[:port] of a URL, dropping user, path, query, and fragment; None if not a URL."""
    scheme, separator, _ = text.partition("://")
    if not separator or not _SCHEME_RE.fullmatch(scheme):
        return None
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host:
        return None
    return f"{scheme}://{host}" + (f":{port}" if port is not None else "")


def shown_env_value(value: Any) -> str:
    """A reduced form of an environment value that is safe to put in evidence."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, str):
        return _hidden(value)
    origin = _origin(value)
    if origin:
        return origin
    if _HOST_RE.fullmatch(value) or _SETTING_RE.fullmatch(value):
        return value
    return _hidden(value)


def env_summary(pairs: Iterable[tuple[str, Any]]) -> dict[str, str]:
    """Environment variable name to its shown value; names that look secret are always hidden."""
    return {
        name: _hidden(value) if looks_secret_key(name) else shown_env_value(value)
        for name, value in pairs
    }


def _is_hidden(shown: str) -> bool:
    return shown.startswith(_HIDDEN_PREFIX)


def env_changes(old: dict[str, str], new: dict[str, str], raw_changed: set[str]) -> list[str]:
    """Sentences about what changed between two env_summary results.

    raw_changed holds the names whose raw values differ, computed before reduction.
    """
    sentences = []
    for name in sorted(old.keys() | new.keys()):
        if name not in old:
            sentences.append(f"{name} was added")
        elif name not in new:
            sentences.append(f"{name} was removed")
        elif _is_hidden(old[name]) != _is_hidden(new[name]):
            sentences.append(f"{name} changed (values hidden)")
        elif not _is_hidden(old[name]) and old[name] != new[name]:
            sentences.append(f"{name} changed from {old[name]} to {new[name]}")
        elif name in raw_changed:
            sentences.append(f"{name} may have changed (values hidden)")
    return sentences


def was_not_found(ctx: CollectContext, codes: Sequence[str]) -> bool:
    """True when the last call failed with one of the given error codes."""
    return ctx.last_error is not None and ctx.last_error[0] in codes


def split_csv(value: str | None) -> list[str]:
    """Split on commas, strip each part, and drop empty parts."""
    return [part.strip() for part in (value or "").split(",") if part.strip()]
