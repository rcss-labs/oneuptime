"""Small helpers shared by collectors. This module has no COLLECTOR, so the registry skips it."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence

from triage.context import CollectContext
from triage.redact import key_components, looks_secret_key
from triage.window import Window, WindowError, parse_time

_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
_LABEL_RE = re.compile(r"[A-Za-z0-9-]{1,63}")
_PORT_RE = re.compile(r"[0-9]{1,5}")
_AUTHORITY_CHARS_RE = re.compile(r"[A-Za-z0-9.:\[\]-]*")
_BRACKETED_HOST_RE = re.compile(r"\[[0-9A-Fa-f:.]+\]")
_BOOLEAN_RE = re.compile(r"true|false", re.IGNORECASE)
_SHORT_NUMBER_RE = re.compile(r"[0-9]{1,6}")
_WORD_RE = re.compile(r"[A-Za-z_-]{1,20}")
_SHORT_SETTING_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,14}")
_LONG_HEX_RE = re.compile(r"[0-9A-Fa-f]{16,}")
_MAX_HOST_LENGTH = 253
_MAX_PORT = 65535
# Name components that mark a variable as secret although the redactor does not.
_SECRET_NAME_COMPONENTS = frozenset(
    {"pw", "pin", "salt", "hash", "cred", "creds", "license", "seed", "jwt", "private", "dsn", "signing", "hmac", "cert", "conn"}
)
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


def _valid_host(host: str) -> bool:
    if _BRACKETED_HOST_RE.fullmatch(host):
        return True
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return (
        len(host) <= _MAX_HOST_LENGTH
        and len(labels) >= 2
        and all(_LABEL_RE.fullmatch(label) for label in labels)
        and any(char.isalpha() for char in labels[-1])
    )


def _host_and_port(text: str) -> str | None:
    """text unchanged when it is a valid host or host:port, else None."""
    host, separator, port = text.rpartition(":") if not text.endswith("]") else (text, "", "")
    if not separator:
        host, port = text, ""
    elif not host or not _PORT_RE.fullmatch(port) or int(port) > _MAX_PORT:
        return None
    return text if _valid_host(host) else None


def _origin(text: str) -> str | None:
    """scheme://host[:port] of a URL; None when it is not a plainly safe URL."""
    scheme, separator, rest = text.partition("://")
    if not separator or not _SCHEME_RE.fullmatch(scheme):
        return None
    cut = min((rest.find(mark) for mark in "/?#" if mark in rest), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" in tail:
        return None
    host_and_port = authority.rpartition("@")[2]
    if not _AUTHORITY_CHARS_RE.fullmatch(host_and_port):
        return None
    shown = _host_and_port(host_and_port)
    return f"{scheme}://{shown}" if shown else None


def _plain_setting(text: str) -> bool:
    if _LONG_HEX_RE.fullmatch(text):
        return False
    return any(
        pattern.fullmatch(text)
        for pattern in (_BOOLEAN_RE, _SHORT_NUMBER_RE, _WORD_RE, _SHORT_SETTING_RE)
    )


def shown_env_value(value: Any) -> str:
    """A reduced form of an environment value that is safe to put in evidence."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, str):
        return _hidden(value)
    if "://" in value:
        return _origin(value) or _hidden(value)
    if _plain_setting(value) or (not _LONG_HEX_RE.fullmatch(value) and _host_and_port(value)):
        return value
    return _hidden(value)


def _secret_name(name: str) -> bool:
    return looks_secret_key(name) or any(part in _SECRET_NAME_COMPONENTS for part in key_components(name))


def env_summary(pairs: Iterable[tuple[str, Any]]) -> dict[str, str]:
    """Environment variable name to its shown value; names that look secret are always hidden."""
    return {
        name: _hidden(value) if _secret_name(name) else shown_env_value(value)
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
