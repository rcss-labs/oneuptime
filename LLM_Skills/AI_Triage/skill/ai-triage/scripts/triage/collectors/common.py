"""Small helpers shared by collectors. This module has no COLLECTOR, so the registry skips it."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence

from triage.context import CollectContext
from triage.redact import SECRET_WORDS, key_components, looks_secret_key
from triage.window import Window, WindowError, parse_time

_LABEL_RE = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")
_PORT_RE = re.compile(r"[0-9]{1,5}")
_AUTHORITY_CHARS_RE = re.compile(r"[A-Za-z0-9.:\[\]-]*")
_BOOLEAN_RE = re.compile(r"true|false", re.IGNORECASE)
_REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]")
_SHORT_NUMBER_RE = re.compile(r"[0-9]{1,6}")
_DURATION_RE = re.compile(r"[0-9]{1,5}(?:ms|s|m|h|d)")
_FRACTION_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}")
_WORD_RE = re.compile(r"[A-Za-z_-]{1,20}")
_SHORT_SETTING_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,14}")
_ARN_RE = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[A-Za-z0-9:/_.+=,-]{1,200}")
_PATH_RE = re.compile(r"/[A-Za-z0-9._/-]{0,200}")
_LONG_HEX_RE = re.compile(r"[0-9A-Fa-f]{16,}")
_HEX_RUN_RE = re.compile(r"[0-9A-Fa-f]{32,}")
_MAX_HOST_LENGTH = 253
_MAX_PORT = 65535
_MAX_SINGLE_LABEL = 20
_URL_SCHEMES = frozenset({
    "http", "https", "ws", "wss", "tcp", "udp", "redis", "rediss", "postgres", "postgresql", "mysql",
    "mongodb", "mongodb+srv", "amqp", "amqps", "kafka", "nats", "grpc", "grpcs", "s3", "memcached",
    "ldap", "ldaps", "smtp", "smtps", "ftp", "sftp",
})
# Name words that mark a variable as secret or personal; the value is then always hidden.
_SECRET_NAME_WORDS = SECRET_WORDS | frozenset({
    "pin", "salt", "hash", "license", "seed", "jwt", "private", "dsn", "signing", "hmac", "cert", "conn",
    "key", "passcode", "pincode", "code", "otp", "mfa", "pepper", "nonce",
})
_PERSONAL_NAME_WORDS = frozenset({"user", "username", "login", "email", "owner"})
# Name words that mark a variable as a plain setting; its short plain values are then shown.
SETTING_WORDS = frozenset({
    "env", "environment", "stage", "region", "zone", "az", "level", "port", "host", "hostname", "endpoint",
    "url", "uri", "addr", "address", "server", "mode", "timeout", "ttl", "interval", "delay", "retry",
    "retries", "version", "enabled", "disabled", "debug", "feature", "flag", "name", "database", "db",
    "schema", "bucket", "queue", "topic", "table", "stream", "cluster", "service", "namespace", "index",
    "size", "count", "limit", "max", "min", "workers", "threads", "concurrency", "pool", "tz", "timezone",
    "lang", "locale", "profile", "path", "dir", "arn", "log", "format", "type", "driver", "protocol",
    "scheme", "domain",
})
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


def _valid_host(host: str, allow_single_label: bool) -> bool:
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
        return host.endswith("]")
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return (
        len(host) <= _MAX_HOST_LENGTH
        and (len(labels) >= 2 or allow_single_label)
        and all(_LABEL_RE.fullmatch(label) for label in labels)
        and any(char.isalpha() for char in labels[-1])
    )


def _split_port(text: str) -> tuple[str, str] | None:
    """(host, port) with port possibly empty; None when the port is malformed."""
    if text.startswith("["):
        close = text.find("]")
        host, rest = text[: close + 1], text[close + 1:]
        if close < 0 or rest not in ("",) and not rest.startswith(":"):
            return None
        port = rest[1:] if rest else ""
        has_port = bool(rest)
    elif text.count(":") > 1:
        return None
    else:
        host, separator, port = text.partition(":")
        has_port = bool(separator)
    if has_port and not (_PORT_RE.fullmatch(port) and int(port) <= _MAX_PORT):
        return None
    return host, port


def _host_and_port(text: str, allow_single_label: bool) -> str | None:
    """text unchanged when it is a valid host or host:port, else None.

    A single-label host (redis:6379) needs a port and a short name; a bare word is not a host.
    """
    parts = _split_port(text)
    if parts is None or not _valid_host(parts[0], allow_single_label):
        return None
    host, port = parts
    if "." not in host and not host.startswith("[") and (not port or len(host) > _MAX_SINGLE_LABEL):
        return None
    return text


def _origin(text: str, allow_single_label: bool) -> str | None:
    """scheme://host[:port] of a URL; None when it is not a plainly safe URL."""
    scheme, separator, rest = text.partition("://")
    if not separator or scheme.lower() not in _URL_SCHEMES:
        return None
    cut = min((rest.find(mark) for mark in "/?#" if mark in rest), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" in tail:
        return None
    host_and_port = authority.rpartition("@")[2]
    if not _AUTHORITY_CHARS_RE.fullmatch(host_and_port):
        return None
    shown = _host_and_port(host_and_port, allow_single_label)
    return f"{scheme}://{shown}" if shown else None


def _setting_shaped(text: str) -> bool:
    """A short, plain value of the kinds a setting holds. Never a long hex token."""
    if _LONG_HEX_RE.fullmatch(text) or _HEX_RUN_RE.search(text):
        return False
    return any(
        pattern.fullmatch(text)
        for pattern in (
            _BOOLEAN_RE, _SHORT_NUMBER_RE, _DURATION_RE, _FRACTION_RE, _WORD_RE, _SHORT_SETTING_RE,
            _ARN_RE, _PATH_RE,
        )
    )


def _secret_or_personal_name(name: str) -> bool:
    parts = set(key_components(name))
    return looks_secret_key(name) or bool(parts & (_SECRET_NAME_WORDS | _PERSONAL_NAME_WORDS))


def _setting_name(name: str) -> bool:
    return bool(set(key_components(name)) & SETTING_WORDS)


def shown_env_value(name: str, value: Any) -> str:
    """A reduced form of an environment value that is safe to put in evidence.

    Secret and personal names hide the value. Under any other name only booleans, regions, and
    dotted hosts and URLs are shown; under a setting-like name short plain values are shown too.
    """
    if _secret_or_personal_name(name):
        return _hidden(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value) if isinstance(value, (int, float)) else value
    if not isinstance(text, str):
        return _hidden(value)
    setting = _setting_name(name)
    if "://" in text:
        return _origin(text, setting) or _hidden(value)
    if _BOOLEAN_RE.fullmatch(text) or _REGION_RE.fullmatch(text):
        return text
    if not _LONG_HEX_RE.fullmatch(text) and _host_and_port(text, setting):
        return text
    if setting and _setting_shaped(text):
        return text
    return _hidden(value)


def env_summary(pairs: Iterable[tuple[str, Any]]) -> dict[str, str]:
    """Environment variable name to its shown value; secret and personal names are always hidden."""
    return {name: shown_env_value(name, value) for name, value in pairs}


def _is_hidden(shown: str) -> bool:
    return shown.startswith(_HIDDEN_PREFIX)


def env_changes(old: dict[str, str], new: dict[str, str], raw_changed: set[str]) -> list[str]:
    """Sentences about what changed between two env_summary results.

    raw_changed holds the names whose raw values differ, computed before reduction.
    A hidden value is never printed.
    """
    sentences = []
    for name in sorted(old.keys() | new.keys()):
        if name not in old:
            sentences.append(f"{name} was added")
        elif name not in new:
            sentences.append(f"{name} was removed")
        elif _is_hidden(old[name]) or _is_hidden(new[name]):
            if _is_hidden(old[name]) != _is_hidden(new[name]) or name in raw_changed:
                sentences.append(f"{name} changed (values hidden)")
        elif old[name] != new[name]:
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
