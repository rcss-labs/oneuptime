"""Small helpers shared by collectors. This module has no COLLECTOR, so the registry skips it."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence

from triage.context import CollectContext
from triage.redact import key_components, looks_personal_key, looks_secret_key
from triage.window import Window, WindowError, parse_time

# --- value shapes ---------------------------------------------------------------------------
_LABEL_RE = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")
_PORT_RE = re.compile(r"[0-9]{1,5}")
_AUTHORITY_CHARS_RE = re.compile(r"[A-Za-z0-9.:\[\]-]*")
_BOOLEAN_RE = re.compile(r"true|false", re.IGNORECASE)
_SWITCH_RE = re.compile(r"true|false|yes|no|on|off|0|1", re.IGNORECASE)
_REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]")
_ENUM_RE = re.compile(r"[A-Za-z][A-Za-z0-9_./,-]{0,39}")
_MAX_ENUM_DIGITS = 4
_NUMBER_RES = (
    re.compile(r"-?[0-9]+(?:\.[0-9]+)?"),  # a number or a fraction
    re.compile(r"[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h|d|w)"),  # a duration
    re.compile(r"[0-9]+(?:\.[0-9]+)?(?:[KMGTPE]i|[KMGTPEkmgtpe][Bb]?)"),  # a size
    re.compile(r"[0-9]+/[0-9]+"),  # a ratio
)
_MAX_NUMBER_LENGTH = 12
_VERSION_RES = (
    re.compile(r"(?:[A-Za-z]{1,10}[-_])?[vV]?[0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9.]{1,20})?"),  # 1.4.2, v1.4.2-rc.1
    re.compile(r"[vV][0-9]{1,4}"),  # v2
)
_HEX_VERSION_RE = re.compile(r"(?:[A-Za-z]{1,10}[-_])?[0-9A-Fa-f]{7,40}")  # abc1234, sha-abc1234
_MAX_VERSION_LENGTH = 32
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9._-]{1,63}")
_PATH_PART_RE = re.compile(r"[a-z0-9._-]{1,32}")
_ARN_RE = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[A-Za-z0-9:/_.+=,-]{1,200}")
# Key material: a long base64 or hex run, or a long unseparated mix of letters and digits.
_KEY_RUN_RE = re.compile(r"[A-Za-z0-9+/]{20,}")
_KEY_SEPARATORS = frozenset("._-")
_KEY_MIX_LENGTH = 16
_DIALECT_RE = re.compile(r"[a-z0-9]{1,20}")
_SQS_HOST_RE = re.compile(r"(?:sqs\.[a-z0-9-]+|[a-z0-9-]+\.queue)\.amazonaws\.com(?:\.cn)?", re.IGNORECASE)
_SQS_PATH_RE = re.compile(r"/[0-9]{12}/([A-Za-z0-9_-]{1,80}(?:\.fifo)?)/?")
_MAX_HOST_LENGTH = 253
_MAX_PORT = 65535
_URL_SCHEMES = frozenset({
    "http", "https", "ws", "wss", "tcp", "udp", "redis", "rediss", "postgres", "postgresql", "mysql",
    "mongodb", "mongodb+srv", "amqp", "amqps", "kafka", "nats", "grpc", "grpcs", "s3", "memcached",
    "ldap", "ldaps", "smtp", "smtps", "ftp", "sftp", "sqlserver", "clickhouse",
})
_GENERAL_MIN_LABELS = 3  # outside a matching kind, first.last and user.name:pin look like two-label hosts

# --- kinds of setting, by name word (rule 3) ---------------------------------------------------
ADDRESS, PORT, ENUM, NUMBER, VERSION, SWITCH, IDENTIFIER, PATH, ARN, OPTS = (
    "address", "port", "enum", "number", "version", "switch", "identifier", "path", "arn", "opts",
)
_KIND_WORDS = {
    ADDRESS: ("host", "hostname", "hosts", "endpoint", "endpoints", "url", "uri", "addr", "address", "server",
              "servers", "broker", "brokers", "bootstrap", "domain", "origin", "proxy"),
    PORT: ("port",),
    ENUM: ("env", "environment", "stage", "profile", "profiles", "mode", "level", "loglevel", "region", "zone", "az",
           "tz", "timezone", "lang", "locale", "type", "format", "driver", "protocol", "scheme", "active"),
    NUMBER: ("timeout", "ttl", "interval", "delay", "retry", "retries", "size", "count", "limit", "max", "min",
             "workers", "threads", "concurrency", "pool", "memory", "cpu", "replicas", "conn", "connections"),
    VERSION: ("version", "tag", "sha", "commit", "revision", "release", "build"),
    SWITCH: ("enabled", "disabled", "debug", "feature", "flag", "verbose", "dry"),
    IDENTIFIER: ("name", "database", "db", "schema", "bucket", "queue", "topic", "table", "stream", "cluster",
                 "service", "namespace", "index", "group", "role", "app", "application", "component", "tier"),
    PATH: ("path", "dir", "directory", "file", "home", "root"),
    ARN: ("arn",),
    OPTS: ("opts", "options", "args", "flags"),
}
_KIND_OF_WORD = {word: kind for kind, words in _KIND_WORDS.items() for word in words}
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


def _key_like(text: str) -> bool:
    """A token, not a name: a long base64 or hex run, or 16+ characters of letters and digits with no separator."""
    if _KEY_RUN_RE.search(text):
        return True
    return (
        len(text) >= _KEY_MIX_LENGTH
        and not any(char in _KEY_SEPARATORS for char in text)
        and any(char.isalpha() for char in text)
        and any(char.isdigit() for char in text)
    )


def _valid_host(host: str, min_labels: int) -> bool:
    if host.startswith("["):
        inner = host[1:-1]
        if not host.endswith("]") or "%" in inner:  # a zone id may carry any text
            return False
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return False
        return True
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return (
        len(host) <= _MAX_HOST_LENGTH
        and len(labels) >= min_labels
        and all(_LABEL_RE.fullmatch(label) for label in labels)
        and any(char.isalpha() for char in labels[-1])
        and (len(labels) > 1 or not _key_like(host))
    )


def _split_port(text: str) -> tuple[str, str] | None:
    """(host, port) with port possibly empty; None when the port is malformed."""
    if text.startswith("["):
        close = text.find("]")
        host, rest = text[: close + 1], text[close + 1:]
        if close < 0 or rest and not rest.startswith(":"):
            return None
        port = rest[1:]
        has_port = bool(rest)
    elif text.count(":") > 1:
        return None
    else:
        host, separator, port = text.partition(":")
        has_port = bool(separator)
    if has_port and not (_PORT_RE.fullmatch(port) and int(port) <= _MAX_PORT):
        return None
    return host, port


def _is_host_and_port(text: str, min_labels: int) -> bool:
    parts = _split_port(text)
    return parts is not None and _valid_host(parts[0], min_labels)


def _known_scheme(scheme: str, extended: bool) -> bool:
    lowered = scheme.lower()
    if lowered in _URL_SCHEMES:
        return True
    base, plus, dialect = lowered.partition("+")
    return extended and bool(plus) and base in _URL_SCHEMES and bool(_DIALECT_RE.fullmatch(dialect))


def _url_parts(text: str, min_labels: int, extended: bool) -> tuple[str, str] | None:
    """(origin, path) of a URL whose scheme is on the list; None when it is not a plainly safe URL.

    extended also accepts the jdbc: prefix and scheme+dialect forms (address kinds only).
    """
    prefix = ""
    if extended and text[:5].lower() == "jdbc:":
        prefix, text = text[:5], text[5:]
    scheme, separator, rest = text.partition("://")
    if not separator or not _known_scheme(scheme, extended):
        return None
    cut = min((rest.find(mark) for mark in "/?#;" if mark in rest), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" in tail:
        return None
    host_and_port = authority.rpartition("@")[2]
    if not _AUTHORITY_CHARS_RE.fullmatch(host_and_port) or not _is_host_and_port(host_and_port, min_labels):
        return None
    return f"{prefix}{scheme}://{host_and_port}", tail


def _origin(text: str, min_labels: int, extended: bool = False) -> str | None:
    parts = _url_parts(text, min_labels, extended)
    return parts[0] if parts else None


def _address_item(item: str) -> str | None:
    if "://" not in item:
        return item if _is_host_and_port(item, 1) else None
    parts = _url_parts(item, 1, extended=True)
    if parts is None:
        return None
    origin, tail = parts
    host = _split_port(origin.partition("://")[2])
    queue = _SQS_PATH_RE.fullmatch(tail)
    if host and _SQS_HOST_RE.fullmatch(host[0]) and queue and not _key_like(queue.group(1)):
        return f"{origin} (queue {queue.group(1)})"
    return origin


def _address_value(text: str) -> str | None:
    """A URL origin, a host[:port], or a comma list of them."""
    shown = [_address_item(item.strip()) for item in text.split(",")]
    return ",".join(shown) if all(shown) else None  # type: ignore[arg-type]


def _enum_value(text: str) -> str | None:
    fits = _ENUM_RE.fullmatch(text) and sum(char.isdigit() for char in text) <= _MAX_ENUM_DIGITS
    return text if fits else None


def _number_value(text: str) -> str | None:
    fits = len(text) <= _MAX_NUMBER_LENGTH and any(pattern.fullmatch(text) for pattern in _NUMBER_RES)
    return text if fits else None


def _version_value(text: str) -> str | None:
    dotted = len(text) <= _MAX_VERSION_LENGTH and any(pattern.fullmatch(text) for pattern in _VERSION_RES)
    return text if dotted or _HEX_VERSION_RE.fullmatch(text) else None


def _identifier_value(text: str) -> str | None:
    return text if _IDENTIFIER_RE.fullmatch(text) and not _key_like(text) else None


def _path_value(text: str) -> str | None:
    if not text.startswith("/"):
        return None
    parts = text[1:].removesuffix("/").split("/") if text != "/" else []
    fits = all(_PATH_PART_RE.fullmatch(part) and not _key_like(part) for part in parts)
    return text if fits else None


_KIND_CHECKS: dict[str, Callable[[str], str | None]] = {
    ADDRESS: _address_value,
    PORT: lambda text: text if _PORT_RE.fullmatch(text) else None,
    ENUM: _enum_value,
    NUMBER: _number_value,
    VERSION: _version_value,
    SWITCH: lambda text: text if _SWITCH_RE.fullmatch(text) else None,
    IDENTIFIER: _identifier_value,
    PATH: _path_value,
    ARN: lambda text: text if _ARN_RE.fullmatch(text) else None,
    OPTS: lambda text: None,  # free-form option strings carry passwords too often
}


def _general_value(text: str) -> str | None:
    """Rule 4, under any name that is not secret or personal: booleans, regions, and plainly public addresses."""
    if _BOOLEAN_RE.fullmatch(text) or _REGION_RE.fullmatch(text):
        return text
    if "://" in text:
        return _origin(text, _GENERAL_MIN_LABELS)
    return text if _is_host_and_port(text, _GENERAL_MIN_LABELS) else None


def _secret_or_personal_name(name: str) -> bool:
    """Secret or personal by the redactor's name checks, for the whole name or any leading part of it.

    The leading parts matter because the redactor reads DB_PASSWORD_NAME and API_KEY2_URL as references
    (by their last part), yet a value under them can still be the secret itself.
    """
    if looks_personal_key(name) or looks_secret_key(name):
        return True
    parts = key_components(name)
    return any(looks_secret_key("_".join(parts[:end])) for end in range(1, len(parts)))


def _setting_kind(name: str) -> str | None:
    """The kind of setting a name says it is, from its last part only (trailing digits stripped)."""
    parts = [part.rstrip("0123456789") for part in key_components(name)]
    parts = [part for part in parts if part]
    return _KIND_OF_WORD.get(parts[-1]) if parts else None


def shown_env_value(name: str, value: Any) -> str:
    """A reduced form of an environment value that is safe to put in evidence, decided by value type.

    Under a secret or personal name only the origin of a URL is shown. Under any other name a value is
    shown when its shape fits the kind of setting the name says it is, or when it is a boolean, a region,
    or a plainly public address. Everything else is hidden.
    """
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        return _hidden(value)
    if _secret_or_personal_name(name):
        return _origin(text, 1) or _hidden(value)
    kind = _setting_kind(name)
    shown = _KIND_CHECKS[kind](text) if kind else None
    return shown or _general_value(text) or _hidden(value)


def env_summary(pairs: Iterable[tuple[str, Any]]) -> dict[str, str]:
    """Environment variable name to its shown value; see shown_env_value."""
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
