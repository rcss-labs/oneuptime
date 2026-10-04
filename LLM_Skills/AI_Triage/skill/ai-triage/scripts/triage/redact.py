"""Redact secrets and personal data from text before it enters evidence."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable

Span = tuple[int, int]

PLACEHOLDER_RE = re.compile(r"<[A-Z]+-\d+>")
SECRET_KEY_WORDS = (
    "password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "credential", "auth",
)
_KEY_PATTERN = (
    r"(?:[\w-]*(?:" + "|".join(SECRET_KEY_WORDS) + r")[\w-]*|[\w-]*[_-]key)"
)
INFRASTRUCTURE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    )
)
_ENV_NAME_KEYS = ("name", "Name")
_ENV_VALUE_KEYS = ("value", "Value")
_REFERENCE_KEY = "valueFrom"

PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)
URL_CREDENTIAL_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+(?:@[^\s:/@]+)?:(?P<secret>[^\s@/]+)@"
)
AUTH_HEADER_RE = re.compile(
    r"""Authorization["']?[ \t]*[:=][ \t]*["']?(?:Bearer|Basic)[ \t]+(?P<secret>[^\s"']+)""",
    re.IGNORECASE,
)
# Key positions only: key=value, key: value, "key": "value", ?key=value. The key may not be
# part of a longer hostname or path (no dots or slashes before it), so auth.example.com is safe.
SECRET_PAIR_RE = re.compile(
    r"(?<![\w./-])" + _KEY_PATTERN + r"""["']?(?:[ \t]*=[ \t]*|[ \t]*:[ \t]+|(?<=["']):[ \t]*)"""
    r"""(?!["']?(?:Bearer|Basic)\s)(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bare>[^\s&,;"'}\]]+))""",
    re.IGNORECASE,
)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
JWT_RE = re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
IPV4_RE = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w]|\.\d)")


def looks_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(word in lowered for word in SECRET_KEY_WORDS) or lowered.endswith(("_key", "-key"))


def _group_span(match: re.Match[str], *groups: str) -> Span | None:
    for group in groups:
        if match.group(group):
            return match.span(group)
    return None


def _secret_group_span(match: re.Match[str]) -> Span | None:
    return _group_span(match, "secret")


def _pair_span(match: re.Match[str]) -> Span | None:
    return _group_span(match, "double", "single", "bare")


def _whole_span(match: re.Match[str]) -> Span | None:
    return match.span()


# (audit category, pattern, which part of a match is the secret), in redaction order.
SECRET_RULES: tuple[tuple[str, re.Pattern[str], Callable[[re.Match[str]], Span | None]], ...] = (
    ("private_key", PEM_RE, _whole_span),
    ("url_credential", URL_CREDENTIAL_RE, _secret_group_span),
    ("auth_header", AUTH_HEADER_RE, _secret_group_span),
    ("secret_key_value", SECRET_PAIR_RE, _pair_span),
    ("aws_access_key", AWS_KEY_RE, _whole_span),
    ("jwt", JWT_RE, _whole_span),
)


def _secret_spans(text: str, pattern: re.Pattern[str], pick: Callable[[re.Match[str]], Span | None]) -> list[Span]:
    spans = []
    for match in pattern.finditer(text):
        span = pick(match)
        if span and not PLACEHOLDER_RE.fullmatch(text[span[0]:span[1]]):
            spans.append(span)
    return spans


def _is_public_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not any(address in network for network in INFRASTRUCTURE_NETWORKS)


class Redactor:
    """Replaces sensitive values with stable placeholders such as <SECRET-1>."""

    def __init__(self) -> None:
        # Keyed by a digest so the original values are never held in memory.
        self._numbers: dict[str, dict[str, int]] = {"SECRET": {}, "EMAIL": {}, "IP": {}}

    def _placeholder(self, category: str, original: str) -> str:
        digest = hashlib.sha256(original.encode()).hexdigest()
        numbers = self._numbers[category]
        number = numbers.setdefault(digest, len(numbers) + 1)
        return f"<{category}-{number}>"

    def _replace_spans(self, text: str, spans: list[Span], category: str) -> str:
        pieces, position = [], 0
        for start, end in spans:
            pieces.append(text[position:start])
            pieces.append(self._placeholder(category, text[start:end]))
            position = end
        pieces.append(text[position:])
        return "".join(pieces)

    def text(self, value: str) -> str:
        for _, pattern, pick in SECRET_RULES:
            value = self._replace_spans(value, _secret_spans(value, pattern, pick), "SECRET")
        value = EMAIL_RE.sub(lambda m: self._placeholder("EMAIL", m.group()), value)
        return IPV4_RE.sub(
            lambda m: self._placeholder("IP", m.group()) if _is_public_ip(m.group()) else m.group(),
            value,
        )

    def value(self, obj: Any, key: str | None = None) -> Any:
        if isinstance(obj, str):
            if key is not None and obj and looks_secret_key(key):
                return self._placeholder("SECRET", obj)
            return self.text(obj)
        if isinstance(obj, dict):
            return self._dict(obj)
        if isinstance(obj, (list, tuple)):
            return [self.value(item) for item in obj]
        return obj

    def _dict(self, obj: dict) -> dict:
        name_key = next((k for k in _ENV_NAME_KEYS if k in obj), None)
        value_key = next((k for k in _ENV_VALUE_KEYS if k in obj), None)
        env_name = obj.get(name_key) if name_key else None
        is_env_entry = isinstance(env_name, str) and value_key is not None
        result = {}
        for key, item in obj.items():
            if key == _REFERENCE_KEY:
                result[key] = item
            elif is_env_entry and key == value_key:
                result[key] = self.value(item, env_name)
            else:
                result[key] = self.value(item, key if isinstance(key, str) else None)
        return result

    def counts(self) -> dict[str, int]:
        return {category.lower(): len(numbers) for category, numbers in self._numbers.items()}


@dataclass(frozen=True)
class AuditHit:
    category: str
    line: int
    column: int


def audit_text(text: str) -> list[AuditHit]:
    """Locate anything rules 1 to 6 would still match. Reports positions, never values."""
    hits = []
    for category, pattern, pick in SECRET_RULES:
        for start, _ in _secret_spans(text, pattern, pick):
            line = text.count("\n", 0, start) + 1
            column = start - (text.rfind("\n", 0, start) + 1) + 1
            hits.append(AuditHit(category, line, column))
    return sorted(hits, key=lambda hit: (hit.line, hit.column))
