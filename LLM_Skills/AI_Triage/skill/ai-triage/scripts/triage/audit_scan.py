"""An independent second detector for the publish audit.

It looks for secrets and personal data in a finished report with its own rules and
shares nothing with the redaction module, so a shape the redactor misses is not
automatically missed here. A Hit records where something is and what kind it is,
never the text itself.
"""
from __future__ import annotations

import math
import re
import unicodedata
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    kind: str
    line: int  # 1-based
    column: int  # 1-based, in the original text
    length: int


# Entropy threshold in bits per character. Random base64 of 24 characters averages about 4.3
# (sd 0.15) while the identifiers that look most like it (class names, pod names, slugs) stay under 3.9.
ENTROPY_THREE_CLASSES = 4.0
ENTROPY_TWO_CLASSES = 4.3
MIN_TOKEN_LENGTH = 24
MIN_HEX_LENGTH = 40

_ZERO_WIDTH = "​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎"
_SPECIAL_RE = re.compile(
    r"(?P<ansi>\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]?)"
    r"|(?P<zw>[" + _ZERO_WIDTH + r"])"
    r"|(?P<pct>(?:%[0-9A-Fa-f]{2})+)"
    r"|(?P<uni>[^\x00-\x7f" + _ZERO_WIDTH + r"]+)"
)


class _Normalised:
    """A normalised copy of the text with a map from its offsets back to the original."""

    def __init__(self, original: str) -> None:
        self.original = original
        parts: list[str] = []
        # one entry per copied piece: where it starts in the copy, where it came from, and whether it is 1:1
        self._starts: list[int] = []
        self._segments: list[tuple[int, int, bool]] = []
        position = 0
        copy_length = 0
        for match in _SPECIAL_RE.finditer(original):
            if match.start() > position:
                piece = original[position : match.start()]
                self._add(copy_length, position, match.start(), True)
                parts.append(piece)
                copy_length += len(piece)
            replacement = self._replacement(match)
            if replacement:
                self._add(copy_length, match.start(), match.end(), len(replacement) == match.end() - match.start() and match.lastgroup == "uni")
                parts.append(replacement)
                copy_length += len(replacement)
            position = match.end()
        if position < len(original):
            self._add(copy_length, position, len(original), True)
            parts.append(original[position:])
        self.text = "".join(parts)
        self._line_starts = [0] + [m.end() for m in re.finditer("\n", original)]

    def _add(self, start: int, origin: int, origin_end: int, linear: bool) -> None:
        self._starts.append(start)
        self._segments.append((origin, origin_end, linear))

    @staticmethod
    def _replacement(match: re.Match) -> str:
        kind = match.lastgroup
        if kind in ("ansi", "zw"):
            return ""
        if kind == "pct":
            raw = bytes(int(h, 16) for h in re.findall(r"%([0-9A-Fa-f]{2})", match.group()))
            return unicodedata.normalize("NFKC", raw.decode("utf-8", errors="replace"))
        return unicodedata.normalize("NFKC", match.group())

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        first = self._segment(start)
        last = self._segment(end - 1)
        origin = first[0] + (start - first[3] if first[2] else 0)
        origin_end = last[0] + (end - last[3] if last[2] else last[1] - last[0])
        return origin, max(origin_end, origin + 1)

    def _segment(self, index: int) -> tuple[int, int, bool, int]:
        slot = max(bisect_right(self._starts, index) - 1, 0)
        origin, origin_end, linear = self._segments[slot]
        return origin, origin_end, linear, self._starts[slot]

    def line_column(self, origin: int) -> tuple[int, int]:
        line = bisect_right(self._line_starts, origin)
        return line, origin - self._line_starts[line - 1] + 1


def _boundary(pattern: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9])(?:" + pattern + r")")


_AWS_PREFIXES = "AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA"
_VENDOR_RULES = [
    re.compile(r"(?<![A-Z0-9])(?:" + _AWS_PREFIXES + r")[A-Z0-9]{16}(?![A-Z0-9])"),
    _boundary(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    _boundary(r"github_pat_[A-Za-z0-9_]{20,}"),
    _boundary(r"glpat-[A-Za-z0-9_-]{20,}"),
    _boundary(r"xox[a-z]-[A-Za-z0-9-]{10,}"),
    re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/_-]{8,}"),
    _boundary(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}"),
    _boundary(r"whsec_[A-Za-z0-9]{16,}"),
    _boundary(r"AIza[A-Za-z0-9_-]{30,}"),
    _boundary(r"ya29\.[A-Za-z0-9_-]{20,}"),
    _boundary(r"GOCSPX-[A-Za-z0-9_-]{20,}"),
    _boundary(r"npm_[A-Za-z0-9]{30,}"),
    _boundary(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    _boundary(r"hvs\.[A-Za-z0-9_-]{20,}"),
    _boundary(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
]
# userinfo of scheme://user:password@host; the password may not start a placeholder
_BASIC_AUTH_RE = re.compile(r"(?<=://)[^\s/:@<>]+:[^\s/@<>]+(?=@)")

_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_PUBLIC_PEM = ("CERTIFICATE", "PUBLIC KEY")
_BASE64_LINE_RE = re.compile(r"^[ \t]*([A-Za-z0-9+/]{60,}={0,2})[ \t]*$", re.MULTILINE)

_CHUNK_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX_RE = re.compile(r"(?<![A-Za-z0-9])[0-9A-Fa-f]{40,}(?![A-Za-z0-9])")
_UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")
_AWS_ID_RE = re.compile(r"^(?:i|sg|vpc|subnet|eni|vol|ami|rtb|igw|nat|snap|lt|eipalloc|eipassoc|acl|pcx|tgw|vpce|fs|key)-[0-9a-f]{8,17}$")
_PLACEHOLDER_RE = re.compile(r"^<[A-Z][A-Z_]*(?:-\d+)?>$")
_DIGEST_BEFORE_RE = re.compile(r"(?:sha(?:1|224|256|384|512)|md5):$", re.IGNORECASE)

_NAME_WORDS = r"password|passwd|pwd|secret|token|apikey|api_key|api-key|authorization|cookie"
_NAME_RE = re.compile(_NAME_WORDS, re.IGNORECASE)
# what may follow a name word: the rest of the name, an optional quote, a separator, then the value
_NAMED_TAIL_RE = re.compile(
    r"[\w.-]{0,40}[\"']?[ \t]*[:=][ \t]*"
    r"(?:(?:bearer|basic|digest|token)[ \t]+)?"
    r"(?P<value>\"[^\"\n]*\"|'[^'\n]*'|[^\s,;\"']+)",
    re.IGNORECASE,
)
_NOT_A_VALUE = {"true", "false", "yes", "no", "ok", "none", "null"}

_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_PHONE_RE = re.compile(r"(?<![\w+])\+\d(?:[ .()-]?\d){7,14}(?!\d)")
_ACCOUNT_RE = re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])")


def _entropy(token: str) -> float:
    counts = Counter(token)
    total = len(token)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


_LOWER_WORD_RE = re.compile(r"[a-z]{5,}")


def _looks_like_a_name(token: str) -> bool:
    """Identifiers: mostly words (class names) or many short hyphen or underscore separated parts."""
    wordy = sum(len(run) for run in _LOWER_WORD_RE.findall(token))
    if wordy / len(token) >= 0.35:
        return True
    separators = sum(token.count(c) for c in "-_")
    return separators >= 3 and len(token) / (separators + 1) < 10


def _is_high_entropy(token: str) -> bool:
    token = token.rstrip("=")
    if len(token) < MIN_TOKEN_LENGTH or _UUID_RE.match(token) or _AWS_ID_RE.match(token):
        return False
    if re.fullmatch(r"[0-9A-Fa-f]+", token) or not any(c.isdigit() for c in token):
        return False
    lower = any(c.islower() for c in token)
    upper = any(c.isupper() for c in token)
    if not (lower or upper):
        return False
    if "/" in token and not (lower and upper):
        return False
    if not (lower and upper) and not token.isalnum():
        return False  # lower case with separators is a pod or resource name, not a key
    if _looks_like_a_name(token):
        return False
    threshold = ENTROPY_THREE_CLASSES if lower and upper else ENTROPY_TWO_CLASSES
    return _entropy(token) >= threshold


def _entropy_spans(text: str):
    for match in _HEX_RE.finditer(text):
        if not _DIGEST_BEFORE_RE.search(text[max(0, match.start() - 8) : match.start()]):
            yield match.start(), match.end()
    for match in _CHUNK_RE.finditer(text):
        chunk = match.group()
        before = text[max(0, match.start() - 8) : match.start()]
        if _DIGEST_BEFORE_RE.search(before):
            continue
        if "/" not in chunk:
            if _is_high_entropy(chunk):
                yield match.start(), match.end()
            continue
        if not chunk.startswith("/") and "//" not in chunk and _is_high_entropy(chunk):
            yield match.start(), match.end()
            continue
        offset = match.start()
        for segment in chunk.split("/"):
            if _is_high_entropy(segment):
                yield offset, offset + len(segment)
            offset += len(segment) + 1


def _is_placeholder(value: str) -> bool:
    inner = value.strip("\"'").strip()
    return (
        not inner
        or inner.lower() in _NOT_A_VALUE
        or bool(_PLACEHOLDER_RE.match(inner))
        or inner in ("[REDACTED]", "***")
    )


def _candidates(text: str, allowed: frozenset[str]):
    """Yield (priority, start, end, kind) in the normalised text; lower priority wins an overlap."""
    for match in _PEM_RE.finditer(text):
        if not any(word in match.group() for word in _PUBLIC_PEM):
            yield 0, match.start(), match.end(), "private_key"
    for match in _BASE64_LINE_RE.finditer(text):
        body = match.group(1)
        classes = sum(
            (any(c.islower() for c in body), any(c.isupper() for c in body), any(c.isdigit() for c in body), any(c in "+/" for c in body))
        )
        if classes >= 3 and len(set(body)) >= 12:
            yield 0, match.start(1), match.end(1), "private_key"
    for rule in _VENDOR_RULES:
        for match in rule.finditer(text):
            yield 1, match.start(), match.end(), "vendor_token"
    for match in _BASIC_AUTH_RE.finditer(text):
        yield 1, match.start(), match.end(), "vendor_token"
    resume = 0
    for name in _NAME_RE.finditer(text):
        if name.start() < resume:
            continue
        tail = _NAMED_TAIL_RE.match(text, name.end())
        if tail:
            resume = tail.end()
            if not _is_placeholder(tail.group("value")):
                yield 2, tail.start("value"), tail.end("value"), "named_value"
    for match in _EMAIL_RE.finditer(text):
        yield 3, match.start(), match.end(), "email"
    for match in _PHONE_RE.finditer(text):
        if 8 <= sum(c.isdigit() for c in match.group()) <= 15:
            yield 4, match.start(), match.end(), "phone"
    for match in _ACCOUNT_RE.finditer(text):
        in_uuid = match.start() >= 24 and _UUID_RE.match(text[match.start() - 24 : match.end()])
        if match.group() not in allowed and not in_uuid:
            yield 5, match.start(), match.end(), "account_id"
    for start, end in _entropy_spans(text):
        yield 6, start, end, "entropy"


def scan(text: str, allowed_account_aliases: frozenset[str] = frozenset()) -> list[Hit]:
    """Find secrets and personal data in text. Never raises; never returns the matched text."""
    try:
        normalised = _Normalised(text)
        body = normalised.text
        taken = bytearray(len(body))
        accepted: list[tuple[int, int, str]] = []
        for _, start, end, kind in sorted(_candidates(body, allowed_account_aliases)):
            if end <= start or any(taken[start:end]):
                continue
            taken[start:end] = b"\x01" * (end - start)
            accepted.append((start, end, kind))
        hits = []
        for start, end, kind in accepted:
            origin, origin_end = normalised.original_span(start, end)
            line, column = normalised.line_column(origin)
            hits.append(Hit(kind, line, column, origin_end - origin))
        return sorted(hits, key=lambda hit: (hit.line, hit.column))
    except Exception:  # noqa: BLE001 - the audit must fail closed, never crash the publish
        return [Hit("unreadable", 1, 1, len(text) if isinstance(text, str) else 0)]


def describe(hits: list[Hit]) -> list[str]:
    """One line per hit: kind, line, column, length. No matched text."""
    return [f"{hit.kind} at line {hit.line}, column {hit.column}, length {hit.length}" for hit in hits]
