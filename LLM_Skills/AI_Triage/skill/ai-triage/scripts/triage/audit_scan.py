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
ENTROPY_LOWERCASE = 3.6
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
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                decoded = raw.decode("latin-1")
            return unicodedata.normalize("NFKC", decoded)
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
    # a two-letter prefix and 32 hex characters (the shape of Twilio account and API key sids)
    re.compile(r"(?<![A-Za-z0-9])(?:SK|AC)[0-9a-f]{32}(?![A-Za-z0-9])"),
]
# userinfo of scheme://user:password@host; the password may not start a placeholder
_BASIC_AUTH_RE = re.compile(r"(?<=://)[^\s/:@<>]*:[^\s/@<>]+(?=@)")

_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_PUBLIC_PEM = ("CERTIFICATE", "PUBLIC KEY")
_BASE64_LINE_RE = re.compile(r"^[ \t]*([A-Za-z0-9+/]{60,}={0,2})[ \t]*$", re.MULTILINE)

_CHUNK_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX_RE = re.compile(r"(?<![A-Za-z0-9])[0-9A-Fa-f]{40,}(?![A-Za-z0-9])")
_UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")
_AWS_ID_RE = re.compile(r"^(?:i|sg|vpc|subnet|eni|vol|ami|rtb|igw|nat|snap|lt|eipalloc|eipassoc|acl|pcx|tgw|vpce|fs|key)-[0-9a-f]{8,17}$")
_RDS_ID_RE = re.compile(r"^(?:db|cluster)-[A-Z0-9]{26}$")
_PREFIXED_ULID_RE = re.compile(r"^[A-Za-z]{2,10}_[0-9A-HJKMNP-TV-Z]{26}$")
_COMMIT_CONTEXT_RE = re.compile(
    r"(?<![A-Za-z])(?:commit|revision|git|sha\d*(?![A-Za-z])|image|tag|version|build|deploy)", re.IGNORECASE
)
_DIGEST_BEFORE_RE = re.compile(r"(?:sha(?:1|224|256|384|512)|md5):$", re.IGNORECASE)

_SECRET_WORDS = {"password", "passwd", "pwd", "secret", "token", "apikey", "authorization", "cookie"}
_KEY_PREFIX_WORDS = {"api", "secret", "private", "access"}
_NAME_PART_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
# a key: a run of name characters that does not continue a longer word or an ARN, followed by a separator
_KEY_RUN_RE = re.compile(r"(?<![\w.:-])[\w.-]{1,60}(?=[\"']?[ \t]*[:=])")
_NAMED_VALUE_RE = re.compile(
    r"[\"']?[ \t]*[:=][ \t]*"
    r"(?:(?:bearer|basic|digest|token)[ \t]+)?"
    r"(?P<value>\"[^\"\n]*\"|'[^'\n]*'|[^\s,;\"']+)",
    re.IGNORECASE,
)
_TABLE_ROW_RE = re.compile(r"\|[ \t]*(?P<name>[^|\n]{1,80}?)[ \t]*\|(?P<value>[^|\n]+?)(?=\|[ \t]*(?:\n|$)|\|)", re.MULTILINE)
_PROSE_RE = re.compile(
    r"(?<![\w])(?:password|passwd|pwd|secret|token|api[ _-]?key)[ \t]+is[ \t]+"
    r"(?P<value>`[^`\n]+`|\"[^\"\n]+\"|'[^'\n]+'|[^\s,;]+)",
    re.IGNORECASE,
)
_NOT_A_VALUE = {"true", "false", "yes", "no", "ok", "none", "null", "redacted", "[redacted]"}
_NUMBER_RE = re.compile(r"^[+-]?\d[\d.,_]*$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ][\d:.+-]*[Zz]?)?$")
_MASK_RE = re.compile(r"^(?:[*#.\u2022-]{3,}|[xX]{3,})$")
_ANY_PLACEHOLDER_RE = re.compile(r"^<[^<>\n]*>$")
# plain words that follow "the password is" in ordinary prose
_PROSE_WORDS = {
    "the", "a", "an", "in", "not", "set", "stored", "rotated", "managed", "required", "invalid", "expired",
    "correct", "incorrect", "wrong", "missing", "empty", "unchanged", "changed", "reset", "from", "hashed",
    "encrypted", "masked", "unknown", "default", "blank", "valid", "used", "shared", "now", "also", "still",
    "kept", "saved", "read", "passed", "sent", "then", "no", "on", "at", "to", "as", "being", "never", "only",
}


def _is_secret_name(key: str) -> bool:
    """True when the last word of the name is a secret word: db_password, apiKey, auth-token."""
    parts = [part.lower() for piece in re.split(r"[_.-]+", key) for part in _NAME_PART_RE.findall(piece)]
    while parts and parts[-1].isdigit():
        parts.pop()
    if not parts:
        return False
    if parts[-1] in _SECRET_WORDS:
        return True
    return parts[-1] == "key" and len(parts) > 1 and parts[-2] in _KEY_PREFIX_WORDS


def _is_not_a_secret_value(value: str) -> bool:
    """Empty, a flag, a number, a date, an ARN, a structure, a mask or a placeholder."""
    inner = value.strip().strip("\"'`").strip()
    return (
        not inner
        or inner.lower() in _NOT_A_VALUE
        or bool(_NUMBER_RE.match(inner) or _DATE_RE.match(inner) or _MASK_RE.match(inner))
        or bool(_ANY_PLACEHOLDER_RE.match(inner))
        or inner.lower().startswith("arn:")
        or inner[0] in "[{"
    )


def _named_values(text: str):
    """Yield (start, end) of values that follow a secret name, in a pair, a table row or a sentence."""
    resume = 0
    for key in _KEY_RUN_RE.finditer(text):
        if key.start() < resume or not _is_secret_name(key.group()):
            continue
        tail = _NAMED_VALUE_RE.match(text, key.end())
        if tail:
            resume = tail.end()
            if not _is_not_a_secret_value(tail.group("value")):
                yield tail.start("value"), tail.end("value")
    for row in _TABLE_ROW_RE.finditer(text):
        name = row.group("name").strip("`*_ \t")
        value = row.group("value")
        if re.fullmatch(r"[\w.-]+", name) and _is_secret_name(name) and not _is_not_a_secret_value(value):
            lead = len(value) - len(value.lstrip(" \t`*"))
            yield row.start("value") + lead, row.end("value") - (len(value) - len(value.rstrip(" \t`*")))
    for sentence in _PROSE_RE.finditer(text):
        value = sentence.group("value").rstrip(".:!?)")
        bare = value.lower()
        if _is_not_a_secret_value(value) or (bare.isalpha() and bare in _PROSE_WORDS):
            continue
        yield sentence.start("value"), sentence.start("value") + len(value)


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


def _is_lowercase_secret(token: str) -> bool:
    """Random lower case letters and digits: a mix of both, switching often, with spread-out characters."""
    digits = sum(c.isdigit() for c in token)
    if sum(len(run) for run in _LOWER_WORD_RE.findall(token)) / len(token) >= 0.6:
        return False  # mostly words stuck together
    if not 0.12 <= digits / len(token) <= 0.65:
        return False
    switches = sum(a.isdigit() != b.isdigit() for a, b in zip(token, token[1:]))
    return switches >= len(token) / 6 and _entropy(token) >= ENTROPY_LOWERCASE


def _is_high_entropy(token: str) -> bool:
    token = token.rstrip("=")
    if len(token) < MIN_TOKEN_LENGTH or _UUID_RE.match(token) or _AWS_ID_RE.match(token):
        return False
    if _RDS_ID_RE.match(token) or _PREFIXED_ULID_RE.match(token):
        return False
    if re.fullmatch(r"[0-9A-Fa-f]+", token) or not any(c.isdigit() for c in token):
        return False
    lower = any(c.islower() for c in token)
    upper = any(c.isupper() for c in token)
    if not (lower or upper):
        return False
    if lower and not upper and token.isalnum():
        return _is_lowercase_secret(token)
    if "/" in token and not (lower and upper):
        return False
    if not (lower and upper) and not token.isalnum():
        return False  # lower case with separators is a pod or resource name, not a key
    if _looks_like_a_name(token):
        return False
    threshold = ENTROPY_THREE_CLASSES if lower and upper else ENTROPY_TWO_CLASSES
    return _entropy(token) >= threshold


def _line_of(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    return text[line_start : len(text) if line_end < 0 else line_end]


def _entropy_spans(text: str):
    for match in _HEX_RE.finditer(text):
        if _DIGEST_BEFORE_RE.search(text[max(0, match.start() - 8) : match.start()]):
            continue
        if match.end() - match.start() == 40 and _COMMIT_CONTEXT_RE.search(_line_of(text, match.start(), match.end())):
            continue  # a git commit id in a sentence or table row about a deploy
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


_WRAP_RE = re.compile(r"[ \t]*\r?\n[ \t]*")


def _wrapped_vendor_candidates(text: str):
    """Vendor tokens broken by a line wrap: scan a copy with the breaks and their indentation removed."""
    if "\n" not in text:
        return
    pieces: list[str] = []
    slots: list[tuple[int, int]] = []  # (start in the joined copy, start in text)
    joins: list[int] = []
    position = joined_length = 0
    for gap in _WRAP_RE.finditer(text):
        piece = text[position : gap.start()]
        slots.append((joined_length, position))
        pieces.append(piece)
        joined_length += len(piece)
        joins.append(joined_length)
        position = gap.end()
    slots.append((joined_length, position))
    pieces.append(text[position:])
    joined = "".join(pieces)
    joined_starts = [slot[0] for slot in slots]

    def to_text(index: int) -> int:
        slot = slots[bisect_right(joined_starts, index) - 1]
        return slot[1] + index - slot[0]

    for rule in _VENDOR_RULES:
        for match in rule.finditer(joined):
            crossing = bisect_right(joins, match.start())
            if crossing < len(joins) and joins[crossing] < match.end():
                yield 1, to_text(match.start()), to_text(match.end() - 1) + 1, "vendor_token"


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
    for start, end in _named_values(text):
        yield 2, start, end, "named_value"
    yield from _wrapped_vendor_candidates(text)
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
    """Find secrets and personal data in text. Never raises; never returns the matched text.

    allowed_account_aliases is the set of 12-digit account ids that are allowed to appear in the text;
    a 12-digit run that is in the set is not reported.
    """
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
