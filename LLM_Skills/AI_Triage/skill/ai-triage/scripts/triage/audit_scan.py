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
    word: str = ""  # the secret word a "secret_word_value" hit follows; never the value


# Entropy threshold in bits per character. Random base64 of 24 characters averages about 4.3
# (sd 0.15) while the identifiers that look most like it (class names, pod names, slugs) stay under 3.9.
ENTROPY_THREE_CLASSES = 4.0
ENTROPY_TWO_CLASSES = 4.3
ENTROPY_LOWERCASE = 3.6
LINE_WINDOW = 160  # how far around a value its line is read, so one huge line stays cheap
MIN_TOKEN_LENGTH = 24
MIN_LOWERCASE_LENGTH = 20
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

_CHUNK_RE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
_HEX_RE = re.compile(r"(?<![A-Za-z0-9])[0-9A-Fa-f]{40,}(?![A-Za-z0-9])")
_UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")
_AWS_ID_RE = re.compile(r"^(?:i|sg|vpc|subnet|eni|vol|ami|rtb|igw|nat|snap|lt|eipalloc|eipassoc|acl|pcx|tgw|vpce|fs|key)-[0-9a-f]{8,17}$")
_RDS_ID_RE = re.compile(r"^(?:db|cluster)-[A-Z0-9]{26}$")
_PREFIXED_ULID_RE = re.compile(r"^[A-Za-z]{2,10}_[0-9A-HJKMNP-TV-Z]{26}$")
_COMMIT_CONTEXT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:commit|revision|git|sha\d*|image|tag|version|build|deploy)(?![A-Za-z0-9])", re.IGNORECASE
)
# a secret word anywhere on the line, as a whole word or as the end of one, switches every exemption off
_SECRET_CONTEXT_RE = re.compile(r"(?:token|key|secret|password|passwd|credential|auth)s?(?![A-Za-z])", re.IGNORECASE)
_CONTAINER_SCHEME_RE = re.compile(r"(?:containerd|docker|cri-o)://$")
_CONTAINER_KEY_RE = re.compile(
    r"(?:container|image)id[\"'`]?[ \t]*[:=|]|sandbox[ \t]+container|container[ \t]+id", re.IGNORECASE
)
_WORD_RE = re.compile(r"[^\s|:=\"'`\[\](),]+")
_REQUEST_ID_KEYS = {"xamzcfid", "xamzid2", "xamzrequestid", "xamznrequestid", "requestid", "traceid"}
_HEX_ONLY_RE = re.compile(r"[0-9A-Fa-f]+")
_BASE64_ONLY_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_OIDC_ID_RE = re.compile(r"(?:^|/)id/[0-9A-Fa-f]{32}$")
_DIGEST_KEYS = ("sha256", "sha1", "md5", "digest", "checksum", "hash", "etag", "fingerprint", "thumbprint")
_DIGEST_BEFORE_RE = re.compile(r"(?:sha(?:1|224|256|384|512)|md5):$", re.IGNORECASE)

_SECRET_WORDS = (
    "password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "authorization", "cookie",
    "credential", "credentials",
)
_ERROR_WORDS = ("invalid", "expired", "missing", "malformed", "unrecognized", "incomplete", "bad", "unauthorized", "unsupported")
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
    r"(?<![\w])(?:password|passwd|pwd|passphrase|secret|token|api[ _-]?key)[ \t]+"
    r"(?:is(?:[ \t]+now|[ \t]+set[ \t]+to)?|(?:was[ \t]+)?(?:set|changed|reset)[ \t]+to)[ \t]+"
    r"(?P<value>`[^`\n]+`|\"[^\"\n]+\"|'[^'\n]+'|[^\s,;]+)",
    re.IGNORECASE,
)
_HTPASSWD_RE = re.compile(r"(?<![\w])htpasswd(?:[ \t]+-[A-Za-z]+)*[ \t]+(?P<user>\S+)[ \t]+(?P<value>\S+)", re.IGNORECASE)
_NETRC_RE = re.compile(r"(?<![\w])login[ \t]+\S+[ \t]+password[ \t]+(?P<value>\S+)|^[ \t]*password[ \t]+(?P<alone>\S+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_KEY_LINE_RE = re.compile(
    r"(?<![\w.-])(?:ParameterKey|Key|Name)[\"']?[ \t]*[:=][ \t]*[\"']?(?P<name>[\w.-]{1,60})", re.IGNORECASE
)
_VALUE_LINE_RE = re.compile(
    r"(?<![\w.-])(?:ParameterValue|Value)[\"']?[ \t]*[:=][ \t]*(?P<value>\"[^\"\n]*\"|'[^'\n]*'|[^\s,;\"'}]+)",
    re.IGNORECASE,
)
_NOT_A_VALUE = {"true", "false", "yes", "no", "ok", "none", "null", "redacted", "[redacted]"}
_WORD_PATH_RE = re.compile(r"^/?[a-z]+(?:[-_][a-z]+)*(?:/[a-z]+(?:[-_][a-z]+)*)+$")
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
    first = parts[0]
    if first in _ERROR_WORDS or (len(parts) == 1 and first.startswith(_ERROR_WORDS)):
        return False  # InvalidIdentityToken and ExpiredToken are error codes
    if parts[-1] == "auth" or parts[-1].endswith(_SECRET_WORDS):  # also glued names: PGPASSWORD, githubtoken
        return True
    return parts[-1] == "key" and len(parts) > 1 and parts[-2] in _KEY_PREFIX_WORDS


def _is_not_a_secret_value(value: str) -> bool:
    """Empty, a flag, a number, a date, an ARN, a structure, a mask or a placeholder."""
    inner = value.strip().strip("\"'`").strip()
    if inner[:1] in ("[", "{"):
        return True
    inner = inner.rstrip("),;.]}").rstrip("\"'`")
    return (
        not inner
        or bool(_WORD_PATH_RE.match(inner))
        or inner.lower() in _NOT_A_VALUE
        or bool(_NUMBER_RE.match(inner) or _DATE_RE.match(inner) or _MASK_RE.match(inner))
        or bool(_ANY_PLACEHOLDER_RE.match(inner))
        or inner.lower().startswith("arn:")
    )


_SEPARATOR_ROW_RE = re.compile(r"[^\n]{0,400}\n[ \t]*\|?[ \t]*:?-{3,}")


def _is_header_row(text: str, row_end: int) -> bool:
    return bool(_SEPARATOR_ROW_RE.match(text, row_end))


def _paired_values(text: str):
    """A value line within three lines of a key line whose name is a secret (CloudFormation, env lists)."""
    for key in _KEY_LINE_RE.finditer(text):
        if not _is_secret_name(key.group("name")):
            continue
        low = high = key.start()
        for _ in range(3):
            newline = text.rfind("\n", max(0, low - 300), low)
            low = newline if newline >= 0 else low
            if newline < 0:
                break
        low = text.rfind("\n", 0, low) + 1 if low > 0 else 0
        for _ in range(4):
            newline = text.find("\n", high + 1, high + 300)
            if newline < 0:
                high = min(len(text), high + 300)
                break
            high = newline
        for value in _VALUE_LINE_RE.finditer(text, low, high):
            if not _is_not_a_secret_value(value.group("value")):
                yield value.start("value"), value.end("value")


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
        if _is_header_row(text, row.end()):
            continue
        if re.fullmatch(r"[\w. -]+", name) and _is_secret_name(name.replace(" ", "_")) and not _is_not_a_secret_value(value):
            lead = len(value) - len(value.lstrip(" \t`*"))
            yield row.start("value") + lead, row.end("value") - (len(value) - len(value.rstrip(" \t`*")))
    for sentence in _PROSE_RE.finditer(text):
        value = sentence.group("value").rstrip(".:!?)")
        bare = value.lower()
        if _is_not_a_secret_value(value) or (bare.isalpha() and bare in _PROSE_WORDS):
            continue
        yield sentence.start("value"), sentence.start("value") + len(value)
    for line in _NETRC_RE.finditer(text):
        value = line.group("value") or line.group("alone")
        if _is_not_a_secret_value(value) or (value.isalpha() and value.lower() in _PROSE_WORDS):
            continue
        group = "value" if line.group("value") else "alone"
        yield line.start(group), line.end(group)
    yield from _paired_values(text)
    for command in _HTPASSWD_RE.finditer(text):
        value = command.group("value")
        if command.group("user").lower() in _PROSE_WORDS | {"is", "was", "file", "for", "command", "tool", "utility", "and", "or"}:
            continue
        if not _is_not_a_secret_value(value):
            yield command.start("value"), command.end("value")


_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_PHONE_RE = re.compile(r"(?<![\w+])\+\d(?:[ .()-]{0,2}\d){7,14}(?!\d)")
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
    wordy = sum(len(run) for run in _LOWER_WORD_RE.findall(token))
    if wordy / len(token) >= 0.6 and len(token) - wordy < 10:
        return False  # words stuck together with hardly anything else
    if not 0.12 <= digits / len(token) <= 0.65:
        return False
    switches = sum(a.isdigit() != b.isdigit() for a, b in zip(token, token[1:]))
    return switches >= len(token) / 6 and _entropy(token) >= ENTROPY_LOWERCASE


def _is_high_entropy(token: str) -> bool:
    token = token.rstrip("=")
    if len(token) < MIN_LOWERCASE_LENGTH or _UUID_RE.match(token) or _AWS_ID_RE.match(token):
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
    if len(token) < MIN_TOKEN_LENGTH:
        return False
    if "/" in token and not (lower and upper):
        return False
    if not (lower and upper) and not token.isalnum():
        return False  # lower case with separators is a pod or resource name, not a key
    if _looks_like_a_name(token):
        return False
    threshold = ENTROPY_THREE_CLASSES if lower and upper else ENTROPY_TWO_CLASSES
    return _entropy(token) >= threshold


def _line_of(text: str, start: int, end: int) -> str:
    """The line holding text[start:end], without that part itself."""
    window_start = max(0, start - LINE_WINDOW)
    line_start = text.rfind("\n", window_start, start) + 1 or window_start
    line_end = text.find("\n", end, end + LINE_WINDOW)
    return text[line_start:start] + " " + text[end : end + LINE_WINDOW if line_end < 0 else line_end]


def _normalise_key(word: str) -> str:
    return re.sub(r"[^a-z0-9]", "", word.lower())


def _preceding_words(text: str, start: int, count: int) -> list[str]:
    """The last few words before the value on its line, without quotes, separators or brackets."""
    before = text[max(0, start - 100) : start].rsplit("\n", 1)[-1]
    return [_normalise_key(word) for word in _WORD_RE.findall(before)[-count:]]


def _is_digest_key(name: str) -> bool:
    return re.sub(r"(?:list|s)$", "", name).endswith(_DIGEST_KEYS)


def _is_digest_shape(value: str) -> bool:
    if _HEX_ONLY_RE.fullmatch(value):
        return len(value) in (32, 40, 64, 128)
    return bool(_BASE64_ONLY_RE.fullmatch(value)) and len(value) in (24, 28, 44, 88)


def _table_cells(line: str) -> list[str]:
    cells = line.split("|")
    if line.lstrip().startswith("|"):
        cells = cells[1:]
    return [_normalise_key(cell) for cell in cells]


def _line_start(text: str, position: int) -> int:
    """Start of the line holding position, looking back at most LINE_WINDOW characters."""
    floor = max(0, position - LINE_WINDOW)
    newline = text.rfind("\n", floor, position)
    return newline + 1 if newline >= 0 else floor


def _in_digest_table(text: str, start: int) -> bool:
    """The value sits in a table column headed by, or in a row named by, a thumbprint or digest key."""
    line_start = _line_start(text, start)
    if "|" not in text[line_start:start]:
        return False
    line_end = text.find("\n", start, start + LINE_WINDOW)
    row = text[line_start : start + LINE_WINDOW if line_end < 0 else line_end]
    column = text[line_start:start].count("|") - (1 if row.lstrip().startswith("|") else 0)
    cells = _table_cells(row)
    if 0 <= column - 1 < len(cells) and any(key in cells[column - 1] for key in _DIGEST_KEYS):
        return True  # the cell to the left names the value
    position = line_start
    for _ in range(40):  # walk up to the separator row, whose line above is the header
        if position <= 0:
            return False
        previous = _line_start(text, position - 1)
        if re.match(r"[ \t]*\|?[ \t]*:?-{3,}", text[previous:position]):
            top = _line_start(text, previous - 1)
            header = _table_cells(text[top : min(previous - 1, top + 2 * LINE_WINDOW)])
            return any(key in cell for cell in header for key in _DIGEST_KEYS)
        position = previous
    return False


def _is_known_identifier(text: str, start: int, end: int) -> bool:
    """A commit, container id, digest or request id that ordinary evidence carries; never next to a secret word."""
    value = text[start:end]
    length = len(value)
    is_hex = bool(_HEX_ONLY_RE.fullmatch(value))
    known = False
    words = _preceding_words(text, start, 3)
    if _is_digest_shape(value) and (any(_is_digest_key(word) for word in words) or _in_digest_table(text, start)):
        known = True
    elif words and (words[-1] in _REQUEST_ID_KEYS or "".join(words[-2:]) in _REQUEST_ID_KEYS):
        known = True
    elif is_hex and length in (40, 64):
        line = _line_of(text, start, end)
        if length == 40:
            before = text[max(0, start - 200) : start]
            in_path = before.endswith("/") and re.search(r"\S*$", before).group().count("/") >= 2
            known = bool(_COMMIT_CONTEXT_RE.search(line)) or in_path
        else:
            known = bool(
                _CONTAINER_SCHEME_RE.search(text[max(0, start - 13) : start]) or _CONTAINER_KEY_RE.search(line)
            )
    return known and not _SECRET_CONTEXT_RE.search(_line_of(text, start, end))


def _entropy_spans(text: str):
    for match in _HEX_RE.finditer(text):
        if _DIGEST_BEFORE_RE.search(text[max(0, match.start() - 8) : match.start()]):
            continue
        if len(set(match.group())) < 8 or _is_known_identifier(text, match.start(), match.end()):
            continue  # a run of one or two digits, such as git's all-zero id, is not a key
        yield match.start(), match.end()
    for match in _CHUNK_RE.finditer(text):
        chunk = match.group()
        before = text[max(0, match.start() - 8) : match.start()]
        if _DIGEST_BEFORE_RE.search(before) or ("/id/" in chunk and _OIDC_ID_RE.search(chunk)):
            continue
        if "/" not in chunk or (not chunk.startswith("/") and "//" not in chunk):
            if _is_high_entropy(chunk) and not _is_known_identifier(text, match.start(), match.end()):
                yield match.start(), match.end()
                continue
            if "/" not in chunk:
                continue
        offset = match.start()
        known = None
        for segment in chunk.split("/"):
            if _is_high_entropy(segment):
                if known is None:
                    known = _is_known_identifier(text, match.start(), match.end())
                if not known:
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


_SECRET_WORD_RE = re.compile(
    r"(?:api[ _-]?key|access[ _-]?key|key|token|secret|credential|passphrase|lease)s?"
    r"(?=$|[\s|,;\"'`()\[\]{}:=<>*.!?])",
    re.IGNORECASE,
)
_AFTER_WORD_RE = re.compile(r"<[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)*>|[^\s|,;\"'`()\[\]{}:=<>*]+")
MIN_VALUE_AFTER_WORD = 16


def _secret_word_values(text: str, allowed: frozenset[str], words: dict):
    """Any token of 16 or more characters within three words after a secret word, whatever its shape."""
    for word in _SECRET_WORD_RE.finditer(text):
        line_end = text.find("\n", word.end(), word.end() + LINE_WINDOW)
        stop = word.end() + LINE_WINDOW if line_end < 0 else line_end
        floor = max(0, word.start() - LINE_WINDOW)
        chunk_start = max(text.rfind(" ", floor, word.start()), text.rfind("\n", floor, word.start()), floor - 1) + 1
        if text[chunk_start : chunk_start + 4].lower() == "arn:":
            continue  # the word is a part of an ARN
        for count, token in enumerate(_AFTER_WORD_RE.finditer(text, word.end(), stop)):
            if count == 3:
                break
            value = token.group()
            if value.lower() == "arn" and text[token.end() : token.end() + 1] == ":":
                break  # an ARN follows; its pieces are not secrets
            if value.startswith("<") or len(value) < MIN_VALUE_AFTER_WORD or value in allowed:
                continue  # a mask, a short word or a configured alias
            words[(token.start(), token.end())] = re.sub(r"s$", "", word.group().lower())
            yield token.start(), token.end()


def _candidates(text: str, allowed: frozenset[str], words: dict | None = None):
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
    for start, end in _secret_word_values(text, allowed, words if words is not None else {}):
        yield 2, start, end, "secret_word_value"
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
        words: dict[tuple[int, int], str] = {}
        for _, start, end, kind in sorted(_candidates(body, allowed_account_aliases, words)):
            if end <= start or any(taken[start:end]):
                continue
            taken[start:end] = b"\x01" * (end - start)
            accepted.append((start, end, kind))
        hits = []
        for start, end, kind in accepted:
            origin, origin_end = normalised.original_span(start, end)
            line, column = normalised.line_column(origin)
            hits.append(Hit(kind, line, column, origin_end - origin, words.get((start, end), "")))
        return sorted(hits, key=lambda hit: (hit.line, hit.column))
    except Exception:  # noqa: BLE001 - the audit must fail closed, never crash the publish
        return [Hit("unreadable", 1, 1, len(text) if isinstance(text, str) else 0)]


def describe(hits: list[Hit]) -> list[str]:
    """One line per hit: kind, line, column, length. No matched text."""
    return [
        f"{hit.kind} at line {hit.line}, column {hit.column}, length {hit.length}"
        + (f", value after the word '{hit.word}'" if hit.word else "")
        for hit in hits
    ]
