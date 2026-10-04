"""Redact secrets and personal data from text before it enters evidence."""
from __future__ import annotations

import ast
import bisect
import copy
import functools
import hashlib
import ipaddress
import json
import re
import threading
import warnings
from dataclasses import dataclass
from typing import Any, Callable

Span = tuple[int, int]
SpanRule = Callable[[str], list[Span]]

PLACEHOLDER_RE = re.compile(r"<[A-Z]+-\d+>")
_NUMBERED_PLACEHOLDER_RE = re.compile(r"<(SECRET|EMAIL|IP)-(\d+)>")
_SCHEME_AND_PLACEHOLDER_RE = re.compile(r"(?:[A-Za-z]+ )?<[A-Z]+-\d+>")

# A name is secret when one of its parts (split on separators and camel case, trailing digits
# stripped) holds a secret stem, unless its last part says it names something else (see
# NAME_ENDINGS). SECRET_WORDS stays exported for collectors that look up single words.
SECRET_WORDS = frozenset({
    "password", "passwords", "passwd", "pass", "pwd", "passphrase", "secret", "secrets", "token",
    "apikey", "apikeys", "credential", "credentials", "auth", "cookie", "cookies",
    "authorization", "proxyauthorization", "pw", "cred", "creds",
})
# Long stems match anywhere inside a part.
LONG_SECRET_STEMS = (
    "pass", "passwd", "password", "secret", "token", "cred", "auth", "private", "session", "cookie",
    "bearer", "signature", "license", "licence", "hmac",
)
# Whole English words that hold a long stem but never name a secret ("Gates passed: ...").
STEM_WORD_EXCEPTIONS = frozenset({"passed", "passing", "bypass", "passenger", "passengers", "compass"})
# Short stems match a whole part only.
SHORT_SECRET_STEMS = frozenset({
    "key", "keys", "pwd", "pw", "psw", "pswd", "psk", "sk", "pat", "pin", "otp", "mfa", "jwt", "sig",
    "salt", "pepper", "nonce", "seed", "dsn", "cert", "code",
})
# These short stems also match at the end of a part (apikey, mysqlpwd).
END_SECRET_STEMS = ("key", "keys", "pwd")
KEY_WORDS = frozenset({"key", "keys"})
# A "key" part is not secret when the part before it (or its own prefix) says what kind of key it is.
NON_SECRET_KEY_KINDS = frozenset({
    "partition", "sort", "s3", "routing", "cache", "kms", "primary", "foreign", "idempotency",
    "object", "hash", "shard", "range", "dedup", "group", "row", "public", "index", "tag",
    "metric", "map", "lookup", "parameter", "attribute",
})
# A name ending in one of these names a reference, a setting or a measurement, not the secret.
REFERENCE_SUFFIXES = frozenset({
    "arn", "id", "ids", "name", "names", "status", "type", "version", "count", "enabled",
    "expiry", "expires", "rotation", "length", "policy", "url", "path",
    "ttl", "timeout", "age", "days", "seconds", "validity", "units", "date", "time", "used",
    "expiration", "mode", "stages", "flows", "prevention", "required", "file",
    "at", "failures", "attempts", "errors", "audience",
})
NAME_ENDINGS = REFERENCE_SUFFIXES | frozenset({
    "source", "endpoint", "flow", "requests", "remaining", "state", "schema", "usage", "spec",
    "metadata", "fingerprint", "ms", "latency",
})
PERSONAL_WORDS = frozenset({"user", "usr", "username", "login", "email", "mail", "owner", "phone", "msisdn", "ssn"})
AUTHORIZATION_WORDS = frozenset({"authorization", "proxyauthorization"})
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Environment-entry shapes: (name key, value key).
NAME_VALUE_KEYS = (
    ("name", "value"), ("Name", "Value"), ("key", "value"), ("Key", "Value"),
    ("ParameterKey", "ParameterValue"),
)
REFERENCE_KEY = "valueFrom"


@functools.lru_cache(maxsize=8192)
def _components(key: str) -> tuple[str, ...]:
    spaced = _CAMEL_BOUNDARY_RE.sub(" ", key)
    return tuple(part.lower() for part in re.split(r"[^A-Za-z0-9]+", spaced) if part)


def key_components(key: str) -> list[str]:
    return list(_components(key))


@functools.lru_cache(maxsize=8192)
def _name_parts(key: str) -> tuple[str, ...]:
    """Lower-case parts of a name with trailing digits stripped: DbPassword2 -> (db, password)."""
    parts = (part.rstrip("0123456789") for part in _components(key))
    return tuple(part for part in parts if part)


@functools.lru_cache(maxsize=8192)
def is_reference_key(key: str) -> bool:
    parts = _name_parts(key)
    return bool(parts) and parts[-1] in NAME_ENDINGS


@functools.lru_cache(maxsize=8192)
def is_authorization_key(key: str) -> bool:
    components = _components(key)
    return bool(components) and components[-1] in AUTHORIZATION_WORDS


def _is_key_kind(part: str) -> bool:
    return part in NON_SECRET_KEY_KINDS or part.rstrip("0123456789") in NON_SECRET_KEY_KINDS


def _secret_part(parts: tuple[str, ...], raw: tuple[str, ...], index: int) -> bool:
    part = parts[index]
    if part in STEM_WORD_EXCEPTIONS:
        return False
    if any(stem in part for stem in LONG_SECRET_STEMS):
        return True
    if part in KEY_WORDS:  # a bare "key" is a lookup key (S3 Key=, a tag Key)
        return len(parts) > 1 and not (index > 0 and _is_key_kind(raw[index - 1]))
    if part in SHORT_SECRET_STEMS:
        return True
    for stem in END_SECRET_STEMS:
        if part.endswith(stem) and len(part) > len(stem):
            return stem not in KEY_WORDS or not _is_key_kind(part[:-len(stem)])
    return False


@functools.lru_cache(maxsize=8192)
def looks_secret_key(key: str) -> bool:
    """Whether a name says its value is a secret.

    Order: the name's last part is checked first; a reference or measurement ending (Name, Id,
    Arn, Endpoint, Count, ...) means "not secret" whatever stems the name holds (ruling 9). Only
    then are the stems tried (ruling 11). A bare "key" and a key qualified by a non-secret kind
    (PartitionKey, AttributeKey) are not secret.
    """
    parts = _name_parts(key)
    if not parts or parts[-1] in NAME_ENDINGS:
        return False
    raw = tuple(part for part in _components(key) if part.rstrip("0123456789"))
    return any(_secret_part(parts, raw, index) for index in range(len(parts)))


@functools.lru_cache(maxsize=8192)
def looks_personal_key(key: str) -> bool:
    """Whether a name says its value is personal data (user, email, phone ...), by whole parts."""
    return any(part in PERSONAL_WORDS for part in _name_parts(key))


# --- span rules: each returns the spans of text that are secret --------------------------

def _usable(text: str, span: Span | None) -> bool:
    return bool(span) and span[1] > span[0] and not PLACEHOLDER_RE.fullmatch(text[span[0]:span[1]])


def _merge(spans: list[Span]) -> list[Span]:
    merged: list[Span] = []
    for span in sorted(spans, key=lambda item: (item[0], -item[1])):
        if not merged or span[0] >= merged[-1][1]:
            merged.append(span)
    return merged


def _group_rule(pattern: re.Pattern[str], *groups: str) -> SpanRule:
    """Spans of the first of the named groups that took part in each match."""
    def find(text: str) -> list[Span]:
        spans = []
        for match in pattern.finditer(text):
            span = next((match.span(g) for g in groups if match.group(g) is not None), None)
            if span and _usable(text, span):
                spans.append(span)
        return spans
    return find


PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)
# Userinfo ends at the last "@" that is followed by a host; the password may hold any character.
URL_CREDENTIAL_RE = re.compile(
    r"""(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://[^\s:/@"',]{0,256}(?:@[^\s:/@"',]{0,256})?"""
    r""":(?!\d{1,5}[/?#])(?P<secret>[^\s"',]{1,256}?)@(?=[^\s@/?#"',]+(?:[/:?#\s"',]|$))"""
)
URL_USERINFO_RE = re.compile(r"""(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://[^\s/?#@",]{0,256}@""")
AUTHORIZATION_RE = re.compile(
    r"""(?<![\w-])(?i:(?:proxy-)?authorization)\\?["']?[ \t]*[:=][ \t]*\\?["']?"""
    r"""(?:(?i:digest)[ \t]+(?P<digest>[^\r\n]+)"""
    r"""|(?P<scheme>[A-Za-z][\w-]*)[ \t]+(?P<token>[^\s"'\\]+)"""
    r"""|(?P<bare>[^\s"'\\]+))"""
)
SECRET_HEADER_RE = re.compile(
    r"""(?<![\w-])(?<!://)\w+(?:-\w+)*-(?:token|key|secret)\\?["']?[ \t]*:[ \t]*(?![\\"'])(?P<value>[^\r\n"']*[^\s"'\\])""",
    re.IGNORECASE,
)
AUTHORIZATION_SENTENCE_RE = re.compile(
    r"""\bauthorization\b(?![ \t]*[:=])[^\r\n]{0,20}?\b(?:Basic|Bearer|Digest|Token|Negotiate|NTLM|Hawk|Bot|ApiKey)[ \t]+"""
    r"""(?P<token>[^\s"'\\]+)""",
    re.IGNORECASE,
)
WEBHOOK_RE = re.compile(
    r"""(?<![\w.-])(?:hooks\.slack\.com/(?P<slack>services/[^\s"'<>]+)"""
    r"""|discord(?:app)?\.com/(?P<discord>api/webhooks/[^\s"'<>]+)"""
    r"""|[\w-]+(?:\.[\w-]+)*\.webhook\.office\.com/(?P<office>[^\s"'<>]+))"""
)
BEARER_RE = re.compile(r"\bBearer[ \t]+(?P<token>[A-Za-z0-9._~+/-]{16,}=*)", re.IGNORECASE)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
VENDOR_TOKEN_RE = re.compile(
    r"(?<![\w-])(?:(?:ghp_|gho_|ghs_|github_pat_|xoxb-|xoxp-|xoxa-|sk_live_|sk_test_|rk_live_|whsec_)[A-Za-z0-9_-]{10,}"
    r"|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,})"
)
AWS_SECRET_KEY_RE = re.compile(r"(?<![\w/+=-])[A-Za-z0-9/+]{40}(?![\w/+=-])")
JWT_RE = re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+")

KV_START_RE = re.compile(
    r"""(?<![\w.\-/:@])(?P<key>-{0,2}[A-Za-z_][\w.\-]*)(?P<quote>\\?["']?)(?P<sep>[ \t]*(?:=>|=|:)[ \t]*)"""
)
XML_PAIR_RE = re.compile(r"<(?P<key>[A-Za-z_][\w.\-]*)>(?P<value>[^<\n]+)</(?P=key)>")
LITERAL_VALUES = frozenset({"null", "true", "false", "yes", "no", "none"})
_VALUE_END_RE = re.compile(r'[),"]| \(')
_SCHEME_AND_TOKEN_RE = re.compile(r"(?P<scheme>[A-Za-z][\w-]*)(?P<gap>[ \t]+)(?P<token>\S.*)", re.DOTALL)
_BLOCK_SCALAR_RE = re.compile(r"[|>][+-]?\d?")
_BARE_VALUE_RE = re.compile(r"""[^\s&,;"'}\]]+""")


def _pem_spans(text: str) -> list[Span]:
    return [m.span() for m in PEM_RE.finditer(text)]


def _auth_spans(text: str) -> list[Span]:
    authorization = _group_rule(AUTHORIZATION_RE, "digest", "token", "bare")
    header = _group_rule(SECRET_HEADER_RE, "value")
    bearer = _group_rule(BEARER_RE, "token")
    sentence = _group_rule(AUTHORIZATION_SENTENCE_RE, "token")
    return _merge(authorization(text) + header(text) + bearer(text) + sentence(text))


def _aws_secret_key_spans(text: str) -> list[Span]:
    spans = []
    for match in AWS_SECRET_KEY_RE.finditer(text):
        candidate = match.group()
        mixed = any(c.isupper() for c in candidate) and any(c.islower() for c in candidate)
        if mixed and any(c.isdigit() for c in candidate) and not re.fullmatch(r"[0-9a-fA-F]+", candidate):
            spans.append(match.span())
    return spans


_line_cache = threading.local()


def _line_end(text: str, start: int) -> int:
    """Offset of the end of the line holding start. Newline offsets are computed once per text."""
    if getattr(_line_cache, "text", None) is not text:
        _line_cache.text = text
        _line_cache.newlines = [m.start() for m in re.finditer("\n", text)]
    newlines = _line_cache.newlines
    index = bisect.bisect_left(newlines, start)
    return newlines[index] if index < len(newlines) else len(text)


def _quoted_span(text: str, start: int) -> Span | None:
    """The inside of a quoted value starting at start, honouring escapes; None if not quoted."""
    if text.startswith(("\\\"", "\\'"), start):
        limit = _line_end(text, start)
        closing = "\\" + text[start + 1]
        end = text.find(closing, start + 2, limit)
        return (start + 2, limit if end == -1 else end)
    if start < len(text) and text[start] in "\"'":
        limit = _line_end(text, start)
        quote, index = text[start], start + 1
        while index < limit:
            if text[index] == "\\":
                index += 2
                continue
            if text[index] == quote:
                break
            index += 1
        return (start + 1, min(index, limit))
    return None


def _block_scalar_span(text: str, after_line: int) -> Span | None:
    """The indented lines that follow a YAML `key: |` line."""
    first = last = None
    position = after_line + 1
    while position <= len(text):
        end = _line_end(text, position)
        line = text[position:end]
        if line.strip() and not line[0] in " \t":
            break
        if line.strip():
            if first is None:
                first = position + len(line) - len(line.lstrip())
            last = end
        if end >= len(text):
            break
        position = end + 1
    return (first, last) if first is not None else None


@functools.lru_cache(maxsize=8192)
def _kv_candidate_is_secret(key: str, quote: str, sep: str) -> bool:
    if not looks_secret_key(key) or is_authorization_key(key):
        return False  # Authorization values keep their scheme word: the authorization rule handles them
    colon_only = "=" not in sep
    if colon_only and not quote and "." in key.strip("-"):
        # auth.example.com: refused is a hostname; db.password: x is a key.
        return looks_secret_key(key.rsplit(".", 1)[-1])
    return True


def _kv_value_span(text: str, start: int, quote: str, sep: str, stop_at_delimiters: bool = True) -> Span | None:
    colon_only = "=" not in sep
    if start >= len(text) or text[start] in "\r\n":
        return None
    quoted = _quoted_span(text, start)
    if quoted:
        return quoted
    if colon_only and not quote:
        if not sep.endswith((" ", "\t")) and text[start] in "0123456789/\\":
            return None  # host:port or a path, not a value
        end = _line_end(text, start)
        while end > start and text[end - 1] in " \t\r":
            end -= 1
        if _BLOCK_SCALAR_RE.fullmatch(text[start:end]):
            return _block_scalar_span(text, end)
        if stop_at_delimiters:
            delimiter = _VALUE_END_RE.search(text, start, end)
            if delimiter:
                end = delimiter.start()
        return (start, end) if end > start else None
    bare = _BARE_VALUE_RE.match(text, start)
    return bare.span() if bare else None


def _key_value_spans(text: str) -> list[Span]:
    spans: list[Span] = []
    position = 0
    while True:
        match = KV_START_RE.search(text, position)
        if not match:
            break
        key, quote, sep = match.group("key"), match.group("quote"), match.group("sep")
        if not _kv_candidate_is_secret(key, quote, sep):
            position = match.end("key")
            continue
        span = _kv_value_span(text, match.end(), quote, sep)
        position = max(match.end(), span[1]) if span else match.end()
        if not span or not _usable(text, span):
            continue
        value = text[span[0]:span[1]]
        if _SCHEME_AND_PLACEHOLDER_RE.fullmatch(value) or value.lower() in LITERAL_VALUES:
            continue
        spans.append(span)
    for match in XML_PAIR_RE.finditer(text):
        if looks_secret_key(match.group("key")) and _usable(text, match.span("value")):
            spans.append(match.span("value"))
    return _merge(spans)


_NAME_KEY = r"(?:name|Name|Key|ParameterKey)"
_VALUE_KEY = r"(?:value|Value|ParameterValue)"
_Q = r"""\\?["']"""
# {"name": N, <other scalar pairs>, "value": V} with any whitespace, either quote style, in plain or escaped JSON.
JSON_NAME_VALUE_RE = re.compile(
    _Q + _NAME_KEY + _Q + r"""\s*:\s*""" + _Q + r"""(?P<name>[^"'\\]{0,200})""" + _Q
    + r"""(?:\s*,\s*""" + _Q + r"""[\w.-]{1,60}""" + _Q + r"""\s*:\s*(?:""" + _Q + r"""[^"'\\]{0,200}""" + _Q
    + r"""|[^,{}\[\]\s"']{1,60})){0,8}"""
    + r"""\s*,\s*""" + _Q + _VALUE_KEY + _Q + r"""\s*:\s*"""
)
YAML_NAME_VALUE_RE = re.compile(
    r"""^(?P<lead>[ \t]*(?:-[ \t]+)?)""" + _NAME_KEY + r""":[ \t]*(?P<quote>["']?)(?P<name>[^\s"']+)(?P=quote)[ \t]*\r?\n"""
    r"""(?P<indent2>[ \t]*)""" + _VALUE_KEY + r""":[ \t]*""",
    re.MULTILINE,
)


def _name_value_spans(text: str) -> list[Span]:
    """The value of a name/value entry whose name is a secret key, in JSON or YAML text."""
    spans: list[Span] = []
    for match in JSON_NAME_VALUE_RE.finditer(text):
        if looks_secret_key(match.group("name")):
            span = _quoted_span(text, match.end()) or (_BARE_VALUE_RE.match(text, match.end()) or match).span()
            if span[0] >= match.end() and _usable(text, span) and text[span[0]:span[1]].lower() not in LITERAL_VALUES:
                spans.append(span)
    for match in YAML_NAME_VALUE_RE.finditer(text):
        # The value key sits in the column of the name key itself, however many spaces follow the dash.
        if len(match.group("indent2")) == len(match.group("lead")) and looks_secret_key(match.group("name")):
            span = _kv_value_span(text, match.end(), "", ": ", stop_at_delimiters=False)
            if span and _usable(text, span) and text[span[0]:span[1]].lower() not in LITERAL_VALUES:
                spans.append(span)
    return _merge(spans)


_FLAG_RE = re.compile(r"(?<!\S)(?P<flag>--?[A-Za-z][\w-]*)[ \t]+(?=\S)")
_TRAILING_PUNCTUATION = "\"'`,;)"


def _flag_value_span(text: str, start: int) -> Span:
    quoted = _quoted_span(text, start)
    if quoted:
        return quoted
    end = start
    while end < len(text) and not text[end].isspace():
        end += 1
    while end > start and text[end - 1] in _TRAILING_PUNCTUATION:
        end -= 1
    return (start, end)


def _flag_spans(text: str) -> list[Span]:
    """The argument after a flag whose name is a secret key (--db-password VALUE)."""
    spans: list[Span] = []
    for match in _FLAG_RE.finditer(text):
        start = match.end()
        if text[start] == "-" or not looks_secret_key(match.group("flag").lstrip("-")):
            continue
        span = _flag_value_span(text, start)
        if _usable(text, span):
            spans.append(span)
    return _merge(spans)


# Commands whose credentials sit in short flags. Regions run to the end of the command: the line, a
# ; | or && separator, the next command word, or 2000 characters.
_COMMAND_RE = re.compile(
    r"(?<![\w.-])(?P<command>curl|wget|mysqldump|mysqladmin|mysql|docker[ \t]+login|sshpass|redis-cli)(?![\w-])"
)
_COMMAND_END_RE = re.compile(r";|\||&&")
_TOKEN = r"""(?:"[^"\n]*"|'[^'\n]*'|[^\s"']+)"""
_USER_FLAG_RE = re.compile(
    r"(?<!\S)(?:(?:--user|--proxy-user)(?:=|[ \t]+)(?P<long>" + _TOKEN + r")|-u(?P<gap>[ \t]*)(?P<short>" + _TOKEN + r"))"
)
_ATTACHED_P_RE = re.compile(r"(?<!\S)-p(?P<value>[^\s-]\S*)")
_SPACED_P_RE = re.compile(r"(?<!\S)-p[ \t]*(?P<value>" + _TOKEN + r")")
_REDIS_A_RE = re.compile(r"(?<!\S)-a[ \t]+(?P<value>" + _TOKEN + r")")
_COMMANDS_WITH_USER_FLAG = ("curl", "wget")
_COMMANDS_WITH_ATTACHED_P = ("mysql", "mysqladmin", "mysqldump")


def _token_inner(text: str, start: int, end: int) -> Span:
    """The span of a token without its quotes or trailing punctuation."""
    if end - start >= 2 and text[start] in "\"'" and text[end - 1] == text[start]:
        return (start + 1, end - 1)
    while end > start and text[end - 1] in _TRAILING_PUNCTUATION:
        end -= 1
    return (start, end)


def _password_after_colon(text: str, start: int, end: int) -> Span | None:
    inner = _token_inner(text, start, end)
    colon = text.find(":", inner[0], inner[1])
    return (colon + 1, inner[1]) if colon != -1 else None


def _command_spans(text: str) -> list[Span]:
    """Credentials in a command string: curl -u user:pass, mysql -pPASS, docker login -p PASS."""
    matches = list(_COMMAND_RE.finditer(text))
    spans: list[Span] = []
    for index, match in enumerate(matches):
        limit = min(_line_end(text, match.end()), match.end() + 2000)
        if index + 1 < len(matches):
            limit = min(limit, matches[index + 1].start())
        separator = _COMMAND_END_RE.search(text, match.end(), limit)
        if separator:
            limit = separator.start()
        command = match.group("command").split()[0]
        if command in _COMMANDS_WITH_USER_FLAG:
            for found in _USER_FLAG_RE.finditer(text, match.end(), limit):
                group = "long" if found.group("long") else "short"
                span = _password_after_colon(text, found.start(group), found.end(group))
                attached_without_colon = group == "short" and not found.group("gap") and span is None
                if span and not attached_without_colon:
                    spans.append(span)
        elif command in _COMMANDS_WITH_ATTACHED_P:
            for found in _ATTACHED_P_RE.finditer(text, match.end(), limit):
                spans.append(_token_inner(text, found.start("value"), found.end("value")))
        elif command in ("docker", "sshpass"):
            for found in _SPACED_P_RE.finditer(text, match.end(), limit):
                spans.append(_token_inner(text, found.start("value"), found.end("value")))
        elif command == "redis-cli":
            for found in _REDIS_A_RE.finditer(text, match.end(), limit):
                spans.append(_token_inner(text, found.start("value"), found.end("value")))
    return _merge([span for span in spans if _usable(text, span)])


def _webhook_spans(text: str) -> list[Span]:
    return _group_rule(WEBHOOK_RE, "slack", "discord", "office")(text)


# (audit category, rule), in redaction order.
SECRET_RULES: tuple[tuple[str, SpanRule], ...] = (
    ("private_key", _pem_spans),
    ("url_credential", _group_rule(URL_CREDENTIAL_RE, "secret")),
    ("auth_header", _auth_spans),
    ("secret_key_value", _key_value_spans),
    ("secret_name_value", _name_value_spans),
    ("secret_flag", _flag_spans),
    ("secret_command", _command_spans),
    ("webhook_url", _webhook_spans),
    ("aws_access_key", lambda text: [m.span() for m in AWS_KEY_RE.finditer(text)]),
    ("vendor_token", lambda text: [m.span() for m in VENDOR_TOKEN_RE.finditer(text)]),
    ("aws_secret_key", _aws_secret_key_spans),
    ("jwt", lambda text: [m.span() for m in JWT_RE.finditer(text)]),
)

# --- emails and addresses ----------------------------------------------------------------

EMAIL_RE = re.compile(
    r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"
)
_SCP_PATH_AFTER_RE = re.compile(r":[A-Za-z~./_]")
IPV4_RE = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w]|\.\d)")


def _url_userinfo_spans(text: str) -> list[Span]:
    """Spans the URL rules matched: an email inside one is a user name, not an email address."""
    return _merge(
        [m.span() for m in URL_CREDENTIAL_RE.finditer(text)] + [m.span() for m in URL_USERINFO_RE.finditer(text)]
    )


def _is_email(text: str, match: re.Match[str], userinfo: list[Span], starts: list[int]) -> bool:
    index = bisect.bisect_right(starts, match.start()) - 1
    if index >= 0 and match.start() < userinfo[index][1]:
        return False
    return not _SCP_PATH_AFTER_RE.match(text, match.end())


def _is_public_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


MAX_EMBEDDED_SPAN = 200_000      # longest {...} or [...] span parsed structurally
MAX_STRUCTURE_DEPTH = 50         # deeper structures go through the pattern rules instead
MAX_DIRECT_DEPTH = 200           # depth limit for objects handed to value() directly
MAX_EMBEDDED_PARSES = 500        # parse attempts per outermost text() call
MAX_EMBEDDED_CHARS = 2_000_000   # characters parsed per outermost text() call
MAX_EMBEDDED_NESTING = 4         # text() -> structure -> string -> text() levels
DEEP_STRUCTURE_PLACEHOLDER = "<DEEP-STRUCTURE-OMITTED>"
_BRACKET_RE = re.compile(r"[{}\[\]]")
_CLOSERS = {"{": "}", "[": "]"}


def _command_arguments(items: list) -> dict[int, str]:
    """Positions of credential arguments in an exec-form command list, with how to redact each."""
    if not items or not all(isinstance(item, str) for item in items):
        return {}
    command = items[0].rsplit("/", 1)[-1]
    found: dict[int, str] = {}
    for index, item in enumerate(items):
        following = index + 1 < len(items)
        if command in _COMMANDS_WITH_USER_FLAG:
            if item in ("-u", "--user", "--proxy-user") and following:
                found[index + 1] = "user"
            elif item.startswith(("--user=", "--proxy-user=")):
                found[index] = "user-equals"
            elif item.startswith("-u") and len(item) > 2 and ":" in item:
                found[index] = "user-attached"
        elif command in _COMMANDS_WITH_ATTACHED_P:
            if item.startswith("-p") and len(item) > 2 and item[2] != "-":
                found[index] = "attached"
        elif (command == "docker" and items[1:2] == ["login"]) or command == "sshpass":
            if item == "-p" and following:
                found[index + 1] = "whole"
            elif item.startswith("-p") and len(item) > 2 and item[2] != "-":
                found[index] = "attached"
        elif command == "redis-cli" and item == "-a" and following:
            found[index + 1] = "whole"
    return found


class _TooDeep(Exception):
    """Raised inside a structural walk that goes below the depth limit."""


_FAILED = object()


def _balanced_spans(text: str) -> list[list]:
    """Balanced {...} and [...] spans as [start, end, children] trees, in one linear pass.

    Quotes are ignored on purpose: free text holds stray apostrophes. Opens beyond the stack
    limit are counted but not tracked, so hostile nesting costs nothing extra.
    """
    top: list[list] = []
    stack: list[list] = []  # [start, opener, children]
    overflow = 0
    limit = MAX_STRUCTURE_DEPTH + 10
    for match in _BRACKET_RE.finditer(text):
        char = match.group()
        if char in _CLOSERS:
            if len(stack) < limit:
                stack.append([match.start(), char, []])
            else:
                overflow += 1
        elif overflow:
            overflow -= 1
        elif stack and _CLOSERS[stack[-1][1]] == char:
            start, _, children = stack.pop()
            (stack[-1][2] if stack else top).append([start, match.end(), children])
    while stack:  # unclosed openers: their finished children still count
        _, _, children = stack.pop()
        (stack[-1][2] if stack else top).extend(children)
    return top


class Redactor:
    """Replaces sensitive values with stable placeholders such as <SECRET-1>."""

    def __init__(self) -> None:
        # Keyed by a digest so the original values are never held in memory.
        self._numbers: dict[str, dict[str, int]] = {"SECRET": {}, "EMAIL": {}, "IP": {}}
        self._highest: dict[str, int] = {"SECRET": 0, "EMAIL": 0, "IP": 0}
        self._depth = 0
        self._depth_limit = MAX_DIRECT_DEPTH
        self._embedded_nesting = 0
        self._parses_left = MAX_EMBEDDED_PARSES
        self._chars_left = MAX_EMBEDDED_CHARS

    def _reserve_existing_placeholders(self, text: str) -> None:
        for match in _NUMBERED_PLACEHOLDER_RE.finditer(text):
            category = match.group(1)
            self._highest[category] = max(self._highest[category], int(match.group(2)))

    def _placeholder(self, category: str, original: str) -> str:
        digest = hashlib.sha256(original.encode()).hexdigest()
        numbers = self._numbers[category]
        if digest not in numbers:
            self._highest[category] += 1
            numbers[digest] = self._highest[category]
        return f"<{category}-{numbers[digest]}>"

    def _replace_spans(self, text: str, spans: list[Span]) -> str:
        pieces, position = [], 0
        for start, end in spans:
            pieces.append(text[position:start])
            pieces.append(self._placeholder("SECRET", text[start:end]))
            position = end
        pieces.append(text[position:])
        return "".join(pieces)

    def _replace_emails(self, text: str) -> str:
        pieces, position = [], 0
        userinfo = _url_userinfo_spans(text)
        starts = [start for start, _ in userinfo]
        for match in EMAIL_RE.finditer(text):
            if _is_email(text, match, userinfo, starts):
                pieces.append(text[position:match.start()])
                pieces.append(self._placeholder("EMAIL", match.group()))
                position = match.end()
        pieces.append(text[position:])
        return "".join(pieces)

    def _parse_structure(self, source: str) -> tuple[Any, bool] | None:
        """Parse a span as JSON, then as a Python literal. Returns (object, is_json) or None."""
        try:
            parsed = json.loads(source)
            if isinstance(parsed, (dict, list)):
                return parsed, True
            return None
        except Exception:
            pass
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # free text is full of invalid escapes
                parsed = ast.literal_eval(source)
        except Exception:
            return None
        return (parsed, False) if isinstance(parsed, (dict, list)) else None

    def _redact_span(self, source: str) -> str | None | object:
        """Replacement text for a span, None to keep it as is, or _FAILED when it does not parse."""
        if len(source) > MAX_EMBEDDED_SPAN:
            return _FAILED
        if self._parses_left <= 0 or self._chars_left < len(source):
            return None
        if '"' not in source and "'" not in source:
            return None
        self._parses_left -= 1
        self._chars_left -= len(source)
        parsed = self._parse_structure(source)
        if parsed is None:
            return _FAILED
        obj, is_json = parsed
        result = self._walk_bounded(obj)
        if result is _FAILED or result == obj:
            return None
        if is_json:
            return json.dumps(result, separators=(",", ":"), ensure_ascii=False)
        return repr(result)

    def _redact_embedded(self, text: str) -> str:
        """Redact JSON and Python-literal objects found inside free text, structurally."""
        if self._embedded_nesting >= MAX_EMBEDDED_NESTING or ("{" not in text and "[" not in text):
            return text
        if self._embedded_nesting == 0:
            self._parses_left, self._chars_left = MAX_EMBEDDED_PARSES, MAX_EMBEDDED_CHARS
        self._embedded_nesting += 1
        try:
            replacements: list[tuple[int, int, str]] = []
            pending = _balanced_spans(text)
            while pending:
                start, end, children = pending.pop(0)
                outcome = self._redact_span(text[start:end])
                if outcome is _FAILED:
                    pending = children + pending
                elif outcome is not None:
                    replacements.append((start, end, outcome))
            if not replacements:
                return text
            pieces, position = [], 0
            for start, end, replacement in sorted(replacements):
                pieces.append(text[position:start])
                pieces.append(replacement)
                position = end
            pieces.append(text[position:])
            return "".join(pieces)
        except Exception:
            return text
        finally:
            self._embedded_nesting -= 1

    def text(self, value: str) -> str:
        self._reserve_existing_placeholders(value)
        value = self._redact_embedded(value)
        for _, rule in SECRET_RULES:
            value = self._replace_spans(value, rule(value))
        value = self._replace_emails(value)
        return IPV4_RE.sub(
            lambda m: self._placeholder("IP", m.group()) if _is_public_ip(m.group()) else m.group(),
            value,
        )

    def value(self, obj: Any, key: str | None = None) -> Any:
        secret = key is not None and looks_secret_key(key)
        try:
            return self._walk(obj, secret, secret, key is not None and is_authorization_key(key))
        except (_TooDeep, RecursionError):
            return DEEP_STRUCTURE_PLACEHOLDER

    def _secret_scalar(self, obj: Any) -> str:
        text = str(obj)
        return text if PLACEHOLDER_RE.fullmatch(text) else self._placeholder("SECRET", text)

    def _authorization_value(self, text: str) -> str:
        """Keep the scheme word of an Authorization value and redact the token."""
        match = _SCHEME_AND_TOKEN_RE.match(text)
        if not match:
            return self._secret_scalar(text)
        token = match.group("token")
        return text if PLACEHOLDER_RE.fullmatch(token) else (
            match.group("scheme") + match.group("gap") + self._secret_scalar(token)
        )

    def _json_string(self, text: str) -> Any:
        """Redact JSON held inside a string structurally; None when the string is not JSON."""
        if text.lstrip()[:1] not in ("{", "["):
            return None
        try:
            parsed = json.loads(text)
        except Exception:
            return None
        if not isinstance(parsed, (dict, list)):
            return None
        result = self._walk_bounded(parsed)
        if result is _FAILED:
            return None  # too deep to walk: the caller sends the string through the pattern rules
        return json.dumps(result, separators=(",", ":"), ensure_ascii=False)

    def _walk_bounded(self, obj: Any) -> Any:
        """Walk a structure parsed from a string, at most MAX_STRUCTURE_DEPTH levels deep."""
        saved_limit = self._depth_limit
        self._depth_limit = self._depth + MAX_STRUCTURE_DEPTH
        try:
            return self._walk(obj, False, False, False)
        except (_TooDeep, RecursionError):
            return _FAILED
        finally:
            self._depth_limit = saved_limit

    def _walk(self, obj: Any, secret: bool, immediate: bool, authorization: bool, keep: bool = False) -> Any:
        """secret: inside a secret value; immediate: the key directly above is itself secret;
        keep: inside a settings dict such as TokenValidityUnits, where values are not secret."""
        if isinstance(obj, (dict, list, tuple, set, frozenset)):
            self._depth += 1
            try:
                if self._depth > self._depth_limit:
                    raise _TooDeep()
                return self._walk_container(obj, secret, immediate, authorization, keep)
            finally:
                self._depth -= 1
        return self._walk_scalar(obj, secret, immediate, authorization)

    def _walk_scalar(self, obj: Any, secret: bool, immediate: bool, authorization: bool) -> Any:
        if isinstance(obj, bool) or obj is None:
            return obj
        if isinstance(obj, (int, float)):
            return self._secret_scalar(obj) if secret and immediate else obj
        if isinstance(obj, bytes):
            obj = obj.decode("utf-8", errors="replace")
        if isinstance(obj, str):
            if secret:
                if not obj or obj.lower() in LITERAL_VALUES:
                    return obj
                return self._authorization_value(obj) if authorization else self._secret_scalar(obj)
            structured = self._json_string(obj)
            return structured if structured is not None else self.text(obj)
        return obj

    def _walk_container(self, obj: Any, secret: bool, immediate: bool, authorization: bool, keep: bool) -> Any:
        if isinstance(obj, dict):
            return self._walk_dict(obj, secret, immediate, keep)
        if isinstance(obj, (set, frozenset)):
            return self._walk_list(sorted(obj, key=repr), secret, immediate, authorization, keep)
        return self._walk_list(list(obj), secret, immediate, authorization, keep)

    def _command_item(self, item: str, kind: str) -> str:
        """Redact the credential part of one exec-form argument."""
        if kind == "whole":
            return self._secret_scalar(item)
        if kind == "attached":  # -pVALUE
            return item[:2] + self._secret_scalar(item[2:])
        prefix = ""
        if kind == "user-equals":  # --user=name:password
            prefix, item = item[:item.index("=") + 1], item[item.index("=") + 1:]
        elif kind == "user-attached":  # -uname:password
            prefix, item = item[:2], item[2:]
        colon = item.find(":")
        if colon == -1 or colon == len(item) - 1:
            return prefix + item
        return prefix + item[:colon + 1] + self._secret_scalar(item[colon + 1:])

    def _walk_list(self, items: list, secret: bool, immediate: bool, authorization: bool, keep: bool = False) -> list:
        commands = {} if secret or keep else _command_arguments(items)
        result, previous = [], None
        for index, item in enumerate(items):
            if index in commands and isinstance(item, str):
                result.append(self._command_item(item, commands[index]))
                previous = item
                continue
            follows_secret_flag = not keep and (
                isinstance(previous, str) and isinstance(item, str)
                and previous.startswith("-") and "=" not in previous
                and not item.startswith("-") and looks_secret_key(previous.lstrip("-"))
            )
            flagged = secret or follows_secret_flag
            result.append(self._walk(item, flagged, immediate or follows_secret_flag, authorization, keep))
            previous = item
        return result

    def _walk_dict(self, obj: dict, secret: bool, immediate: bool, keep: bool = False) -> dict:
        entry_name = entry_name_key = entry_value_key = None
        for name_key, value_key in NAME_VALUE_KEYS:
            if name_key in obj and value_key in obj and isinstance(obj[name_key], str):
                entry_name, entry_name_key, entry_value_key = obj[name_key], name_key, value_key
                break
        entry_secret = entry_name is not None and looks_secret_key(entry_name) and not keep
        result = {}
        for key, item in obj.items():
            new_key = self.text(key) if isinstance(key, str) else key
            if keep:
                result[new_key] = self._walk(item, False, False, False, True)
            elif key == REFERENCE_KEY:
                result[new_key] = copy.deepcopy(item)
            elif key == entry_name_key or (key == "key" and "path" in obj):
                result[new_key] = self._walk(item, False, False, False)  # a name or a volume item, not a secret
            elif key == entry_value_key:
                result[new_key] = self._walk(
                    item, secret or entry_secret, entry_secret, entry_secret and is_authorization_key(entry_name)
                )
            elif isinstance(key, str):
                own = looks_secret_key(key)
                # Inside a secret value, keys that only name a reference (an ARN, a status) stay readable.
                child_secret = own or (secret and not is_reference_key(key))
                result[new_key] = self._walk(
                    item, child_secret, own, own and is_authorization_key(key), key_components(key)[-1:] == ["units"]
                )
            else:
                result[new_key] = self._walk(item, secret, False, False)
        return result

    def counts(self) -> dict[str, int]:
        return {category.lower(): len(numbers) for category, numbers in self._numbers.items()}


@dataclass(frozen=True)
class AuditHit:
    category: str
    line: int
    column: int


def audit_text(text: str) -> list[AuditHit]:
    """Locate anything the secret rules would still change, for secrets only: emails and IP
    addresses are not reported. Reports positions, never values."""
    line_starts = [0] + [match.end() for match in re.finditer("\n", text)]
    hits = []
    for category, rule in SECRET_RULES:
        for start, _ in rule(text):
            line = bisect.bisect_right(line_starts, start)
            hits.append(AuditHit(category, line, start - line_starts[line - 1] + 1))
    return sorted(hits, key=lambda hit: (hit.line, hit.column))
