"""Redact secrets and personal data from text before it enters evidence."""
from __future__ import annotations

import copy
import bisect
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

Span = tuple[int, int]
SpanRule = Callable[[str], list[Span]]

PLACEHOLDER_RE = re.compile(r"<[A-Z]+-\d+>")
_NUMBERED_PLACEHOLDER_RE = re.compile(r"<(SECRET|EMAIL|IP)-(\d+)>")
_SCHEME_AND_PLACEHOLDER_RE = re.compile(r"(?:[A-Za-z]+ )?<[A-Z]+-\d+>")

# A key is secret when one of its components is a secret word, ends in one, or "key" follows a qualifier.
SECRET_WORDS = frozenset({
    "password", "passwords", "passwd", "pass", "pwd", "passphrase", "secret", "secrets", "token",
    "apikey", "apikeys", "credential", "credentials", "auth", "cookie", "cookies",
    "authorization", "proxyauthorization",
})
SECRET_SUFFIXES = ("token", "secret", "password", "passwd", "apikey")
KEY_QUALIFIERS = frozenset({
    "api", "access", "secret", "private", "encryption", "signing", "auth", "license", "master",
    "ssh", "session", "client",
})
KEY_WORDS = frozenset({"key", "keys"})
# A final "key" is secret unless the component before it says what kind of key it is.
NON_SECRET_KEY_KINDS = frozenset({
    "partition", "sort", "s3", "routing", "cache", "kms", "primary", "foreign", "idempotency",
    "object", "hash", "shard", "range", "dedup", "group", "row", "public", "index", "tag",
    "metric", "map", "lookup",
    "parameter",
})
# A key ending in one of these names a reference or a setting, not the secret itself.
REFERENCE_SUFFIXES = frozenset({
    "arn", "id", "ids", "name", "names", "status", "type", "version", "count", "enabled",
    "expiry", "expires", "rotation", "length", "policy", "url", "path",
    "ttl", "timeout", "age", "days", "seconds", "validity", "units", "date", "time", "used",
    "expiration", "mode", "stages", "flows", "prevention", "required", "file",
})
AUTHORIZATION_WORDS = frozenset({"authorization", "proxyauthorization"})
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Environment-entry shapes: (name key, value key).
NAME_VALUE_KEYS = (
    ("name", "value"), ("Name", "Value"), ("key", "value"), ("Key", "Value"),
    ("ParameterKey", "ParameterValue"),
)
REFERENCE_KEY = "valueFrom"


def key_components(key: str) -> list[str]:
    spaced = _CAMEL_BOUNDARY_RE.sub(" ", key)
    return [part.lower() for part in re.split(r"[^A-Za-z0-9]+", spaced) if part]


def is_reference_key(key: str) -> bool:
    components = key_components(key)
    return bool(components) and components[-1] in REFERENCE_SUFFIXES


def is_authorization_key(key: str) -> bool:
    components = key_components(key)
    return bool(components) and components[-1] in AUTHORIZATION_WORDS


def looks_secret_key(key: str) -> bool:
    components = key_components(key)
    if not components or components[-1] in REFERENCE_SUFFIXES:
        return False
    for index, part in enumerate(components):
        if part in SECRET_WORDS or part.endswith(SECRET_SUFFIXES):
            return True
        if any(part.endswith(qualifier + "key") for qualifier in KEY_QUALIFIERS):
            return True
        if part in KEY_WORDS and index > 0 and components[index - 1] in KEY_QUALIFIERS:
            return True
    last = components[-1]
    return last in KEY_WORDS and len(components) > 1 and components[-2] not in NON_SECRET_KEY_KINDS


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
    r"""(?<![\w-])\w+(?:-\w+)*-(?:token|key|secret)\\?["']?[ \t]*:[ \t]*(?![\\"'])(?P<value>[^\r\n]*[^\s])""",
    re.IGNORECASE,
)
BEARER_RE = re.compile(r"\bBearer[ \t]+(?P<token>[A-Za-z0-9._~+/-]{16,}=*)", re.IGNORECASE)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
VENDOR_TOKEN_RE = re.compile(
    r"(?<![\w-])(?:(?:ghp_|gho_|ghs_|github_pat_|xoxb-|xoxp-|xoxa-|sk_live_|sk_test_|rk_live_)[A-Za-z0-9_-]{10,}"
    r"|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,})"
)
AWS_SECRET_KEY_RE = re.compile(r"(?<![\w/+=-])[A-Za-z0-9/+]{40}(?![\w/+=-])")
JWT_RE = re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+")

KV_START_RE = re.compile(
    r"""(?<![\w.\-/:@])(?P<key>-{0,2}[A-Za-z_][\w.\-]*)(?P<quote>\\?["']?)(?P<sep>[ \t]*(?:=>|=|:)[ \t]*)"""
)
XML_PAIR_RE = re.compile(r"<(?P<key>[A-Za-z_][\w.\-]*)>(?P<value>[^<\n]+)</(?P=key)>")
LITERAL_VALUES = frozenset({"null", "true", "false"})
_SCHEME_AND_TOKEN_RE = re.compile(r"(?P<scheme>[A-Za-z][\w-]*)(?P<gap>[ \t]+)(?P<token>\S.*)", re.DOTALL)
_BLOCK_SCALAR_RE = re.compile(r"[|>][+-]?\d?")
_BARE_VALUE_RE = re.compile(r"""[^\s&,;"'}\]]+""")


def _pem_spans(text: str) -> list[Span]:
    return [m.span() for m in PEM_RE.finditer(text)]


def _auth_spans(text: str) -> list[Span]:
    authorization = _group_rule(AUTHORIZATION_RE, "digest", "token", "bare")
    header = _group_rule(SECRET_HEADER_RE, "value")
    bearer = _group_rule(BEARER_RE, "token")
    return _merge(authorization(text) + header(text) + bearer(text))


def _aws_secret_key_spans(text: str) -> list[Span]:
    spans = []
    for match in AWS_SECRET_KEY_RE.finditer(text):
        candidate = match.group()
        mixed = any(c.isupper() for c in candidate) and any(c.islower() for c in candidate)
        if mixed and any(c.isdigit() for c in candidate) and not re.fullmatch(r"[0-9a-fA-F]+", candidate):
            spans.append(match.span())
    return spans


def _line_end(text: str, start: int) -> int:
    end = text.find("\n", start)
    return len(text) if end == -1 else end


def _quoted_span(text: str, start: int) -> Span | None:
    """The inside of a quoted value starting at start, honouring escapes; None if not quoted."""
    limit = _line_end(text, start)
    if text.startswith(("\\\"", "\\'"), start):
        closing = "\\" + text[start + 1]
        end = text.find(closing, start + 2, limit)
        return (start + 2, limit if end == -1 else end)
    if start < len(text) and text[start] in "\"'":
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


def _kv_candidate_is_secret(key: str, quote: str, sep: str) -> bool:
    if not looks_secret_key(key) or is_authorization_key(key):
        return False  # Authorization values keep their scheme word: the authorization rule handles them
    colon_only = "=" not in sep
    if colon_only and not quote and "." in key.strip("-"):
        # auth.example.com: refused is a hostname; db.password: x is a key.
        return looks_secret_key(key.rsplit(".", 1)[-1])
    return True


def _kv_value_span(text: str, start: int, quote: str, sep: str) -> Span | None:
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
        parenthesis = text.find(" (", start, end)
        return (start, end if parenthesis == -1 else parenthesis)
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
JSON_NAME_VALUE_RE = re.compile(
    r"""\\?"(?P<namekey>""" + _NAME_KEY + r""")\\?"[ \t]*:[ \t]*\\?"(?P<name>[^"\\]*)\\?"[ \t]*,[ \t]*"""
    r"""\\?"(?:""" + _VALUE_KEY + r""")\\?"[ \t]*:[ \t]*"""
)
YAML_NAME_VALUE_RE = re.compile(
    r"""^(?P<indent>[ \t]*)(?P<dash>- )?""" + _NAME_KEY + r""":[ \t]*(?P<quote>["']?)(?P<name>[^\s"']+)(?P=quote)[ \t]*\r?\n"""
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
        same_column = len(match.group("indent2")) == len(match.group("indent")) + len(match.group("dash") or "")
        if same_column and looks_secret_key(match.group("name")):
            span = _kv_value_span(text, match.end(), '"', ": ")
            if span and _usable(text, span) and text[span[0]:span[1]].lower() not in LITERAL_VALUES:
                spans.append(span)
    return _merge(spans)


_FLAG_RE = re.compile(r"(?<!\S)(?P<flag>--?[A-Za-z][\w-]*)[ \t]+(?=\S)")
_USER_FLAGS = frozenset({"--user", "--proxy-user", "-u"})
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
    """The argument after a secret flag in a command string, and the password of curl -u user:password."""
    spans: list[Span] = []
    for match in _FLAG_RE.finditer(text):
        flag, start = match.group("flag"), match.end()
        if text[start] == "-":
            continue
        span = _flag_value_span(text, start)
        if flag in _USER_FLAGS and (flag != "-u" or "curl" in text[max(0, match.start() - 300):match.start()]):
            colon = text.find(":", span[0], span[1])
            password = (colon + 1, span[1]) if colon != -1 else None
            if password and not text[password[0]:password[1]].isdigit() and _usable(text, password):
                spans.append(password)
        elif looks_secret_key(flag.lstrip("-")) and _usable(text, span):
            spans.append(span)
    return _merge(spans)


# (audit category, rule), in redaction order.
SECRET_RULES: tuple[tuple[str, SpanRule], ...] = (
    ("private_key", _pem_spans),
    ("url_credential", _group_rule(URL_CREDENTIAL_RE, "secret")),
    ("auth_header", _auth_spans),
    ("secret_key_value", _key_value_spans),
    ("secret_name_value", _name_value_spans),
    ("secret_flag", _flag_spans),
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


class Redactor:
    """Replaces sensitive values with stable placeholders such as <SECRET-1>."""

    def __init__(self) -> None:
        # Keyed by a digest so the original values are never held in memory.
        self._numbers: dict[str, dict[str, int]] = {"SECRET": {}, "EMAIL": {}, "IP": {}}
        self._highest: dict[str, int] = {"SECRET": 0, "EMAIL": 0, "IP": 0}

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

    def text(self, value: str) -> str:
        self._reserve_existing_placeholders(value)
        for _, rule in SECRET_RULES:
            value = self._replace_spans(value, rule(value))
        value = self._replace_emails(value)
        return IPV4_RE.sub(
            lambda m: self._placeholder("IP", m.group()) if _is_public_ip(m.group()) else m.group(),
            value,
        )

    def value(self, obj: Any, key: str | None = None) -> Any:
        secret = key is not None and looks_secret_key(key)
        return self._walk(obj, secret, secret, key is not None and is_authorization_key(key))

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
        except (ValueError, RecursionError):
            return None
        if not isinstance(parsed, (dict, list)):
            return None
        return json.dumps(self._walk(parsed, False, False, False), separators=(",", ":"), ensure_ascii=False)

    def _walk(self, obj: Any, secret: bool, immediate: bool, authorization: bool) -> Any:
        """secret: inside a secret value; immediate: the key directly above is itself secret."""
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
        if isinstance(obj, dict):
            return self._walk_dict(obj, secret, immediate)
        if isinstance(obj, (set, frozenset)):
            return self._walk_list(sorted(obj, key=repr), secret, immediate, authorization)
        if isinstance(obj, (list, tuple)):
            return self._walk_list(list(obj), secret, immediate, authorization)
        return obj

    def _walk_list(self, items: list, secret: bool, immediate: bool, authorization: bool) -> list:
        result, previous = [], None
        for item in items:
            follows_secret_flag = (
                isinstance(previous, str) and isinstance(item, str)
                and previous.startswith("-") and "=" not in previous
                and not item.startswith("-") and looks_secret_key(previous.lstrip("-"))
            )
            flagged = secret or follows_secret_flag
            result.append(self._walk(item, flagged, immediate or follows_secret_flag, authorization))
            previous = item
        return result

    def _walk_dict(self, obj: dict, secret: bool, immediate: bool) -> dict:
        entry_name = entry_name_key = entry_value_key = None
        for name_key, value_key in NAME_VALUE_KEYS:
            if name_key in obj and value_key in obj and isinstance(obj[name_key], str):
                entry_name, entry_name_key, entry_value_key = obj[name_key], name_key, value_key
                break
        entry_secret = entry_name is not None and looks_secret_key(entry_name)
        result = {}
        for key, item in obj.items():
            new_key = self.text(key) if isinstance(key, str) else key
            if key == REFERENCE_KEY:
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
                result[new_key] = self._walk(item, child_secret, own, own and is_authorization_key(key))
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
