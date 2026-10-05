"""Redact secrets and personal data from text before it enters evidence."""
from __future__ import annotations

import ast
import bisect
import collections
import copy
import functools
import hashlib
import ipaddress
import math
import json
import re
import threading
import unicodedata
import urllib.parse
import warnings

import yaml
from dataclasses import dataclass
from typing import Any, Callable

Span = tuple[int, int]
SpanRule = Callable[[str], list[Span]]

PLACEHOLDER_RE = re.compile(r"<[A-Z]+-\d+>")
_NUMBERED_PLACEHOLDER_RE = re.compile(r"<(SECRET|EMAIL|IP|TOKEN|PHONE|UNREADABLE)-(\d+)>")
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
    # beyond ruling 11, from the re-review's leak shapes: refresh_tok, and card and identity numbers
    "tok", "ssn", "cvv", "cvc", "iban", "card",
})
# "code" names a status, not a one-time code, after these qualifiers (statusCode, exit_code).
NON_SECRET_CODE_QUALIFIERS = frozenset({
    "status", "exit", "error", "err", "response", "http", "return", "reason", "result", "country",
    "currency", "language", "lang", "zip", "postal", "region", "event", "sql", "elb", "target",
    "state", "iso", "area", "op", "program", "char", "unicode", "color", "colour", "product",
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
    # a secret word qualifying a network or an error thing: PrivateIpAddress, KeyError
    "address", "addresses", "ip", "ips", "dns", "duration", "error", "exception",
    # references to a secret (secretKeyRef, secretRef, valueFrom) and limits on a count
    "ref", "refs", "from", "limit", "limits", "quota",
})
# A plain number is not a secret under a counted name: a plural of a secret word as the last
# part (tokens, keys, secrets) or a counting word anywhere (max_tokens, num_keys).
# "number" is not one: card_number, account_number hold the secret itself.
COUNTING_WORDS = frozenset({"max", "min", "num", "total", "count", "limit", "remaining", "used", "avg"})
# AWS IAM service prefixes: service:Operation is an action name, not a user:password pair.
IAM_SERVICE_PREFIXES = frozenset({
    "secretsmanager", "kms", "ssm", "sts", "iam", "s3", "ec2", "ecs", "ecr", "eks", "lambda", "logs",
    "cloudwatch", "dynamodb", "rds", "sqs", "sns", "kinesis", "firehose", "elasticloadbalancing",
    "autoscaling", "cloudformation", "events", "states", "apigateway", "execute-api", "es", "elasticache",
    "route53", "acm", "cognito-idp", "cognito-identity", "cloudtrail", "codebuild", "codedeploy",
    "codepipeline", "glue", "athena", "xray", "sso", "organizations", "tag", "ssm-messages", "ssmmessages",
    "ec2messages", "kafka", "elasticfilesystem", "backup", "config", "guardduty", "wafv2", "cloudfront",
    "rds-db", "redshift", "sagemaker", "bedrock", "appconfig", "servicediscovery", "application-autoscaling",
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
    if part == "code" and index > 0 and parts[index - 1] in NON_SECRET_CODE_QUALIFIERS:
        return False
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
    return any(_secret_part(parts, raw, index) for index in range(len(parts))) or _odd_case_secret(key)


def _odd_case_secret(key: str) -> bool:
    """PaSsWoRd, PASSword: odd casing cuts a stem into camel pieces, so each chunk between
    separators is also checked whole when its camel split left pieces of three letters or fewer."""
    for chunk in re.split(r"[^A-Za-z0-9]+", key):
        pieces = [piece for piece in _CAMEL_BOUNDARY_RE.sub(" ", chunk).split() if piece.isalpha()]
        if len(pieces) < 2 or not any(len(piece) <= 3 for piece in pieces):
            continue
        whole = chunk.lower().rstrip("0123456789")
        if whole not in STEM_WORD_EXCEPTIONS and any(stem in whole for stem in LONG_SECRET_STEMS):
            return True
    return False


@functools.lru_cache(maxsize=8192)
def looks_personal_key(key: str) -> bool:
    """Whether a name says its value is personal data (user, email, phone ...), by whole parts."""
    return any(part in PERSONAL_WORDS for part in _name_parts(key))


# --- plain words: what file paths and identifiers are made of ---------------------------------

_SUBPART_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_PIECE_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_PLAIN_PATH_RE = re.compile(r"~?/[\w.\-/]*")


def _plain_piece(piece: str) -> bool:
    """Whether a run of letters and digits reads like a word, a number or a short id, not key material."""
    if len(piece) <= 3 or piece.isdigit():
        return True
    single_case = piece.islower() or piece.isupper()
    if single_case and (len(piece) <= 12 or (_HEX_RE.fullmatch(piece) and len(piece) < 40)):
        return True
    subparts = _SUBPART_RE.findall(piece)
    if "".join(subparts) != piece or any(len(part) == 1 and part.isalpha() for part in subparts):
        return False
    return len(subparts) * 3 <= len(piece)


def _plain_words(text: str) -> bool:
    return all(_plain_piece(piece) for piece in _PIECE_SPLIT_RE.split(text) if piece)


def _is_plain_path(value: str) -> bool:
    """An absolute file path whose parts are plain words: /etc/ssl/private/server.key."""
    return bool(_PLAIN_PATH_RE.fullmatch(value)) and _plain_words(value)


def _looks_like_path(text: str) -> bool:
    """Slash-separated text with at least two plain word segments: a file or URL path."""
    if "/" not in text:
        return False
    words = [part for part in text.split("/") if len(part) >= 3 and _plain_words(part)]
    return len(words) >= 2 or (text.startswith("/") and len(words) >= 1)


_IAM_OPERATION_RE = re.compile(r"\*|[A-Z][A-Za-z0-9]*\*?")
_PLAIN_NUMBER_RE = re.compile(r"[+-]?\d+(?:\.\d+)?")


def _is_iam_action(value: str) -> bool:
    service, colon, operation = value.partition(":")
    return bool(colon) and service.lower() in IAM_SERVICE_PREFIXES and bool(_IAM_OPERATION_RE.fullmatch(operation))


@functools.lru_cache(maxsize=8192)
def is_counted_key(key: str) -> bool:
    """tokens, max_tokens, num_keys: the value counts secrets rather than being one."""
    parts = _name_parts(key)
    if not parts:
        return False
    last = parts[-1]
    plural = last.endswith("s") and len(last) > 3 and looks_secret_key(last[:-1])
    return plural or any(part in COUNTING_WORDS for part in parts)


def _harmless_secret_value(value: str, key: str | None = None) -> bool:
    """Values that are not secrets even under a secret name: literals, plain absolute paths, IAM
    actions, and a plain number under a counted name (password: 123456 stays masked)."""
    if value.lower() in LITERAL_VALUES or _is_plain_path(value) or _is_iam_action(value):
        return True
    return key is not None and is_counted_key(key) and bool(_PLAIN_NUMBER_RE.fullmatch(value))


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
    r"""(?<![\w.-])(?:hooks\.slack\.com/(?P<slack>(?:services|workflows|triggers)/[^\s"'<>]+)"""
    r"""|discord(?:app)?\.com/(?P<discord>api/webhooks/[^\s"'<>]+)"""
    r"""|[\w-]+(?:\.[\w-]+)*\.webhook\.office\.com/(?P<office>[^\s"'<>]+))"""
)
BEARER_RE = re.compile(r"\bBearer[ \t]+(?P<token>[A-Za-z0-9._~+/-]{16,}=*)", re.IGNORECASE)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
VENDOR_TOKEN_RE = re.compile(
    r"(?<![\w-])(?:(?:ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|xoxb-|xoxp-|xoxa-|xoxs-|xoxr-|xapp-|xoxe\.xox[a-z]-|xoxe-"
    r"|sk_live_|sk_test_|rk_live_|rk_test_|whsec_|glpat-|glptt-|gldt-|GR1348941|npm_|GOCSPX-|hvs\.|hvb\.|hvr\."
    r"|dckr_pat_|shpat_|shpss_|dop_v1_|pypi-|xkeysib-)[A-Za-z0-9_-]{10,}"
    r"|AIza[0-9A-Za-z_-]{30,}"
    r"|ya29\.[0-9A-Za-z_-]{10,}"
    r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
    r"|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,})"
)
AWS_SECRET_KEY_RE = re.compile(r"(?<![\w/+=-])[A-Za-z0-9/+]{40}(?![\w/+=-])")
JWT_RE = re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+")

KV_START_RE = re.compile(
    r"""(?<![\w.\-/@])(?<![\w/:]:)(?P<key>-{0,2}[A-Za-z_][\w.\-]*)(?P<quote>\\?["']?\]?)"""
    r"""(?P<sep>[ \t]*(?:=>|:=|=|:)[ \t]*)"""
)
_XML_NAME = r"(?:[A-Za-z_][\w.\-]*:)?[A-Za-z_][\w.\-]*"
XML_PAIR_RE = re.compile(r"<(?P<key>" + _XML_NAME + r")(?:[ \t][^<>]*)?>(?P<value>[^<]+)</(?P=key)>")
XML_CDATA_RE = re.compile(r"<(?P<key>" + _XML_NAME + r")(?:[ \t][^<>]*)?>\s*<!\[CDATA\[(?P<value>.*?)\]\]>\s*</(?P=key)>", re.DOTALL)
XML_TAG_RE = re.compile(r"<" + _XML_NAME + r"(?P<attrs>(?:\s+" + _XML_NAME + r"""\s*=\s*(?:"[^"]*"|'[^']*'))+)\s*/?>""")
XML_ATTR_RE = re.compile(r"(?P<name>" + _XML_NAME + r""")\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""")
XML_NAME_VALUE_RE = re.compile(
    r"<(?P<nk>Name|Key|name|key)>(?P<name>[^<]{1,200})</(?P=nk)>\s*<(?P<vk>Value|value)>(?P<value>[^<]*)</(?P=vk)>"
)
LITERAL_VALUES = frozenset({"null", "true", "false", "yes", "no", "none", "ok"})
_VALUE_END_RE = re.compile(r"""[),"]| \(|'(?=[\s,;)\]}]|$)""")
_SCHEME_AND_TOKEN_RE = re.compile(r"(?P<scheme>[A-Za-z][\w-]*)(?P<gap>[ \t]+)(?P<token>\S.*)", re.DOTALL)
_BLOCK_SCALAR_RE = re.compile(r"[|>][+-]?\d?")
_BARE_VALUE_RE = re.compile(r"""[^\s&,;"'}\]\[{]+""")
# After a delimiter, a bare value goes on unless the next thing is another key=.
_NEXT_PAIR_RE = re.compile(r"""[ \t]*[\w.\-\[\]]+=""")
_DIGIT_GROUP_RE = re.compile(r"\d+(?![^\s&,;])")
# An environment dump line: KEY=value runs to the end of the line, spaces included.
_ENV_LINE_KEY_RE = re.compile(r"[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*$")
TAB_PAIR_RE = re.compile(r"(?:^|(?<=\t))(?P<key>[A-Za-z_][\w.\-]*)\t+(?P<value>[^\t\r\n]+)", re.MULTILINE)
PHP_VAR_DUMP_RE = re.compile(r'\["(?P<key>[^"\n]{1,100})"\]=>\s*string\(\d+\)\s*"(?P<value>[^"\n]*)"')


_SQL_QUOTED = r"""(?:'(?P<sq>(?:[^'\\\n]|\\.|'')*)'|"(?P<dq>(?:[^"\\\n]|\\.)*)")"""
SQL_PASSWORD_RE = re.compile(
    r"(?i)(?:\b(?:(?:UN)?ENCRYPTED[ \t]+)?PASSWORD[ \t]+(?:FOR[ \t]+\S+[ \t]*)?(?:=[ \t]*)?(?:PASSWORD[ \t]*\([ \t]*)?"
    r"|\bIDENTIFIED[ \t]+(?:WITH[ \t]+\S+[ \t]+)?BY[ \t]+(?:PASSWORD[ \t]+)?"
    r"|\bPASSWORD[ \t]*=[ \t]*PASSWORD[ \t]*\([ \t]*)" + _SQL_QUOTED
)
# AWS CLI shorthand: ParameterKey=N,ParameterValue=V, Key=N,Value=V, name=N,value=V.
SHORTHAND_PAIR_RE = re.compile(
    r"""(?<![\w-])(?:Parameter)?(?:Key|key|Name|name)=(?P<name>[^,\s{}\[\]=]+),[ \t]*"""
    r"""(?:(?:UsePreviousValue|ResolvedValue|Type|type)=[^,\s}\]]*,[ \t]*)?(?:Parameter)?(?:Value|value)="""
    r"""(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|(?P<bare>[^,\s}\]]+))"""
)
PEM_END_RE = re.compile(r"-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")
# A PEM body line on its own: 64 (or 76) base64 characters, or a shorter last line with padding.
PEM_BODY_LINE_RE = re.compile(
    r"^[ \t]*(?P<body>[A-Za-z0-9+/]{64}|[A-Za-z0-9+/]{76}|[A-Za-z0-9+/]{20,75}={1,2})[ \t]*\r?$", re.MULTILINE
)
PUTTY_PRIVATE_RE = re.compile(r"^Private-Lines:[ \t]*\d+[ \t]*\r?\n(?P<body>(?:[A-Za-z0-9+/=]+\r?(?:\n|$))+)", re.MULTILINE)


_SQL_CALL_RE = re.compile(r"[A-Za-z_]\w*\(")


def _sql_spans(text: str) -> list[Span]:
    if "assword" not in text and "ASSWORD" not in text and "dentified" not in text.lower():
        return []
    spans = _group_rule(SQL_PASSWORD_RE, "sq", "dq")(text)
    return [span for span in spans if not PLACEHOLDER_RE.fullmatch(text[span[0]:span[1]].strip("'\""))]


def _shorthand_spans(text: str) -> list[Span]:
    spans = []
    for match in SHORTHAND_PAIR_RE.finditer(text):
        if looks_secret_key(match.group("name")):
            group = next(g for g in ("dq", "sq", "bare") if match.group(g) is not None)
            if _usable(text, match.span(group)):
                spans.append(match.span(group))
    return spans


def _three_classes(text: str) -> bool:
    classes = (any(c.islower() for c in text), any(c.isupper() for c in text), any(c.isdigit() for c in text))
    return sum(classes) == 3


def _pem_spans(text: str) -> list[Span]:
    spans = [m.span() for m in PEM_RE.finditer(text)]
    if "PRIVATE KEY" in text:
        # An END line with no BEGIN before it: the body arrived in this text without its header.
        first_end = PEM_END_RE.search(text)
        if first_end and not (spans and spans[0][0] < first_end.start()):
            spans.append((0, first_end.end()))
    for match in PEM_BODY_LINE_RE.finditer(text):
        if _three_classes(match.group("body")) and not _looks_like_path(match.group("body")):
            spans.append(match.span("body"))
    for match in PUTTY_PRIVATE_RE.finditer(text):
        start, end = match.span("body")
        while end > start and text[end - 1] in "\r\n":
            end -= 1
        spans.append((start, end))
    return _merge(spans)


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


def _newlines(text: str) -> list[int]:
    """Newline offsets of text, computed once per text."""
    if getattr(_line_cache, "text", None) is not text:
        _line_cache.text = text
        _line_cache.newlines = [m.start() for m in re.finditer("\n", text)]
    return _line_cache.newlines


def _line_end(text: str, start: int) -> int:
    """Offset of the end of the line holding start."""
    newlines = _newlines(text)
    index = bisect.bisect_left(newlines, start)
    return newlines[index] if index < len(newlines) else len(text)


def _line_start(text: str, position: int) -> int:
    """Offset of the start of the line holding position."""
    newlines = _newlines(text)
    index = bisect.bisect_left(newlines, position) - 1
    return newlines[index] + 1 if index >= 0 else 0


def _quoted_span(text: str, start: int) -> Span | None:
    """The inside of a quoted value starting at start, honouring escapes; None if not quoted."""
    if text.startswith(("\'\'\'", '"""'), start):  # TOML or Python triple-quoted, may span lines
        closing = text.find(text[start:start + 3], start + 3)
        return (start + 3, len(text) if closing == -1 else closing)
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


def _block_scalar_span(text: str, after_line: int, key_column: int) -> Span | None:
    """The lines of a YAML `key: |` scalar: those indented deeper than the key itself."""
    first = last = None
    position = after_line + 1
    while position <= len(text):
        end = _line_end(text, position)
        line = text[position:end]
        if line.strip() and len(line) - len(line.lstrip(" \t")) <= key_column:
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


def _kv_value_span(
    text: str, start: int, quote: str, sep: str, stop_at_delimiters: bool = True, key_column: int = 0
) -> Span | None:
    colon_only = "=" not in sep
    if start >= len(text) or text[start] in "\r\n[{":
        return None  # a nested structure is walked on its own; never consume its opening bracket
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
            return _block_scalar_span(text, end, key_column)
        if stop_at_delimiters:
            delimiter = _VALUE_END_RE.search(text, start, end)
            if delimiter:
                end = delimiter.start()
        return (start, end) if end > start else None
    return _bare_value_span(text, start)


def _bare_value_span(text: str, start: int) -> Span | None:
    """An unquoted value: it ends at whitespace, or at & , ; when another key= follows."""
    bare = _BARE_VALUE_RE.match(text, start)
    if not bare:
        return None
    end = bare.end()
    while end < len(text):
        if text[end] in "&,;" and not _NEXT_PAIR_RE.match(text, end + 1):
            more = _BARE_VALUE_RE.match(text, end + 1)
            if more:
                end = more.end()
                continue
        elif text[end] == " " and text[start:end].replace("-", "").replace(" ", "").isdigit():
            more = _DIGIT_GROUP_RE.match(text, end + 1)  # a card or account number in groups
            if more:
                end = more.end()
                continue
        break
    return (start, end)


def _xml_local(name: str) -> str:
    return name.rsplit(":", 1)[-1]


def _xml_spans(text: str) -> list[Span]:
    """Secret element bodies (namespaced, multi-line, CDATA), attributes and Name/Value pairs."""
    spans: list[Span] = []
    for match in XML_CDATA_RE.finditer(text):
        if looks_secret_key(_xml_local(match.group("key"))):
            spans.append(match.span("value"))
    for match in XML_PAIR_RE.finditer(text):
        if looks_secret_key(_xml_local(match.group("key"))):
            start, end = match.span("value")
            while start < end and text[start].isspace():
                start += 1
            while end > start and text[end - 1].isspace():
                end -= 1
            spans.append((start, end))
    for match in XML_TAG_RE.finditer(text):
        attributes = {}
        for attr in XML_ATTR_RE.finditer(text, match.start("attrs"), match.end("attrs")):
            group = "dq" if attr.group("dq") is not None else "sq"
            attributes[_xml_local(attr.group("name")).lower()] = (attr.group(group), attr.span(group))
        named = next((attributes[k][0] for k in ("key", "name") if k in attributes), None)
        for name, (value, span) in attributes.items():
            secret_value = name == "value" and named is not None and looks_secret_key(named)
            if (secret_value or (name not in ("key", "name") and looks_secret_key(name))) and not _harmless_secret_value(value):
                spans.append(span)
    for match in XML_NAME_VALUE_RE.finditer(text):
        if looks_secret_key(match.group("name")):
            spans.append(match.span("value"))
    return spans


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
        line_start = _line_start(text, match.start("key"))
        key_column = match.start("key") - line_start
        span = _kv_value_span(text, match.end(), quote, sep, key_column=key_column)
        if (span and sep.strip() == "=" and not quote and text[match.end()] not in "\"'"
                and _ENV_LINE_KEY_RE.match(text, line_start, match.start("key") + len(key))):
            end = _line_end(text, span[0])
            while end > span[0] and text[end - 1] in " \t\r":
                end -= 1
            span = (span[0], max(span[1], end))
        position = max(match.end(), span[1]) if span else match.end()
        if not span or not _usable(text, span):
            continue
        value = text[span[0]:span[1]]
        first_word = value.split(None, 1)[0] if value.strip() else value
        if sep == ":" and key.lower() in IAM_SERVICE_PREFIXES and _IAM_OPERATION_RE.fullmatch(first_word):
            continue  # secretsmanager:GetSecretValue is an IAM action name
        if is_counted_key(key.lstrip("-")) and _PLAIN_NUMBER_RE.fullmatch(first_word.rstrip(",;")):
            continue  # tokens: 512 counts tokens; an unquoted colon value runs on to the line end
        if (_SCHEME_AND_PLACEHOLDER_RE.fullmatch(value) or _harmless_secret_value(value, key.lstrip("-"))
                or _SQL_CALL_RE.fullmatch(value)):
            continue  # a SQL PASSWORD(...) call: the SQL rule masks its argument
        spans.append(span)
    if "\t" in text:
        for match in TAB_PAIR_RE.finditer(text):
            if looks_secret_key(match.group("key")) and not _harmless_secret_value(match.group("value").strip()):
                spans.append(match.span("value"))
    if "]=>" in text:
        for match in PHP_VAR_DUMP_RE.finditer(text):
            if looks_secret_key(match.group("key")):
                spans.append(match.span("value"))
    if "<" in text:
        spans.extend(_xml_spans(text))
    return _merge([span for span in spans if _usable(text, span)])


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
            if span[0] >= match.end() and _usable(text, span) and not _harmless_secret_value(text[span[0]:span[1]]):
                spans.append(span)
    for match in YAML_NAME_VALUE_RE.finditer(text):
        # The value key sits in the column of the name key itself, however many spaces follow the dash.
        if len(match.group("indent2")) == len(match.group("lead")) and looks_secret_key(match.group("name")):
            span = _kv_value_span(
                text, match.end(), "", ": ", stop_at_delimiters=False, key_column=len(match.group("indent2"))
            )
            if span and _usable(text, span) and not _harmless_secret_value(text[span[0]:span[1]]):
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
        if _usable(text, span) and not _harmless_secret_value(text[span[0]:span[1]]):
            spans.append(span)
    return _merge(spans)


# Commands whose credentials sit in short flags. Regions run to the end of the command: the line, a
# ; | or && separator, the next command word, or 2000 characters.
_COMMAND_RE = re.compile(
    r"(?<![\w.-])(?P<command>curl|wget|mysqldump|mysqladmin|mysql|mariadb-dump|mariadb|docker[ \t]+login|sshpass|redis-cli"
    r"|put-parameter|htpasswd|ldapsearch|ldapmodify|ldapadd|ldapdelete|ldapwhoami|ldappasswd|smbclient)(?![\w-])"
)
_COMMAND_END_RE = re.compile(r";|\||&&")
_TOKEN = r"""(?:"[^"\n]*"|'[^'\n]*'|[^\s"']+)"""
_USER_FLAG_RE = re.compile(
    r"(?<!\S)(?:(?:--user|--proxy-user)(?:=|[ \t]+)(?P<long>" + _TOKEN + r")|-u(?P<gap>[ \t]*)(?P<short>" + _TOKEN + r"))"
)
_ATTACHED_P_RE = re.compile(r"(?<!\S)-p(?P<value>[^\s-]\S*)")
_SPACED_P_RE = re.compile(r"(?<!\S)-p[ \t]*(?P<value>" + _TOKEN + r")")
_REDIS_A_RE = re.compile(r"(?<!\S)-a[ \t]+(?P<value>" + _TOKEN + r")")
_PARAMETER_VALUE_RE = re.compile(r"(?<!\S)--value(?:=|[ \t]+)(?P<value>" + _TOKEN + r")")
_COMMANDS_WITH_USER_FLAG = ("curl", "wget")
_COMMANDS_WITH_ATTACHED_P = ("mysql", "mysqladmin", "mysqldump", "mariadb", "mariadb-dump")
_REDIS_AUTH_RE = re.compile(r"(?<!\S)(?i:auth)[ \t]+(?P<first>" + _TOKEN + r")(?:[ \t]+(?P<second>" + _TOKEN + r"))?")
_LDAP_W_RE = re.compile(r"(?<!\S)-w[ \t]*(?P<value>" + _TOKEN + r")")
_SMB_USER_RE = re.compile(r"(?<!\S)(?:-U|--user(?:=|[ \t]+))[ \t]*(?P<value>" + _TOKEN + r")")
_ARGUMENT_RE = re.compile(_TOKEN)


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
            for found in _REDIS_AUTH_RE.finditer(text, match.end(), limit):
                group = "second" if found.group("second") else "first"
                spans.append(_token_inner(text, found.start(group), found.end(group)))
        elif command == "htpasswd":  # htpasswd -b FILE USER PASSWORD
            arguments = list(_ARGUMENT_RE.finditer(text, match.end(), limit))
            if any(a.group().startswith("-") and "b" in a.group() for a in arguments):
                positional = [a for a in arguments if not a.group().startswith("-")]
                if len(positional) >= 3:
                    spans.append(_token_inner(text, positional[2].start(), positional[2].end()))
        elif command.startswith("ldap"):
            for found in _LDAP_W_RE.finditer(text, match.end(), limit):
                spans.append(_token_inner(text, found.start("value"), found.end("value")))
        elif command == "smbclient":  # -U user%password
            for found in _SMB_USER_RE.finditer(text, match.end(), limit):
                inner = _token_inner(text, found.start("value"), found.end("value"))
                percent = text.find("%", inner[0], inner[1])
                if percent != -1:
                    spans.append((percent + 1, inner[1]))
        elif command == "put-parameter":  # fail closed: any parameter value may be a secret
            for found in _PARAMETER_VALUE_RE.finditer(text, match.end(), limit):
                spans.append(_token_inner(text, found.start("value"), found.end("value")))
    return _merge([span for span in spans if _usable(text, span)])


def _webhook_spans(text: str) -> list[Span]:
    return _group_rule(WEBHOOK_RE, "slack", "discord", "office")(text)


def _argv_spans(items: list) -> dict[int, list[Span]]:
    """Credential spans in an argument list read as one command line, by item index.

    A leading CMD (Docker exec form) is skipped. A span runs to the end of its item: an argument
    is one token, so the rest of it belongs to the credential.
    """
    if not items or not all(isinstance(item, str) for item in items):
        return {}
    offsets, position = [], 0
    for item in items:
        offsets.append(position)
        position += len(item) + 1
    line = " ".join(item.replace("\n", " ").replace("\r", " ") for item in items)
    found: dict[int, list[Span]] = {}
    for start, _ in _command_spans(line):
        index = bisect.bisect_right(offsets, start) - 1
        relative = start - offsets[index]
        if 0 <= relative < len(items[index]):
            found.setdefault(index, []).append((relative, len(items[index])))
    return found


_YAML_LIST_KEY_RE = re.compile(
    r"^(?P<lead>[ \t]*(?:-[ \t]+)?)(?P<key>command|args|entrypoint|entryPoint|cmd|Cmd|Entrypoint)[ \t]*:[ \t]*(?P<rest>[^\r\n]*)$",
    re.MULTILINE,
)
_YAML_ITEM_RE = re.compile(r"""^(?P<indent>[ \t]*)-[ \t]+(?P<item>[^\r\n]*?)[ \t]*$""", re.MULTILINE)
_JSON_STRING = r'"(?:[^"\\\n]|\\.)*"'
_JSON_STRING_RE = re.compile(_JSON_STRING)
_JSON_STRING_ARRAY_RE = re.compile(r"\[[ \t]*" + _JSON_STRING + r"(?:[ \t]*,[ \t]*" + _JSON_STRING + r")*[ \t]*\]")


def _json_array_argument_spans(text: str) -> list[Span]:
    """Credentials in a JSON array of strings read as a command line (Docker exec form)."""
    if '"' not in text or not _COMMAND_RE.search(text):
        return []
    spans: list[Span] = []
    for match in _JSON_STRING_ARRAY_RE.finditer(text):
        strings = list(_JSON_STRING_RE.finditer(text, match.start(), match.end()))
        items = [found.group()[1:-1] for found in strings]
        for index, item_spans in _argv_spans(items).items():
            for start, stop in item_spans:
                base = strings[index].start() + 1
                spans.append((base + start, base + stop))
    return _merge([span for span in spans if _usable(text, span)])


def _unquoted(text: str, start: int, end: int) -> tuple[str, int]:
    """A YAML scalar's value and where it starts, without matching quotes."""
    if end - start >= 2 and text[start] in "\"'" and text[end - 1] == text[start]:
        return text[start + 1:end - 1], start + 1
    return text[start:end], start


def _yaml_list_items(text: str, match: re.Match[str]) -> tuple[list[str], list[int], int]:
    """The items of a YAML command/args list (block or flow style), their offsets and where it ends."""
    rest = match.group("rest")
    if rest.startswith("["):
        try:
            parsed = yaml.safe_load(rest)
        except Exception:
            return [], [], match.end()
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            return [], [], match.end()
        items, offsets, position = [], [], match.start("rest")
        for item in parsed:
            found = text.find(item, position, match.end()) if item else -1
            if found == -1:
                return [], [], match.end()
            items.append(item)
            offsets.append(found)
            position = found + len(item)
        return items, offsets, match.end()
    if rest.strip():
        return [], [], match.end()
    column = len(match.group("lead"))
    items, offsets, position, end = [], [], match.end() + 1, match.end()
    while position < len(text):
        line_end = _line_end(text, position)
        item = _YAML_ITEM_RE.match(text, position, line_end)
        if not item or len(item.group("indent")) < column - (2 if match.group("lead").rstrip().endswith("-") else 0):
            break
        value, offset = _unquoted(text, item.start("item"), item.end("item"))
        items.append(value)
        offsets.append(offset)
        end, position = line_end, line_end + 1
    return items, offsets, end


def _yaml_argument_spans(text: str) -> list[Span]:
    """Credentials in YAML command/args lists, read together as one command line."""
    if not _COMMAND_RE.search(text):
        return []
    spans: list[Span] = []
    pending: dict[int, tuple[list[str], list[int], int]] = {}  # command lists by key column
    for match in _YAML_LIST_KEY_RE.finditer(text):
        items, offsets, end = _yaml_list_items(text, match)
        if not items:
            continue
        column = len(match.group("lead"))
        if match.group("key") == "args" and column in pending:
            command_items, command_offsets, command_end = pending.pop(column)
            between = text[command_end:match.start()]
            if all(not line.strip() or len(line) - len(line.lstrip()) >= column for line in between.split("\n")[1:]):
                items, offsets = command_items + items, command_offsets + offsets
        elif match.group("key") != "args":
            pending[column] = (items, offsets, end)
        for index, item_spans in _argv_spans(items).items():
            for start, stop in item_spans:
                spans.append((offsets[index] + start, offsets[index] + stop))
    return _merge([span for span in spans if _usable(text, span)])


# --- name/value pairs the strict patterns miss ---------------------------------------------

_LOOSE_NAME_RE = re.compile(
    r"""(?P<q>\\?["']?)(?:name|Name|key|Key|ParameterKey)(?P=q)[ \t]*[:=][ \t]*(?P<nq>\\?["']?)"""
    r"""(?P<name>[^"'\\\s,{}\[\]()=:]{1,200})(?P=nq)(?=[ \t]*[,}\n\r)]|[ \t]*$)"""
)
_LOOSE_TOKEN_RE = re.compile(
    r"""[{}\[\]]|(?P<vk>(?<![\w-])\\?["']?(?:value|Value|ParameterValue)\\?["']?[ \t]*[:=](?!=)[ \t]*)"""
)
LOOSE_WINDOW = 2000


def _loose_value_span(text: str, start: int) -> Span | None:
    if start >= len(text) or text[start] in "{[\r\n":
        return None
    quoted = _quoted_span(text, start)
    if quoted:
        return quoted
    match = re.compile(r"""[^\s,}\])"']+""").match(text, start)
    return match.span() if match else None


def _loose_name_value_spans(text: str) -> list[Span]:
    """The value of a name/value object whose name is secret, wherever the value key sits in the
    same object: after nested objects, many other pairs or non-literal values, or before the name.
    Brackets are counted so that only keys of the same object are paired."""
    if "alue" not in text:
        return []
    spans: list[Span] = []
    for match in _LOOSE_NAME_RE.finditer(text):
        if not looks_secret_key(match.group("name")):
            continue
        depth, found = 0, None
        for token in _LOOSE_TOKEN_RE.finditer(text, match.end(), min(len(text), match.end() + LOOSE_WINDOW)):
            if token.group("vk"):
                if depth == 0:
                    found = token.end()
                    break
            elif token.group() in "{[":
                depth += 1
            else:
                depth -= 1
                if depth < 0:
                    break
        if found is None:  # the value key may come before the name in the same object
            depth, opening = 0, max(0, match.start() - LOOSE_WINDOW)
            tokens = list(_LOOSE_TOKEN_RE.finditer(text, opening, match.start()))
            for token in reversed(tokens):
                if token.group("vk"):
                    if depth == 0:
                        found = token.end()
                        break
                elif token.group() in "}]":
                    depth += 1
                else:
                    depth -= 1
                    if depth < 0:
                        break
        if found is not None:
            span = _loose_value_span(text, found)
            if span and _BLOCK_SCALAR_RE.fullmatch(text[span[0]:span[1]]):
                continue  # a YAML block scalar: the YAML rules mask its lines
            if span and _usable(text, span) and not _harmless_secret_value(text[span[0]:span[1]]):
                spans.append(span)
    return spans


_YAML_KEY_LINE_RE = re.compile(r"^(?P<dash>[ \t]*-[ \t]+)?(?P<indent>[ \t]*)(?P<key>[\w.\-]+):(?:[ \t]+(?P<value>[^\r\n]*))?[ \t]*\r?$", re.MULTILINE)


def _yaml_item_spans(text: str) -> list[Span]:
    """YAML list items with a secret `name:` and a `value:` key anywhere in the same item.

    One linear pass: an item is a run of consecutive key lines in one column, and a `- ` line
    starts a new one.
    """
    if "name:" not in text and "key:" not in text and "Name:" not in text and "Key:" not in text:
        return []
    items: list[tuple[list[str], list[tuple[int, Span]]]] = []  # (secret names, value lines)
    current_column, current = None, None
    for match in _YAML_KEY_LINE_RE.finditer(text):
        column = len(match.group("dash") or "") + len(match.group("indent"))
        if current is None or match.group("dash") is not None or column != current_column:
            current, current_column = ([], []), column
            items.append(current)
        key, value = match.group("key"), match.group("value")
        if value is None:
            continue
        if key in ("name", "Name", "key", "Key"):
            current[0].append(value.strip().strip("\"'"))
        elif key in ("value", "Value"):
            current[1].append((column, match.span("value")))
    spans: list[Span] = []
    for names, values in items:
        if not values or not any(looks_secret_key(name) for name in names):
            continue
        for column, value_span in values:
            span = _kv_value_span(text, value_span[0], "", ": ", stop_at_delimiters=False, key_column=column)
            if span and _usable(text, span) and not _harmless_secret_value(text[span[0]:span[1]]):
                spans.append(span)
    return spans


# --- sentences and more commands -----------------------------------------------------------

_SENTENCE_STOP_WORDS = frozenset({
    "incorrect", "invalid", "required", "expired", "missing", "empty", "wrong", "not", "too", "null",
    "none", "valid", "correct", "set", "ok", "true", "false", "being", "now", "still", "the", "a", "an",
    "also", "changed", "reset", "blank", "weak", "strong", "short", "long", "old", "new", "mandatory",
    "optional", "accepted", "rejected", "locked", "revoked", "used", "unknown", "undefined", "present",
    "absent", "configured", "stale", "needed", "provided", "different", "same", "unchanged", "updated",
    "<redacted>", "redacted", "hidden", "masked", "nil", "undefined.", "expiring", "rotated", "ready",
})
SENTENCE_IS_RE = re.compile(
    r"""(?i)\b(?:password|passwd|passphrase|secret|token|api[ _-]?key|pin)[ \t]+(?:is|was)[ \t]+[:=]?[ \t]*"""
    r"""(?:'(?P<sq>[^'\n]+)'|"(?P<dq>[^"\n]+)"|(?P<bare>[^\s'",;]+))"""
)
SENTENCE_SET_RE = re.compile(
    r"""(?i)\b(?:set|setting|sets|change[sd]?|changing|reset|resetting|update[sd]?|updating)[ \t]+(?:the[ \t]+)?"""
    r"""(?:[\w-]+[ \t]+){0,2}?(?:password|passwd|secret|token|pin)[ \t]+(?:to|=)[ \t]+"""
    r"""(?:'(?P<sq>[^'\n]+)'|"(?P<dq>[^"\n]+)"|(?P<bare>[^\s,;]+))"""
)


def _sentence_spans(text: str) -> list[Span]:
    """password is X; setting password to 'X'."""
    lowered_hint = ("assw" in text or "ecret" in text or "oken" in text or "ASSW" in text or "pin" in text
                    or "PIN" in text or "pi" in text.lower())
    if not lowered_hint:
        return []
    spans = []
    for pattern in (SENTENCE_IS_RE, SENTENCE_SET_RE):
        for match in pattern.finditer(text):
            group = next(g for g in ("sq", "dq", "bare") if match.group(g) is not None)
            value = match.group(group)
            if group == "bare" and (value.lower().rstrip(".") in _SENTENCE_STOP_WORDS or value.rstrip(".") == ""
                                    or "(" in value):
                continue  # "(": a SQL PASSWORD(...) call, masked by the SQL rule
            if _usable(text, match.span(group)) and not _harmless_secret_value(value):
                start, end = match.span(group)
                while group == "bare" and end > start and text[end - 1] in ".)":
                    end -= 1
                spans.append((start, end))
    return spans


REDIS_LOG_AUTH_RE = re.compile(r'(?i)"AUTH"[ \t]+"(?P<first>[^"\n]*)"(?:[ \t]+"(?P<second>[^"\n]*)")?')
STDIN_LOGIN_RE = re.compile(
    r"""(?<![\w-])(?:echo|printf)[ \t]+(?:-[a-z]+[ \t]+)*(?:(?:'%s'|"%s")[ \t]+)?(?P<value>""" + _TOKEN + r""")"""
    r"""[ \t]*\|[ \t]*(?:sudo[ \t]+)?[\w./-]*(?:docker|podman|helm|oras|crane|skopeo|nerdctl)[ \t]+(?:registry[ \t]+)?login\b"""
)


def _more_command_spans(text: str) -> list[Span]:
    spans = []
    if "AUTH" in text or "auth" in text:
        for match in REDIS_LOG_AUTH_RE.finditer(text):
            group = "second" if match.group("second") is not None else "first"
            spans.append(match.span(group))
    if "login" in text:
        for match in STDIN_LOGIN_RE.finditer(text):
            spans.append(_token_inner(text, match.start("value"), match.end("value")))
    return [span for span in spans if _usable(text, span)]


_ESCAPED_UNICODE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _escaped_unicode_spans(text: str) -> list[Span]:
    """Run the rules on a view with \\uXXXX escapes decoded, and map what they find back."""
    if "\\u" not in text or not _ESCAPED_UNICODE_RE.search(text):
        return []
    pieces, starts, ends, position = [], [], [], 0
    for match in _ESCAPED_UNICODE_RE.finditer(text):
        for index in range(position, match.start()):
            pieces.append(text[index])
            starts.append(index)
            ends.append(index + 1)
        pieces.append(chr(int(match.group(1), 16)))
        starts.append(match.start())
        ends.append(match.end())
        position = match.end()
    for index in range(position, len(text)):
        pieces.append(text[index])
        starts.append(index)
        ends.append(index + 1)
    decoded = "".join(pieces)
    spans = []
    for category, rule in SECRET_RULES:
        if category in ("escaped_unicode", "percent_encoded"):
            continue
        for start, end in rule(decoded):
            if end > start:
                spans.append((starts[start], ends[end - 1]))
    return [span for span in _merge(spans) if _usable(text, span)]


# (audit category, rule), in redaction order.
SECRET_RULES: tuple[tuple[str, SpanRule], ...] = (
    ("percent_encoded", lambda text: _percent_spans(text, emails=False)),
    ("escaped_unicode", _escaped_unicode_spans),
    ("private_key", _pem_spans),
    ("sql_password", _sql_spans),
    ("url_credential", _group_rule(URL_CREDENTIAL_RE, "secret")),
    ("auth_header", _auth_spans),
    ("secret_key_value", _key_value_spans),
    ("secret_name_value", _name_value_spans),
    ("cli_shorthand", _shorthand_spans),
    ("secret_loose_name_value", lambda text: _merge(_loose_name_value_spans(text) + _yaml_item_spans(text))),
    ("secret_sentence", _sentence_spans),
    ("secret_flag", _flag_spans),
    ("secret_command", _command_spans),
    ("secret_argument_list", lambda text: _merge(_yaml_argument_spans(text) + _json_array_argument_spans(text))),
    ("webhook_url", _webhook_spans),
    ("secret_command_log", _more_command_spans),
    ("aws_access_key", lambda text: [m.span() for m in AWS_KEY_RE.finditer(text)]),
    ("vendor_token", lambda text: [m.span() for m in VENDOR_TOKEN_RE.finditer(text)]),
    ("aws_secret_key", _aws_secret_key_spans),
    ("jwt", lambda text: [m.span() for m in JWT_RE.finditer(text)]),
)

# --- normalisation and percent-encoding -------------------------------------------------

_ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|\x9b[0-?]*[ -/]*[@-~]"
)
_INVISIBLE_RE = re.compile("[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")


def strip_invisible(text: str) -> str:
    """Text without ANSI escape sequences and zero-width or bidi control characters."""
    if "\x1b" in text or "\x9b" in text:
        text = _ANSI_RE.sub("", text)
    if not text.isascii():
        text = _INVISIBLE_RE.sub("", text)
    return text


def normalise(text: str) -> str:
    """Text as the rules see it: stripped of invisible characters, in NFKC form."""
    text = strip_invisible(text)
    return text if text.isascii() else unicodedata.normalize("NFKC", text)


_PERCENT_TOKEN_RE = re.compile(r"""[^\s"'<>&?;,]*%[0-9A-Fa-f]{2}[^\s"'<>&?;,]*""")
_PERCENT_KEY_RE = re.compile(r"[\w.\-\[\]]+")


def _decoded(token: str) -> str:
    for _ in range(3):  # double and triple encoding
        decoded = urllib.parse.unquote(token, errors="surrogateescape")
        if decoded == token:
            break
        token = decoded
    return token


def _percent_spans(text: str, emails: bool) -> list[Span]:
    """Tokens with percent-escapes whose decoded form holds a secret (or, with emails, an email address).

    All decoded tokens are checked in one pass over one joined text, so the cost stays linear.
    The value after a plain key= is masked; otherwise the whole token is.
    """
    if "%" not in text:
        return []
    tokens = [m for m in _PERCENT_TOKEN_RE.finditer(text)]
    decoded = [_decoded(m.group()) for m in tokens]
    candidates = [(m, d) for m, d in zip(tokens, decoded) if d != m.group()]
    if not candidates:
        return []
    joined, starts, position = [], [], 0
    for _, value in candidates:
        starts.append(position)
        joined.append(value)
        position += len(value) + 1
    combined = "\n".join(joined)
    if emails:
        hits = [m.start() for m in EMAIL_RE.finditer(combined)]
    else:
        hits = [start for category, rule in SECRET_RULES if category != "percent_encoded" for start, _ in rule(combined)]
    flagged = {bisect.bisect_right(starts, hit) - 1 for hit in hits}
    spans = []
    for index in sorted(flagged):
        match = candidates[index][0]
        token = match.group()
        equals = token.find("=")
        if equals > 0 and _PERCENT_KEY_RE.fullmatch(token[:equals]) and equals + 1 < len(token):
            spans.append((match.start() + equals + 1, match.end()))
        else:
            spans.append(match.span())
    return [span for span in spans if _usable(text, span)]


# --- emails, phone numbers and addresses ---------------------------------------------------

EMAIL_RE = re.compile(
    r"(?<![\w.%+-])(?:[\w.%+-]+|\"[^\"\n@]{1,64}\")@[^\W_](?:[\w-]*[^\W_])?(?:\.[^\W_](?:[\w-]*[^\W_])?)*"
    r"\.[^\W\d_]{2,}(?![\w-])"
)
_SCP_PATH_AFTER_RE = re.compile(r":[A-Za-z~./_]")
PHONE_RE = re.compile(r"(?<![\w+:./-])\+\d(?:[ .\-()]{0,2}\d){7,14}(?![\d])")
_TIME_BEFORE_RE = re.compile(r"\d:\d\d(?::\d\d(?:[.,]\d+)?)?[ \t]$")
# --- fail closed: key material that no name explains -----------------------------------------

_TOKEN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{24,}")
_INTERIOR_EQUALS_RE = re.compile(r"=+(?=[^=])")
_ARN_RE = re.compile(r"\barn:aws[\w-]*:[^\s\"'<>,]+")
_DIGEST_LABEL_RE = re.compile(r"(?i)\b(?:sha(?:1|224|256|384|512)?|md5)[:= ]$")
MIN_TOKEN_LENGTH = 24
MIN_HEX_TOKEN_LENGTH = 40
TOKEN_ENTROPY = 4.0  # bits per character
HEX_TOKEN_ENTROPY = 3.0


def _entropy(text: str) -> float:
    counts = collections.Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _classes(text: str) -> int:
    return sum((
        any(c.islower() for c in text), any(c.isupper() for c in text),
        any(c.isdigit() for c in text), any(c in "+/=_-" for c in text),
    ))


def _key_like(token: str) -> bool:
    """Random-looking key material: long, mixed or high-entropy, and not made of words and short ids."""
    body = token.rstrip("=")
    if len(body) < MIN_TOKEN_LENGTH:
        return False
    if _HEX_RE.fullmatch(body):
        # Hex key material mixes digits and letters; a run of one character or a long number is not a key.
        mixed = any(c.isdigit() for c in body) and any(c.isalpha() for c in body)
        return len(body) >= MIN_HEX_TOKEN_LENGTH and mixed and _entropy(body) >= HEX_TOKEN_ENTROPY
    if _plain_words(body):
        return False
    return _classes(body) >= 3 or _entropy(body) >= TOKEN_ENTROPY


def _token_spans(text: str) -> list[Span]:
    """Spans of key-like tokens in free text (ruling: fail closed), whatever their name says."""
    arns = [m.span() for m in _ARN_RE.finditer(text)] if "arn:" in text else []
    arn_starts = [start for start, _ in arns]
    spans: list[Span] = []
    for match in _TOKEN_CANDIDATE_RE.finditer(text):
        index = bisect.bisect_right(arn_starts, match.start()) - 1
        if index >= 0 and match.start() < arns[index][1]:
            continue
        pieces, position = [], match.start()
        for equals in _INTERIOR_EQUALS_RE.finditer(text, match.start(), match.end()):
            pieces.append((position, equals.start()))
            position = equals.end()
        pieces.append((position, match.end()))
        for start, end in pieces:
            spans.extend(_token_piece_spans(text, start, end))
    return spans


def _token_piece_spans(text: str, start: int, end: int) -> list[Span]:
    token = text[start:end]
    if len(token) < MIN_TOKEN_LENGTH:
        return []
    if _HEX_RE.fullmatch(token) and _DIGEST_LABEL_RE.search(text, max(0, start - 8), start):
        return []  # a labelled digest such as sha256:...
    if _looks_like_path(token):
        spans, position = [], start
        for segment in token.split("/"):
            if _key_like(segment):
                spans.append((position, position + len(segment)))
            position += len(segment) + 1
        return spans
    return [(start, end)] if _key_like(token) else []


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


def _secret_header_pair(items: list) -> bool:
    """A two-item [name, value] list whose name is a secret header (cookie, authorization, x-api-key)."""
    if len(items) != 2 or not all(isinstance(item, (str, bytes)) for item in items):
        return False
    name = items[0].decode("utf-8", errors="replace") if isinstance(items[0], bytes) else items[0]
    return not name.startswith("-") and len(name) <= 64 and looks_secret_key(name)


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


PLACEHOLDER_CATEGORIES = ("SECRET", "EMAIL", "IP", "TOKEN", "PHONE", "UNREADABLE")
# counts() always reports these; the others only once they occur.
_ALWAYS_COUNTED = ("SECRET", "EMAIL", "IP")


def _digest(original: str) -> str:
    # surrogatepass: half an emoji from a truncated JSON escape must not make redaction raise
    return hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()


class Redactor:
    """Replaces sensitive values with stable placeholders such as <SECRET-1>."""

    def __init__(self) -> None:
        # Keyed by a digest so the original values are never held in memory.
        self._numbers: dict[str, dict[str, int]] = {category: {} for category in PLACEHOLDER_CATEGORIES}
        self._highest: dict[str, int] = {category: 0 for category in PLACEHOLDER_CATEGORIES}
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
        digest = _digest(original)
        numbers = self._numbers[category]
        if digest not in numbers:
            self._highest[category] += 1
            numbers[digest] = self._highest[category]
        return f"<{category}-{numbers[digest]}>"

    def _spans_as(self, text: str, spans: list[Span], category: str) -> list[str]:
        pieces, position = [], 0
        for start, end in spans:
            pieces.append(text[position:start])
            pieces.append(self._placeholder(category, text[start:end]))
            position = end
        pieces.append(text[position:])
        return pieces

    def _replace_spans(self, text: str, spans: list[Span]) -> str:
        pieces, position = [], 0
        for start, end in spans:
            pieces.append(text[position:start])
            pieces.append(self._placeholder("SECRET", text[start:end]))
            position = end
        pieces.append(text[position:])
        return "".join(pieces)

    def _replace_emails(self, text: str) -> str:
        encoded = _percent_spans(text, emails=True)
        if encoded:
            text = "".join(self._spans_as(text, encoded, "EMAIL"))
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
            pending = collections.deque(_balanced_spans(text))
            while pending:
                start, end, children = pending.popleft()
                outcome = self._redact_span(text[start:end])
                if outcome is _FAILED:
                    pending.extendleft(reversed(children))
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

    def _unreadable(self, original: Any) -> str:
        """The last safety net: a whole-string placeholder, never the original and never a crash."""
        try:
            key = original if isinstance(original, str) else f"{type(original).__name__}:{id(original)}"
            digest = _digest(key)
        except Exception:
            digest = f"unhashable:{id(original)}"
        numbers = self._numbers["UNREADABLE"]
        if digest not in numbers:
            self._highest["UNREADABLE"] += 1
            numbers[digest] = self._highest["UNREADABLE"]
        return f"<UNREADABLE-{numbers[digest]}>"

    def text(self, value: str) -> str:
        try:
            return self._text(value)
        except Exception:
            return self._unreadable(value)

    def _replace_phones(self, text: str) -> str:
        if "+" not in text:
            return text
        pieces, position = [], 0
        for match in PHONE_RE.finditer(text):
            if _TIME_BEFORE_RE.search(text, max(0, match.start() - 16), match.start()):
                continue  # a time zone offset after a clock time, then a number
            pieces.append(text[position:match.start()])
            pieces.append(self._placeholder("PHONE", match.group()))
            position = match.end()
        pieces.append(text[position:])
        return "".join(pieces)

    def _text(self, value: str) -> str:
        stripped = strip_invisible(value)
        normalised = stripped if stripped.isascii() else unicodedata.normalize("NFKC", stripped)
        redacted = self._redact_normalised(normalised)
        # Matching runs on NFKC text; text in which nothing was found keeps its own characters
        # (an ellipsis stays an ellipsis). Text that changed is returned in NFKC form.
        return stripped if redacted == normalised else redacted

    def _redact_normalised(self, value: str) -> str:
        self._reserve_existing_placeholders(value)
        value = self._redact_embedded(value)
        for _, rule in SECRET_RULES:
            value = self._replace_spans(value, rule(value))
        value = self._replace_emails(value)
        value = self._replace_phones(value)
        value = IPV4_RE.sub(
            lambda m: self._placeholder("IP", m.group()) if _is_public_ip(m.group()) else m.group(),
            value,
        )
        return "".join(self._spans_as(value, _token_spans(value), "TOKEN"))

    def value(self, obj: Any, key: str | None = None) -> Any:
        try:
            secret = key is not None and looks_secret_key(key)
            return self._walk(obj, secret, secret, key is not None and is_authorization_key(key))
        except (_TooDeep, RecursionError):
            return DEEP_STRUCTURE_PLACEHOLDER
        except Exception:
            return self._unreadable(obj)

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
        try:
            return self._walk_scalar_unguarded(obj, secret, immediate, authorization)
        except Exception:
            return self._unreadable(obj)

    def _walk_scalar_unguarded(self, obj: Any, secret: bool, immediate: bool, authorization: bool) -> Any:
        if isinstance(obj, bool) or obj is None:
            return obj
        if isinstance(obj, (int, float)):
            return self._secret_scalar(obj) if secret and immediate else obj
        if isinstance(obj, bytes):
            obj = obj.decode("utf-8", errors="replace")
        if isinstance(obj, str):
            if secret:
                if not obj or _harmless_secret_value(obj):
                    return obj
                return self._authorization_value(obj) if authorization else self._secret_scalar(obj)
            structured = self._json_string(obj)
            return structured if structured is not None else self.text(obj)
        return self._secret_scalar(obj) if secret else obj

    def _walk_container(self, obj: Any, secret: bool, immediate: bool, authorization: bool, keep: bool) -> Any:
        if isinstance(obj, dict):
            return self._walk_dict(obj, secret, immediate, keep)
        if isinstance(obj, (set, frozenset)):
            return self._walk_list(sorted(obj, key=repr), secret, immediate, authorization, keep)
        return self._walk_list(list(obj), secret, immediate, authorization, keep)

    def _masked_item(self, item: str, spans: list[Span]) -> str:
        """An argument with its credential spans replaced."""
        for start, end in sorted(_merge(spans), reverse=True):
            item = item[:start] + self._secret_scalar(item[start:end]) + item[end:]
        return item

    def _walk_list(
        self, items: list, secret: bool, immediate: bool, authorization: bool, keep: bool = False,
        argv: dict[int, list[Span]] | None = None,
    ) -> list:
        if not secret and not keep and _secret_header_pair(items):
            name = items[0].decode("utf-8", errors="replace") if isinstance(items[0], bytes) else items[0]
            return [name, self._walk(items[1], True, True, is_authorization_key(name))]
        if argv is None:
            argv = {} if secret or keep else _argv_spans(items)
        result, previous = [], None
        for index, item in enumerate(items):
            if index in argv and isinstance(item, str):
                result.append(self.text(self._masked_item(item, argv[index])))
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
        command_args = None if secret or keep else self._command_and_args(obj)
        result = {}
        for key, item in obj.items():
            new_key = self.text(key) if isinstance(key, str) else key
            if command_args is not None and key in command_args:
                result[new_key] = self._walk_list(item, False, False, False, argv=command_args[key])
            elif keep:
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
                if own and is_counted_key(key) and isinstance(item, (int, float)) and not isinstance(item, bool):
                    result[new_key] = item  # max_tokens: 4096 counts tokens; password: 123456 is still masked
                    continue
                # Inside a secret value, keys that only name a reference (an ARN, a status) stay readable.
                child_secret = own or (secret and not is_reference_key(key))
                result[new_key] = self._walk(
                    item, child_secret, own, own and is_authorization_key(key), key_components(key)[-1:] == ["units"]
                )
            else:
                result[new_key] = self._walk(item, secret, False, False)
        return result

    @staticmethod
    def _command_and_args(obj: dict) -> dict[str, dict[int, list[Span]]] | None:
        """Kubernetes command and args lists in one dict, read together as one command line."""
        command, args = obj.get("command"), obj.get("args")
        if not (isinstance(command, list) and isinstance(args, list)):
            return None
        found = _argv_spans(command + args)
        if not found and not (command and args):
            return None
        return {
            "command": {index: spans for index, spans in found.items() if index < len(command)},
            "args": {index - len(command): spans for index, spans in found.items() if index >= len(command)},
        }

    def counts(self) -> dict[str, int]:
        return {
            category.lower(): len(numbers) for category, numbers in self._numbers.items()
            if numbers or category in _ALWAYS_COUNTED
        }


@dataclass(frozen=True)
class AuditHit:
    category: str
    line: int
    column: int


def audit_text(text: str) -> list[AuditHit]:
    """Locate anything the secret rules would still change, for secrets only: emails and IP
    addresses are not reported. Reports positions, never values."""
    try:
        text = normalise(text)  # positions refer to the normalised text
        line_starts = [0] + [match.end() for match in re.finditer("\n", text)]
        hits = []
        for category, rule in SECRET_RULES:
            for start, _ in rule(text):
                line = bisect.bisect_right(line_starts, start)
                hits.append(AuditHit(category, line, start - line_starts[line - 1] + 1))
        return sorted(hits, key=lambda hit: (hit.line, hit.column))
    except Exception:
        return [AuditHit("unreadable", 1, 1)]  # fail closed: the text cannot be shown to be clean
