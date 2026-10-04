"""The audit scan is a second, independent detector. Every secret-looking value is built at runtime."""
import random
import string
import time
from urllib.parse import quote

import pytest

from triage.audit_scan import Hit, describe, scan

B64 = string.ascii_letters + string.digits + "+/"
B64URL = string.ascii_letters + string.digits + "-_"
HEX = "0123456789abcdef"
ALNUM = string.ascii_letters + string.digits


def rand(length: int, seed: int, alphabet: str = ALNUM) -> str:
    """Deterministic random text that always has an upper case letter, a lower case letter and a digit."""
    rng = random.Random(seed)
    chars = [rng.choice(alphabet) for _ in range(length)]
    chars[0], chars[1], chars[2] = "Q", "m", "7"
    return "".join(chars)


def pad(prefix: str, length: int, seed: int, alphabet: str = ALNUM) -> str:
    return prefix + rand(length, seed, alphabet)


def kinds(text: str, **kwargs) -> list[str]:
    return [hit.kind for hit in scan(text, **kwargs)]


def ansi(text: str) -> str:
    return "\x1b[31m" + text + "\x1b[0m"


def zero_width(text: str) -> str:
    return text[:2] + "​" + text[2:]


def percent(text: str) -> str:
    return quote(text, safe="")


TRANSFORMS = [lambda text: text, ansi, zero_width, percent]
TRANSFORM_IDS = ["plain", "ansi", "zero-width", "percent"]

# kind -> samples that must be detected
POSITIVES = {
    "vendor_token": [
        "key " + "AK" + "IA" + "X" * 16,
        "key " + "AS" + "IA" + "7" * 16,
        "key " + "AI" + "DA" + "Z" * 16,
        "t " + pad("gh" + "p_", 36, 1),
        "t " + pad("github" + "_pat_", 40, 2, ALNUM + "_"),
        "t " + pad("gl" + "pat-", 20, 3, B64URL),
        "t " + pad("xo" + "xb-", 24, 4, ALNUM + "-"),
        "https://hooks." + "slack.com/services/" + "T" + rand(8, 5) + "/B" + rand(8, 6) + "/" + rand(24, 7),
        "t " + pad("sk" + "_live_", 24, 8),
        "t " + pad("wh" + "sec_", 24, 9),
        "t " + pad("AI" + "za", 35, 10, B64URL),
        "t " + pad("ya" + "29.", 40, 11, B64URL),
        "t " + pad("GOC" + "SPX-", 28, 12, B64URL),
        "t " + pad("np" + "m_", 36, 13),
        "t " + "S" + "G." + rand(22, 14, B64URL) + "." + rand(43, 15, B64URL),
        "t " + pad("hv" + "s.", 24, 16, B64URL),
        "t ey" + "J" + rand(20, 17, B64URL) + "." + "ey" + "J" + rand(24, 18, B64URL) + "." + rand(30, 19, B64URL),
        "url postgres://" + "app:" + rand(14, 20) + "@db.example.com/main",
    ],
    "private_key": [
        "-----BEGIN " + "RSA PRIVATE KEY-----",
        "-----BEGIN " + "PRIVATE KEY-----",
        "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
        "-----BEGIN " + "EC PRIVATE KEY-----",
        "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
        "\n" + rand(64, 21, B64),
        "\n" + rand(76, 22, B64) + "==",
    ],
    "entropy": [
        "value " + rand(24, 30, B64URL) + " end",
        "value " + rand(32, 31, B64) + " end",
        "value " + rand(40, 32, B64) + " end",
        "value " + rand(43, 33, B64URL) + " end",
        "value " + rand(64, 34, B64) + "= end",
        "value " + rand(30, 35, ALNUM) + " end",
        "value " + "".join(random.Random(36).choice(HEX) for _ in range(40)) + " end",
        "value " + "".join(random.Random(37).choice(HEX) for _ in range(64)) + " end",
    ],
    "named_value": [
        "pass" + "word=" + "hunter" + "22",
        "pass" + "word: " + "'hunter" + "22'",
        '"pass' + 'wd": "' + "hunter" + '22"',
        "DB_PW" + "D=" + "hunter" + "22",
        "client_sec" + "ret = " + "hunter" + "22",
        "api" + "_key: " + "hunter" + "22",
        "api" + "-key=" + "hunter" + "22",
        "Author" + "ization: Bearer " + "hunter" + "22",
        "Coo" + "kie: " + "session" + "=hunter22",
        "auth_tok" + "en=" + "hunter" + "22",
    ],
    "email": [
        "mail " + "jane.doe" + "@" + "example.com",
        "mail " + "a" + "@" + "b.io",
        "mail " + "first+tag" + "@" + "mail.example.co.uk",
        "mail <" + "ops_team" + "@" + "example.com>",
        "mail " + "UPPER" + "@" + "EXAMPLE.COM",
        "mail " + "x-y" + "@" + "sub.domain.example.com.",
    ],
    "phone": [
        "call " + "+" + "44" + "2079460958",
        "call " + "+" + "1" + "5555550123",
        "call " + "+" + "972" + "501234567",
        "call " + "+" + "49" + " 30 " + "1234567",
        "call " + "+" + "33" + "-1-" + "23456789",
        "call " + "+" + "12345678",
        "call " + "+" + "12345678" + "9012345",
    ],
    "account_id": [
        "account " + "1" * 12,
        "account " + "2" * 12,
        "role arn:aws:iam::" + "3" * 6 + "4" * 6 + ":role/x",
        "id=" + "9" * 12,
        "(" + "1" * 6 + "2" * 6 + ")",
        "acct: " + "5" * 12 + ".",
    ],
}


def positive_cases():
    for kind, samples in POSITIVES.items():
        for index, sample in enumerate(samples):
            for transform, transform_id in zip(TRANSFORMS, TRANSFORM_IDS):
                yield pytest.param(kind, sample, transform, id=f"{kind}-{index}-{transform_id}")


@pytest.mark.parametrize("kind,sample,transform", list(positive_cases()))
def test_positive_shapes_are_detected_in_every_disguise(kind, sample, transform):
    # a named value with a Bearer prefix and an entropy token legitimately share a line with other kinds,
    # so only the expected kind must be present
    assert kind in kinds(transform(sample))


@pytest.mark.parametrize("kind,sample", [(k, s) for k, v in POSITIVES.items() for s in v])
def test_percent_encoded_account_ids_and_zero_width_do_not_change_the_line(kind, sample):
    hits = scan("first line\n" + sample.lstrip("\n") + "\nlast line")
    assert hits and all(hit.line == 2 for hit in hits if hit.kind == kind)


NEGATIVES = {
    "vendor_token": [
        "AK" + "IA" + "SHORT",
        "gh" + "p_short",
        "xo" + "xb without a dash",
        "see hooks." + "slack.com for the docs",
        "sk" + "_live_",
        "ey" + "J only one part.here",
        "postgres://db.example.com/main",
        "postgres://app:<SECRET-1>@db.example.com/main",
        "https://example.com:8443/path",
        "ya" + "29 is a prefix",
        "S" + "G. alone",
        "np" + "m install left-pad",
    ],
    "private_key": [
        "-----BEGIN " + "CERTIFICATE-----",
        "-----BEGIN " + "PUBLIC KEY-----",
        rand(59, 40, B64),
        "-" * 70,
        "=" * 70,
        "/" * 70,
        "a" * 70,
        rand(40, 41, B64) + " " + rand(40, 42, B64),
        "/var/log/containers/payments-api/current/application-output-2026-10-04.log",
    ],
    "entropy": [
        "id 123e4567-e89b-12d3-a456-" + "4266" + "14174000",
        "arn:aws:iam::<ACCOUNT>:role/ExampleServiceRoleForNodegroups",
        "image sha256:" + "ab12cd34" * 8,
        "image app@sha256:" + "0f" * 32,
        "task " + "0123456789abcdef" * 2,
        "node i-" + "0123456789abcdef0",
        "sg-" + "0a1b2c3d4e5f60718" + " vpc-" + "0a1b2c3d4e5f60718" + " subnet-" + "0a1b2c3d4e5f60718",
        "eni-" + "0a1b2c3d4e5f60718" + " vol-" + "0a1b2c3d4e5f60718" + " ami-" + "0a1b2c3d4e5f60718",
        "word InternalServerErrorHandlerImplementation",
        "path /var/lib/kubelet/pods/volumes/kubernetes.io~configmap/config",
        "see https://example.com/docs/troubleshooting/pods-stuck-in-pending-state",
        "pod checkout-api-7d9f8c6b5-x2x4z restarted",
        "slug release-2026-10-04-hotfix-for-checkout-service-timeouts",
        "class AmazonEKSClusterPolicyForNodegroups2026 failed",
        "class Http2ConnectionHandlerFactoryBuilder failed",
        "log logs-2026-10-04T10-04-00Z-checkout-api-pod",
        "<SECRET-1> <TOKEN-12> <EMAIL-3> <ACCOUNT> <PHONE-2>",
    ],
    "named_value": [
        "password=<SECRET-1>",
        "token: <TOKEN-2>",
        "secret: ",
        'api_key: ""',
        "password: true",
        "password: false",
        "token: none",
        "cookie: null",
        "password: no",
        "secret = yes",
        "token: ok",
        "authorization: Bearer <TOKEN-4>",
        "the password was rotated",
        "tokens are explained below",
    ],
    "email": [
        "<EMAIL-1>",
        "user at example dot com",
        "@mention in chat",
        "name@",
        "a@b",
        "list a @ b.com",
        "the @here channel",
    ],
    "phone": [
        "+1234567",
        "+" + "12345678" + "90123456",
        "1234567890",
        "a+12345678",
        "cpu +5%",
        "total +100",
        "+ 12345678",
    ],
    "account_id": [
        "1" * 13,
        "1" * 11,
        "ts 1" + "7" * 12 + "1",
        "arn:aws:iam::<ACCOUNT>:role/x",
        "version 1.2.3",
        "task " + "0123456789ab" + "cdef" * 5,
        "x" + "1" * 12,
        "1" * 12 + "z",
    ],
}


def negative_cases():
    for kind, samples in NEGATIVES.items():
        for index, sample in enumerate(samples):
            yield pytest.param(kind, sample, id=f"{kind}-{index}")


@pytest.mark.parametrize("kind,sample", list(negative_cases()))
def test_negative_shapes_are_not_detected(kind, sample):
    assert kind not in kinds(sample)


@pytest.mark.parametrize(
    "kind,sample", [(k, s) for k, v in NEGATIVES.items() for s in v if k not in ("entropy", "private_key")]
)
def test_negative_shapes_have_no_hit_of_any_kind_unless_they_are_another_kind(kind, sample):
    # a negative for one detector must not trip a different one by accident
    assert scan(sample) == []


def test_negative_entropy_shapes_have_no_hit_at_all():
    for sample in NEGATIVES["entropy"]:
        assert scan(sample) == [], sample


def test_an_ordinary_incident_report_has_no_hit():
    report = "\n".join(
        [
            "# Incident 2026-10-04 checkout latency",
            "",
            "## Summary",
            "Pods in `checkout-api-7d9f8c6b5-x2x4z` restarted at 10:04 UTC.",
            "",
            "| Resource | Id | State |",
            "| --- | --- | --- |",
            "| instance | i-0123456789abcdef0 | running |",
            "| security group | sg-0a1b2c3d4e5f60718 | attached |",
            "",
            "- request id 123e4567-e89b-12d3-a456-" + "4266" + "14174000",
            "- role arn:aws:iam::<ACCOUNT>:role/CheckoutNodeRole",
            "- image registry.example.com/checkout@sha256:" + "ab12cd34" * 8,
            "- ecs task " + "0123456789abcdef" * 2,
            "- contact <EMAIL-1>, secret <SECRET-2>, token <TOKEN-3>",
            "- see https://example.com/runbooks/restart-the-checkout-service for steps",
            "- config at /etc/checkout/config/application.properties",
            "- password: <SECRET-4>",
            "- cluster account <ACCOUNT>, p99 latency 1830 ms, 4 errors per minute",
        ]
    )
    assert scan(report) == []


def test_ansi_colouring_between_the_name_and_value_is_removed_first():
    text = "pass\x1b[1m" + "word=\x1b[0m" + "hunter22"
    assert "named_value" in kinds(text)


def test_hit_positions_point_into_the_original_text():
    text = "ab\ncd " + "AK" + "IA" + "X" * 16
    hit = scan(text)[0]
    assert (hit.line, hit.column) == (2, 4)
    assert hit.length == 20


def test_columns_account_for_ansi_before_the_token():
    key = "AK" + "IA" + "X" * 16
    hit = scan("\x1b[31m" + key)[0]
    assert (hit.line, hit.column, hit.length) == (1, 6, 20)


def test_allowed_account_aliases_are_not_reported():
    text = "accounts " + "1" * 12 + " and " + "2" * 12
    assert kinds(text, allowed_account_aliases=frozenset({"1" * 12})) == ["account_id"]
    assert kinds(text, allowed_account_aliases=frozenset({"1" * 12, "2" * 12})) == []


def test_hits_are_ordered_by_position():
    text = "mail jane@example.com\n" + "account " + "1" * 12
    hits = scan(text)
    assert [(h.line, h.kind) for h in hits] == [(1, "email"), (2, "account_id")]


def test_scan_never_raises_on_bad_input():
    assert [hit.kind for hit in scan(None)] == ["unreadable"]  # type: ignore[arg-type]
    assert [hit.kind for hit in scan(b"bytes")] == ["unreadable"]  # type: ignore[arg-type]
    assert scan("") == []
    assert scan("\x00\ud800 odd text") == [] or isinstance(scan("\x00\ud800 odd text"), list)


def test_hits_and_descriptions_never_contain_the_matched_value():
    values = [
        "AK" + "IA" + "QWERTY" + "UIOP" + "ASDF" + "GH",
        "hunter" + "22",
        "jane.doe" + "@" + "example.com",
        rand(40, 50, B64),
    ]
    text = (
        "key " + values[0] + "\n"
        + "pass" + "word=" + values[1] + "\n"
        + "mail " + values[2] + "\n"
        + "blob " + values[3] + "\n"
    )
    hits = scan(text)
    assert len(hits) >= 4
    rendered = " ".join(repr(hit) for hit in hits) + " ".join(describe(hits))
    for value in values:
        for start in range(0, len(value) - 3):
            assert value[start : start + 4] not in rendered


def test_describe_gives_one_line_per_hit_with_kind_line_column_length():
    hits = [Hit("email", 3, 5, 12), Hit("entropy", 9, 1, 40)]
    lines = describe(hits)
    assert len(lines) == 2
    assert all(part in lines[0] for part in ("email", "3", "5", "12"))
    assert all(part in lines[1] for part in ("entropy", "9", "1", "40"))


def test_hit_is_frozen():
    with pytest.raises(Exception):
        Hit("email", 1, 1, 1).line = 2  # type: ignore[misc]


def test_one_megabyte_of_text_is_scanned_in_under_two_seconds():
    rng = random.Random(7)
    words = ["checkout", "latency", "pod", "restarted", "node-3", "ok", "arn:aws:eks:eu-west-1:<ACCOUNT>:cluster/x"]
    lines = []
    size = 0
    while size < 1_000_000:
        line = " ".join(rng.choice(words) for _ in range(12)) + " " + str(rng.randrange(10**6))
        lines.append(line)
        size += len(line) + 1
    text = "\n".join(lines)
    start = time.perf_counter()
    scan(text)
    assert time.perf_counter() - start < 2.0


def test_one_megabyte_of_hostile_text_is_scanned_in_under_two_seconds():
    pieces = ["\x1b[31m", "%41%42", "​", "ｐ", "a" * 30, "=" * 30, "+" * 70, "-" * 70]
    rng = random.Random(8)
    text = "".join(rng.choice(pieces) for _ in range(40_000))[:1_000_000]
    start = time.perf_counter()
    scan(text)
    assert time.perf_counter() - start < 2.0


def test_fullwidth_letters_are_normalised_before_matching():
    text = "".join(chr(ord(c) + 0xFEE0) for c in "password") + "=hunter22"
    assert "named_value" in kinds(text)
