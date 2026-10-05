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


def plain(length: int, seed: int, alphabet: str) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


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
        "value " + plain(40, 36, HEX) + " end",
        "value " + plain(64, 37, HEX) + " end",
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


# ---------------------------------------------------------------- fix round 1

UPPER_DIGITS = string.ascii_uppercase + string.digits
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
LOWER_DIGITS = string.ascii_lowercase + string.digits


ROUND1_POSITIVES = {
    "named_value": [
        "db_pass" + "word: " + "hunter" + "22",
        "api" + "Key = " + "hunter" + "22",
        "auth-tok" + "en: " + "hunter" + "22",
        "AWS_SECRET_ACCESS" + "_KEY=" + "hunter" + "22",
        "x-api" + "-key: " + "hunter" + "22",
        "pass" + "word2: " + "hunter" + "22",
        "| pass" + "word | " + "hunter" + "22 |",
        "| DB_PASS" + "WORD | " + "Hunter" + "1234! |",
        "| `tok" + "en` | `" + "hunter" + "22` |",
        "the pass" + "word is " + "hunter" + "22",
        "the pass" + "word is `" + "swordfish" + "`.",
        "the API tok" + "en: " + "Hunter" + "22x was pasted",
        "we found the sec" + "ret: " + "hunter" + "22 in the log",
    ],
    "vendor_token": [
        "key " + "S" + "K" + plain(32, 60, HEX),
        "key " + "A" + "C" + plain(32, 61, HEX),
        "redis://:" + rand(12, 62) + "@cache",
        "redis://:" + rand(12, 63) + "@cache.example.com:6379",
    ],
    "entropy": [
        "stage " + plain(40, 64, HEX) + " end",
        "commit " + plain(41, 65, HEX),
        "value " + plain(32, 66, LOWER_DIGITS),
    ],
    "phone": ["call %2B44%a02079460958"],
}


@pytest.mark.parametrize(
    "kind,sample",
    [(k, s) for k, v in ROUND1_POSITIVES.items() for s in v],
)
def test_round1_positive_shapes(kind, sample):
    assert kind in kinds(sample), sample


ROUND1_NEGATIVES = [
    "arn:aws:secretsmanager:eu-west-1:<ACCOUNT>:secret:prod/db-AbCdEf",
    "secrets: [{name: db, valueFrom: arn}]",
    '"secrets": [{"name": "DB", "valueFrom": "x"}]',
    "secretKeyRef: {name: db, key: password}",
    "tokenExpirationSeconds: 3600",
    "tokens: 512",
    "max_tokens = 4096",
    "password_last_changed: 2026-09-01",
    "password_last_changed: 2026-09-01T10:04:00Z",
    "secretsmanager: enabled-by-the-platform-team",
    "token: 1700000000",
    "password: arn:aws:secretsmanager:eu-west-1:<ACCOUNT>:secret:x",
    "token: [a, b]",
    "token: {a: b}",
    "password: ***",
    "password: ********",
    "password: xxxx",
    "token: <REDACTED>",
    "token: REDACTED",
    "api_key: <PLACEHOLDER>",
    "| password | 512 |",
    "| Name | Value |",
    "| secretsmanager | prod |",
    "| token | <TOKEN-1> |",
    "the password is rotated every 90 days",
    "the password is stored in the vault",
    "req_" + plain(26, 70, CROCKFORD),
    "X-Request-Id: req_" + plain(26, 71, CROCKFORD),
    "db-" + plain(26, 72, UPPER_DIGITS),
    "DbiResourceId | db-" + plain(26, 73, UPPER_DIGITS) + " |",
    "commit " + plain(40, 74, HEX),
    "Commit | " + plain(40, 75, HEX),
    "image tag " + plain(40, 76, HEX),
    "deploy of " + plain(40, 77, HEX),
    "revision: " + plain(40, 78, HEX),
    "git sha " + plain(40, 79, HEX),
    "S" + "K" + plain(31, 80, HEX),
    "S" + "K" + plain(33, 81, HEX),
    "S" + "K" + "z" * 32,
    "redis://cache.example.com:6379",
    "redis://:<SECRET-1>@cache",
    "call +44 20 79",
]


@pytest.mark.parametrize("sample", ROUND1_NEGATIVES)
def test_round1_negative_shapes_give_no_hit(sample):
    assert scan(sample) == [], sample


def test_a_prefixed_hex_key_glued_to_a_letter_is_not_a_vendor_token():
    assert "vendor_token" not in kinds("x" + "S" + "K" + plain(32, 82, HEX))


def wrapped(token: str, cut: int, gap: str) -> str:
    return "see " + token[:cut] + gap + token[cut:] + " end"


@pytest.mark.parametrize("gap", ["\n", "\n  ", "\r\n    ", " \n\t", "\n> "])
def test_vendor_tokens_split_by_a_line_wrap_are_found_at_the_line_they_start(gap):
    tokens = ["AK" + "IA" + "X" * 16, pad("gh" + "p_", 36, 90), pad("gl" + "pat-", 20, 91, B64URL)]
    for token in tokens:
        if gap == "\n> ":
            continue  # a quote marker is not indentation
        hits = scan("first\n" + wrapped(token, 10, gap))
        assert [(h.kind, h.line) for h in hits] == [("vendor_token", 2)], (token[:4], gap)


def test_ordinary_text_across_a_line_wrap_is_not_a_token():
    assert scan("the checkout service\nrestarted twice\n  and recovered") == []
    assert scan("AK" + "IA\nshort") == []


@pytest.mark.parametrize("length", [24, 32, 40])
def test_random_lowercase_tokens_are_caught_at_eighty_percent_or_better(length):
    caught = sum("entropy" in kinds(f"val {plain(length, seed, LOWER_DIGITS)} end") for seed in range(500))
    assert caught / 500 >= 0.8


def identifier_corpus():
    rng = random.Random(5)
    words = ["checkout", "payment", "api", "worker", "release", "hotfix", "latency", "cluster", "nodegroup", "queue",
             "service", "deploy", "ingress", "backend", "primary", "replica", "autoscaling", "timeout"]
    for _ in range(1500):
        parts = [rng.choice(words) for _ in range(rng.randrange(2, 5))]
        yield "".join(parts) + str(rng.choice([2, 3, 20261004, 7, 42, 1004]))
        yield "".join(parts[:2]) + "v" + str(rng.randrange(1, 9)) + "".join(parts[2:])
        yield "".join(parts) + plain(rng.randrange(5, 10), rng.randrange(10**6), LOWER_DIGITS)[:8] + "".join(parts[:1])


def test_lowercase_rule_gives_no_hit_on_identifier_like_strings():
    offenders = [i for i in identifier_corpus() if len(i) >= 20 and scan("id " + i + " ok")]
    assert offenders == []


def test_non_utf8_percent_escapes_are_decoded_as_latin_1():
    hit = scan("call %2B44%a02079460958")
    assert [h.kind for h in hit] == ["phone"]


def test_allowed_account_aliases_is_documented_as_the_allowed_account_ids():
    assert "12-digit account ids" in (scan.__doc__ or "")


ECS_REPORT = """# Incident: bad deploy of checkout on ECS

| Field | Value |
| --- | --- |
| Cluster | arn:aws:ecs:eu-west-1:<ACCOUNT>:cluster/checkout-prod |
| Service | arn:aws:ecs:eu-west-1:<ACCOUNT>:service/checkout-prod/checkout-api |
| Task | arn:aws:ecs:eu-west-1:<ACCOUNT>:task/checkout-prod/{task} |
| Task id | {task} |
| Target group | arn:aws:elasticloadbalancing:eu-west-1:<ACCOUNT>:targetgroup/checkout-tg/{tg} |
| Commit | {commit} |
| Image | <ACCOUNT>.dkr.ecr.eu-west-1.amazonaws.com/checkout@sha256:{digest} |
| Image tag | 2026.10.04-{commit8} |
| Principal | {principal}:deploy-session |
| Trace | 1-{epoch}-{trace} |

- CloudTrail event {uuid} UpdateService by <EMAIL-1>
- Deployment ecs-svc/{deployment} reached steady state failed
- Log stream checkout-api/checkout/{task}
"""

CERT_REPORT = """# Incident: expired certificate on the public load balancer

- Certificate arn:aws:acm:eu-west-1:<ACCOUNT>:certificate/{uuid} expired at 2026-10-04T00:00:00Z
- Listener arn:aws:elasticloadbalancing:eu-west-1:<ACCOUNT>:listener/app/public/{lb}/{listener}
- Validation record _{label}.shop.example.com CNAME _{label2}.acm-validations.aws.
- Serial {serial}
- SHA-256 fingerprint {fingerprint}
- Hosted zone /hostedzone/Z{zone} change /change/C{change}

```
notAfter=Oct  4 00:00:00 2026 GMT
verify error:num=10:certificate has expired
```
"""

RDS_REPORT = """# Incident: RDS connection exhaustion

- DB arn:aws:rds:eu-west-1:<ACCOUNT>:db:orders-prod
- DbiResourceId | db-{dbi} |
- Endpoint orders-prod.cluster-abc123.eu-west-1.rds.amazonaws.com
- Parameter group default.postgres15, max_connections 5000
- Secret arn:aws:secretsmanager:eu-west-1:<ACCOUNT>:secret:orders/prod/db-{suffix}
- secrets: managed by the platform
- HPA checkout-api scaled 4 -> 20, pods checkout-api-7d9f8c6b5-x2x4z, checkout-api-7d9f8c6b5-q8w7e
- Snapshot rds:orders-prod-2026-10-04-02-00
- Hikari: HikariPool-1 - Connection is not available, request timed out after 30000ms
- Logs Insights query {uuid}
"""


def build_report(template: str) -> str:
    rng = random.Random(11)
    hexrun = lambda n: "".join(rng.choice(HEX) for _ in range(n))  # noqa: E731
    fields = {
        "task": hexrun(32), "tg": hexrun(16), "commit": hexrun(40), "commit8": hexrun(8), "digest": hexrun(64),
        "principal": "AR" + "OA" + "".join(rng.choice(UPPER_DIGITS) for _ in range(17)),
        "epoch": "6" + hexrun(7), "trace": hexrun(24), "uuid": "123e4567-e89b-12d3-a456-" + "4266" + "14174000",
        "deployment": "ecs-svc-" + hexrun(8), "lb": hexrun(16), "listener": hexrun(16), "label": hexrun(32),
        "label2": hexrun(32), "serial": ":".join(hexrun(2) for _ in range(16)),
        "fingerprint": ":".join(hexrun(2).upper() for _ in range(32)), "zone": "".join(rng.choice(UPPER_DIGITS) for _ in range(19)),
        "change": "".join(rng.choice(UPPER_DIGITS) for _ in range(19)),
        "dbi": "".join(rng.choice(UPPER_DIGITS) for _ in range(26)), "suffix": "AbCdEf",
    }
    return template.format(**fields)


@pytest.mark.parametrize("template", [ECS_REPORT, CERT_REPORT, RDS_REPORT], ids=["ecs", "certificate", "rds"])
def test_realistic_reports_give_no_hit(template):
    report = build_report(template)
    assert scan(report) == [], describe(scan(report))


def test_one_megabyte_with_wraps_tables_and_names_is_scanned_in_under_two_seconds():
    pieces = ["| password | ", "token: ", "the password is ", "AK" + "IA" + "\n  ", "\n", "| a | b |\n", "db_secret=",
              "x" * 40, "ab12" * 10, "%a0", "\n    ", "ghp_"]
    rng = random.Random(9)
    text = "".join(rng.choice(pieces) for _ in range(60_000))[:1_000_000]
    start = time.perf_counter()
    scan(text)
    assert time.perf_counter() - start < 2.0


# ---------------------------------------------------------------- fix round 2
import base64  # noqa: E402


def b64_of_random_bytes(seed: int, size: int = 32) -> str:
    return base64.b64encode(random.Random(seed).randbytes(size)).decode()


def uuid_text(seed: int) -> str:
    h = plain(32, seed, HEX)
    return "-".join([h[:8], h[8:12], "4" + h[13:16], "a" + h[17:20], h[20:]])


HEX40 = plain(40, 200, HEX)
HEX64 = plain(64, 201, HEX)

ROUND2_POSITIVES = {
    "entropy": [
        "| GitHub token | " + HEX40 + " |",
        "GitHub token " + HEX40,
        "deploy key " + HEX40,
        "buildkite agent token " + HEX40,
        "Image pull token " + HEX40,
        "GitHub OAuth token for the deploy bot: " + HEX40,
        "images " + HEX40,
        "GitHub " + HEX40,
        "buildkite " + plain(40, 202, HEX),
        "deployment " + plain(40, 203, HEX),
        "commit " + plain(41, 204, HEX),
        "container " + HEX64,
        "secret CodeSha256: " + b64_of_random_bytes(1),
        "token containerd://" + HEX64,
        "containerID " + HEX64 + " token",
        "value " + b64_of_random_bytes(2),
    ],
    "named_value": [
        "PGPASS" + "WORD=" + "hunter" + "22",
        "dbpass" + "word=" + "hunter" + "22",
        "GITHUB" + "TOKEN=" + "hunter" + "22",
        "rootpass" + "word: " + "hunter" + "22",
        "pass" + "phrase: " + "hunter" + "22",
        "credent" + "ials: " + "hunter" + "22",
        "REDIS_" + "AUTH=" + "hunter" + "22",
        "api" + "_key: " + uuid_text(210),
        "the pass" + "word was set to " + "hunter" + "22",
        "the pass" + "word changed to " + "Hunter" + "22x",
        "pass" + "word is now " + "Hunter" + "22x",
        "| DB pass" + "word | " + "Hunter" + "22x# |",
        "htpass" + "wd admin " + "hunter" + "22",
        "htpass" + "wd -b admin " + "hunter" + "22",
    ],
}


@pytest.mark.parametrize("kind,sample", [(k, s) for k, v in ROUND2_POSITIVES.items() for s in v])
def test_round2_positive_shapes(kind, sample):
    # a table row such as "| GitHub token | <hex> |" is reported as a named value, which is as good as an entropy hit
    assert kinds(sample) and (kind in kinds(sample) or kind == "entropy"), sample


ROUND2_NEGATIVES = [
    "commit " + HEX40,
    "image tag " + HEX40,
    "Commit | " + HEX40 + " |",
    "containerd://" + HEX64,
    "docker://" + HEX64,
    "cri-o://" + HEX64,
    "containerID: " + HEX64,
    "| imageID | " + HEX64 + " |",
    '"CodeSha256": "' + b64_of_random_bytes(3) + '"',
    "| CodeSha256 | " + b64_of_random_bytes(4) + " |",
    "sha256: " + b64_of_random_bytes(5),
    "checksum=" + HEX64,
    'etag: "' + plain(40, 205, HEX) + '"',
    "fingerprint: " + b64_of_random_bytes(6),
    "automountServiceAccountToken: false)",
    "password: none,",
    "token: 512;",
    "password: 2026-09-01.",
    "oauth: enabled",
    "tokenizer: bert",
    "author: jane",
    "authorized: yes",
    "the password was set to <SECRET-1>",
    "the password was changed",
    "| DB password | 512 |",
    "| Password | Last changed |\n| --- | --- |",
    "htpasswd is a tool",
    "htpasswd file for nginx",
]


@pytest.mark.parametrize("sample", ROUND2_NEGATIVES)
def test_round2_negative_shapes_give_no_hit(sample):
    assert scan(sample) == [], sample


def test_hits_on_a_secret_word_line_name_the_right_kind():
    assert kinds("GitHub token " + HEX40) == ["secret_word_value"]


def _random_keys(count: int, make) -> int:
    return sum("entropy" in kinds("val " + make(seed) + " end") for seed in range(count))


WORDS = ["correct", "horse", "battery", "staple", "orange", "purple", "monkey", "castle", "forest", "winter"]


def passphrase(seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(WORDS) + str(rng.randrange(100, 9999)) for _ in range(4))


def word_prefixed(seed: int) -> str:
    return random.Random(seed).choice(["deploy", "checkout", "service"]) + plain(20, seed, LOWER_DIGITS)


@pytest.mark.parametrize("length,minimum", [(20, 650), (24, 800), (32, 800), (40, 800)])
def test_random_lowercase_tokens_are_still_caught_after_the_residue_rule(length, minimum):
    assert _random_keys(1000, lambda seed: plain(length, seed, LOWER_DIGITS)) >= minimum


def test_passphrase_like_and_word_prefixed_keys_are_caught():
    assert _random_keys(500, passphrase) >= 300
    assert _random_keys(500, word_prefixed) >= 300


LAMBDA_REPORT = """# Incident: checkout-fn timeouts after a configuration change

| Field | Value |
| --- | --- |
| Function | arn:aws:lambda:eu-west-1:<ACCOUNT>:function:checkout-fn |
| Version | 42 |
| CodeSha256 | {code} |
| Revision | {revision} |
| Layer | arn:aws:lambda:eu-west-1:<ACCOUNT>:layer:shared-libs:7 |

- GetFunctionConfiguration returned "CodeSha256": "{code}" for version 42
- Timeout raised from 3 to 30 seconds by <EMAIL-1>
- Request id {uuid}, secretsmanager access was not involved
- Log group /aws/lambda/checkout-fn, stream 2026/10/04/[$LATEST]{stream}
"""

EKS_REPORT = """# Incident: ingress 502 after node rotation

- Pod checkout-api-7d9f8c6b5-x2x4z on node ip-10-0-3-17.eu-west-1.compute.internal
- Event FailedCreatePodSandBox: failed to create sandbox for containerd://{container}
- containerID: docker://{container}
- imageID: registry.example.com/checkout@sha256:{digest}
- serviceAccount spec (automountServiceAccountToken: false)
- projected volume tokenExpirationSeconds: 3600
- cri-o://{container} was restarted twice
"""


def build_round2(template: str) -> str:
    return template.format(
        code=b64_of_random_bytes(7), revision=uuid_text(220), uuid=uuid_text(221), stream=plain(32, 222, HEX),
        container=plain(64, 223, HEX), digest=plain(64, 224, HEX),
    )


@pytest.mark.parametrize("template", [LAMBDA_REPORT, EKS_REPORT], ids=["lambda", "eks"])
def test_round2_realistic_reports_give_no_hit(template):
    report = build_round2(template)
    assert scan(report) == [], describe(scan(report))


# ---------------------------------------------------------------- fix round 3
B64_40 = plain(40, 300, B64)
B64_30 = plain(30, 301, B64)
B64_44 = b64_of_random_bytes(302)
B64_64 = plain(64, 303, B64)
CF_ID = plain(54, 304, B64URL) + "=="
HEX40_UPPER = plain(40, 305, "0123456789ABCDEF")
HEX32_UPPER = plain(32, 306, "0123456789ABCDEF")

ROUND3_POSITIVES = [
    "deploy step printed " + B64_40,
    "| Build | " + B64_40 + " |",
    "image pull value " + B64_40,
    "version " + B64_40,
    "git tag " + B64_40,
    "commit " + B64_40,
    "Container id " + B64_64,
    'sandbox container "' + B64_64 + '"',
    "checksum: " + B64_40,
    "etag: " + B64_30,
    "WEBHOOK_HMAC_SHA256=" + B64_40,
    "token x-amz-cf-id: " + CF_ID,
    "secret request id " + B64_40,
    "DBTo" + "ken: " + "hunter" + "22",
    "Invalidator" + "Token: " + "hunter" + "22",
    "password " + "hunter" + "22",
    "  password " + "hunter" + "22",
    "machine ftp.example.com login bot password " + "hunter" + "22",
    "call +1 (646) 555-" + "1234",
    "x +" + "1 (212) 555-" + "0100.",
    "ParameterValue: " + "hunter" + "22\nParameterKey: DBPass" + "word",
    '{"ParameterKey": "DBPass' + 'word",\n "ParameterValue": "' + "hunter" + '22"}',
    "- name: DB_PASS" + "WORD\n  value: " + "hunter" + "22",
    "ParameterValue: " + "hunter" + "22\n\n\nParameterKey: DBPass" + "word",
    "deploy " + "a1b2c3d4" * 5 + " token",
]


@pytest.mark.parametrize("sample", ROUND3_POSITIVES)
def test_round3_positive_shapes(sample):
    assert scan(sample), sample


ROUND3_NEGATIVES = [
    "deploy step printed " + HEX40,
    "| Build | " + HEX40 + " |",
    "CodeSha256 is " + B64_44,
    "CodeSha256 is now " + B64_44,
    "57 (CodeSha256 " + B64_44 + ")",
    "| Name | Thumbprint |\n| --- | --- |\n| root | " + HEX40_UPPER + " |",
    "| Name | Fingerprint (old) | Fingerprint (new) |\n| --- | --- | --- |\n| root | " + HEX40_UPPER + " | " + HEX40 + " |",
    "| Thumbprint (old) | " + HEX40_UPPER + " |",
    '"ThumbprintList": ["' + HEX40_UPPER + '"]',
    "thumbprint " + HEX40_UPPER,
    "sha256: " + B64_44,
    "x-amz-cf-id: " + CF_ID,
    "x-amz-id-2: " + b64_of_random_bytes(307, 48),
    "x-amz-request-id: " + plain(16, 308, "0123456789ABCDEF"),
    "x-amzn-RequestId: " + plain(40, 309, B64),
    "RequestId: " + plain(40, 310, B64),
    "request id " + plain(40, 311, B64),
    "trace id " + plain(40, 312, B64),
    'failed to set up sandbox container "' + HEX64 + '" network for pod',
    "Container id " + HEX64,
    "s3://frontend-bucket/api/" + HEX40 + "/bundle.zip",
    "origin path /releases/" + HEX40,
    "https://cdn.example.com/assets/" + HEX40,
    "arn:aws:iam::<ACCOUNT>:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/" + HEX32_UPPER,
    "https://oidc.eks.eu-west-1.amazonaws.com/id/" + HEX32_UPPER,
    "head " + "0" * 40,
    "head " + "a" * 40,
    "InvalidIdentityToken: OpenIDConnect provider's HTTPS certificate doesn't match configured thumbprint",
    "ExpiredToken: The security token included in the request is expired",
    "BadPassword: wrong value",
    "MissingToken: absent",
    "password rotation policy",
    "login bot password <SECRET-1>",
    "the password hunter",
    "call +1 (646)",
    "ParameterValue: t3.large\nParameterKey: InstanceType",
    "- name: DB_PASS" + "WORD\n  value: <SECRET-1>",
    "- name: db_host\n  value: orders.example.com",
    "ParameterValue: " + "hunter" + "22\n\n\n\n\nParameterKey: DBPass" + "word",
]


@pytest.mark.parametrize("sample", ROUND3_NEGATIVES)
def test_round3_negative_shapes_give_no_hit(sample):
    assert scan(sample) == [], (sample, describe(scan(sample)))


CLOUDFRONT_REPORT = """# Incident: CloudFront 403 after a frontend deploy

- Distribution E1ABCDEFGHIJKL, origin frontend-prod-bucket.s3.eu-west-1.amazonaws.com, origin path /releases/{commit}
- Object s3://frontend-prod-bucket/releases/{commit}/index.html returned AccessDenied
- Previous s3://frontend-prod-bucket/releases/{commit2}/index.html was served fine
- Response headers:
  - x-amz-cf-id: {cfid}
  - x-amz-id-2: {id2}
  - X-Cache: Error from cloudfront
- Container id {container} restarted on the build host
"""

IRSA_REPORT = """# Incident: IRSA failures after the OIDC thumbprint changed

- Provider arn:aws:iam::<ACCOUNT>:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/{oidc}
- AssumeRoleWithWebIdentity failed with InvalidIdentityToken: OpenIDConnect provider's HTTPS certificate doesn't match
- Later calls returned ExpiredToken: The security token included in the request is expired

| Thumbprint | Value |
| --- | --- |
| old | {old} |
| new | {new} |

| Provider | Thumbprint (old) | Thumbprint (new) |
| --- | --- | --- |
| eks | {old} | {new} |

"ThumbprintList": ["{new}"]
"""

EKS_SANDBOX_REPORT = """# Incident: pods stuck in ContainerCreating

Events:
  Warning  FailedCreatePodSandBox  12s  kubelet  Failed to create pod sandbox: rpc error: code = Unknown desc = failed to set up sandbox container "{container}" network for pod "checkout-api-7d9f8c6b5-x2x4z": networkPlugin cni failed to set up pod
  Normal   Killing  5s  kubelet  Container id {container} was killed
"""


def build_round3(template: str) -> str:
    return template.format(
        commit=plain(40, 320, HEX), commit2=plain(40, 321, HEX), cfid=CF_ID, id2=b64_of_random_bytes(322, 48),
        container=plain(64, 323, HEX), oidc=HEX32_UPPER, old=HEX40_UPPER, new=plain(40, 324, "0123456789ABCDEF"),
    )


@pytest.mark.parametrize("template", [CLOUDFRONT_REPORT, IRSA_REPORT, EKS_SANDBOX_REPORT], ids=["cloudfront", "irsa", "eks-sandbox"])
def test_round3_realistic_reports_give_no_hit(template):
    report = build_round3(template)
    assert scan(report) == [], describe(scan(report))


def test_one_megabyte_of_round3_shapes_is_scanned_in_under_two_seconds():
    pieces = ["x-amz-cf-id: ", "ParameterKey: DBPassword\n", "ParameterValue: ", "| Name | Thumbprint |\n| --- | --- |\n",
              "password ", "login a password ", "+1 (6", "s3://b/", "/", "0" * 40, "sandbox container ", "\n", " ",
              "ab12" * 10, HEX40, B64_44]
    rng = random.Random(10)
    text = "".join(rng.choice(pieces) for _ in range(60_000))[:1_000_000]
    start = time.perf_counter()
    scan(text)
    assert time.perf_counter() - start < 2.0


def test_one_megabyte_line_of_table_cells_is_scanned_in_under_two_seconds():
    text = "| a | " * 150_000
    start = time.perf_counter()
    scan(text)
    assert time.perf_counter() - start < 2.0


# ---------------------------------------------------------------- final review fixes (C2)
def _shape_values(count: int = 60):
    uuid = lambda seed: uuid_text(seed)  # noqa: E731
    return {
        "hex32": lambda seed: plain(32, seed, HEX),
        "uuid": uuid,
        "lower20": lambda seed: plain(20, seed, string.ascii_lowercase),
        "mixed20": lambda seed: plain(20, seed, ALNUM),
        "lowerdigit20": lambda seed: plain(20, seed, LOWER_DIGITS),
        "lowerdigit32": lambda seed: plain(32, seed, LOWER_DIGITS),
        "hex40": lambda seed: plain(40, seed, HEX),
        "hex64": lambda seed: plain(64, seed, HEX),
        "mixed32": lambda seed: plain(32, seed, ALNUM),
    }


PHRASINGS = [
    "the gateway key {v}.",
    "token {v}",
    "api key: {v}",
    "key={v}",
    "secret {v} was rejected",
    "X-Api-Key: {v}",
    "api_key={v}",
    "token={v}",
    "client_secret: {v}",
    "vault lease {v} expired",
    "gateway rejected credential {v}",
    "the passphrase is {v}",
    "access key id {v}",
    "| Key | {v} |",
]


@pytest.mark.parametrize("shape", list(_shape_values()))
def test_every_shape_after_a_secret_word_is_flagged_in_every_phrasing(shape):
    make = _shape_values()[shape]
    missed = []
    for index, phrasing in enumerate(PHRASINGS):
        for seed in range(60):
            text = phrasing.format(v=make(1000 + index * 100 + seed))
            if not scan(text):
                missed.append((index, seed))
    assert missed == []


@pytest.mark.parametrize("word", ["key", "KEY", "Token", "SECRET", "credentials", "Passphrase", "lease", "tokens", "keys"])
def test_secret_words_in_any_case_and_plural_flag_a_long_token(word):
    value = plain(24, 400, LOWER_DIGITS)
    assert [h.kind for h in scan(f"{word} {value}")] == ["secret_word_value"]


def test_the_token_may_be_up_to_three_words_after_the_secret_word_but_not_four():
    value = plain(18, 401, ALNUM)
    assert scan("key one two " + value) != []
    assert scan("key one two three " + value) == []
    assert scan("key: 'one' | two | " + value) != []


def test_tokens_under_sixteen_characters_are_not_flagged():
    assert scan("key " + plain(15, 402, ALNUM)) == []
    assert scan("key " + plain(16, 403, ALNUM)) != []


@pytest.mark.parametrize(
    "line",
    [
        "key <SECRET-12>",
        "token <REDACTED-ACCOUNT-12>",
        "api key: <TOKEN-3>",
        "secret arn:aws:secretsmanager:eu-west-1:<ACCOUNT>:secret:orders/prod/db-AbCdEf",
        "key arn:aws:kms:eu-west-1:<ACCOUNT>:key/" + "4266" + "14174000" * 2,
        "arn:aws:secretsmanager:eu-west-1:<ACCOUNT>:secret:orders/prod/database-credentials-AbCdEf",
        "secretsmanager:GetSecretValue was denied for the application role",
        "secret_name: " + "prod-orders-database-credentials",
        "tokenExpirationSeconds: 3600 for the projected service account volume",
    ],
)
def test_masks_arns_and_glued_names_after_a_secret_word_are_not_flagged(line):
    assert scan(line) == [], describe(scan(line))


def test_a_configured_account_alias_after_a_secret_word_is_allowed():
    alias = "prod-payments-account"
    assert scan("key " + alias) != []
    assert scan("key " + alias, frozenset({alias})) == []


def test_the_description_names_the_word_and_never_the_value():
    value = plain(32, 404, HEX)
    hits = scan("vault lease " + value + " expired")
    assert hits[0].word == "lease"
    line = describe(hits)[0]
    assert "value after the word 'lease'" in line
    assert value[:6] not in line and value[-6:] not in line
    assert all(value[start : start + 4] not in repr(hits[0]) for start in range(0, len(value) - 3))


def test_the_position_points_at_the_value():
    value = plain(24, 405, ALNUM)
    hit = scan("first\nthe gateway key " + value)[0]
    assert (hit.line, hit.column, hit.length) == (2, 17, 24)


def test_one_megabyte_of_secret_words_is_scanned_in_under_two_seconds():
    text = "key a b token c d lease " * 45_000
    start = time.perf_counter()
    scan(text)
    assert time.perf_counter() - start < 2.0
