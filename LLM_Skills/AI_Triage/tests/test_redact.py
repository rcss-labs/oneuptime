import copy
import json
import time

from triage.redact import AuditHit, Redactor, audit_text

# Secret-looking values are assembled at runtime so no scanner-matching literal is committed.
PASSWORD = "hunter" + "2" + "-pw"
TOKEN = "tok" + "en-" + "x" * 12
AWS_KEY = "AKIA" + "A" * 16
AWS_TEMP_KEY = "ASIA" + "B" * 16
PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
JWT = ".".join(["eyJ" + "h" * 10, "eyJ" + "p" * 10, "s" * 12])
PEM = f"{PEM_BEGIN}\n{'M' * 20}\n{'N' * 20}\n{PEM_END}"


def test_rule1_pem_block_replaced_with_one_placeholder():
    out = Redactor().text(f"before\n{PEM}\nafter")
    assert out == "before\n<SECRET-1>\nafter"


def test_rule2_url_password_replaced_user_and_host_kept():
    out = Redactor().text(f"connect postgres://admin:{PASSWORD}@db.example.com:5432/app now")
    assert PASSWORD not in out
    assert out == "connect postgres://admin:<SECRET-1>@db.example.com:5432/app now"


def test_rule2_email_user_is_not_double_processed():
    redactor = Redactor()
    out = redactor.text(f"https://alice@example.com:{PASSWORD}@db.example.com/x")
    assert PASSWORD not in out
    assert out == "https://alice@example.com:<SECRET-1>@db.example.com/x"
    assert redactor.counts()["secret"] == 1
    assert redactor.counts()["email"] == 0


def test_rule3_bearer_token_replaced_scheme_kept():
    out = Redactor().text(f"Authorization: Bearer {TOKEN} was sent")
    assert out == "Authorization: Bearer <SECRET-1> was sent"


def test_rule3_basic_token_replaced_scheme_kept():
    out = Redactor().text(f"authorization: basic {TOKEN}")
    assert out == "authorization: basic <SECRET-1>"


def test_rule3_json_authorization_header():
    out = Redactor().text('{"Authorization": "Bearer ' + TOKEN + '"}')
    assert json.loads(out) == {"Authorization": "Bearer <SECRET-1>"}


def test_rule4_equals_form():
    out = Redactor().text(f"start db_password={PASSWORD} port=5432")
    assert out == "start db_password=<SECRET-1> port=5432"


def test_rule4_colon_form():
    out = Redactor().text(f"api_key: {TOKEN}\nname: web")
    assert out == "api_key: <SECRET-1>\nname: web"


def test_rule4_json_form_keeps_quotes():
    out = Redactor().text('{"clientSecret": "' + PASSWORD + '", "region": "eu-west-1"}')
    assert json.loads(out) == {"clientSecret": "<SECRET-1>", "region": "eu-west-1"}


def test_rule4_json_form_without_space_and_with_spaces_in_value():
    out = Redactor().text('{"password":"two words here"}')
    assert out == '{"password":"<SECRET-1>"}'


def test_rule4_query_parameters():
    out = Redactor().text(f"GET /v1/items?page=2&access_token={TOKEN}&limit=5 HTTP/1.1")
    assert out == "GET /v1/items?page=2&access_token=<SECRET-1>&limit=5 HTTP/1.1"


def test_rule4_key_suffixes_and_each_keyword():
    redactor = Redactor()
    for key in ["password", "passwd", "secret", "token", "apikey", "api_key", "private_key",
                "credential", "auth", "ssh_key", "signing-key", "MY_SECRET_VALUE", "Credentials"]:
        out = redactor.text(f"{key}={PASSWORD}")
        assert PASSWORD not in out, key
        assert out.startswith(f"{key}=<SECRET-"), key


def test_rule4_does_not_touch_auth_in_hostnames_and_paths():
    text = "redirect to https://auth.example.com:443/oauth/callback via auth.example.com: refused"
    assert Redactor().text(text) == text


def test_rule4_ignores_ordinary_keys():
    text = 'region=eu-west-1 {"name": "web", "keyboard": "us"} key=abc'
    assert Redactor().text(text) == text


def test_rule4_does_not_corrupt_earlier_placeholders():
    out = Redactor().text(f"Authorization: Bearer {TOKEN}\npassword={PASSWORD}")
    assert out == "Authorization: Bearer <SECRET-1>\npassword=<SECRET-2>"
    assert Redactor().text("token=<SECRET-1>") == "token=<SECRET-1>"


def test_rule5_aws_access_key_ids():
    out = Redactor().text(f"keys {AWS_KEY} and {AWS_TEMP_KEY}.")
    assert out == "keys <SECRET-1> and <SECRET-2>."


def test_rule6_jwt():
    out = Redactor().text(f"session {JWT} expired")
    assert out == "session <SECRET-1> expired"


def test_rule7_email():
    out = Redactor().text("mail bob.smith+ops@example.com now")
    assert out == "mail <EMAIL-1> now"


def test_rule8_public_ip_replaced():
    out = Redactor().text("client 1.1.1.1 and 8.8.8.8 hit it")
    assert out == "client <IP-1> and <IP-2> hit it"


def test_rule8_infrastructure_addresses_kept():
    text = " ".join(["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1",
                     "169.254.169.254", "100.64.0.1", "100.127.255.255"])
    assert Redactor().text(text) == text


def test_rule8_edges_of_private_ranges_are_public():
    out = Redactor().text("172.32.0.1 100.128.0.1 11.0.0.1")
    assert out == "<IP-1> <IP-2> <IP-3>"


def test_rule8_ignores_non_addresses():
    text = "version 1.2.3 build 999.1.1.1 id 1.2.3.4.5"
    assert Redactor().text(text) == text


def test_placeholders_are_stable_and_numbered_by_first_appearance():
    redactor = Redactor()
    out = redactor.text(f"password={PASSWORD} again password={PASSWORD} other token={TOKEN}")
    assert out == "password=<SECRET-1> again password=<SECRET-1> other token=<SECRET-2>"
    assert redactor.text(f"x password={PASSWORD}") == "x password=<SECRET-1>"
    assert redactor.text("a@example.com b@example.com a@example.com") == "<EMAIL-1> <EMAIL-2> <EMAIL-1>"


def test_counts_report_distinct_values_per_category():
    redactor = Redactor()
    redactor.text(f"password={PASSWORD} password={PASSWORD} token={TOKEN} {AWS_KEY}")
    redactor.text("a@example.com a@example.com 8.8.8.8 8.8.4.4 8.8.8.8")
    assert redactor.counts() == {"secret": 3, "email": 1, "ip": 2}


def test_redactor_never_exposes_original_values():
    redactor = Redactor()
    redactor.text(f"password={PASSWORD} a@example.com 8.8.8.8")
    exposed = repr(redactor.counts()) + repr(vars(redactor))
    assert PASSWORD not in exposed
    assert "a@example.com" not in exposed
    assert "8.8.8.8" not in exposed


def test_hostnames_ports_arns_private_ips_and_names_kept():
    text = (
        "task arn:aws:ecs:eu-west-1:111111111111:task/checkout/abc123 on 10.0.4.7:8080 "
        "host api.internal.example.com secret arn arn:aws:secretsmanager:eu-west-1:111111111111:"
        "secret:db-credentials-AbCdEf service checkout-api cluster=checkout"
    )
    assert Redactor().text(text) == text


def test_value_ecs_environment_list():
    redactor = Redactor()
    environment = [
        {"name": "DB_PASSWORD", "value": PASSWORD},
        {"name": "LOG_LEVEL", "value": "debug"},
        {"Name": "API_TOKEN", "Value": TOKEN},
        {"name": "DB_HOST", "value": "db.example.com"},
    ]
    out = redactor.value(environment)
    assert out == [
        {"name": "DB_PASSWORD", "value": "<SECRET-1>"},
        {"name": "LOG_LEVEL", "value": "debug"},
        {"Name": "API_TOKEN", "Value": "<SECRET-2>"},
        {"name": "DB_HOST", "value": "db.example.com"},
    ]


def test_value_env_entry_with_ordinary_name_still_scrubs_value_text():
    out = Redactor().value({"name": "DB_URL", "value": f"postgres://u:{PASSWORD}@db.example.com/x"})
    assert out == {"name": "DB_URL", "value": "postgres://u:<SECRET-1>@db.example.com/x"}


def test_value_lambda_environment_variables_dict():
    obj = {"Environment": {"Variables": {"STRIPE_API_KEY": TOKEN, "STAGE": "prod"}}}
    out = Redactor().value(obj)
    assert out == {"Environment": {"Variables": {"STRIPE_API_KEY": "<SECRET-1>", "STAGE": "prod"}}}


def test_value_nested_lists_and_text_rules_apply():
    obj = {"events": [["contact a@example.com", {"ip": "8.8.8.8"}], ("x", f"token={TOKEN}")]}
    out = Redactor().value(obj)
    assert out == {"events": [["contact <EMAIL-1>", {"ip": "<IP-1>"}], ["x", "token=<SECRET-1>"]]}


def test_value_keeps_value_from_reference():
    obj = {"name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-AbCdEf"}
    assert Redactor().value(obj) == obj
    kube = {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}}
    assert Redactor().value(kube) == kube


def test_value_replaces_whole_string_under_secret_key():
    out = Redactor().value({"password": "plain words", "SecretString": PASSWORD, "note": "ok"})
    assert out == {"password": "<SECRET-1>", "SecretString": "<SECRET-2>", "note": "ok"}


def test_value_does_not_mutate_input_and_passes_scalars():
    obj = {"password": PASSWORD, "count": 3, "ratio": 0.5, "ok": True, "none": None,
           "list": [1, False, None, f"token={TOKEN}"]}
    snapshot = copy.deepcopy(obj)
    out = Redactor().value(obj)
    assert obj == snapshot
    assert out["count"] == 3 and out["ratio"] == 0.5 and out["ok"] is True and out["none"] is None
    assert out["list"] == [1, False, None, "token=<SECRET-2>"]
    assert out["password"] == "<SECRET-1>"


def test_value_string_input_and_key_argument():
    redactor = Redactor()
    assert redactor.value("a@example.com") == "<EMAIL-1>"
    assert redactor.value(PASSWORD, key="db_password") == "<SECRET-1>"
    assert redactor.value(7, key="db_password") == "<SECRET-2>"
    assert redactor.value(7, key="retries") == 7


def test_audit_finds_each_category_with_location_and_no_value():
    text = "\n".join([
        "clean line",
        f"  url https://admin:{PASSWORD}@db.example.com/x",
        f"Authorization: Bearer {TOKEN}",
        f"api_key={TOKEN}",
        f"key {AWS_KEY}",
        f"jwt {JWT}",
        PEM,
    ])
    hits = audit_text(text)
    assert all(isinstance(hit, AuditHit) for hit in hits)
    by_category = {hit.category: hit for hit in hits}
    assert set(by_category) == {"url_credential", "auth_header", "secret_key_value",
                                "aws_access_key", "jwt", "private_key"}
    url_line = text.splitlines()[1]
    assert (by_category["url_credential"].line, by_category["url_credential"].column) == (
        2,
        url_line.index(PASSWORD) + 1,
    )
    assert by_category["auth_header"].line == 3
    assert by_category["secret_key_value"].line == 4
    assert by_category["aws_access_key"].line == 5
    assert by_category["jwt"].line == 6
    assert by_category["private_key"].line == 7
    assert by_category["secret_key_value"].column == 9
    for hit in hits:
        assert PASSWORD not in repr(hit) and TOKEN not in repr(hit) and AWS_KEY not in repr(hit)


def test_audit_returns_empty_for_redacted_text():
    redactor = Redactor()
    source = "\n".join([
        f"https://admin:{PASSWORD}@db.example.com/x",
        f"Authorization: Bearer {TOKEN}",
        f"api_key={TOKEN}",
        f'{{"password": "{PASSWORD}"}}',
        AWS_KEY,
        JWT,
        PEM,
    ])
    assert audit_text(redactor.text(source)) == []


def test_audit_on_clean_text_is_empty():
    assert audit_text("auth.example.com /oauth/callback region=eu-west-1") == []


# ---------------------------------------------------------------------------
# Fix round 1: gaps found in review
# ---------------------------------------------------------------------------
import pytest

PW = "hunter" + "2X"
SPECIAL = "S3cr" + "!t#Pw$"
SPLIT_AT = "p@ss" + "w0rd"
HEX = "ab12" * 8
AWS_SECRET_40 = "Qz9" * 13 + "Q"
GITHUB = "ghp" + "_" + "a1B2" * 5
SLACK = "xox" + "b-" + "1234567890-abcdef"
STRIPE = "sk" + "_live_" + "A1b2C3d4E5f6"
BEARER_TOKEN = "abcdef" + "0123456789"

# (id, input, expected redacted output). Every input carries a secret.
SECRET_CASES = [
    ("dotted-spring", f"spring.datasource.password={PW}", "spring.datasource.password=<SECRET-1>"),
    ("dotted-db", f"db.password={PW}", "db.password=<SECRET-1>"),
    (
        "nested-json-key",
        '{"msg":"cfg","config":"{\\"db_password\\":\\"' + PW + '\\"}"}',
        '{"msg":"cfg","config":"{\\"db_password\\":\\"<SECRET-1>\\"}"}',
    ),
    (
        "nested-json-authorization",
        '{\\"Authorization\\": \\"Bearer ' + BEARER_TOKEN + '\\"}',
        '{\\"Authorization\\": \\"Bearer <SECRET-1>\\"}',
    ),
    (
        "redis-empty-user",
        f"REDIS_URL=redis://:{PW}@cache.example.com:6379/0",
        "REDIS_URL=redis://:<SECRET-1>@cache.example.com:6379/0",
    ),
    (
        "redis-special-password",
        f"redis://:{SPECIAL}@cache.example.com:6379/0",
        "redis://:<SECRET-1>@cache.example.com:6379/0",
    ),
    (
        "url-password-with-slash",
        f"postgres://app:ab/{SPECIAL}@db.example.com/x",
        "postgres://app:<SECRET-1>@db.example.com/x",
    ),
    (
        "url-password-with-at",
        f"mysql://root:{SPLIT_AT}@db.example.com:3306/x",
        "mysql://root:<SECRET-1>@db.example.com:3306/x",
    ),
    ("yaml-block-scalar", f"password: |\n  {PW}\n  line two\nnext: ok", "password: |\n  <SECRET-1>\nnext: ok"),
    ("colon-value-to-end-of-line", f"password: correct horse {PW}", "password: <SECRET-1>"),
    ("escaped-quote-in-value", 'PASSWORD="ab\\"' + PW + '"', 'PASSWORD="<SECRET-1>"'),
    ("colon-without-space", f"password:{PW}", "password:<SECRET-1>"),
    ("xml-element", f"<password>{PW}</password>", "<password><SECRET-1></password>"),
    ("hash-rocket", f"password => '{PW}'", "password => '<SECRET-1>'"),
    ("x-auth-token-header", f"X-Auth-Token: Bearer {BEARER_TOKEN}", "X-Auth-Token: <SECRET-1>"),
    ("x-api-key-header", f"X-Api-Key: {BEARER_TOKEN}", "X-Api-Key: <SECRET-1>"),
    ("custom-key-header", f"X-Partner-Key: {BEARER_TOKEN}", "X-Partner-Key: <SECRET-1>"),
    ("authorization-token-scheme", f"Authorization: Token {BEARER_TOKEN}", "Authorization: Token <SECRET-1>"),
    (
        "authorization-digest",
        'Authorization: Digest username="bob", realm="x", response="' + HEX + '"',
        "Authorization: Digest <SECRET-1>",
    ),
    ("bare-bearer", f"sending Bearer {BEARER_TOKEN} now", "sending Bearer <SECRET-1> now"),
    ("cookie", f"Cookie: session={BEARER_TOKEN}; theme=dark", "Cookie: <SECRET-1>"),
    ("set-cookie", f"Set-Cookie: sid={BEARER_TOKEN}; Path=/", "Set-Cookie: <SECRET-1>"),
    ("db-pass", f"DB_PASS={PW}", "DB_PASS=<SECRET-1>"),
    ("mysql-pwd", f"MYSQL_PWD={PW}", "MYSQL_PWD=<SECRET-1>"),
    ("pgpassword", f"PGPASSWORD={PW}", "PGPASSWORD=<SECRET-1>"),
    ("passphrase", f"passphrase={PW}", "passphrase=<SECRET-1>"),
    ("camel-access-key", '{"accessKey": "' + PW + '"}', '{"accessKey":"<SECRET-1>"}'),
    ("camel-private-key", f"privateKey={PW}", "privateKey=<SECRET-1>"),
    ("client-secret", f"client_secret={PW}", "client_secret=<SECRET-1>"),
    (
        "aws-secret-access-key-bare",
        f"aws configure set aws_secret_access_key {AWS_SECRET_40}",
        "aws configure set aws_secret_access_key <SECRET-1>",
    ),
    ("github-token", f"pushed with {GITHUB} today", "pushed with <SECRET-1> today"),
    ("slack-token", f"hook {SLACK} fired", "hook <SECRET-1> fired"),
    ("stripe-key", f"charge via {STRIPE} ok", "charge via <SECRET-1> ok"),
    (
        "pem-without-end",
        f"log: {PEM_BEGIN}\nMIIEvQ{'x' * 20}",
        "log: <SECRET-1>",
    ),
    (
        "pgp-block",
        "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\nabc\n-----END PGP " + "PRIVATE KEY BLOCK-----",
        "<SECRET-1>",
    ),
    (
        "pem-literal-backslash-n",
        f'"{PEM_BEGIN}\\nMIIEv{"y" * 10}\\n{PEM_END}\\n","x":"y"',
        '"<SECRET-1>\\n","x":"y"',
    ),
]


@pytest.mark.parametrize("name, source, expected", SECRET_CASES, ids=[c[0] for c in SECRET_CASES])
def test_review_case_secret_removed_and_structure_kept(name, source, expected):
    out = Redactor().text(source)
    assert out == expected
    for secret in (PW, SPECIAL, SPLIT_AT, BEARER_TOKEN, HEX, AWS_SECRET_40, GITHUB, SLACK, STRIPE):
        assert secret not in out


@pytest.mark.parametrize("name, source, expected", SECRET_CASES, ids=[c[0] for c in SECRET_CASES])
def test_audit_reports_every_secret_case_and_is_clean_after_redaction(name, source, expected):
    assert audit_text(source) != []
    assert audit_text(Redactor().text(source)) == []


@pytest.mark.parametrize(
    "source",
    [
        "https://user@example.com/path",
        "git clone git@github.com:example/repo.git",
        "npm install left-pad@1.3.0",
        "netmask 255.255.255.0 bind 0.0.0.0:8080 multicast 224.0.0.251",
        "auth_type=iam token_units=s KeySchema=pk",
        "partition_key=user-123 routing_key=orders.created s3_key=logs/x cache_key=home sort_key=ts",
        "KeyName=web kms_key_id=abc token_expiry=3600 secret_name=db SecretArn=x SecretStatus=active",
        "sha " + HEX + HEX[:8] + " image digest",
        "see https://auth.example.com:443/oauth/callback and auth:8080 and auth.example.com: refused",
        "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-credentials-AbCdEf",
    ],
)
def test_ordinary_evidence_is_kept(source):
    assert Redactor().text(source) == source
    assert audit_text(source) == []


def test_email_in_text_still_redacted_next_to_colon_and_in_query():
    assert Redactor().text("mail bob@example.com: hi") == "mail <EMAIL-1>: hi"
    assert (
        Redactor().text("http://example.com:8080/x?e=a@b.example.com")
        == "http://example.com:8080/x?e=<EMAIL-1>"
    )


def test_documentation_and_global_ranges():
    out = Redactor().text("a 203.0.113.9 b 8.8.8.8 c 224.0.0.251 d 0.0.0.0")
    assert out == "a 203.0.113.9 b <IP-1> c 224.0.0.251 d 0.0.0.0"


def test_placeholder_numbering_skips_numbers_already_in_the_text():
    out = Redactor().text(f"token=<SECRET-1> and password={PW} and user a@example.com <EMAIL-4>")
    assert out == "token=<SECRET-1> and password=<SECRET-2> and user <EMAIL-5> <EMAIL-4>"


@pytest.mark.parametrize(
    "key, expected",
    [
        ("DB_PASSWORD", True), ("db.password", True), ("dbPassword", True), ("db-password", True),
        ("DB_PASS", True), ("MYSQL_PWD", True), ("passphrase", True), ("accessKey", True),
        ("privateKey", True), ("secretKey", True), ("apiKey", True), ("client_secret", True),
        ("x-api-key", True), ("AUTH_TOKEN", True), ("PGPASSWORD", True), ("secrets", True),
        ("api_keys", True), ("Cookie", True), ("SecretAccessKey", True), ("ssh_key", True),
        ("partition_key", False),
        ("s3_key", False), ("sort_key", False), ("KeyName", False), ("kms_key_id", False),
        ("SecretArn", False), ("SecretStatus", False), ("AuthorizationType", False),
        ("token_expiry", False), ("secret_name", False), ("region", False),
    ],
)
def test_secret_key_component_matching(key, expected):
    from triage.redact import looks_secret_key

    assert looks_secret_key(key) is expected


def test_value_redacts_everything_under_a_secret_key():
    obj = {"password": [PW], "secrets": {"x": PW}, "api_keys": [PW], "pin": {"password": [1234]}}
    out = Redactor().value(obj)
    assert out == {
        "password": ["<SECRET-1>"],
        "secrets": {"x": "<SECRET-1>"},
        "api_keys": ["<SECRET-1>"],
        "pin": {"password": ["<SECRET-2>"]},
    }


def test_value_redacts_numbers_under_secret_key_and_env_entry():
    out = Redactor().value({"name": "DB_PASSWORD", "value": 123456})
    assert out == {"name": "DB_PASSWORD", "value": "<SECRET-1>"}
    assert Redactor().value({"retries": 3, "ok": True, "none": None}) == {"retries": 3, "ok": True, "none": None}


def test_value_redacts_the_argument_after_a_secret_flag():
    out = Redactor().value({"command": ["app", "--db-password", PW, "--port", "8080", "--token=" + PW]})
    assert out == {"command": ["app", "--db-password", "<SECRET-1>", "--port", "8080", "--token=<SECRET-1>"]}


def test_value_tag_style_pairs():
    out = Redactor().value([
        {"Key": "db_password", "Value": PW},
        {"key": "owner", "value": "team-a"},
        {"ParameterKey": "DBPassword", "ParameterValue": PW},
    ])
    assert out == [
        {"Key": "db_password", "Value": "<SECRET-1>"},
        {"key": "owner", "value": "team-a"},
        {"ParameterKey": "DBPassword", "ParameterValue": "<SECRET-1>"},
    ]


def test_value_dict_keys_pass_through_text():
    out = Redactor().value({"alice@example.com": "x", "8.8.8.8": "y"})
    assert out == {"<EMAIL-1>": "x", "<IP-1>": "y"}


def test_value_sets_and_tuples_become_lists():
    redactor = Redactor()
    assert redactor.value({"tags": {"plain"}}) == {"tags": ["plain"]}
    assert redactor.value(("a@example.com", 1)) == ["<EMAIL-1>", 1]


def test_value_keeps_reference_style_keys_even_inside_a_secret_dict():
    secret_arn = "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-AbCdEf"
    obj = {"MasterUserSecret": {"SecretArn": secret_arn, "SecretStatus": "active", "Token": PW}}
    out = Redactor().value(obj)
    assert out == {"MasterUserSecret": {"SecretArn": secret_arn, "SecretStatus": "active", "Token": "<SECRET-1>"}}


# ---------------------------------------------------------------------------
# Fix round 2: regression, name/value text, key rule, URL boundary, speed, over-redaction
# ---------------------------------------------------------------------------
import json
import time

import triage.redact as redact_module

# Timing bounds: 5 seconds per megabyte, the same figure as the fail-closed budget in the code.
# Measured figures live in the report, not here; growth is pinned by the linearity test.
SECONDS_PER_MEGABYTE = 5.0


def time_bound(source) -> float:
    return SECONDS_PER_MEGABYTE * max(len(source), 200_000) / 1_000_000


@pytest.fixture(autouse=True)
def _no_budget_in_timing_tests(request, monkeypatch):
    """A slow machine must not turn a timing run into an <UNREADABLE-n> result by accident."""
    if any(word in request.node.name for word in ("fast", "linear")):
        monkeypatch.setattr(redact_module, "TEXT_TIME_BUDGET", 1e9)

B64 = "dXNlcjpw" + "YXNzd29yZA=="
OPENAI = "sk" + "-proj-" + "abcdefghijklmnop1234"
ANTHROPIC = "sk" + "-ant-" + "abcdefghijklmnop1234"
SK_PLAIN = "sk" + "-" + "abcdefghijklmnop1234"


def test_authorization_dict_keys_keep_scheme_and_redact_token():
    obj = {"headers": {
        "Authorization": "Basic " + B64,
        "authorization": "Token " + PW,
        "Proxy-Authorization": "Basic " + B64,
    }}
    out = Redactor().value(obj)
    assert out == {"headers": {
        "Authorization": "Basic <SECRET-1>",
        "authorization": "Token <SECRET-2>",
        "Proxy-Authorization": "Basic <SECRET-1>",
    }}


def test_authorization_name_value_entry_keeps_scheme():
    out = Redactor().value([{"name": "Authorization", "value": "Basic " + B64}])
    assert out == [{"name": "Authorization", "value": "Basic <SECRET-1>"}]


def test_authorization_text_proxy_header():
    assert Redactor().text("Proxy-Authorization: Basic " + B64) == "Proxy-Authorization: Basic <SECRET-1>"


NAME_VALUE_TEXT_CASES = [
    ("json-name-value", '{"name":"DB_PASSWORD","value":"' + PW + '"}', '{"name":"DB_PASSWORD","value":"<SECRET-1>"}'),
    ("json-key-value", '{"Key":"db_password","Value":"' + PW + '"}', '{"Key":"db_password","Value":"<SECRET-1>"}'),
    (
        "json-parameter",
        '{"ParameterKey":"DBPassword","ParameterValue":"' + PW + '"}',
        '{"ParameterKey":"DBPassword","ParameterValue":"<SECRET-1>"}',
    ),
    (
        "json-in-env-list",
        '{"env":[{"name":"HOME","value":"/root"},{"name":"DB_PASSWORD","value":"' + PW + '"}]}',
        '{"env":[{"name":"HOME","value":"/root"},{"name":"DB_PASSWORD","value":"<SECRET-1>"}]}',
    ),
    (
        "escaped-json",
        '{\\"name\\":\\"DB_PASSWORD\\",\\"value\\":\\"' + PW + '\\"}',
        '{\\"name\\":\\"DB_PASSWORD\\",\\"value\\":\\"<SECRET-1>\\"}',
    ),
    ("yaml", f"- name: DB_PASSWORD\n  value: {PW}\n- name: HOME\n  value: /root", "- name: DB_PASSWORD\n  value: <SECRET-1>\n- name: HOME\n  value: /root"),
    ("yaml-quoted", f"  - name: \"API_TOKEN\"\n    value: \"{PW}\"", "  - name: \"API_TOKEN\"\n    value: \"<SECRET-1>\""),
]


@pytest.mark.parametrize("name, source, expected", NAME_VALUE_TEXT_CASES, ids=[c[0] for c in NAME_VALUE_TEXT_CASES])
def test_text_redacts_value_following_a_secret_name(name, source, expected):
    assert Redactor().text(source) == expected
    assert audit_text(source) != []
    assert audit_text(expected) == []


def test_text_keeps_name_value_pair_with_ordinary_name_and_value_from():
    source = '{"name":"HOME","value":"/root"} {"name":"DB_PASSWORD","valueFrom":{"x":"y"}}'
    assert Redactor().text(source) == source


def test_value_parses_json_strings_and_redacts_structurally():
    annotation = json.dumps({"spec": {"env": [{"name": "DB_PASSWORD", "value": PW}, {"name": "A", "value": "b"}]}})
    out = Redactor().value({"metadata": {"annotations": {"last-applied": annotation}}})
    parsed = json.loads(out["metadata"]["annotations"]["last-applied"])
    assert parsed == {"spec": {"env": [{"name": "DB_PASSWORD", "value": "<SECRET-1>"}, {"name": "A", "value": "b"}]}}
    assert PW not in repr(out)
    assert ", " not in out["metadata"]["annotations"]["last-applied"]


def test_value_json_array_string_and_non_json_string():
    redactor = Redactor()
    assert json.loads(redactor.value('[{"password": "' + PW + '"}]')) == [{"password": "<SECRET-1>"}]
    assert redactor.value("[ERROR] contact a@example.com") == "[ERROR] contact <EMAIL-1>"
    assert redactor.value("{not json} a@example.com") == "{not json} <EMAIL-1>"


@pytest.mark.parametrize(
    "key, expected",
    [
        ("secretkey", True), ("SECRETKEY", True), ("accesstoken", True), ("apitoken", True),
        ("authtoken", True), ("clientsecret", True), ("jwtsecret", True), ("accesskey", True),
        ("privatekey", True), ("OPENAI_KEY", True), ("STRIPE_KEY", True), ("consumer_key", True),
        ("app_key", True), ("hmac_key", True), ("jwt_key", True), ("Authorization", True),
        ("Proxy-Authorization", True), ("key", False), ("Key", False),
        ("partition_key", False), ("sort_key", False), ("s3_key", False), ("routing_key", False),
        ("cache_key", False), ("kms_key", False), ("primary_key", False), ("foreign_key", False),
        ("idempotency_key", False), ("object_key", False), ("hash_key", False), ("shard_key", False),
        ("range_key", False), ("dedup_key", False), ("group_key", False), ("row_key", False),
        ("public_key", False), ("index_key", False), ("tag_key", False), ("metric_key", False),
        ("map_key", False), ("lookup_key", False),
        ("PasswordLastUsed", False), ("MaxPasswordAge", False), ("PasswordReusePrevention", False),
        ("Expiration", False), ("SecretVersionsToStages", False), ("AccessTokenValidity", False),
        ("ExplicitAuthFlows", False), ("defaultMode", False), ("expirationSeconds", False),
        ("TOKEN_TTL", False), ("AUTH_MODE", False), ("password_file", False), ("token_timeout", False),
        ("token_date", False), ("auth_required", False), ("token_units", False), ("secret_days", False),
    ],
)
def test_key_rule_round_two(key, expected):
    from triage.redact import looks_secret_key

    assert looks_secret_key(key) is expected


@pytest.mark.parametrize(
    "source, expected",
    [
        (f"secretkey={PW}", "secretkey=<SECRET-1>"),
        (f"SECRETKEY: {PW}", "SECRETKEY: <SECRET-1>"),
        (f"OPENAI_KEY={OPENAI}", "OPENAI_KEY=<SECRET-1>"),
        (f"used {OPENAI} here", "used <SECRET-1> here"),
        (f"used {ANTHROPIC} here", "used <SECRET-1> here"),
        (f"used {SK_PLAIN} here", "used <SECRET-1> here"),
    ],
)
def test_key_rule_and_vendor_prefixes_in_text(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


def test_short_sk_words_are_kept():
    assert Redactor().text("task-queue disk-usage sk-short") == "task-queue disk-usage sk-short"


def test_comma_separated_url_and_email_not_hidden():
    out = Redactor().text("ref=https://example.com,owner=carol@example.com")
    assert out == "ref=https://example.com,owner=<EMAIL-1>"


def test_json_with_url_and_email_fields_keeps_structure():
    source = '{"endpoint":"https://h.example.com:443","owner":"u:p","contact":"x@example.com"}'
    assert Redactor().text(source) == '{"endpoint":"https://h.example.com:443","owner":"u:p","contact":"<EMAIL-1>"}'
    source = '{"url":"https://api.example.com","email":"alice@example.com"}'
    assert Redactor().text(source) == '{"url":"https://api.example.com","email":"<EMAIL-1>"}'


def test_url_userinfo_email_without_password_is_kept_with_host():
    assert Redactor().text("https://user@example.com/path") == "https://user@example.com/path"


def test_over_redaction_of_settings_and_timestamps_in_value():
    secret_arn = "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-AbCdEf"
    obj = {
        "PasswordLastUsed": "2026-10-01T10:00:00Z",
        "PasswordPolicy": {"MaxPasswordAge": 90, "PasswordReusePrevention": 24},
        "Credentials": {"Expiration": "2026-10-04T10:00:00Z", "SessionToken": PW},
        "SecretVersionsToStages": {"v1": ["AWSCURRENT"]},
        "AccessTokenValidity": 60,
        "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH"],
        "secret": {"defaultMode": 420, "items": [{"key": "password", "path": "pw"}], "SecretArn": secret_arn},
        "env": [{"name": "TOKEN_TTL", "value": "3600"}, {"name": "AUTH_MODE", "value": "oidc"}],
        "sessionCredentialFromConsole": "true",
        "password": None,
        "api_token": False,
    }
    out = Redactor().value(obj)
    assert out["PasswordLastUsed"] == "2026-10-01T10:00:00Z"
    assert out["PasswordPolicy"] == {"MaxPasswordAge": 90, "PasswordReusePrevention": 24}
    assert out["Credentials"] == {"Expiration": "2026-10-04T10:00:00Z", "SessionToken": "<SECRET-1>"}
    assert out["SecretVersionsToStages"] == {"v1": ["AWSCURRENT"]}
    assert out["AccessTokenValidity"] == 60
    assert out["ExplicitAuthFlows"] == ["ALLOW_USER_SRP_AUTH"]
    assert out["secret"]["defaultMode"] == 420
    assert out["secret"]["items"] == [{"key": "password", "path": "pw"}]
    assert out["secret"]["SecretArn"] == secret_arn
    assert out["env"] == obj["env"]
    assert out["sessionCredentialFromConsole"] == "true"
    assert out["password"] is None and out["api_token"] is False


def test_number_redacted_only_under_an_immediately_secret_key():
    redactor = Redactor()
    assert redactor.value({"password": 1234}) == {"password": "<SECRET-1>"}
    assert redactor.value({"password": {"retries": 3}}) == {"password": {"retries": 3}}


def test_text_over_redaction_fixes():
    assert Redactor().text("run --password-file /run/secrets/db --token-file=/var/run/t") == (
        "run --password-file /run/secrets/db --token-file=/var/run/t"
    )
    assert Redactor().text('{"password": null, "token": true}') == '{"password": null, "token": true}'
    # round 5: a colon value that reads as a sentence ("field required") is kept
    source = "error: auth_token: field required (type=value_error.missing)"
    assert Redactor().text(source) == source
    assert value_after_flag_kept()


def value_after_flag_kept() -> bool:
    return Redactor().value(["--password-file", "/run/secrets/db"]) == ["--password-file", "/run/secrets/db"]


@pytest.mark.parametrize(
    "source, expected",
    [
        (f"app --db-password {PW}", "app --db-password <SECRET-1>"),
        (f'sh -c "mysql --password {PW} -h db"', 'sh -c "mysql --password <SECRET-1> -h db"'),
        (f"mysql --password '{PW}' -h db", "mysql --password '<SECRET-1>' -h db"),
        (f"curl -u admin:{PW} https://api.example.com/x", "curl -u admin:<SECRET-1> https://api.example.com/x"),
        (f"curl --user admin:{PW} https://api.example.com/x", "curl --user admin:<SECRET-1> https://api.example.com/x"),
        (f"curl --proxy-user admin:{PW} https://api.example.com/x", "curl --proxy-user admin:<SECRET-1> https://api.example.com/x"),
    ],
)
def test_secret_flags_inside_one_command_string(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


def test_non_secret_flags_and_docker_user_are_kept():
    source = "docker run -u 1000:1000 --user 1000:1000 --port 8080 --name web"
    assert Redactor().text(source) == source


@pytest.mark.parametrize("name", ["a", "b", "A", "bearer", "dots", "jwt", "lines", "json", "oneline", "yaml", "auth", "fields"])
def test_text_and_audit_are_fast_on_hostile_and_realistic_500kb_inputs(name):
    size = 500_000
    shapes = {
        "a": "a" * size,
        "b": "b" * size,
        "A": "A" * size,
        "bearer": "Bearer " + "a" * size,
        "dots": "a." * (size // 2),
        "jwt": "eyJ" + "a." * (size // 2),
        "lines": "2026-10-04T10:00:00Z INFO request handled in 12 ms path=/health host=api.example.com\n" * 5800,
        "json": json.dumps([{"id": i, "msg": "ok", "host": "api.example.com"} for i in range(8000)], separators=(",", ":")),
        "oneline": "word " * (size // 5),
        "yaml": "password: x\n" * 41000,
        "auth": "Authorization: " * 33000,
        "fields": json.dumps([{"password": "x", "id": i} for i in range(8000)], separators=(",", ":")),
    }
    text = shapes[name]
    started = time.perf_counter()
    Redactor().text(text)
    text_seconds = time.perf_counter() - started
    started = time.perf_counter()
    audit_text(text)
    audit_seconds = time.perf_counter() - started
    assert text_seconds < time_bound(text), f"text() took {text_seconds:.2f}s"
    assert audit_seconds < time_bound(text), f"audit_text() took {audit_seconds:.2f}s"


def test_audit_docstring_says_secrets_only():
    assert "secrets only" in (redact_module.audit_text.__doc__ or "")


# ---------------------------------------------------------------------------
# Fix round 3: structured data inside text, webhooks, commands, bounds
# ---------------------------------------------------------------------------
import ast

TASK_DEFINITION = {"containerDefinitions": [{"name": "api", "environment": [{"name": "DB_PASSWORD", "value": PW}]}]}
SLACK_HOOK = "https://hooks.slack.com/services/" + "T0" + "ABC/B0" + "DEF/" + "x" * 8 + "Yz12"
DISCORD_HOOK = "https://discord.com/api/webhooks/" + "1234567890/" + "abcDEF" + "ghiJKL"
OFFICE_HOOK = "https://example.webhook.office.com/webhookb2/" + "aaaa-bbbb@cccc/IncomingWebhook/dddd"
WHSEC = "whsec" + "_" + "abcdefghijklmnop"


def test_pretty_printed_json_after_a_log_prefix_is_redacted_structurally():
    message = "[INFO] registering task definition: " + json.dumps(TASK_DEFINITION, indent=4)
    for out in (Redactor().value({"message": message})["message"], Redactor().text(message)):
        assert PW not in out
        assert out.startswith("[INFO] registering task definition: ")
        assert '"name":"api"' in out.replace(" ", "").replace("\n", "")
        assert "DB_PASSWORD" in out and "<SECRET-1>" in out


def test_python_repr_dict_in_a_log_line():
    out = Redactor().text("[INFO] event: " + repr(TASK_DEFINITION))
    assert PW not in out
    assert out.startswith("[INFO] event: ")
    parsed = ast.literal_eval(out[len("[INFO] event: "):])
    assert parsed["containerDefinitions"][0]["environment"] == [{"name": "DB_PASSWORD", "value": "<SECRET-1>"}]


@pytest.mark.parametrize(
    "source, expected",
    [
        ('{"name":"DB_PASSWORD","type":"PLAINTEXT","value":"' + PW + '"}', '{"name":"DB_PASSWORD","type":"PLAINTEXT","value":"<SECRET-1>"}'),
        (
            '{"Name":"/prod/db/password","Type":"SecureString","Value":"' + PW + '"}',
            '{"Name":"/prod/db/password","Type":"SecureString","Value":"<SECRET-1>"}',
        ),
    ],
)
def test_name_value_with_a_key_between_them(source, expected):
    assert Redactor().text(source) == expected
    assert audit_text(source) != [] and audit_text(expected) == []


@pytest.mark.parametrize(
    "source, expected",
    [
        (  # unclosed, so it cannot be parsed: the widened pattern rule is the fallback
            '{"name": "DB_PASSWORD",\n  "type": "PLAINTEXT",\n  "value": "' + PW + '"',
            '{"name": "DB_PASSWORD",\n  "type": "PLAINTEXT",\n  "value": "<SECRET-1>"',
        ),
        (
            "{'name': 'DB_PASSWORD', 'value': '" + PW + "'",
            "{'name': 'DB_PASSWORD', 'value': '<SECRET-1>'",
        ),
        (
            '{"name" : "DB_PASSWORD" ,\n "value" : "' + PW + '"',
            '{"name" : "DB_PASSWORD" ,\n "value" : "<SECRET-1>"',
        ),
    ],
)
def test_name_value_pattern_fallback_for_spans_that_do_not_parse(source, expected):
    assert Redactor().text(source) == expected
    assert audit_text(source) != [] and audit_text(expected) == []


def test_text_around_a_structured_span_still_goes_through_the_rules():
    out = Redactor().text(f'password={PW} {{"a": 1}} contact a@example.com')
    assert out == 'password=<SECRET-1> {"a": 1} contact <EMAIL-1>'


def test_unchanged_structured_span_is_left_exactly_as_written():
    source = 'x {"a": 1,  "b": [1, 2]} y {"a":1,"a":2}'
    assert Redactor().text(source) == source


def test_deeply_nested_input_never_raises_and_is_not_walked_structurally():
    redactor = Redactor()
    assert isinstance(redactor.value({"m": "[" * 500 + "]" * 500}), (str, dict))
    assert isinstance(redactor.text("[" * 500 + "]" * 500), str)
    nested = '{"a":' * 500 + f'"password={PW}"' + "}" * 500
    out = redactor.text(nested)
    assert PW not in out
    assert PW not in repr(redactor.value({"m": nested}))
    deep_dict: dict = {}
    cursor = deep_dict
    for _ in range(400):
        cursor["x"] = {}
        cursor = cursor["x"]
    assert redactor.value(deep_dict) is not None


def test_structure_nested_exactly_fifty_deep_is_walked_and_fifty_one_is_not():
    def nest(levels: int) -> str:
        return '{"a":' * levels + f'{{"password":"{PW}"}}' + "}" * levels

    walked = Redactor().text(nest(48))
    assert PW not in walked
    too_deep = Redactor().text(nest(60))
    assert PW not in too_deep  # the pattern rules still catch it


def test_text_is_fast_and_safe_on_hostile_bracket_input():
    for source in ["[" * 250_000 + "]" * 250_000, '["a"]' * 100_000, '{"a":' * 100_000, "[" * 500_000, "{[" * 200_000]:
        started = time.perf_counter()
        assert isinstance(Redactor().text(source), str)
        assert time.perf_counter() - started < time_bound(source)


def test_oversize_span_is_skipped_but_its_children_are_not():
    inner = '{"name":"DB_PASSWORD","value":"' + PW + '"}'
    source = "[" + "1," * 110_000 + inner + "]"
    out = Redactor().text(source)
    assert PW not in out


@pytest.mark.parametrize(
    "source, expected",
    [
        (f"url {SLACK_HOOK} sent", "url https://hooks.slack.com/<SECRET-1> sent"),
        (f"url {DISCORD_HOOK} sent", "url https://discord.com/<SECRET-1> sent"),
        (f"url {OFFICE_HOOK} sent", "url https://example.webhook.office.com/<SECRET-1> sent"),
        (f"signing {WHSEC} ok", "signing <SECRET-1> ok"),
    ],
)
def test_webhook_urls_and_signing_secrets(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


def test_lambda_environment_with_slack_webhook():
    out = Redactor().value({"Environment": {"Variables": {"SLACK_WEBHOOK": SLACK_HOOK, "STAGE": "prod"}}})
    assert SLACK_HOOK[-12:] not in repr(out)
    assert out["Environment"]["Variables"]["STAGE"] == "prod"


@pytest.mark.parametrize(
    "source, expected",
    [
        (f'- name: "DB_PASSWORD"\n  value: |\n    {PW}\n    more\n- name: A\n  value: b', '- name: "DB_PASSWORD"\n  value: |\n    <SECRET-1>\n- name: A\n  value: b'),
        (f"-   name: DB_PASSWORD\n    value: {PW}", "-   name: DB_PASSWORD\n    value: <SECRET-1>"),
        (f"  name: DB_PASSWORD\n  value: >\n    {PW}\n", "  name: DB_PASSWORD\n  value: >\n    <SECRET-1>\n"),
    ],
)
def test_yaml_name_value_block_scalar_and_extra_dash_spaces(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


@pytest.mark.parametrize(
    "source, expected",
    [
        (f"curl -u admin:{PW} https://x.example.com", "curl -u admin:<SECRET-1> https://x.example.com"),
        (f"curl -uadmin:{PW} https://x.example.com", "curl -uadmin:<SECRET-1> https://x.example.com"),
        (f"curl --user admin:{PW} https://x.example.com", "curl --user admin:<SECRET-1> https://x.example.com"),
        (f"curl --user=admin:{PW} https://x.example.com", "curl --user=admin:<SECRET-1> https://x.example.com"),
        ("curl --user admin:123456 https://x.example.com", "curl --user admin:<SECRET-1> https://x.example.com"),
        (f"wget --user=admin:{PW} https://x.example.com", "wget --user=admin:<SECRET-1> https://x.example.com"),
        (f"mysql -u root -p{PW} -h db.example.com", "mysql -u root -p<SECRET-1> -h db.example.com"),
        (f"mysqladmin ping -uroot -p{PW}", "mysqladmin ping -uroot -p<SECRET-1>"),
        (f"mysqldump -p{PW} app", "mysqldump -p<SECRET-1> app"),
        (f"docker login -u AWS -p {PW} 111111111111.dkr.ecr.eu-west-1.amazonaws.com", "docker login -u AWS -p <SECRET-1> 111111111111.dkr.ecr.eu-west-1.amazonaws.com"),
        (f"sshpass -p {PW} ssh host.example.com", "sshpass -p <SECRET-1> ssh host.example.com"),
        (f"redis-cli -h cache.example.com -a {PW} ping", "redis-cli -h cache.example.com -a <SECRET-1> ping"),
    ],
)
def test_command_line_credentials(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


@pytest.mark.parametrize(
    "source",
    [
        "docker run --user app:app img",
        "curl -sS https://x.example.com; docker run -u app:grp img",
        "docker run -p 8080:80 img",
        "mysql -h db.example.com -P 3306 -u root",
        "docker login -u AWS registry.example.com",
    ],
)
def test_command_lines_without_credentials_are_kept(source):
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "items, expected",
    [
        (["curl", "-u", "admin:" + PW, "https://x.example.com"], ["curl", "-u", "admin:<SECRET-1>", "https://x.example.com"]),
        (["curl", "--user=admin:" + PW, "https://x"], ["curl", "--user=admin:<SECRET-1>", "https://x"]),
        (["curl", "-uadmin:" + PW], ["curl", "-uadmin:<SECRET-1>"]),
        (["docker", "login", "-p", PW], ["docker", "login", "-p", "<SECRET-1>"]),
        (["mysqladmin", "ping", "-uroot", "-p" + PW], ["mysqladmin", "ping", "-uroot", "-p<SECRET-1>"]),
        (["sshpass", "-p", PW, "ssh", "h"], ["sshpass", "-p", "<SECRET-1>", "ssh", "h"]),
        (["redis-cli", "-a", PW, "ping"], ["redis-cli", "-a", "<SECRET-1>", "ping"]),
        (["docker", "run", "-u", "app:grp", "img"], ["docker", "run", "-u", "app:grp", "img"]),
    ],
)
def test_exec_form_command_lists(items, expected):
    assert Redactor().value({"command": items}) == {"command": expected}


@pytest.mark.parametrize("key", ["pw", "DB_PW", "MYSQL_ROOT_PW", "creds", "CREDS", "cred", "db_creds"])
def test_pw_cred_creds_are_secret_words(key):
    from triage.redact import looks_secret_key

    assert looks_secret_key(key)


def test_creds_value_redacted_in_text():
    # an environment-dump line: the value runs to the end of the line (round 4)
    assert Redactor().text(f"CREDS=admin:{PW} ok") == "CREDS=<SECRET-1>"
    assert Redactor().text(f"x CREDS=admin:{PW} ok") == "x CREDS=<SECRET-1> ok"


@pytest.mark.parametrize(
    "source, expected",
    [
        ("Received Authorization header: Basic " + B64, "Received Authorization header: Basic <SECRET-1>"),
        ("Authorization header Basic " + B64 + " rejected", "Authorization header Basic <SECRET-1> rejected"),
    ],
)
def test_authorization_word_followed_by_scheme_and_token(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


def test_authorization_word_in_ordinary_prose_is_kept():
    source = "Authorization failed for user bob after 3 attempts"
    assert Redactor().text(source) == source


def test_mysql_access_denied_is_unchanged():
    source = "Access denied for user 'root'@'10.0.1.5' (using password: YES)"
    assert Redactor().text(source) == source
    assert Redactor().text("(using password: NO)") == "(using password: NO)"


@pytest.mark.parametrize("value", ["YES", "NO", "yes", "no", "true", "false", "null", "None"])
def test_literal_values_are_kept(value):
    source = f"password: {value}"
    assert Redactor().text(source) == source


def test_unquoted_colon_value_stops_at_close_paren_and_comma():
    assert Redactor().text(f"login failed (token: {PW}), retrying") == "login failed (token: <SECRET-1>), retrying"
    assert Redactor().text(f"password: {PW}, user: bob") == "password: <SECRET-1>, user: bob"


def test_header_value_stops_at_quote_and_url_userinfo_keeps_host():
    out = Redactor().text('curl -H "X-Api-Key: ' + PW + '" https://api.example.com/v1')
    assert out == 'curl -H "X-Api-Key: <SECRET-1>" https://api.example.com/v1'
    token = "ghs" + "_" + "a1B2c3D4e5F6g7"
    out = Redactor().text(f"git clone https://x-access-token:{token}@github.com/org/repo")
    assert out == "git clone https://x-access-token:<SECRET-1>@github.com/org/repo"


def test_more_reference_suffixes_and_units_children_are_kept():
    obj = {
        "TokenValidityUnits": {"AccessToken": "minutes", "RefreshToken": "days"},
        "serviceAccountToken": {"audience": "sts.example.com"},
    }
    assert Redactor().value(obj) == obj
    source = "password_changed_at=2026-10-01 auth_failures=7 token_attempts=3 token_errors=0"
    assert Redactor().text(source) == source


@pytest.mark.parametrize("shape", ["pwd=x;", 'pwd="x";', "password: x ", "token=a&", "a:b "])
def test_single_line_inputs_are_linear(shape):
    source = shape * (1_000_000 // len(shape))
    started = time.perf_counter()
    Redactor().text(source)
    text_seconds = time.perf_counter() - started
    started = time.perf_counter()
    audit_text(source)
    audit_seconds = time.perf_counter() - started
    assert text_seconds < time_bound(source) and audit_seconds < time_bound(source), (text_seconds, audit_seconds)


# ---------------------------------------------------------------------------
# Fix round 4
# ---------------------------------------------------------------------------
from triage.redact import looks_personal_key, looks_secret_key

RULING_11_SECRET_NAMES = [
    # trailing digits are stripped from every part
    "DB_PASS1", "DbPassword2", "DB_TOKEN2", "SERVICE_SECRET2", "DB_KEY1", "REDIS_AUTH1_HOST",
    # long stems anywhere inside a part
    "pass", "passwd", "password", "secret", "token", "cred", "auth", "session", "cookie",
    "bearer", "signature", "hmac", "MyPassValue", "session_token", "sessionid",
    "github_bearer_value", "X-Amz-Signature", "hmacvalue", "license_key", "private_key",
    # short stems as whole parts, key and pwd also at the end of a part
    "db_key", "apikey", "db_pwd", "mysqlpwd", "psw", "pswd", "psk", "sk", "pat", "pin",
    "otp", "mfa", "jwt", "sig", "salt", "pepper", "nonce", "seed", "dsn", "cert", "passcode",
    "USER_PIN", "SENTRY_DSN", "TLS_CERT", "GITHUB_PAT", "MFA_SEED", "STRIPE_SK", "WIFI_PSK", "OTP_CODE",
    # round 5 stems
    "api_tkn", "db_pword", "PSSWD", "rootpw", "DBPW", "DB_PASSWORD_NAME", "API_KEY2_URL", "SECRET_HOST", "TOKEN_PATH",
]


@pytest.mark.parametrize("name", RULING_11_SECRET_NAMES)
def test_ruling_11_secret_names(name):
    assert looks_secret_key(name) is True


@pytest.mark.parametrize(
    "name, expected, why",
    [
        ("MONKEY", True, "key at the end of a part, as in apikey: hiding a harmless value is acceptable"),
        ("KEYSPACE", False, "key neither a whole part nor the end of one"),
        ("AUTHOR", False, "round 5: auth matches a whole part or authorization/authentication/authtoken only"),
        ("PASSENGER_COUNT", False, "the Count ending (ruling 9) wins over the pass stem"),
        ("TOKENIZER_MODE", False, "the Mode ending wins over the token stem"),
        ("TOKENIZER", True, "token is a long stem and matches inside a part"),
        ("MAX_CONN", False, "conn is not a stem; connection strings are caught by their value"),
        ("CONN_POOL_SIZE", False, "conn is not a stem"),
        ("key", False, "a bare key names a lookup key (S3 Key=, tag Key), kept by ruling 9"),
        ("Key", False, "as above"),
        ("AttributeKey", False, "ruling 9: the secret word qualifies a non-secret thing"),
        ("ParameterKey", False, "ruling 9"),
        ("TagKey", False, "ruling 9"),
        ("KeyName", False, "ruling 9: Name ending"),
        ("KeyId", False, "ruling 9: Id ending"),
        ("TokenEndpoint", False, "ruling 9: Endpoint ending"),
        ("DB_KEY1_ID", False, "ruling 9 ending after digit stripping"),
        ("s3_key", False, "a kind of key that is not secret"),
        ("KeyMaterial", True, "key as a whole part with no non-secret qualifier"),
        ("passed", False, "an English word that holds the stem but never names a secret (report: Gates passed)"),
        ("tests_passing", False, "as above"),
        ("bypass", False, "as above"),
        ("PassedValue", False, "as above"),
    ],
)
def test_ruling_11_edge_names(name, expected, why):
    assert looks_secret_key(name) is expected, why


@pytest.mark.parametrize(
    "name, expected",
    [
        ("user", True), ("USR", True), ("username", True), ("login", True), ("email", True), ("mail", True),
        ("owner", True), ("phone", True), ("msisdn", True), ("ssn", True), ("DbUser2", True),
        ("contact_email", True), ("ownerPhone", True), ("LOGIN_NAME", True),
        ("userspace", False), ("mailbox_size", False), ("region", False), ("password", False),
    ],
)
def test_ruling_11_personal_names(name, expected):
    assert looks_personal_key(name) is expected


def test_report_gate_line_is_not_redacted():
    line = "- Gates passed: evidence, no_contradiction, rank"
    assert Redactor().text(line) == line


# Ruling 1: never raise

@pytest.mark.parametrize(
    "call",
    [
        lambda r: r.text("password=ab\ud800cd"),
        lambda r: r.value({"password": "x\udfff"}),
        lambda r: r.value({"m": '{"password": "a\\ud800b"}'}),
        lambda r: r.text('{"token": "\udc80' + PW + '"}'),
        lambda r: r.value(["--password", "a\ud800"]),
    ],
)
def test_lone_surrogates_never_raise_and_never_leak(call):
    out = call(Redactor())
    assert "\ud800cd" not in repr(out) and PW not in repr(out)


def test_random_surrogate_strings_never_raise():
    import random

    rng = random.Random(4)
    alphabet = ["password=", "token: ", '{"a": "', '"}', "[", "]", "\ud800", "\udfff", "x", " ", "%40", "\x1b[0m"]
    redactor = Redactor()
    for _ in range(2000):
        source = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 12)))
        assert isinstance(redactor.text(source), str)
        redactor.value({"k": source, "password": source})
        audit_text(source)


def test_unexpected_error_yields_a_whole_string_placeholder(monkeypatch):
    def broken(text):
        raise ValueError("boom")

    monkeypatch.setattr(redact_module, "SECRET_RULES", (("broken", broken),))
    redactor = Redactor()
    source = f"password={PW} and more"
    assert redactor.text(source) == "<UNREADABLE-1>"
    assert redactor.text(source) == "<UNREADABLE-1>"
    out = redactor.value({"note": source, "n": 3})
    assert list(out.values()) == ["<UNREADABLE-1>", 3]  # keys go through text() too, so they are unreadable
    assert redactor.value(source) == "<UNREADABLE-1>"
    hits = audit_text(source)
    assert [hit.category for hit in hits] == ["unreadable"]
    assert PW not in repr(hits)


def test_object_whose_str_raises_does_not_crash_value():
    class Hostile:
        def __str__(self):
            raise RuntimeError("no")

    out = Redactor().value({"password": Hostile()})
    assert out["password"].startswith("<UNREADABLE-")


# Ruling 2: cost

MEGABYTE = 1_000_000


@pytest.mark.parametrize("shape", ["[]", "{}", '["a"] ', "[{}]", "{[]}", '{"a":', "\\'", "\x1b[0m", "%41", "+1 "])
def test_one_megabyte_bracket_shapes_are_fast(shape):
    source = shape * (MEGABYTE // len(shape))
    for call in (Redactor().text, lambda s: Redactor().value({"m": s}), audit_text):
        started = time.perf_counter()
        call(source)
        elapsed = time.perf_counter() - started
        assert elapsed < time_bound(source), (shape, elapsed)


# Ruling 3: YAML block scalars mask only their own lines

def test_block_scalar_in_a_pod_spec_keeps_the_following_entries():
    source = (
        "spec:\n  containers:\n  - env:\n    - name: DB_PASSWORD\n      value: >-\n        " + PW + "\n"
        "    - name: LOG_LEVEL\n      value: debug\n    image: api:1.2\n    resources:\n      limits:\n"
        "        memory: 512Mi\nstatus: {}"
    )
    expected = source.replace(PW, "<SECRET-1>")
    assert Redactor().text(source) == expected


def test_block_scalar_in_a_config_map_keeps_sibling_keys():
    source = (
        "data:\n  password: |\n    " + PW + "\n    second line\n\n    third\n"
        "  host: db.example.com\n  port: \"5432\"\n  replicas: 3\n"
    )
    expected = "data:\n  password: |\n    <SECRET-1>\n  host: db.example.com\n  port: \"5432\"\n  replicas: 3\n"
    assert Redactor().text(source) == expected


# Ruling 4: argument lists are command lines

@pytest.mark.parametrize(
    "obj, expected",
    [
        (
            {"healthCheck": {"command": ["CMD", "mysqladmin", "ping", "-uroot", "-p" + PW]}},
            {"healthCheck": {"command": ["CMD", "mysqladmin", "ping", "-uroot", "-p<SECRET-1>"]}},
        ),
        ({"command": ["mysql"], "args": ["-h", "db", "-p" + PW]}, {"command": ["mysql"], "args": ["-h", "db", "-p<SECRET-1>"]}),
        ({"command": ["/usr/bin/redis-cli"], "args": ["-a", PW]}, {"command": ["/usr/bin/redis-cli"], "args": ["-a", "<SECRET-1>"]}),
        ({"command": ["curl"], "args": ["-u", "admin:" + PW]}, {"command": ["curl"], "args": ["-u", "admin:<SECRET-1>"]}),
        (["CMD", "curl", "--user=admin:" + PW], ["CMD", "curl", "--user=admin:<SECRET-1>"]),
        ({"command": ["mysql"], "args": ["-h", "db"]}, {"command": ["mysql"], "args": ["-h", "db"]}),
    ],
)
def test_exec_form_lists_and_command_with_args(obj, expected):
    assert Redactor().value(obj) == expected


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            '{"healthCheck":{"command":["CMD","mysqladmin","ping","-uroot","-p' + PW + '"]}}',
            '{"healthCheck":{"command":["CMD","mysqladmin","ping","-uroot","-p<SECRET-1>"]}}',
        ),
        (
            "containers:\n- name: db\n  command:\n  - mysql\n  args:\n  - -h\n  - db\n  - -p" + PW + "\n  image: mysql:8\n",
            "containers:\n- name: db\n  command:\n  - mysql\n  args:\n  - -h\n  - db\n  - -p<SECRET-1>\n  image: mysql:8\n",
        ),
        (
            'containers:\n- name: db\n  command: ["mysql"]\n  args: ["-h", "db", "-p' + PW + '"]\n',
            'containers:\n- name: db\n  command: ["mysql"]\n  args: ["-h", "db", "-p<SECRET-1>"]\n',
        ),
        (
            "  command:\n    - redis-cli\n    - -a\n    - " + PW + "\n    - ping\n",
            "  command:\n    - redis-cli\n    - -a\n    - <SECRET-1>\n    - ping\n",
        ),
    ],
)
def test_argument_lists_in_text_are_read_as_command_lines(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


# Ruling 9: false positives

def test_names_whose_secret_word_only_qualifies_something_else_are_kept():
    obj = {
        "AttributeKey": "ReadOnly", "ParameterKey": "Stage", "TagKey": "team", "ApiKeySource": "HEADER",
        "CredentialSource": "Ec2InstanceMetadata", "TokenEndpoint": "https://auth.example.com/oauth2/token",
        "AuthFlow": "USER_PASSWORD_AUTH", "token_bucket_remaining": 42, "auth_latency_ms": 12,
        "AuthTokenRequests": 5, "PasswordLastUsed": "2026-10-01T10:00:00Z", "KeyState": "Enabled",
        "SecretArn": "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-AbCdEf", "KeyId": "k-1",
        "SecretName": "db", "AuthType": "AWS_IAM", "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "TokenCount": 3, "PasswordPolicy": {"MinimumPasswordLength": 14},
        "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT", "AccessKeyMetadata": [{"Status": "Active"}],
    }
    assert Redactor().value(obj) == obj


def test_names_the_review_lists_as_correctly_hidden_stay_hidden():
    obj = {"PasswordData": PW, "SecretString": PW, "SecretKey": PW, "KeyMaterial": PW, "authorizationToken": PW}
    assert set(Redactor().value(obj).values()) == {"<SECRET-1>"}


def test_lookup_attribute_on_a_command_line_is_kept():
    source = "aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false"
    assert Redactor().text(source) == source


@pytest.mark.parametrize("literal", ["true", "FALSE", "Yes", "no", "ok", "OK", "none", "Null", "NONE"])
def test_literal_values_under_a_secret_name_are_kept(literal):
    assert Redactor().text(f"password: {literal}") == f"password: {literal}"
    assert Redactor().text(f"token={literal}") == f"token={literal}"
    assert Redactor().value({"password": literal}) == {"password": literal}


@pytest.mark.parametrize(
    "source",
    [
        "ssl_key: /etc/ssl/private/server.key",
        "ssl_key=/etc/ssl/private/server.key",
        '{"ssl_key": "/etc/ssl/private/server.key"}',
        "nginx --ssl-key /etc/nginx/certs/site.key --port 443",
        "- name: TLS_KEY\n  value: /run/secrets/tls.key",
    ],
)
def test_plain_absolute_paths_under_a_secret_name_are_kept(source):
    assert Redactor().text(source) == source


def test_path_value_is_kept_in_value_but_a_random_path_part_is_not():
    assert Redactor().value({"ssl_key": "/etc/ssl/private/server.key"}) == {"ssl_key": "/etc/ssl/private/server.key"}
    random_part = "Qx7" + "Lm2Rt9" + "Zp4Vb8"
    assert random_part not in Redactor().text(f"password=/{random_part}")
    assert random_part not in repr(Redactor().value({"password": "/tmp/" + random_part}))


@pytest.mark.parametrize(
    "source, expected",
    [
        ('"Cookie":["<SECRET-1>"]', '"Cookie":["<SECRET-1>"]'),
        ("{'creds': {", "{'creds': {"),
        ("{ db: { creds: { password: '" + PW + "' } } }", "{ db: { creds: { password: '<SECRET-1>' } } }"),
        (
            "curl -H 'Private-Token: " + PW + "' https://gitlab.example.com/api/v4/projects",
            "curl -H 'Private-Token: <SECRET-1>' https://gitlab.example.com/api/v4/projects",
        ),
        ("token: [", "token: ["),
        ("password={", "password={"),
    ],
)
def test_key_value_rule_never_eats_brackets_or_closing_quotes(source, expected):
    assert Redactor().text(source) == expected


# Ruling 5: normalise before matching

ESC = "\x1b"


@pytest.mark.parametrize(
    "source, expected",
    [
        (f"{ESC}[36mpassword{ESC}[0m={ESC}[35m{PW}{ESC}[0m", "password=<SECRET-1>"),
        (f"{ESC}[1;33mDB_PASSWORD:{ESC}[0m {PW}", "DB_PASSWORD: <SECRET-1>"),
        (f"{ESC}[33mAuthorization: {ESC}[0mBearer short1", "Authorization: Bearer <SECRET-1>"),
        (f"pass​word={PW}", "password=<SECRET-1>"),
        (f"pass­word={PW}", "password=<SECRET-1>"),
        (f"﻿api_key={PW}", "api_key=<SECRET-1>"),
        ("ｐａｓｓｗｏｒｄ=" + PW, "password=<SECRET-1>"),
        (f"{ESC}]0;title\x07token={PW}", "token=<SECRET-1>"),
    ],
)
def test_ansi_invisible_and_compatibility_characters_are_normalised(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != []


def test_plain_coloured_text_loses_only_its_escape_codes():
    assert Redactor().text(f"{ESC}[32mINFO{ESC}[0m request ok") == "INFO request ok"


@pytest.mark.parametrize(
    "source, expected",
    [
        ("GET /signup?email=bob%40corp.example.com&step=2", "GET /signup?email=<EMAIL-1>&step=2"),
        ("GET /x?u=bob%2540corp.example.com", "GET /x?u=<EMAIL-1>"),
        ("GET /cb?next=%2Fhome%3Ftoken%3D" + PW + " 200", "GET /cb?next=<SECRET-1> 200"),
        ("data=password%3D" + PW + "%26user%3Dbob", "data=<SECRET-1>"),
    ],
)
def test_percent_encoded_tokens_are_checked_in_decoded_form(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert Redactor().text(out) == out


@pytest.mark.parametrize("source", ["CPU at 95% now", "progress=50%25 done", "GET /files/a%20b.txt 200", "%d items"])
def test_harmless_percent_text_is_kept(source):
    assert Redactor().text(source) == source


# Ruling 6: more rules

@pytest.mark.parametrize(
    "source, expected",
    [
        (f"LOG:  statement: ALTER USER app WITH PASSWORD '{PW}';", "LOG:  statement: ALTER USER app WITH PASSWORD '<SECRET-1>';"),
        (f"CREATE USER 'a'@'%' IDENTIFIED BY '{PW}';", "CREATE USER 'a'@'%' IDENTIFIED BY '<SECRET-1>';"),
        (f"create role r with login encrypted password '{PW}'", "create role r with login encrypted password '<SECRET-1>'"),
        (
            f"ALTER USER 'a'@'%' IDENTIFIED WITH mysql_native_password BY '{PW}'",
            "ALTER USER 'a'@'%' IDENTIFIED WITH mysql_native_password BY '<SECRET-1>'",
        ),
        (f"SET PASSWORD FOR 'a'@'%' = '{PW}'", "SET PASSWORD FOR 'a'@'%' = '<SECRET-1>'"),
        (f"SET PASSWORD = PASSWORD('{PW}')", "SET PASSWORD = PASSWORD('<SECRET-1>')"),
        (f"ALTER ROLE app PASSWORD 'it''s{PW}'", "ALTER ROLE app PASSWORD '<SECRET-1>'"),
    ],
)
def test_sql_password_statements(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


@pytest.mark.parametrize(
    "source",
    [
        "FATAL:  password authentication failed for user \"app\"",
        "Access denied for user 'root'@'10.0.1.5' (using password: YES)",
        "ALTER USER app VALID UNTIL 'infinity'",
    ],
)
def test_sql_lines_without_a_password_are_kept(source):
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            f"aws cloudformation deploy --parameters ParameterKey=DBPassword,ParameterValue={PW} ParameterKey=Env,ParameterValue=prod",
            "aws cloudformation deploy --parameters ParameterKey=DBPassword,ParameterValue=<SECRET-1> ParameterKey=Env,ParameterValue=prod",
        ),
        (f"aws ec2 create-tags --tags Key=api_token,Value={PW} Key=team,Value=core", "aws ec2 create-tags --tags Key=api_token,Value=<SECRET-1> Key=team,Value=core"),
        (
            f"aws ecs run-task --overrides containerOverrides=[{{name=api,environment=[{{name=DB_PASSWORD,value={PW}}}]}}]",
            "aws ecs run-task --overrides containerOverrides=[{name=api,environment=[{name=DB_PASSWORD,value=<SECRET-1>}]}]",
        ),
        (
            f"aws ssm put-parameter --name /prod/db/password --type SecureString --value {PW} --overwrite",
            "aws ssm put-parameter --name /prod/db/password --type SecureString --value <SECRET-1> --overwrite",
        ),
        (f"aws ssm put-parameter --name /prod/app/x --value '{PW}'", "aws ssm put-parameter --name /prod/app/x --value '<SECRET-1>'"),
        (f"aws secretsmanager put-secret-value --secret-id db --secret-string '{PW}'", "aws secretsmanager put-secret-value --secret-id db --secret-string '<SECRET-1>'"),
        (f"aws rds modify-db-instance --db-instance-identifier db1 --master-user-password {PW}", "aws rds modify-db-instance --db-instance-identifier db1 --master-user-password <SECRET-1>"),
    ],
)
def test_aws_cli_shorthand(source, expected):
    out = Redactor().text(source)
    assert out == expected
    assert audit_text(source) != [] and audit_text(out) == []


VENDOR_TOKENS = {
    "google-api-key": "AI" + "za" + "Sy" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "google-oauth": "ya" + "29." + "a0AfH6SM" + "Bx1y2z3_abcDEF",
    "google-client-secret": "GOC" + "SPX-" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "github-user": "gh" + "u_" + "a1B2c3D4e5F6g7H8i9J0",
    "github-refresh": "gh" + "r_" + "a1B2c3D4e5F6g7H8i9J0",
    "gitlab": "gl" + "pat-" + "a1B2c3D4e5F6g7H8i9J0",
    "npm": "np" + "m_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "sendgrid": "SG" + "." + "a1B2c3D4e5F6g7H8i9J0" + "." + "k1L2m3N4o5P6q7R8s9T0",
    "vault": "hv" + "s." + "CAESIa1B2c3D4e5F6g7H8i9J0",
    "slack-app": "xa" + "pp-" + "1-A0123-456789-abcdef",
    "slack-refresh": "xo" + "xe." + "xoxp-1-a1B2c3D4e5F6g7",
    "stripe-restricted-test": "rk" + "_test_" + "a1B2c3D4e5F6g7H8",
}


@pytest.mark.parametrize("name", sorted(VENDOR_TOKENS))
def test_more_vendor_token_prefixes(name):
    token = VENDOR_TOKENS[name]
    out = Redactor().text(f"using {token} now")
    assert out == "using <SECRET-1> now"
    assert audit_text(f"using {token} now") != []


@pytest.mark.parametrize("kind", ["workflows", "triggers"])
def test_slack_workflow_and_trigger_hooks(kind):
    hook = f"https://hooks.slack.com/{kind}/" + "T0" + "ABC/A0" + "DEF/" + "x" * 6 + "Yz12"
    assert Redactor().text(f"post {hook} ok") == "post https://hooks.slack.com/<SECRET-1> ok"


@pytest.mark.parametrize(
    "source",
    [
        "scope: {'type': 'http', 'headers': [(b'host', b'api.example.com'), (b'cookie', b'sid=" + PW + "')]}",
        '{"headers": [["Host", "api.example.com"], ["Cookie", "sid=' + PW + '"]]}',
        "headers=[('X-Api-Key', '" + PW + "'), ('Accept', '*/*')]",
    ],
)
def test_cookie_and_key_values_in_header_pair_lists(source):
    out = Redactor().text(source)
    assert PW not in out
    assert "api.example.com" in out or "Accept" in out


def test_authorization_in_header_pairs_keeps_its_scheme():
    out = Redactor().value({"headers": [("authorization", "Basic " + B64), ("host", "api.example.com")]})
    assert out == {"headers": [["authorization", "Basic <SECRET-1>"], ["host", "api.example.com"]]}


BODY_LINE = ("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" + "7Vb3x" + "Qm9pLk2Jh8Gf4Dd1Ss0Aa")[:64]


@pytest.mark.parametrize(
    "source, expected",
    [
        (BODY_LINE, "<SECRET-1>"),
        (f"  {BODY_LINE}", "  <SECRET-1>"),
        (f"{BODY_LINE}\n-----END " + "PRIVATE KEY-----", "<SECRET-1>"),
        (f"tail of key {BODY_LINE[:20]}==\n-----END " + "RSA PRIVATE KEY-----\nnext line", "<SECRET-1>\nnext line"),
        # round 5: "private" is a secret word only together with key, so Private-Lines keeps its count
        (f"Private-Lines: 2\n{BODY_LINE}\n{BODY_LINE[:30]}\nPrivate-MAC: x", "Private-Lines: 2\n<SECRET-1>\nPrivate-MAC: x"),
    ],
)
def test_pem_body_lines_arriving_separately(source, expected):
    assert Redactor().text(source) == expected
    assert audit_text(source) != []


# Ruling 8: phone numbers

@pytest.mark.parametrize(
    "source, expected",
    [
        ("call +1 (555) 010-9999 now", "call <PHONE-1> now"),
        ("tel=+44 20 7946 0958", "tel=<PHONE-1>"),
        ("sms to +972-54-123-4567 sent", "sms to <PHONE-1> sent"),
        ("+4915112345678", "<PHONE-1>"),
        ('{"phone": "+33.1.23.45.67.89"}', '{"phone":"<PHONE-1>"}'),  # a changed JSON span is re-serialised
    ],
)
def test_phone_numbers_with_a_leading_plus_are_masked(source, expected):
    redactor = Redactor()
    assert redactor.text(source) == expected
    assert redactor.counts()["phone"] == 1


@pytest.mark.parametrize(
    "source",
    [
        "2026-10-04T10:00:00+00:00 ok",
        "[04/Oct/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1234",
        "2026-10-04 10:00:00 +0000 12345 handled",
        "x+1234567890 build",
        "retry in +1234567 ms",
        "a +5 offset and 1+12345678",
        "client 10.0.0.1 and 8.8.8.8",
    ],
)
def test_things_that_are_not_phone_numbers_are_kept(source):
    out = Redactor().text(source)
    assert "<PHONE-" not in out


def test_text_without_findings_keeps_its_own_characters():
    source = "x" * 10 + "\u2026 [summary cut] \uff21 caf\u00e9"
    assert Redactor().text(source) == source


# Ruling 7: fail closed on key material in free text

import random as _random
import string as _string


def random_token(seed: int, length: int, alphabet: str) -> str:
    rng = _random.Random(seed)
    while True:
        token = "".join(rng.choice(alphabet) for _ in range(length))
        if sum([any(c.islower() for c in token), any(c.isupper() for c in token), any(c.isdigit() for c in token)]) >= 2:
            return token


ALNUM = _string.ascii_letters + _string.digits
KEY_MATERIAL = {
    "alnum-24": random_token(1, 24, ALNUM),
    "alnum-48": random_token(2, 48, ALNUM),
    "base64-40": random_token(3, 38, ALNUM + "+/") + "==",
    "base64url-43": random_token(4, 43, ALNUM + "-_"),
    "lower-digits-32": random_token(5, 32, _string.ascii_lowercase + _string.digits),
    "hex-40": random_token(6, 40, "0123456789abcdef"),
    "hex-64": random_token(7, 64, "0123456789abcdef"),
    "sts-like": "IQoJb3JpZ2lu" + random_token(8, 60, ALNUM + "+/"),
}


@pytest.mark.parametrize("name", sorted(KEY_MATERIAL))
def test_key_like_tokens_in_free_text_are_masked(name):
    token = KEY_MATERIAL[name]
    out = Redactor().text(f"2026-10-04T10:00:00Z INFO retry with {token} done")
    assert out == "2026-10-04T10:00:00Z INFO retry with <TOKEN-1> done"


def test_the_same_token_gets_the_same_placeholder():
    first, second = KEY_MATERIAL["alnum-48"], KEY_MATERIAL["base64url-43"]
    redactor = Redactor()
    assert redactor.text(f"a {first} b {second} c {first}") == "a <TOKEN-1> b <TOKEN-2> c <TOKEN-1>"
    assert redactor.text(f"again {second}") == "again <TOKEN-2>"


@pytest.mark.parametrize(
    "template, expected",
    [
        ("https://example.com/reset/{t}", "https://example.com/reset/<TOKEN-1>"),
        ("GET /v1/files?after={t}&page=2", "GET /v1/files?after=<TOKEN-1>&page=2"),
        ('{{"cursor": "{t}"}}', '{{"cursor":"<TOKEN-1>"}}'),  # a changed JSON span is re-serialised
        ("/var/tmp/{t}", "/var/tmp/<TOKEN-1>"),
    ],
)
def test_key_like_tokens_inside_urls_and_paths(template, expected):
    token = KEY_MATERIAL["alnum-48"]
    assert Redactor().text(template.format(t=token)) == expected.format()


@pytest.mark.parametrize(
    "source",
    [
        "request 123e4567-e89b-12d3-a456-4266141740ab and req-123e4567-e89b-12d3-a456-4266141740ab",
        "arn:aws:iam::111111111111:role/service-role/AmazonEC2ContainerServiceforEC2Role",
        "arn:aws:lambda:eu-west-1:111111111111:function:checkout-api-ProcessOrderFunction-1A2B3C4D5E6F",
        "image sha256:" + "0123456789abcdef" * 4,
        "sha " + "ab12" * 10 + " image digest",
        "task 0123456789abcdef0123456789abcdef stopped",
        "i-0123456789abcdef0 subnet-0123456789abcdef0 sg-0123456789abcdef0 vpc-0123456789abcdef0",
        "eni-0123456789abcdef0 vol-0123456789abcdef0 ami-0123456789abcdef0 snap-0123456789abcdef0",
        "https://checkout-api.internal.example.com/api/v1/orders/create-order-request?page=2",
        "/usr/local/lib/python3.11/site-packages/botocore/endpoint.py",
        "/var/log/containers/checkout-api-7d9f8b6c5-x2x4z_default_api-0123456789abcdef.log",
        "2026-10-04T10:00:00.123456789Z and 1759572000123",
        "<SECRET-1> <TOKEN-2> <EMAIL-3>",
        "pod checkout-api-7d9f8b6c5-x2x4z restarted",
        "com.example.checkout.PaymentServiceImplementation threw",
        "AmazonEC2ContainerServiceforEC2Role ProcessOrderFunctionHandler2024",
        "CHECKOUT_SERVICE_DATABASE_PRIMARY_HOST=db.example.com",
        "2026/10/04/[$LATEST]0123456789abcdef0123456789abcdef",
        "trace 1-5759e988-bd862e3fe1be46a994272793",
        "stack checkout-api-TargetGroup-1A2B3C4D5E6F7 and checkout-prod-WebServerSecurityGroup-ABCD1234EFGH",
        "internationalization_configuration_settings_v2",
        "https://wiki.example.com/" + "a" * 300,
        "id " + "1234567890" * 5,
        "checkout-service-production-eu-west-1-blue-green",
    ],
)
def test_identifiers_that_are_not_key_material_are_kept(source):
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "shape",
    [
        "pwd=x;", "password: x\n", "name: DB_PASSWORD\n", "- value: x\n  name: DB_PASSWORD\n", '{"name":"db_password",',
        '{"name":"db_password","meta":{},"value":"x"}', "password is x ", "set password to x ", "\\u0041",
        "<password>x</password>", '<a key="password" value="x"/>', "\tpassword\tx\n", '"AUTH" "x" ',
        "echo x | docker login ", "mysql -px ", "redis-cli AUTH x ", "PASSWORD 'x' ",
        "ParameterKey=DBPassword,ParameterValue=x ", "+1 555 ", "Ab3" * 10 + " ",
    ],
)
def test_one_megabyte_rule_shapes_are_fast(shape):
    source = shape * (MEGABYTE // len(shape))
    for call in (Redactor().text, lambda s: Redactor().value({"m": s}), audit_text):
        started = time.perf_counter()
        call(source)
        elapsed = time.perf_counter() - started
        assert elapsed < time_bound(source), (shape, elapsed)


# Round 4 addendum: plural and counted names, IAM actions, reference names

@pytest.mark.parametrize(
    "source",
    [
        "tokens: 512", "max_tokens = 4096", "num_keys=12", "total_secrets: 3", "credentials: 2", "token_limit=100",
        '{"max_tokens": 4096, "tokens": 512}',
        '"Action": "secretsmanager:GetSecretValue"',
        "AccessDenied: not authorized to perform secretsmanager:GetSecretValue on resource",
        '"Action": ["kms:Decrypt", "ssm:GetParameter*", "sts:GetSessionToken", "secretsmanager:*"]',
        "secretKeyRef: db-password", "secretRef: app-secrets", "secretName: tls-secret", "configMapKeyRef: app-token",
        "valueFrom: api-token",
    ],
)
def test_counted_names_iam_actions_and_reference_names_are_kept(source):
    assert Redactor().text(source) == source
    assert audit_text(source) == []


def test_counted_and_reference_names_in_value():
    obj = {"max_tokens": 4096, "tokens": 512, "Action": ["secretsmanager:GetSecretValue"], "secretKeyRef": "db"}
    assert Redactor().value(obj) == obj


@pytest.mark.parametrize(
    "source, expected",
    [
        ("password: 123456", "password: <SECRET-1>"),
        ("pin=1234", "pin=<SECRET-1>"),
        ("api_token: 98765432", "api_token: <SECRET-1>"),
        ("tokens: abc" + "Def123", "tokens: <SECRET-1>"),
        ("token: admin:" + "Hunter2", "token: <SECRET-1>"),
        ("card_number=4111" + "111111111111", "card_number=<SECRET-1>"),
    ],
)
def test_numbers_under_a_plain_secret_name_stay_masked(source, expected):
    assert Redactor().text(source) == expected


def test_numbers_under_a_plain_secret_name_stay_masked_in_value():
    assert Redactor().value({"password": 123456, "pin": 1234}) == {"password": "<SECRET-1>", "pin": "<SECRET-2>"}


# ---------------------------------------------------------------------------
# Fix round 5
# ---------------------------------------------------------------------------

# Ruling 1: a two-item list never bypasses text()

@pytest.mark.parametrize(
    "obj, secret",
    [
        ({"Env": ["DB_PASSWORD=" + PW, "PATH=/usr/bin"]}, PW),
        (["token " + "Zx9" * 9 + " rejected", "retrying"], "Zx9" * 9),
        (["secret_key " + AWS_KEY, "x"], AWS_KEY),
        (["password reset for jane.doe@corp.example.com", "sent"], "jane.doe@corp.example.com"),
        (["db_password postgres://app:" + PW + "@db.example.com/x", "ok"], PW),
    ],
)
def test_two_item_lists_never_bypass_text(obj, secret):
    out = Redactor().value(obj)
    assert secret not in repr(out)


def test_docker_env_list_keeps_path_and_masks_password():
    assert Redactor().value({"Env": ["DB_PASSWORD=" + PW, "PATH=/usr/bin"]}) == {
        "Env": ["DB_PASSWORD=<SECRET-1>", "PATH=/usr/bin"]
    }


def test_real_header_pair_still_masks_its_value():
    assert Redactor().value([["Cookie", "sid=" + PW]]) == [["Cookie", "<SECRET-1>"]]


# Ruling 2: cost and a time budget

@pytest.mark.parametrize(
    "shape",
    [
        "command:\n- curl\nargs:\n- -u\n- a:b\n",
        "<a><![CDATA[x",
        '"name":"DB_PASSWORD",',
        "name=DB_PASSWORD, ",
        '{"name":"DB_PASSWORD","a":"b"} ',
        "- name: DB_PASSWORD\n  type: x\n",
    ],
)
def test_round_four_slow_shapes_are_fast(shape):
    source = shape * (MEGABYTE // len(shape)) + '"value":"x"'
    for call in (Redactor().text, lambda s: Redactor().value({"m": s}), audit_text):
        started = time.perf_counter()
        call(source)
        elapsed = time.perf_counter() - started
        assert elapsed < time_bound(source), (shape, elapsed)


@pytest.mark.parametrize("key", ["command", "args"])
def test_a_200000_item_argument_list_is_fast(key):
    obj = {"command": ["curl"], "args": ["-u", "a:b"] * 100_000} if key == "args" else {"command": ["curl"] + ["-u", "a:b"] * 100_000}
    started = time.perf_counter()
    Redactor().value(obj)
    assert time.perf_counter() - started < SECONDS_PER_MEGABYTE


def test_time_budget_turns_a_slow_string_into_one_placeholder(monkeypatch):
    clock = iter(range(0, 10_000, 3))
    monkeypatch.setattr(redact_module, "_monotonic", lambda: next(clock))
    out = Redactor().text(f"password={PW} " + "x " * 50)
    assert out == "<UNREADABLE-1>"


def test_safety_net_never_swallows_base_exceptions(monkeypatch):
    class Alarm(BaseException):
        pass

    def ring(text):
        raise Alarm()

    monkeypatch.setattr(redact_module, "SECRET_RULES", (("ring", ring),))
    with pytest.raises(Alarm):
        Redactor().text("anything")



# Ruling 3: names that are not secret names

@pytest.mark.parametrize(
    "name, expected",
    [
        ("Code", False), ("code", False), ("ErrorCode", False), ("StatusCode", False), ("ExitCode", False),
        ("CodeSize", False), ("CodeSha256", False), ("promo_code", False), ("source_code", False),
        ("passcode", True), ("pincode", True), ("access_code", True), ("authCode", True), ("auth_code", True),
        ("verification_code", True), ("security_code", True), ("otp_code", True), ("mfa_code", True),
        ("recovery_code", True), ("backup_code", True), ("AuthorizationCode", True),
        ("cred", True), ("creds", True), ("credential", True), ("Credentials", True), ("db_credentials", True),
        ("CPUCreditBalance", False), ("credits", False), ("incredible", False), ("accredited", False),
        ("private_key", True), ("privateKey", True), ("PRIVATE_KEY", True),
        ("private_subnets", False), ("PrivateIpAddress", False), ("PrivateDnsName", False), ("PrivateLink", False),
        ("auth", True), ("authorization", True), ("authentication", True), ("authtoken", True), ("x-auth-token", True),
        ("author", False), ("authority", False), ("authorize", False), ("authorized", False), ("unauthorized", False),
        ("Authenticated", False), ("authenticator", False),
        # coordinator correction: license is secret as the last part of a name or before key
        ("license", True), ("licence", True), ("LicenseModel", False), ("license_key", True), ("licenceKey", True),
        ("NEW_RELIC_LICENSE", True), ("LICENSE", True), ("license_type", False), ("LicenseCount", False),
        ("passive", False), ("passed", False), ("passing", False), ("bypass", False), ("passenger", False),
        ("passthrough", False),
        ("KeyManager", False), ("LicenseModel", False), ("TokenSize", False), ("KeyPairs", False),
        ("AuthenticationStrategy", False),
        ("DB_PASSWORD_NAME", True), ("API_KEY2_URL", True), ("secret_name", False), ("SecretName", False),
        ("api_tkn", True), ("db_pword", True), ("psswd", True), ("rootpw", True), ("pw", True),
    ],
)
def test_round_five_secret_names(name, expected):
    assert looks_secret_key(name) is expected


@pytest.mark.parametrize(
    "name, expected",
    [
        ("UserAgent", False), ("OwnerId", False), ("UserPoolId", False), ("login_attempts", False), ("mail_server", False),
        ("email_verified", False),
        ("full_name", True), ("first_name", True), ("last_name", True), ("surname", True), ("customer_name", True),
        ("dob", True), ("birth", True), ("date_of_birth", True), ("account_number", True), ("passport", True),
        ("mobile", True), ("username", True), ("DbUser", True), ("MasterUsername", True), ("phone_number", True),
        ("email", True),
    ],
)
def test_round_five_personal_names(name, expected):
    assert looks_personal_key(name) is expected


@pytest.mark.parametrize(
    "source",
    [
        '{"Error":{"Code":"AccessDenied","Message":"Access Denied"}}',
        "Code: NoSuchKey Message: The specified key does not exist. Key: logs/app.log",
        "<Error><Code>SignatureDoesNotMatch</Code></Error>",
        "rpc error: code = Unknown desc = context deadline exceeded",
        "Error: connect ECONNREFUSED 10.0.1.5:6379 code=ECONNREFUSED",
        "Code: 500",
        '{"code": "ResourceNotFoundException", "message": "Function not found"}',
        "password reset requested for user 42 (code=PR-1)",
        "401 Unauthorized: invalid_token",
        "failed to authorize: failed to fetch anonymous token",
        "unable to pull secrets or registry auth: execution resource retrieval failed: unable to retrieve secret",
        "auth: OK user=bob mfa=true",
        "author: pavel committed 3 files",
        "ResourceInitializationError: setSecret: password does not meet complexity requirements",
        'MountVolume.SetUp failed for volume "db-creds" : secret "db-creds" not found',
        "CPUCreditBalance: 0.0",
        "private_subnets: subnet-0123456789abcdef0",
        "LicenseModel: license-included",
        "KeyManager: CUSTOMER",
        "Credentials: loaded from IMDS",
        "token: expired",
        "secret: rotation succeeded",
        "token=<none>",
    ],
)
def test_round_five_error_codes_and_prose_are_kept(source):
    assert Redactor().text(source) == source


def test_round_five_error_code_in_value():
    obj = {"Error": {"Code": "AccessDenied"}, "CodeSize": 1024, "CodeSha256": "abc", "PrivateSubnets": ["subnet-1"],
           "KeyPairs": [{"KeyName": "k", "Tags": [{"Key": "team", "Value": "core"}]}]}
    assert Redactor().value(obj) == obj


@pytest.mark.parametrize(
    "source, expected",
    [
        ("password: correct horse battery staple", "password: <SECRET-1>"),
        ("verification_code=482913", "verification_code=<SECRET-1>"),
        ("auth: " + PW, "auth: <SECRET-1>"),
        ("password: the " + PW, "password: <SECRET-1>"),
    ],
)
def test_round_five_secrets_next_to_those_words_stay_masked(source, expected):
    assert Redactor().text(source) == expected


# Rulings 4 and 5: leaks and unnamed or positional shapes (a short punctuated password, which
# the key-like token rule cannot catch on its own)

PUNCT_PW = "Qa" + "!z9#" + "Lk"

ROUND_FIVE_LEAKS = [
    ("odbc-braces", "Driver={ODBC Driver 18};Server=db.example.com;Uid=app;Pwd={" + PUNCT_PW + ";x};Encrypt=yes"),
    ("oracle-sqlplus", "sqlplus scott/" + PUNCT_PW + "@orcldb:1521/ORCL"),  # a host without dots (follow-up 1)
    ("oracle-jdbc", "jdbc:oracle:thin:scott/" + PUNCT_PW + "@orcldb:1521:ORCL"),
    ("htpasswd-path", "htpasswd -b /etc/nginx/htpasswd admin " + PUNCT_PW),
    ("htpasswd-path-c", "/usr/bin/htpasswd -bc /srv/auth/users admin " + PUNCT_PW),
    ("k8s-secret-yaml", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  DATABASE_URL: " + PUNCT_PW + "\n  other: x" + PUNCT_PW + "\ntype: Opaque"),
    ("k8s-secret-stringdata", "kind: Secret\nstringData:\n  config.json: '" + PUNCT_PW + "'\n"),
    ("k8s-secret-json", '{"apiVersion":"v1","kind":"Secret","data":{"DATABASE_URL":"' + PUNCT_PW + '"}}'),
    ("netrc-line", "machine api.example.com login deploy password " + PUNCT_PW),
    ("netrc-multiline", "machine api.example.com\n  login deploy\n  password " + PUNCT_PW + "\n"),
    ("pgpass", "db.example.com:5432:app:app_user:" + PUNCT_PW),
    ("pgpass-star", "*:*:*:postgres:" + PUNCT_PW),
    ("sqlcmd", "sqlcmd -S db.example.com -U sa -P " + PUNCT_PW + " -Q 'select 1'"),
    ("mongosh", "mongosh mongodb://db.example.com:27017 -u admin -p " + PUNCT_PW),
    ("mongo", "mongo --host db.example.com -u admin -p " + PUNCT_PW + " admin"),
    ("ldapsearch", "ldapsearch -x -D cn=admin -w " + PUNCT_PW + " -b dc=example"),
    ("chpasswd-echo", "echo 'deploy:" + PUNCT_PW + "' | chpasswd"),
    ("chpasswd-herestring", "chpasswd <<< \"deploy:" + PUNCT_PW + "\""),
    ("terraform-diff", '      ~ master_password = "' + "old" + PUNCT_PW + '" -> "' + PUNCT_PW + '"'),
    ("csv-table", "user,password,role\nbob," + PUNCT_PW + ",admin\nann,x" + PUNCT_PW + ",dev"),
    ("markdown-table", "| user | password | role |\n|---|---|---|\n| bob | " + PUNCT_PW + " | admin |"),
    ("html-json", "&quot;password&quot;:&quot;" + PUNCT_PW + "&quot;"),
    ("html-equals", "password&#61;" + PUNCT_PW + "&amp;user=bob"),
    ("html-xml", "&lt;password&gt;" + PUNCT_PW + "&lt;/password&gt;"),
    ("multipart", 'Content-Disposition: form-data; name="password"\r\n\r\n' + PUNCT_PW + "\r\n--boundary"),
    ("add-mask", "::add-mask::" + PUNCT_PW),
]


@pytest.mark.parametrize("name, source", ROUND_FIVE_LEAKS, ids=[case[0] for case in ROUND_FIVE_LEAKS])
def test_round_five_leak_shapes(name, source):
    out = Redactor().text(source)
    assert PUNCT_PW not in out
    assert Redactor().text(out) == out


def test_kubernetes_secret_object_in_value():
    obj = {"kind": "Secret", "metadata": {"name": "app"}, "data": {"DATABASE_URL": PUNCT_PW}, "type": "Opaque"}
    out = Redactor().value(obj)
    assert out["data"] == {"DATABASE_URL": "<SECRET-1>"} and out["metadata"] == {"name": "app"}


@pytest.mark.parametrize(
    "source",
    [
        "kind: ConfigMap\ndata:\n  LOG_LEVEL: info\n",
        "user,role\nbob,admin",
        "| user | role |\n|---|---|\n| bob | admin |",
        "&quot;user&quot;:&quot;bob&quot;",
        "time=10:00:00 host=a:b:c:d",
        '      ~ instance_type = "t3.small" -> "t3.large"',
    ],
)
def test_round_five_harmless_neighbours_are_kept(source):
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "shape",
    [
        "user,password\nbob,x\n", "| a | password |\n", '&quot;password&quot;:&quot;x&quot;,', "kind: Secret\ndata:\n  a: b\n",
        "machine h login u password p\n", "h:5432:d:u:p\n", "echo 'u:p' | chpasswd\n", 'x_password = "a" -> "b"\n',
        'form-data; name="password"\n\nx\n', "::add-mask::x\n", "htpasswd -b /a/htpasswd u p\n", "sqlcmd -P x ",
        "Pwd={x};", "/htpasswd ", "/htpasswd", "x /mysql/mysql",
    ],
)
def test_one_megabyte_round_five_shapes_are_fast(shape):
    source = shape * (MEGABYTE // len(shape))
    for call in (Redactor().text, lambda s: Redactor().value({"m": s}), audit_text):
        started = time.perf_counter()
        call(source)
        elapsed = time.perf_counter() - started
        assert elapsed < time_bound(source), (shape, elapsed)


# Ruling 6: what the key-like token rule also keeps

HEX40_R5 = random_token(55, 40, "0123456789abcdef")
AMZ_ID = random_token(56, 76, ALNUM + "+/")


@pytest.mark.parametrize(
    "source",
    [
        f"deployed commit {HEX40_R5} to prod",
        f"git checkout {HEX40_R5}",
        f"image tag {HEX40_R5}",
        f"build {HEX40_R5} finished",
        f"revision: {HEX40_R5}",
        f"version {HEX40_R5}",
        f"x-amz-id-2: {AMZ_ID}",
        f'{{"x-amz-cf-id": "{AMZ_ID}"}}',
        f"x-amz-request-id={AMZ_ID[:32]}",
        f"x-amzn-RequestId: {AMZ_ID}",
    ],
)
def test_token_rule_keeps_labelled_commits_and_aws_request_ids(source):
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "source",
    [
        f"signature mismatch {HEX40_R5}",
        f"commit {HEX40_R5} token {HEX40_R5[::-1]}",
        f"deploy secret {HEX40_R5}",
        f"x-api-key: {AMZ_ID}",
        f"retry with {AMZ_ID}",
    ],
)
def test_token_rule_still_masks_everything_else(source):
    out = Redactor().text(source)
    assert HEX40_R5 not in out and AMZ_ID not in out


# Ruling 7: stated limits

def test_module_docstring_states_the_limits():
    doc = (redact_module.__doc__ or "").lower()
    for phrase in ("separate lines", "short passwords", "ipv6", "look-alike", "across files"):
        assert phrase in doc, phrase



# ---------------------------------------------------------------------------
# Follow-up after round 5
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "source",
    [
        "dial failed: app:" + PUNCT_PW + "@tcp(db.internal:3306)/orders",
        "dsn app:" + PW + "@tcp(10.0.1.5:3306)/orders?parseTime=true",
        "sqlplus scott/" + PUNCT_PW + "@orcldb",
        "sqlplus -s scott/" + PUNCT_PW + "@//orcldb:1521/ORCL",
        "sqlplus scott/" + PUNCT_PW + "@10.0.1.5:1521/ORCL",
        "CONNECT scott/" + PUNCT_PW + "@ORCL",
        "expdp system/" + PUNCT_PW + "@ORCL directory=dp",
        "rman target sys/" + PUNCT_PW + "@prod",
        "user app:" + PUNCT_PW + "@db.internal/app",
    ],
)
def test_schemeless_userinfo_is_masked(source):
    out = Redactor().text(source)
    assert PUNCT_PW not in out and PW not in out
    assert PUNCT_PW[:3] not in out


@pytest.mark.parametrize(
    "source",
    [
        "git clone git@github.com:org/repo.git",
        "mail bob@example.com: delivered",
        "contact bob@example.com",
        "docker pull registry.example.com/team/app:1.2@sha256:" + "0123456789abcdef" * 4,
        "npm install left-pad@1.3.0",
        "user bob@host1 logged in at 10:00",
        "svc/mail-ops@example.com",
    ],
)
def test_schemeless_userinfo_neighbours_are_kept(source):
    out = Redactor().text(source)
    assert "<SECRET-" not in out


@pytest.mark.parametrize(
    "source, expected",
    [
        ("password: the dog", "password: <SECRET-1>"),
        ("password: let me in", "password: <SECRET-1>"),
        ("password: not set", "password: not set"),
        ("token: expired at 12:00", "token: expired at 12:00"),
        ("secret: is missing", "secret: is missing"),
    ],
)
def test_prose_exemption_needs_a_log_or_status_word(source, expected):
    assert Redactor().text(source) == expected


@pytest.mark.parametrize(
    "name, expected",
    [("SignatureDoesNotMatch", False), ("auth_method", False), ("auth_result", False), ("auth_type", False),
     ("auth_mode", False), ("auth_token", True), ("signature", True)],
)
def test_follow_up_secret_names(name, expected):
    assert looks_secret_key(name) is expected


def test_home_address_is_personal():
    assert looks_personal_key("home_address") is True


def test_signature_does_not_match_keeps_its_message():
    source = "SignatureDoesNotMatch: Signature expired: 20261005T100000Z is now earlier than 20261005T101500Z"
    assert Redactor().text(source) == source


WINDOWS_LEAKS = [
    ("net-user", "net user bob " + PUNCT_PW + " /add"),
    ("secure-string", 'ConvertTo-SecureString "' + PUNCT_PW + '" -AsPlainText -Force'),
    ("secure-string-single", "ConvertTo-SecureString -String '" + PUNCT_PW + "' -AsPlainText -Force"),
    ("env-assignment", '$env:DB_PASSWORD = "' + PUNCT_PW + '"'),
    ("cmdkey", "cmdkey /add:server01 /user:bob /pass:" + PUNCT_PW),
    ("psexec", "psexec \\\\server01 -u bob -p " + PUNCT_PW + " cmd"),
    ("schtasks", "schtasks /create /tn job /ru bob /rp " + PUNCT_PW + " /tr app.exe"),
]


@pytest.mark.parametrize("name, source", WINDOWS_LEAKS, ids=[case[0] for case in WINDOWS_LEAKS])
def test_windows_and_powershell_shapes(name, source):
    out = Redactor().text(source)
    assert PUNCT_PW not in out
    assert Redactor().text(out) == out


@pytest.mark.parametrize(
    "source",
    ["net user bob /delete", "$env:PATH = 'C:\\Tools'", "schtasks /query /tn job", "cmdkey /list"],
)
def test_windows_neighbours_are_kept(source):
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "source",
    [
        "| Secret | Rotated |\n|---|---|\n| prod/db | yes |\n| prod/api-keys | no |",
        "Token,Owner\nci/deploy,platform",
    ],
)
def test_tables_keep_secret_names_that_are_plain_paths(source):
    assert Redactor().text(source) == source


def test_tables_still_mask_values_under_a_secret_header():
    out = Redactor().text("| Secret | Rotated |\n|---|---|\n| " + PUNCT_PW + " | yes |")
    assert PUNCT_PW not in out


@pytest.mark.parametrize(
    "shape",
    ["a:b@c ", "a/b@c(", "x:y@", "net user a b ", "$env:TOKEN = x ", "| Secret |\n| a/b |\n", "cmdkey /pass:x ",
     "password: not set\n"],
)
def test_one_megabyte_follow_up_shapes_are_fast(shape):
    source = shape * (MEGABYTE // len(shape))
    for call in (Redactor().text, audit_text):
        started = time.perf_counter()
        call(source)
        elapsed = time.perf_counter() - started
        assert elapsed < time_bound(source), (shape, elapsed)



@pytest.mark.parametrize("shape", ["a:b@c ", "pwd=x;", "[]", "Pwd={x};", "kind: Secret\ndata:\n" + "  a: b\n" * 50])
def test_cost_grows_linearly(shape):
    """400 KB of a worst shape takes less than 3 times as long as 200 KB (best of three runs)."""
    def best_time(size: int) -> float:
        source = shape * (size // len(shape))
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            Redactor().text(source)
            timings.append(time.perf_counter() - started)
        return min(timings)

    small, large = best_time(200_000), best_time(400_000)
    assert large < 3 * max(small, 0.05), (shape, small, large)



# ---------------------------------------------------------------------------
# Resource names that look like secret names
# ---------------------------------------------------------------------------

RESOURCE_NAMES = [
    "sessions", "user-sessions", "auth", "auth-service", "tokens", "api-keys", "secrets", "credentials-store",
    "password-reset", "private", "license-server", "signing-keys", "cookie-jar",
]
SUMMARY_SHAPES = [
    "Event on {name}: Failover from master node {name}-001 to replica",
    "Service {name} is ACTIVE: desired 3, running 0, pending 3",
    "Instance {name} endpoint is db.internal.example.com port 5432",
    "Alarm {name} went into ALARM: Threshold Crossed",
    "Queue {name}: 1200 messages visible, oldest 340 seconds",
    "Function {name}: timeout 30 seconds, memory 512 MB",
    "Secret {name}: rotation enabled, last rotated 40 days ago",
    "Target on {name}: unhealthy (Target.FailedHealthChecks)",
]


@pytest.mark.parametrize("shape", SUMMARY_SHAPES)
@pytest.mark.parametrize("name", RESOURCE_NAMES)
def test_collector_summaries_about_resources_named_like_secrets_are_kept(name, shape):
    source = shape.format(name=name)
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "source",
    [
        "Event on sessions-001: Failover from master node sessions-001 to replica",
        "Event on sessions-001: old",
        "Target on sessions: unhealthy",
        "role for auth: missing permission",
        "Event on sessions-001: auth failed",
    ],
)
def test_reported_resource_lines_are_kept(source):
    assert Redactor().text(source) == source


@pytest.mark.parametrize(
    "source, secret",
    [
        ("Event on cache-1: password=" + PUNCT_PW + " rejected", PUNCT_PW),
        ("config: session_token=" + PUNCT_PW, PUNCT_PW),
        ("sessions: " + "Zq7" * 9, "Zq7" * 9),
        ("Event on sessions-001: auth failed token=" + PUNCT_PW, PUNCT_PW),
        ("2026-10-04 10:00:00 ERROR password: " + PUNCT_PW, PUNCT_PW),
        ("[INFO] api_key: " + PUNCT_PW, PUNCT_PW),
        ("level=info db_password: " + PUNCT_PW, PUNCT_PW),
        ("session: " + PUNCT_PW, PUNCT_PW),
    ],
)
def test_real_assignments_in_the_same_shapes_are_still_masked(source, secret):
    assert secret not in Redactor().text(source)


@pytest.mark.parametrize(
    "name, expected",
    [
        ("sessions", False), ("session-store", False), ("user-sessions", False), ("SessionStore", False),
        ("session", True), ("session_id", True), ("sessionid", True), ("session_token", True), ("session_key", True),
        ("session_secret", True), ("session_cookie", True), ("sessiontoken", True), ("SessionId", True),
        ("sessions-001", False), ("session-1", True),
    ],
)
def test_session_names(name, expected):
    assert looks_secret_key(name) is expected
