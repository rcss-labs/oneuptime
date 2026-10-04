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
    text = 'region=eu-west-1 monkey=1 {"name": "web", "keyboard": "us"} key=abc'
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
        "author=bob authority: ca tokenizer=bert max_tokens=4096 auth_type=iam",
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
        ("author", False), ("tokenizer", False), ("max_tokens", False), ("partition_key", False),
        ("s3_key", False), ("sort_key", False), ("KeyName", False), ("kms_key_id", False),
        ("SecretArn", False), ("SecretStatus", False), ("AuthorizationType", False),
        ("token_expiry", False), ("secret_name", False), ("monkey", False), ("region", False),
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
    out = Redactor().text("error: auth_token: field required (type=value_error.missing)")
    assert out == "error: auth_token: <SECRET-1> (type=value_error.missing)"
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
    assert text_seconds < 2, f"text() took {text_seconds:.2f}s"
    assert audit_seconds < 2, f"audit_text() took {audit_seconds:.2f}s"


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
        assert time.perf_counter() - started < 2


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
    assert Redactor().text(f"CREDS=admin:{PW} ok") == "CREDS=<SECRET-1> ok"


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
    assert text_seconds < 2 and audit_seconds < 2, (text_seconds, audit_seconds)
