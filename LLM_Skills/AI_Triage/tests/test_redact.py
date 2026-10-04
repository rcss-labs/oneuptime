import copy

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
    assert out == '{"Authorization": "Bearer <SECRET-1>"}'


def test_rule4_equals_form():
    out = Redactor().text(f"start db_password={PASSWORD} port=5432")
    assert out == "start db_password=<SECRET-1> port=5432"


def test_rule4_colon_form():
    out = Redactor().text(f"api_key: {TOKEN}\nname: web")
    assert out == "api_key: <SECRET-1>\nname: web"


def test_rule4_json_form_keeps_quotes():
    out = Redactor().text('{"clientSecret": "' + PASSWORD + '", "region": "eu-west-1"}')
    assert out == '{"clientSecret": "<SECRET-1>", "region": "eu-west-1"}'


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
    ("camel-access-key", '{"accessKey": "' + PW + '"}', '{"accessKey": "<SECRET-1>"}'),
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
    obj = {"password": [PW], "secrets": {"x": PW}, "api_keys": [PW], "pin": {"password": {"n": 1234}}}
    out = Redactor().value(obj)
    assert out == {
        "password": ["<SECRET-1>"],
        "secrets": {"x": "<SECRET-1>"},
        "api_keys": ["<SECRET-1>"],
        "pin": {"password": {"n": "<SECRET-2>"}},
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
