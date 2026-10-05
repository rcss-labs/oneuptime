import pytest

from helpers import make_context
from triage.collectors.common import (
    env_changes,
    env_summary,
    shown_env_value,
    split_csv,
    was_not_found,
)

HIDDEN = "<hidden: {} characters>"


def hidden(text):
    return HIDDEN.format(len(text))


def shown(value, name="X"):
    return shown_env_value(name, value)


# rule c: shown under any name

def test_dsn_keeps_only_scheme_and_host():
    dsn = "https://" + "a1b2" * 8 + "@o1.ingest.example.com/12345"
    assert shown(dsn) == "https://o1.ingest.example.com"


def test_webhook_secret_path_is_dropped():
    url = "https://hooks.example.com/services/" + "T0/B0/" + "x" * 24
    assert shown(url) == "https://hooks.example.com"


def test_database_url_password_is_dropped_and_port_kept():
    url = "postgres://app:" + "pw" + "7" * 8 + "@db.example.com:5432/orders?sslmode=require"
    assert shown(url) == "postgres://db.example.com:5432"


def test_query_and_fragment_are_dropped():
    assert shown("https://api.example.com/v1?key=" + "k" * 10 + "#frag") == "https://api.example.com"


@pytest.mark.parametrize("text", ["db.example.com", "db.example.com:5432", "cache-1.internal.example.com", "10.0.0.5", "10.0.0.5:6379"])
def test_dotted_hosts_and_ipv4_are_shown_under_any_name(text):
    assert shown(text) == text


@pytest.mark.parametrize("text", ["eu-west-1", "us-east-2", "ap-southeast-1", "true", "False", "TRUE"])
def test_regions_and_booleans_are_shown_under_any_name(text):
    assert shown(text) == text


def test_python_values():
    assert shown(True) == "true"
    assert shown(False) == "false"
    assert shown(42) == hidden("42")
    assert shown(42, "PORT") == "42"
    assert shown(1.5, "SAMPLE_LIMIT") == "1.5"


def test_ip_address_url_is_kept():
    assert shown("http://10.0.0.5:8080/health") == "http://10.0.0.5:8080"


def test_url_userinfo_is_dropped_but_host_and_port_kept():
    assert shown("amqp://guest:guest@mq.example.com:5672/vhost") == "amqp://mq.example.com:5672"


def test_ipv6_url():
    assert shown("https://[2001:db8::1]:8443/x") == "https://[2001:db8::1]:8443"


# values that must be hidden under innocent names

@pytest.mark.parametrize("name", ["X", "VALUE", "DATA", "MISC"])
@pytest.mark.parametrize(
    "value",
    ["huntertwo", "Summer2024", "482913", "Zx9Qw3Zx9Qw3Zx9", "a1b2c3d4e5f6a7b", "dGhpc2lzYXNlY3Jl", "Abc123", "info", "8080", "30s", "redis:6379", "http://api:8080", "/etc/app", ""],
)
def test_plain_looking_values_are_hidden_under_innocent_names(name, value):
    assert shown(value, name) == hidden(value)


def test_long_random_string_is_hidden():
    value = "Zx9" + "Qw3" * 10
    assert shown(value, "LOG_LEVEL") == hidden(value)


def test_non_scalar_is_hidden():
    assert shown(None).startswith("<hidden")
    assert shown({"a": 1}).startswith("<hidden")


@pytest.mark.parametrize(
    "value",
    [
        "postgres://jane.smith:4821#kq9Z@db.example.com/app",
        "postgres://jane.smith:4821?kq9Z@db.example.com/app",
        "postgres://jane.smith:48/21kq9Z@db.example.com/app",
        "postgres://user:pa#ss@db.example.com/app",
        "redis://default:#abc@host",
        "https://example.com/path@secret",
        "https://example.com?next=a@b",
        "https://exa mple.com/x",
        "https://host_name.example.com/x",
        "https://host.example.com:99999/x",
        "https://host.example.com:/x",
    ],
)
def test_urls_with_an_at_sign_after_the_authority_or_odd_authority_are_hidden(value):
    assert shown(value, "API_URL") == hidden(value)


def test_port_range():
    assert shown("db.example.com:65535") == "db.example.com:65535"
    assert shown("db.example.com:65536") == hidden("db.example.com:65536")
    assert shown("db.example.com:0123456") == hidden("db.example.com:0123456")


def test_overlong_dotted_string_is_hidden():
    value = ".".join(["a" * 500] * 4) + ".com"
    assert shown(value) == hidden(value)
    assert shown(("a" * 64) + ".example.com").startswith("<hidden")
    assert shown(("a" * 63) + ".example.com").startswith("a")


def test_host_without_a_letter_in_the_last_label_is_hidden():
    value = "service.internal.example.123"
    assert shown(value) == hidden(value)


def test_bracketed_host_must_be_an_ipv6_address():
    assert shown("[" + "ab" * 20 + "]") == hidden("[" + "ab" * 20 + "]")
    url = "https://u:p@[" + "ab" * 20 + "]/x"
    assert shown(url) == hidden(url)
    assert shown("https://[::1]/x") == "https://[::1]"


def test_scheme_must_be_on_the_list():
    value = "a1b2c3d4e5f6a7b8c9d0://host.example.com"
    assert shown(value) == hidden(value)
    for scheme in ("HTTPS", "mongodb+srv", "postgresql", "grpcs", "sftp"):
        assert shown(f"{scheme}://host.example.com/x") == f"{scheme}://host.example.com"
    assert shown("git+ssh://git.example.com/repo").startswith("<hidden")


def test_label_with_leading_or_trailing_dash_is_hidden():
    assert shown("-bad-.example.com").startswith("<hidden")
    assert shown("bad-.example.com").startswith("<hidden")
    assert shown("good-one.example.com") == "good-one.example.com"


# rule d: shown under setting-like names

@pytest.mark.parametrize(
    "name, value",
    [
        ("LOG_LEVEL", "debug"),
        ("LOG_LEVEL", "INFO"),
        ("PORT", "8080"),
        ("DB_HOST", "redis:6379"),
        ("DB_HOST", "localhost:5432"),
        ("API_URL", "http://api:8080"),
        ("TIMEOUT", "30s"),
        ("TIMEOUT", "500ms"),
        ("INTERVAL", "1h"),
        ("SAMPLE_RATE_LIMIT", "0.5"),
        ("STAGE", "prod"),
        ("APP_VERSION", "v2"),
        ("CONFIG_PATH", "/etc/app/config"),
        ("TOPIC_ARN", "arn:aws:sns:eu-west-1:111111111111:alerts"),
        ("WORKERS", "12"),
        ("logLevel", "warn"),
    ],
)
def test_setting_values_are_shown_under_setting_names(name, value):
    assert shown(value, name) == value


def test_setting_name_does_not_show_a_secret_shaped_value():
    value = "a3f9c0de" * 4
    assert shown(value, "LOG_LEVEL") == hidden(value)
    assert shown("Zx9Qw3Zx9Qw3Zx9Q", "STAGE").startswith("<hidden")


@pytest.mark.parametrize("name", ["DB_PASSWORD_HOST", "USER_NAME", "LOGIN", "OWNER", "EMAIL_HOST", "USERNAME"])
def test_secret_and_personal_words_beat_setting_words(name):
    assert shown("localhost", name) == hidden("localhost")
    assert shown("db.example.com", name) == hidden("db.example.com")


@pytest.mark.parametrize("name", ["SALT", "DB_PW", "PIN", "PASSWORD_HASH", "CREDS", "NEW_RELIC_LICENSE", "OTP_SEED",
                                  "JWT", "PRIVATE", "SENTRY_DSN", "HMAC", "TLS_CERT", "dbPw",
                                  "PASSCODE", "CODE", "OTP", "MFA", "PEPPER", "NONCE", "API_KEY"])
def test_secret_looking_name_components_always_hide(name):
    assert env_summary([(name, "info")]) == {name: hidden("info")}
    assert env_summary([(name, "db.example.com")]) == {name: hidden("db.example.com")}


# The redactor does not read these as secret names (one source for name checks, ruling 1), so only the
# value type decides: a word stays hidden, a three-label host is shown (rule 4), and MAX_CONN-style counts are numbers.
@pytest.mark.parametrize("name", ["SIGNING", "CONN", "KEY", "PINCODE"])
def test_names_the_redactor_does_not_flag_are_decided_by_value_type(name):
    assert env_summary([(name, "info")]) == {name: hidden("info")}
    assert env_summary([(name, "db.example.com")]) == {name: "db.example.com"}


def test_env_summary_mixed():
    summary = env_summary([("DB_PASSWORD", "info"), ("LOG_LEVEL", "info"), ("DB_HOST", "https://db.example.com/x")])
    assert summary == {"DB_PASSWORD": hidden("info"), "LOG_LEVEL": "info", "DB_HOST": "https://db.example.com"}


def test_env_summary_hides_reference_style_secret_names():
    summary = env_summary([("DB_PASSWORD_ARN", "arn:aws:secretsmanager:eu-west-1:111111111111:secret:x")])
    assert summary["DB_PASSWORD_ARN"].startswith("<hidden")


def test_names_that_merely_contain_a_word_are_not_hidden():
    assert env_summary([("PINNED_VERSION", "v2")]) == {"PINNED_VERSION": "v2"}


def test_hex_value_under_salt_and_under_setting():
    value = "a3f9c0de" * 4
    assert env_summary([("SALT", value), ("SETTING", value)]) == {"SALT": hidden(value), "SETTING": hidden(value)}


def test_db_pw_value_hidden():
    assert env_summary([("DB_PW", "huntertwo")]) == {"DB_PW": hidden("huntertwo")}


# env_changes

def test_env_changes_added_removed_changed():
    old = {"A": "x", "B": "y", "HOST": "https://a.example.com"}
    new = {"A": "x", "C": "z", "HOST": "https://b.example.com"}
    assert env_changes(old, new, set()) == [
        "B was removed",
        "C was added",
        "HOST changed from https://a.example.com to https://b.example.com",
    ]


def test_env_changes_one_side_hidden_prints_neither_side():
    old, new = {"TOKEN": hidden("abc")}, {"TOKEN": "info"}
    result = env_changes(old, new, {"TOKEN"})
    assert result == ["TOKEN changed (values hidden)"]
    assert "hidden:" not in result[0] and "info" not in result[0]


def test_env_changes_both_hidden_needs_the_raw_flag():
    old, new = {"TOKEN": hidden("abc")}, {"TOKEN": hidden("abd")}
    assert env_changes(old, new, set()) == []
    assert env_changes(old, new, {"TOKEN"}) == ["TOKEN changed (values hidden)"]


def test_env_changes_same_shown_but_raw_differs():
    same = {"HOST": "https://a.example.com"}
    assert env_changes(same, dict(same), {"HOST"}) == ["HOST may have changed (values hidden)"]
    assert env_changes(same, dict(same), set()) == []


def test_was_not_found(config_data, tmp_path):
    reply = (254, "An error occurred (NoSuchThing) when calling the Op operation: gone")
    ctx, _, _ = make_context(config_data, tmp_path, {"ecs list-clusters": reply})
    assert not was_not_found(ctx, ["NoSuchThing"])
    ctx.aws("ecs", "list-clusters", not_found=["NoSuchThing"])
    assert was_not_found(ctx, ["NoSuchThing", "Other"])
    assert not was_not_found(ctx, ["Other"])
    ctx.aws("ecs", "list-services")
    assert not was_not_found(ctx, ["NoSuchThing"])


@pytest.mark.parametrize(
    "value, expected",
    [(None, []), ("", []), ("a", ["a"]), (" a , b,, c ,", ["a", "b", "c"]), (",,", [])],
)
def test_split_csv(value, expected):
    assert split_csv(value) == expected


def test_url_with_a_single_label_host_is_reduced_to_its_origin_under_a_setting_name():
    assert shown("http://api:8080/x?token=abc", "API_URL") == "http://api:8080"
    assert shown("http://api:8080/x", "X") == hidden("http://api:8080/x")


@pytest.mark.parametrize("name", ["X", "VALUE", "DATA", "MISC"])
@pytest.mark.parametrize("value", ["john.doe", "john.doe:1234", "example.com:443", "example.com"])
def test_two_label_hosts_are_hidden_under_innocent_names(name, value):
    assert shown(value, name) == hidden(value)


def test_two_label_hosts_are_shown_under_setting_names():
    assert shown("example.com:443", "API_HOST") == "example.com:443"
    assert shown("example.com", "API_HOST") == "example.com"


def test_three_label_hosts_are_shown_under_any_name():
    assert shown("db.prod.example.com") == "db.prod.example.com"
    assert shown("cache.internal.example.com:6379", "X") == "cache.internal.example.com:6379"


def test_url_origin_needs_three_labels_or_an_ip_under_an_innocent_name():
    assert shown("https://example.com/x") == hidden("https://example.com/x")
    assert shown("https://api.example.com/x") == "https://api.example.com"
    assert shown("https://example.com/x", "API_URL") == "https://example.com"


def test_changed_two_label_value_prints_neither_side():
    old = env_summary([("X", "john.doe")])
    new = env_summary([("X", "jane.roe")])
    result = env_changes(old, new, {"X"})
    assert result == ["X changed (values hidden)"]
    assert "john" not in result[0] and "jane" not in result[0]


# Fix round 4: the decision is made by value type. Secret-looking values are joined at runtime.

PW = "sun" + "flower"  # a 9-letter dictionary word
SUMMER = "Sum" + "mer" + "2024"
PIN = "48" + "2913"
TOK15 = "Zx9Qw3" + "Zx9Qw3Zx9"
TOK40 = ("Ab3x" + "Y7qK") * 5
HEX40 = "a3f9" + "c0de" * 9
SHAPES = {"pw": PW, "summer": SUMMER, "pin": PIN, "tok15": TOK15}


def is_shown(name, value):
    return not shown_env_value(name, value).startswith("<hidden")


# re-review table 1, row 1: setting-like names with password-shaped values (rule 3 by kind)
ROW_ONE = {
    # identifier kinds take any short plain word, including these shapes
    "DB_NAME": {"pw", "summer", "pin", "tok15"},
    "DB": {"pw", "summer", "pin", "tok15"},
    "INDEX": {"pw", "summer", "pin", "tok15"},
    "TABLE": {"pw", "summer", "pin", "tok15"},
    "NAME": {"pw", "summer", "pin", "tok15"},
    # address kinds take a single-label host; a host's last label needs a letter
    "SERVICE_URL": {"pw", "summer", "tok15"},
    "SERVER": {"pw", "summer", "tok15"},
    "DOMAIN": {"pw", "summer", "tok15"},
    # enum kinds: starts with a letter, at most 4 digits
    "LOG_FORMAT": {"pw", "summer"},
    "PROFILE": {"pw", "summer"},
    "TYPE": {"pw", "summer"},
    "MODE": {"pw", "summer"},
    "DRIVER": {"pw", "summer"},
    "SCHEME": {"pw", "summer"},
    # path kinds need an absolute path
    "PATH": set(),
}


@pytest.mark.parametrize("name", sorted(ROW_ONE))
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_table_one_row_one_setting_names(name, shape):
    assert is_shown(name, SHAPES[shape]) == (shape in ROW_ONE[name])


C1_NAMES = ["DB_PASS1", "DB_PASSWORD2", "DbPassword2", "DB_TOKEN2", "SERVICE_SECRET2", "DB_KEY1", "DB_PWD2",
            "DB_PIN1", "REDIS_AUTH1_HOST", "API_KEY2_URL"]
I1_NAMES = ["DB_PSWD", "DB_PSW", "SERVICE_PSK", "SERVICE_SK", "SERVICE_BEARER", "SERVICE_SIGNATURE", "GITHUB_PAT_NAME"]
HIDDEN_SECRET_NAMES = [
    "dbPasswordHost", "DB_PASSWORD_HOST", "Db_Password_Host", "DBPASSWORDHOST", "API_KEY_URL", "APIKEYURL", "urlToken",
    "PWD_HOST", "DB_PASSWORD_NAME", "DB_PASSWORD_ARN", "SECRETS_PATH", "PASSWD_FILE_PATH", "DB_CRED_PATH", "dbPass",
    "DBPass", "adminPw", "DB_PASSPHRASE", "DB_PASSWD", "DB_PASS_1",
]
PERSONAL_NAMES = ["USERNAME", "USER_NAME", "OWNER_EMAIL", "DBUSER", "LOGINURL", "DB_USR"]
WORDS_INSIDE_WORDS_HIDDEN = ["MONKEY", "AUTHOR", "KEYSPACE", "CASSANDRA_KEYSPACE", "TOKENIZER_MODE",
                             "AUTH0_DOMAIN", "OAUTH_DOMAIN"]


@pytest.mark.parametrize("name", C1_NAMES + I1_NAMES + HIDDEN_SECRET_NAMES + PERSONAL_NAMES + WORDS_INSIDE_WORDS_HIDDEN)
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_secret_personal_and_unmatched_names_hide_password_shapes(name, shape):
    assert not is_shown(name, SHAPES[shape])


# APIKEYURL is one part that the redactor does not read as secret: a password shape stays hidden (rule 4),
# but a three-label host under it would be shown, so it is left out here.
@pytest.mark.parametrize("name", C1_NAMES + I1_NAMES + [n for n in HIDDEN_SECRET_NAMES if n != "APIKEYURL"] + ["USER_NAME", "DB_USR"])
def test_secret_and_personal_names_hide_hosts_numbers_and_switches(name):
    for value in ("db.prod.example.com", "redis:6379", "8080", "true", "eu-west-1", "/etc/app"):
        assert not is_shown(name, value)


def test_users_table_is_an_identifier_and_shows_a_word():
    assert is_shown("USERS_TABLE", PW)


def test_passenger_count_is_a_number_kind():
    assert not is_shown("PASSENGER_COUNT", PW)
    assert not is_shown("PASSENGER_COUNT", SUMMER)
    assert is_shown("PASSENGER_COUNT", PIN)  # any number fits a count


def test_c1_value_never_reaches_a_change_or_the_environment():
    old = env_summary([("DB_PASS1", PW)])
    new = env_summary([("DB_PASS1", PW + "Q")])
    result = env_changes(old, new, {"DB_PASS1"})
    assert result == ["DB_PASS1 changed (values hidden)"]
    assert PW not in repr(old) + repr(new) + repr(result)


@pytest.mark.parametrize("value", ["/hooks/" + TOK40, "/services/" + "T0AB12CD3" + "/" + "B0AB12CD3" + "/" + TOK40[:24]])
@pytest.mark.parametrize("name", ["CALLBACK_PATH", "SLACK_WEBHOOK_PATH"])
def test_i2_paths_with_tokens_are_hidden(name, value):
    assert not is_shown(name, value)


def test_path_with_a_hex_token_is_hidden():
    assert not is_shown("CALLBACK_PATH", "/hooks/" + HEX40)


def test_plain_lower_case_paths_are_shown():
    assert is_shown("CONFIG_PATH", "/etc/app/config.yaml")
    assert is_shown("DATA_DIR", "/var/lib/app/")
    assert not is_shown("CONFIG_PATH", "etc/app")
    assert not is_shown("CONFIG_PATH", "/etc/" + "a" * 33)


@pytest.mark.parametrize("name", ["X", "API_HOST"])
@pytest.mark.parametrize("host", ["[fe80::1%" + PW + "]", "[fe80::1%" + TOK40 + "]:443", "[fe80::1%" + PIN + "]"])
def test_ipv6_zone_id_is_hidden(name, host):
    assert not is_shown(name, host)


def test_plain_ipv6_is_shown():
    assert shown("[2001:db8::1]") == "[2001:db8::1]"
    assert shown("[2001:db8::1]:8443", "API_HOST") == "[2001:db8::1]:8443"


@pytest.mark.parametrize(
    "name, value, expected",
    [
        ("DB_HOST", "admin:1234", "admin:1234"),
        ("X", "jane.m.smith:1234", "jane.m.smith:1234"),
        ("X", HEX40 + ".example.com", HEX40 + ".example.com"),
        ("DB_ARN", "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-main", "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db-main"),
        ("SERVICE_URL", "http://admin:" + PW + "@api:8080/x", "http://api:8080"),
        ("SERVICE_URL", "https://api.example.com/x/" + TOK40, "https://api.example.com"),
        ("SERVICE_URL", "https://api.example.com/x?t=" + TOK40, "https://api.example.com"),
    ],
)
def test_table_one_rows_that_are_shown(name, value, expected):
    assert shown(value, name) == expected


@pytest.mark.parametrize(
    "name, value",
    [
        ("SERVICE_URL", "admin:" + PW + "@db.example.com"),
        ("SERVICE_URL", "admin:" + PIN + "@db.example.com:5432"),
        ("SERVER", "Server=db;User Id=sa;Password=" + PW),
        ("DB_HOST", TOK40),
        ("API_URL", "https://" + TOK40 + "/x"),
    ],
)
def test_table_one_rows_that_are_hidden(name, value):
    assert not is_shown(name, value)


def test_change_lines_for_shown_and_hidden_values():
    old = env_summary([("X", PW), ("VALUE", "a.b.c"), ("DB_NAME", PW), ("API_HOST", "john.doe:1234")])
    new = env_summary([("X", PW + "Q"), ("VALUE", "a.b"), ("DB_NAME", PW + "Q"), ("API_HOST", "john.doe:1235")])
    assert env_changes(old, new, {"X", "VALUE", "DB_NAME", "API_HOST"}) == [
        "API_HOST changed from john.doe:1234 to john.doe:1235",
        f"DB_NAME changed from {PW} to {PW}Q",
        "VALUE changed (values hidden)",
        "X changed (values hidden)",
    ]


# re-review table 2: harmless settings, with what is shown now

@pytest.mark.parametrize(
    "name, value, expected",
    [
        ("DATABASE_URL", "postgres://app:" + PW + "@db.prod.example.com:5432/app", "postgres://db.prod.example.com:5432"),
        ("DATABASE_URL", "postgres://app:" + PW + "@postgres:5432/app", "postgres://postgres:5432"),
        ("MYSQL_URL", "mysql://u:p@mysql:3306/app", "mysql://mysql:3306"),
        ("RABBITMQ_URL", "amqp://app:" + PW + "@rabbit:5672", "amqp://rabbit:5672"),
        ("DATABASE_URL", "postgresql+psycopg2://app:" + PW + "@db.prod.example.com:5432/app", "postgresql+psycopg2://db.prod.example.com:5432"),
        ("SPRING_DATASOURCE_URL", "jdbc:postgresql://db.prod.example.com:5432/app?password=" + PW, "jdbc:postgresql://db.prod.example.com:5432"),
        ("DATABASE_URL", "sqlserver://db.prod.example.com:1433;databaseName=app;password=" + PW, "sqlserver://db.prod.example.com:1433"),
        ("CLICKHOUSE_URL", "clickhouse://app:" + PW + "@ch.prod.example.com:9000/app", "clickhouse://ch.prod.example.com:9000"),
        ("REDIS_HOST", "redis:6379", "redis:6379"),
        ("REDIS_URL", "redis://:" + PW + "@redis:6379/0", "redis://redis:6379"),
        ("REDIS_HOST", "main.ab12cd.ng.0001.euw1.cache.amazonaws.com", "main.ab12cd.ng.0001.euw1.cache.amazonaws.com"),
        ("KAFKA_BROKERS", "b-1.kafka.example.com:9092,b-2.kafka.example.com:9092", "b-1.kafka.example.com:9092,b-2.kafka.example.com:9092"),
        ("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092", "kafka:9092"),
        ("NODE_ENV", "production", "production"),
        ("ENV", "prod", "prod"),
        ("STAGE", "prod", "prod"),
        ("SENTRY_ENVIRONMENT", "production", "production"),
        ("SPRING_PROFILES_ACTIVE", "prod", "prod"),
        ("SPRING_PROFILES_ACTIVE", "prod,eu", "prod,eu"),
        ("AWS_REGION", "eu-west-1", "eu-west-1"),
        ("AWS_DEFAULT_REGION", "us-east-1", "us-east-1"),
        ("S3_BUCKET", "acme-prod-uploads", "acme-prod-uploads"),
        ("S3_BUCKET", "acme-prod-uploads-eu-west-1", "acme-prod-uploads-eu-west-1"),
        ("QUEUE_URL", "https://sqs.eu-west-1.amazonaws.com/111111111111/orders", "https://sqs.eu-west-1.amazonaws.com (queue orders)"),
        ("SQS_QUEUE", "orders-prod", "orders-prod"),
        ("LOG_LEVEL", "debug", "debug"),
        ("TZ", "UTC", "UTC"),
        ("LOGLEVEL", "INFO", "INFO"),
        ("TZ", "Europe/Berlin", "Europe/Berlin"),
        ("MAX_CONNECTIONS", "100", "100"),
        ("DB_POOL_SIZE", "20", "20"),
        ("CONNECTION_TIMEOUT", "30000", "30000"),
        ("GUNICORN_WORKERS", "4", "4"),
        ("WEB_CONCURRENCY", "4", "4"),
        ("CACHE_TTL", "300", "300"),
        ("MAX_CONN", "100", "100"),
        ("CONN_POOL_SIZE", "20", "20"),
        ("MEMORY_LIMIT", "512Mi", "512Mi"),
        ("HEAP_SIZE", "2g", "2g"),
        ("APP_VERSION", "1.4.2", "1.4.2"),
        ("APP_VERSION", "1.4.2-rc.1", "1.4.2-rc.1"),
        ("IMAGE_TAG", "sha-abc1234", "sha-abc1234"),
        ("GIT_SHA", "abc1234", "abc1234"),
        ("AUTH_SERVICE_URL", "https://auth.prod.example.com/oauth?x=" + TOK40, "https://auth.prod.example.com"),
        ("TOKEN_ENDPOINT", "https://auth.prod.example.com/token", "https://auth.prod.example.com"),
        ("USER_SERVICE_URL", "http://users:8080/v1", "http://users:8080"),
        ("LOGIN_URL", "https://login.prod.example.com/start", "https://login.prod.example.com"),
        ("FEATURE_NEW_CHECKOUT", "true", "true"),
        ("FEATURE_NEW_CHECKOUT_ENABLED", "off", "off"),
        ("PORT", "8080", "8080"),
        ("HOSTNAME", "web-1", "web-1"),
        ("DD_AGENT_HOST", "10.0.1.5", "10.0.1.5"),
        ("ELASTICSEARCH_URL", "https://search.prod.example.com:9200", "https://search.prod.example.com:9200"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317", "http://otel-collector:4317"),
        ("DATABASE_HOST", "main.c9akciq32.eu-west-1.rds.amazonaws.com", "main.c9akciq32.eu-west-1.rds.amazonaws.com"),
        ("UPSTREAM", "api.prod.example.com", "api.prod.example.com"),
        ("ALLOWED_HOSTS", "api.prod.example.com,web.prod.example.com", "api.prod.example.com,web.prod.example.com"),
        ("BACKEND", "https://api.prod.example.com/v2", "https://api.prod.example.com"),
    ],
)
def test_table_two_harmless_settings_are_shown(name, value, expected):
    assert shown(value, name) == expected


@pytest.mark.parametrize(
    "name, value",
    [
        ("JAVA_OPTS", "-Xmx512m"),
        ("JAVA_TOOL_OPTIONS", "-XX:MaxRAMPercentage=75"),
        ("NODE_OPTIONS", "--max-old-space-size=4096"),
        ("RUST_LOG", "info"),
        ("COUNTRY_CODE", "DE"),
        ("PARTITION_KEY", "tenant"),
        ("HASH_ALGORITHM", "sha256"),
        ("CERT_PATH", "/etc/ssl/app.pem"),
        ("TOKEN_TTL", "300"),
        ("SESSION_TIMEOUT", "30m"),
        ("PYTHONUNBUFFERED", "1"),
        ("GOMAXPROCS", "2"),
    ],
)
def test_table_two_settings_that_stay_hidden(name, value):
    assert not is_shown(name, value)


# rule 3 kinds: the value must fit the kind the name says

@pytest.mark.parametrize(
    "name, value, expected_shown",
    [
        ("SERVICE_PORT", "8080", True),
        ("SERVICE_PORT", "808080", False),
        ("SERVICE_PORT", PW, False),
        ("LOG_LEVEL", PIN, False),
        ("LOG_LEVEL", "a" * 41, False),
        ("LOG_LEVEL", "x12345", False),
        ("REQUEST_TIMEOUT", "30s", True),
        ("REQUEST_TIMEOUT", "1234567890123", False),
        ("REQUEST_TIMEOUT", PW, False),
        ("SAMPLE_RATE_LIMIT", "0.25", True),
        ("APP_VERSION", SUMMER, False),
        ("APP_VERSION", HEX40, True),
        ("APP_VERSION", "1." + "2" * 40, False),
        ("DEBUG", "yes", True),
        ("DEBUG", PW, False),
        ("S3_BUCKET", "a" * 64, False),
        ("S3_BUCKET", TOK15 + "Q", False),
        ("S3_BUCKET", "acme-" + "b" * 20, False),
        ("S3_BUCKET", "acme-prod", True),
        ("QUEUE_ARN", "arn:aws:sqs:eu-west-1:111111111111:orders", True),
        ("QUEUE_ARN", PW, False),
        ("KAFKA_BROKERS", "b-1.kafka.example.com:9092,", False),
        ("KAFKA_BROKERS", "b-1.kafka.example.com:9092," + PW + ":x", False),
        ("API_URL", "git+ssh://git.example.com/repo", False),
        ("API_URL", "redis+" + "x" * 30 + "://cache.example.com", False),
    ],
)
def test_values_must_fit_the_kind_of_the_name(name, value, expected_shown):
    assert is_shown(name, value) == expected_shown


def test_the_last_kind_word_in_the_name_decides():
    assert shown("arn:aws:sns:eu-west-1:111111111111:alerts", "TOPIC_ARN").startswith("arn:")
    assert is_shown("DB_HOST", "db.example.com:5432")
    assert not is_shown("HOST_TYPE", "example.com:5432")


def test_secret_name_shows_only_a_url_origin():
    assert shown("https://auth.prod.example.com/x", "DB_PASSWORD") == "https://auth.prod.example.com"
    assert not is_shown("DB_PASSWORD", "auth.prod.example.com")
    assert not is_shown("DB_PASSWORD", "jdbc:postgresql://db.prod.example.com:5432/app")


# Known residual shapes, stated so a change in them is noticed. Both need a decision outside this module:
# "bind" is not a secret stem in the redactor (ruling 1 keeps the word list there), and a dictionary word
# inside a plain lower-case path cannot be told from a directory name by its shape.
def test_known_residual_ldap_server_bind_shows_a_single_word_as_a_host():
    assert is_shown("LDAP_SERVER_BIND", PW)


def test_known_residual_dictionary_word_inside_a_path_is_shown():
    assert is_shown("DB_PATH", "/run/" + PW)
