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
                                  "JWT", "PRIVATE", "SENTRY_DSN", "SIGNING", "HMAC", "TLS_CERT", "CONN", "dbPw",
                                  "KEY", "PASSCODE", "PINCODE", "CODE", "OTP", "MFA", "PEPPER", "NONCE", "API_KEY"])
def test_secret_looking_name_components_always_hide(name):
    assert env_summary([(name, "info")]) == {name: hidden("info")}
    assert env_summary([(name, "db.example.com")]) == {name: hidden("db.example.com")}


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
