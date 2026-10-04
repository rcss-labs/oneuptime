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


def test_dsn_keeps_only_scheme_and_host():
    dsn = "https://" + "a1b2" * 8 + "@o1.ingest.example.com/12345"
    assert shown_env_value(dsn) == "https://o1.ingest.example.com"


def test_webhook_secret_path_is_dropped():
    url = "https://hooks.example.com/services/" + "T0/B0/" + "x" * 24
    shown = shown_env_value(url)
    assert shown == "https://hooks.example.com"
    assert "x" * 24 not in shown


def test_database_url_password_is_dropped_and_port_kept():
    url = "postgres://app:" + "pw" + "7" * 8 + "@db.example.com:5432/orders?sslmode=require"
    assert shown_env_value(url) == "postgres://db.example.com:5432"


def test_query_and_fragment_are_dropped():
    assert shown_env_value("https://api.example.com/v1?key=" + "k" * 10 + "#frag") == "https://api.example.com"


@pytest.mark.parametrize("text", ["db.example.com", "db.example.com:5432", "cache-1.internal.example.com"])
def test_bare_hosts_are_kept(text):
    assert shown_env_value(text) == text


@pytest.mark.parametrize("text", ["eu-west-1", "production", "info", "us_east.1"])
def test_short_lowercase_settings_are_kept(text):
    assert shown_env_value(text) == text


def test_booleans_and_numbers():
    assert shown_env_value(True) == "true"
    assert shown_env_value(False) == "false"
    assert shown_env_value(42) == "42"
    assert shown_env_value(1.5) == "1.5"


def test_long_random_string_is_hidden():
    value = "Zx9" + "Qw3" * 10
    assert shown_env_value(value) == hidden(value)


def test_empty_string_is_hidden():
    assert shown_env_value("") == HIDDEN.format(0)


def test_short_mixed_case_value_starting_with_a_letter_is_shown():
    assert shown_env_value("Abc123") == "Abc123"


def test_non_scalar_is_hidden():
    assert shown_env_value(None).startswith("<hidden")
    assert shown_env_value({"a": 1}).startswith("<hidden")


def test_env_summary_hides_secret_names_whatever_the_value():
    summary = env_summary([("DB_PASSWORD", "info"), ("LOG_LEVEL", "info"), ("DB_HOST", "https://db.example.com/x")])
    assert summary == {
        "DB_PASSWORD": hidden("info"),
        "LOG_LEVEL": "info",
        "DB_HOST": "https://db.example.com",
    }


def test_env_summary_keeps_reference_style_names_reduced():
    summary = env_summary([("DB_PASSWORD_ARN", "arn:aws:secretsmanager:eu-west-1:111111111111:secret:x")])
    assert summary["DB_PASSWORD_ARN"].startswith("<hidden")


def test_env_changes_added_removed_changed():
    old = {"A": "x", "B": "y", "HOST": "https://a.example.com"}
    new = {"A": "x", "C": "z", "HOST": "https://b.example.com"}
    assert env_changes(old, new, set()) == [
        "B was removed",
        "C was added",
        "HOST changed from https://a.example.com to https://b.example.com",
    ]


def test_env_changes_one_side_hidden():
    old = {"TOKEN": hidden("abc")}
    new = {"TOKEN": "info"}
    assert env_changes(old, new, {"TOKEN"}) == ["TOKEN changed (values hidden)"]


def test_env_changes_both_hidden_needs_the_raw_flag():
    old, new = {"TOKEN": hidden("abc")}, {"TOKEN": hidden("abd")}
    assert env_changes(old, new, set()) == []
    assert env_changes(old, new, {"TOKEN"}) == ["TOKEN may have changed (values hidden)"]


def test_env_changes_same_shown_but_raw_differs():
    shown = {"HOST": "https://a.example.com"}
    assert env_changes(shown, dict(shown), {"HOST"}) == ["HOST may have changed (values hidden)"]
    assert env_changes(shown, dict(shown), set()) == []


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
    assert shown_env_value(value) == hidden(value)


def test_url_userinfo_is_dropped_but_host_and_port_kept():
    assert shown_env_value("amqp://guest:guest@mq.example.com:5672/vhost") == "amqp://mq.example.com:5672"


def test_ip_address_url_is_kept():
    assert shown_env_value("http://10.0.0.5:8080/health") == "http://10.0.0.5:8080"


def test_username_with_a_pin_is_not_a_host_and_port():
    value = "john.doe:123456"
    assert shown_env_value(value) == hidden(value)


def test_port_range():
    assert shown_env_value("db.example.com:65535") == "db.example.com:65535"
    assert shown_env_value("db.example.com:65536") == hidden("db.example.com:65536")
    assert shown_env_value("db.example.com:0123456") == hidden("db.example.com:0123456")


def test_host_without_a_letter_in_the_last_label_is_hidden():
    value = "service.internal.example.123"
    assert shown_env_value(value) == hidden(value)


def test_overlong_dotted_string_is_hidden():
    value = ".".join(["a" * 500] * 4) + ".com"
    assert shown_env_value(value) == hidden(value)
    assert shown_env_value(("a" * 64) + ".example.com").startswith("<hidden")
    assert shown_env_value(("a" * 63) + ".example.com").startswith("a")


@pytest.mark.parametrize("value", ["30", "8080", "INFO", "True", "DEBUG", "production", "Debug", "v2", "http2", "eu-west-1", "false"])
def test_plain_settings_are_shown(value):
    assert shown_env_value(value) == value


@pytest.mark.parametrize("value", ["1234567", "a1b2c3d4e5f6a7b8", "abcdefabcdefabcdef", "Zx9Qw3Zx9Qw3Zx9Q", "a" * 21, "9abc"])
def test_other_values_are_hidden(value):
    assert shown_env_value(value) == hidden(value)


def test_python_bool_in_any_case():
    assert shown_env_value("TRUE") == "TRUE"


@pytest.mark.parametrize("name", ["SALT", "DB_PW", "PIN", "PASSWORD_HASH", "CREDS", "NEW_RELIC_LICENSE", "OTP_SEED",
                                  "JWT", "PRIVATE", "SENTRY_DSN", "SIGNING", "HMAC", "TLS_CERT", "CONN", "dbPw"])
def test_secret_looking_name_components_always_hide(name):
    assert env_summary([(name, "info")]) == {name: hidden("info")}


def test_hex_value_under_salt_and_under_setting():
    value = "a3f9c0de" * 4
    summary = env_summary([("SALT", value), ("SETTING", value)])
    assert summary == {"SALT": hidden(value), "SETTING": hidden(value)}


def test_db_pw_value_hidden():
    assert env_summary([("DB_PW", "huntertwo")]) == {"DB_PW": hidden("huntertwo")}


def test_names_that_merely_contain_a_word_are_not_hidden():
    assert env_summary([("PINNED_VERSION", "v2")]) == {"PINNED_VERSION": "v2"}
