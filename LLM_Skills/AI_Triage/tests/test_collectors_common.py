import pytest

from triage.collectors.common import (
    env_changes,
    env_summary,
    shown_env_value,
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


def test_mixed_case_short_value_is_hidden():
    assert shown_env_value("Abc123") == hidden("Abc123")


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
