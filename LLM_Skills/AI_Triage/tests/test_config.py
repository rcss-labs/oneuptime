from pathlib import Path

import pytest

from triage.config import ConfigError, load_config, parse_config


def test_example_config_is_valid(config_data):
    cfg = parse_config(config_data)
    assert cfg.profiles() == frozenset({"triage-prod-main", "triage-staging"})
    assert cfg.opensearch_hosts() == frozenset({"opensearch.internal.example.com"})
    assert cfg.kube_contexts() == frozenset({"triage-platform-prod"})
    assert cfg.permission_set == "ai-triage-read-only"
    assert cfg.limits["max_window_hours"] == 6
    assert cfg.cases_dir == Path("~/.ai-triage/cases").expanduser()
    assert cfg.account_for_profile("triage-staging").account_id == "222222222222"
    assert cfg.account_for_profile("admin") is None


def test_optional_sections_default(config_data):
    for key in ("opensearch_clusters", "eks_clusters", "slack", "limits", "typesafe", "permission_set", "cases_dir"):
        config_data.pop(key)
    cfg = parse_config(config_data)
    assert cfg.opensearch_clusters == {} and cfg.eks_clusters == {}
    assert cfg.slack_default_channel is None
    assert cfg.limits["opensearch_max_hits"] == 50
    assert cfg.typesafe_thresholds["evidence_supports"] == 0.8


def test_all_problems_are_reported_together(config_data):
    config_data["accounts"]["prod-main"]["account_id"] = "123"
    config_data["accounts"]["prod-main"]["profile"] = "admin"
    config_data["accounts"]["staging"]["regions"] = ["europe"]
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_data)
    joined = "\n".join(excinfo.value.errors)
    assert "accounts.prod-main.account_id" in joined
    assert "accounts.prod-main.profile: must start with 'triage-'" in joined
    assert "accounts.staging.regions" in joined


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d.pop("oneuptime"), "oneuptime: missing"),
        (lambda d: d["oneuptime"].update(url="http://oneuptime.example.com"), "oneuptime.url: must be an https URL"),
        (lambda d: d.update(accounts={}), "accounts: at least one account is required"),
        (lambda d: d["accounts"]["staging"].update(profile="triage-prod-main"), "used by more than one account"),
        (lambda d: d["opensearch_clusters"]["logs-prod"].update(account="nope"), "unknown account 'nope'"),
        (lambda d: d["opensearch_clusters"]["logs-prod"].update(endpoint="opensearch.internal"), "must be an http or https URL"),
        (lambda d: d["opensearch_clusters"]["logs-prod"].update(allowed_index_patterns=["*"]), "is too broad"),
        (lambda d: d["eks_clusters"]["platform-prod"].update(region="us-west-2"), "is not listed for account"),
        (lambda d: d["eks_clusters"]["platform-prod"].update(context="admin"), "context: must start with 'triage-'"),
        (lambda d: d.pop("confluence"), "confluence: missing"),
        (lambda d: d["confluence"].update(parent_page_id=""), "confluence.parent_page_id: must be set"),
        (lambda d: d["limits"].update(max_window_hours=0), "limits.max_window_hours: must be a positive whole number"),
        (lambda d: d["limits"].update(surprise=1), "limits.surprise: unknown key"),
        (lambda d: d["typesafe"]["thresholds"].update(evidence_supports=1.5), "must be between 0 and 1"),
        (lambda d: d["typesafe"]["thresholds"].update(evidence_supports=True), "must be a number"),
    ],
)
def test_invalid_config_is_rejected(config_data, mutate, expected):
    mutate(config_data)
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_data)
    assert expected in "\n".join(excinfo.value.errors)


@pytest.mark.parametrize("account_id", [111111111111, 12345678901, None, "12345678901", "1111-1111-1111"])
def test_account_id_must_be_twelve_quoted_digits(config_data, account_id):
    config_data["accounts"]["prod-main"]["account_id"] = account_id
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_data)
    assert "accounts.prod-main.account_id: must be 12 digits written in quotes" in excinfo.value.errors


@pytest.mark.parametrize("document", [None, [], "text", 7])
def test_non_mapping_document_is_rejected(document):
    with pytest.raises(ConfigError) as excinfo:
        parse_config(document)
    assert excinfo.value.errors == ["config: must be a mapping"]


def test_load_config_reports_missing_file(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / "absent.yaml")
    assert "file not found" in excinfo.value.errors[0]


def test_load_config_reports_bad_yaml(tmp_path):
    path = tmp_path / "triage-config.yaml"
    path.write_text("accounts: [unclosed")
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "not valid YAML" in excinfo.value.errors[0]


def test_opensearch_connection_settings_default_when_absent(config_data):
    cluster = parse_config(config_data).opensearch_clusters["logs-prod"]
    assert cluster.verify_tls is True
    assert cluster.ca_bundle is None
    assert cluster.message_field == "message"
    assert cluster.level_field == "level"


def test_opensearch_connection_settings_are_accepted(config_data):
    config_data["opensearch_clusters"]["logs-prod"].update(
        verify_tls=False, ca_bundle="/etc/ssl/internal-ca.pem", message_field="log", level_field="severity"
    )
    cluster = parse_config(config_data).opensearch_clusters["logs-prod"]
    assert cluster.verify_tls is False
    assert cluster.ca_bundle == "/etc/ssl/internal-ca.pem"
    assert cluster.message_field == "log"
    assert cluster.level_field == "severity"


@pytest.mark.parametrize(
    "key, value",
    [
        ("verify_tls", "yes"),
        ("verify_tls", 1),
        ("verify_tls", None),
        ("ca_bundle", ""),
        ("ca_bundle", 5),
        ("message_field", "  "),
        ("message_field", ["message"]),
        ("level_field", ""),
        ("level_field", 3),
    ],
)
def test_wrong_opensearch_connection_setting_types_are_rejected(config_data, key, value):
    config_data["opensearch_clusters"]["logs-prod"][key] = value
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_data)
    assert any(f"opensearch_clusters.logs-prod.{key}" in error for error in excinfo.value.errors)


def test_wrong_connection_setting_is_reported_with_other_problems(config_data):
    config_data["opensearch_clusters"]["logs-prod"]["verify_tls"] = "no"
    config_data["accounts"]["prod-main"]["account_id"] = "123"
    with pytest.raises(ConfigError) as excinfo:
        parse_config(config_data)
    joined = "\n".join(excinfo.value.errors)
    assert "opensearch_clusters.logs-prod.verify_tls: must be true or false" in joined
    assert "accounts.prod-main.account_id" in joined
