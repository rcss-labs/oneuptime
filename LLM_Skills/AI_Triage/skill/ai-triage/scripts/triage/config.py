"""Load and validate the team config file (triage-config.yaml)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ACCOUNT_ID_RE = re.compile(r"\d{12}")
REGION_RE = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")
# Names the guard trusts when it compares them with a command line.
SIMPLE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
# One index name or one trailing-star pattern: no commas, no remote clusters, no bare stars.
# An EKS cluster name is the real AWS name, which may hold upper-case letters and underscores.
EKS_CLUSTER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
INDEX_PATTERN_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,}\*?")
PROFILE_PREFIX = "triage-"
DEFAULT_PERMISSION_SET = "ai-triage-read-only"
CONFIG_FILE_NAME = "triage-config.yaml"

DEFAULT_LIMITS = {
    "max_window_hours": 6,
    "logs_insights_max_log_groups": 5,
    "opensearch_max_hits": 50,
    "opensearch_timeout_seconds": 10,
}
MAX_LIMITS = {
    "max_window_hours": 48,
    "logs_insights_max_log_groups": 20,
    "opensearch_max_hits": 500,
    "opensearch_timeout_seconds": 60,
}
DEFAULT_THRESHOLDS = {
    "evidence_supports": 0.8,
    "cause_top_probability": 0.6,
    "ask_engineer_below": 0.5,
}


class ConfigError(Exception):
    """Raised with every problem found, not just the first."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class Account:
    alias: str
    account_id: str
    profile: str
    regions: tuple[str, ...]


@dataclass(frozen=True)
class OpenSearchCluster:
    name: str
    account: str
    endpoint: str
    host: str
    allowed_index_patterns: tuple[str, ...]
    time_field: str
    verify_tls: bool = True
    ca_bundle: str | None = None
    message_field: str = "message"
    level_field: str = "level"


@dataclass(frozen=True)
class EksCluster:
    name: str
    account: str
    region: str
    context: str


@dataclass(frozen=True)
class TriageConfig:
    oneuptime_url: str
    permission_set: str
    accounts: dict[str, Account]
    opensearch_clusters: dict[str, OpenSearchCluster]
    eks_clusters: dict[str, EksCluster]
    confluence_space_key: str
    confluence_parent_page_id: str
    slack_default_channel: str | None
    cases_dir: Path
    limits: dict[str, int]
    typesafe_model: str
    typesafe_thresholds: dict[str, float]

    def profiles(self) -> frozenset[str]:
        return frozenset(a.profile for a in self.accounts.values())

    def opensearch_hosts(self) -> frozenset[str]:
        return frozenset(c.host for c in self.opensearch_clusters.values())

    def kube_contexts(self) -> frozenset[str]:
        return frozenset(c.context for c in self.eks_clusters.values())

    def account_for_profile(self, profile: str) -> Account | None:
        for account in self.accounts.values():
            if account.profile == profile:
                return account
        return None


def _section(data: dict[str, Any], key: str, errors: list[str], required: bool) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        if required:
            errors.append(f"{key}: missing")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{key}: must be a mapping")
        return {}
    return value


def _text(section: dict[str, Any], key: str, where: str, errors: list[str]) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{where}.{key}: must be a non-empty string")
        return ""
    return value.strip()


def _optional_text(section: dict[str, Any], key: str, default: str | None, where: str, errors: list[str]) -> str | None:
    if key not in section:
        return default
    value = section[key]
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{where}.{key}: must be a non-empty string when set")
        return default
    return value.strip()


def is_index_pattern(value: Any) -> bool:
    """True for a single index name or a pattern with one trailing star."""
    return isinstance(value, str) and INDEX_PATTERN_RE.fullmatch(value) is not None


def is_simple_name(value: Any) -> bool:
    return isinstance(value, str) and SIMPLE_NAME_RE.fullmatch(value) is not None


def _check_name(name: str, where: str, errors: list[str]) -> None:
    if not is_simple_name(name):
        errors.append(f"{where}: name must use lower-case letters, digits, and dashes only")


def _check_triage_name(value: str, where: str, errors: list[str]) -> None:
    if value and (not value.startswith(PROFILE_PREFIX) or not is_simple_name(value)):
        errors.append(f"{where}: must start with '{PROFILE_PREFIX}' and use lower-case letters, digits, and dashes only")


def _parse_accounts(raw: dict[str, Any], errors: list[str]) -> dict[str, Account]:
    accounts: dict[str, Account] = {}
    if not raw:
        errors.append("accounts: at least one account is required")
    seen_profiles: set[str] = set()
    for alias, body in raw.items():
        where = f"accounts.{alias}"
        _check_name(str(alias), where, errors)
        if not isinstance(body, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        raw_account_id = body.get("account_id")
        account_id = raw_account_id if isinstance(raw_account_id, str) else ""
        if not ACCOUNT_ID_RE.fullmatch(account_id):
            errors.append(f"{where}.account_id: must be 12 digits written in quotes")
        profile = _text(body, "profile", where, errors)
        _check_triage_name(profile, f"{where}.profile", errors)
        if profile in seen_profiles:
            errors.append(f"{where}.profile: '{profile}' is used by more than one account")
        seen_profiles.add(profile)
        regions = body.get("regions")
        if not isinstance(regions, list) or not regions:
            errors.append(f"{where}.regions: must be a non-empty list")
            regions = []
        for region in regions:
            if not isinstance(region, str) or not REGION_RE.fullmatch(region):
                errors.append(f"{where}.regions: '{region}' is not a region name")
        accounts[str(alias)] = Account(str(alias), account_id, profile, tuple(str(r) for r in regions))
    return accounts


def _parse_opensearch(raw: dict[str, Any], accounts: dict[str, Account], errors: list[str]) -> dict[str, OpenSearchCluster]:
    clusters: dict[str, OpenSearchCluster] = {}
    for name, body in raw.items():
        where = f"opensearch_clusters.{name}"
        _check_name(str(name), where, errors)
        if not isinstance(body, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        account = _text(body, "account", where, errors)
        if account and account not in accounts:
            errors.append(f"{where}.account: unknown account '{account}'")
        endpoint = _text(body, "endpoint", where, errors)
        parsed = urlparse(endpoint)
        if endpoint and (parsed.scheme not in ("http", "https") or not parsed.hostname):
            errors.append(f"{where}.endpoint: must be an http or https URL")
        patterns = body.get("allowed_index_patterns")
        if not isinstance(patterns, list) or not patterns:
            errors.append(f"{where}.allowed_index_patterns: must be a non-empty list")
            patterns = []
        for pattern in patterns:
            if not is_index_pattern(pattern):
                errors.append(f"{where}.allowed_index_patterns: {pattern!r} must be a single index pattern such as app-logs-*")
        time_field = _text(body, "time_field", where, errors)
        verify_tls = body.get("verify_tls", True)
        if not isinstance(verify_tls, bool):
            errors.append(f"{where}.verify_tls: must be true or false")
            verify_tls = True
        ca_bundle = _optional_text(body, "ca_bundle", None, where, errors)
        message_field = _optional_text(body, "message_field", "message", where, errors)
        level_field = _optional_text(body, "level_field", "level", where, errors)
        clusters[str(name)] = OpenSearchCluster(
            str(name), account, endpoint, parsed.hostname or "", tuple(str(p) for p in patterns), time_field,
            verify_tls, ca_bundle, message_field, level_field,
        )
    return clusters


def _parse_eks(raw: dict[str, Any], accounts: dict[str, Account], errors: list[str]) -> dict[str, EksCluster]:
    clusters: dict[str, EksCluster] = {}
    for name, body in raw.items():
        where = f"eks_clusters.{name}"
        if EKS_CLUSTER_NAME_RE.fullmatch(str(name)) is None:
            errors.append(f"{where}: name must be an EKS cluster name: letters, digits, dashes, and underscores, starting with a letter or digit")
        if not isinstance(body, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        account = _text(body, "account", where, errors)
        region = _text(body, "region", where, errors)
        context = _text(body, "context", where, errors)
        if account and account not in accounts:
            errors.append(f"{where}.account: unknown account '{account}'")
        elif account and region and region not in accounts[account].regions:
            errors.append(f"{where}.region: '{region}' is not listed for account '{account}'")
        _check_triage_name(context, f"{where}.context", errors)
        clusters[str(name)] = EksCluster(str(name), account, region, context)
    return clusters


def _parse_numbers(
    raw: dict[str, Any],
    defaults: dict[str, Any],
    where: str,
    kind: type,
    errors: list[str],
    maximums: dict[str, int] | None = None,
) -> dict[str, Any]:
    result = dict(defaults)
    for key, value in raw.items():
        if key not in defaults:
            errors.append(f"{where}.{key}: unknown key")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"{where}.{key}: must be a number")
            continue
        if kind is int and (not isinstance(value, int) or value <= 0):
            errors.append(f"{where}.{key}: must be a positive whole number")
            continue
        if kind is int and maximums and value > maximums[key]:
            errors.append(f"{where}.{key}: must be at most {maximums[key]}")
            continue
        if kind is float and not 0 <= value <= 1:
            errors.append(f"{where}.{key}: must be between 0 and 1")
            continue
        result[key] = kind(value)
    return result


def _parent_page_id(value: Any, errors: list[str]) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()
    errors.append("confluence.parent_page_id: must be set to a non-empty string or a whole number")
    return ""


def parse_config(data: Any) -> TriageConfig:
    errors: list[str] = []
    if not isinstance(data, dict):
        raise ConfigError(["config: must be a mapping"])

    oneuptime = _section(data, "oneuptime", errors, required=True)
    oneuptime_url = _text(oneuptime, "url", "oneuptime", errors) if oneuptime else ""
    if oneuptime_url and urlparse(oneuptime_url).scheme != "https":
        errors.append("oneuptime.url: must be an https URL")

    accounts = _parse_accounts(_section(data, "accounts", errors, required=True), errors)
    opensearch = _parse_opensearch(_section(data, "opensearch_clusters", errors, required=False), accounts, errors)
    eks = _parse_eks(_section(data, "eks_clusters", errors, required=False), accounts, errors)

    confluence = _section(data, "confluence", errors, required=True)
    space_key = _text(confluence, "space_key", "confluence", errors) if confluence else ""
    parent_page_id = _parent_page_id(confluence.get("parent_page_id"), errors) if confluence else ""

    slack = _section(data, "slack", errors, required=False)
    slack_channel = slack.get("default_channel")
    if slack_channel is not None and (not isinstance(slack_channel, str) or not slack_channel.strip()):
        errors.append("slack.default_channel: must be a non-empty string when set")
        slack_channel = None

    permission_set = data.get("permission_set", DEFAULT_PERMISSION_SET)
    if not isinstance(permission_set, str) or not permission_set.strip():
        errors.append("permission_set: must be a non-empty string")
        permission_set = DEFAULT_PERMISSION_SET

    cases_dir = data.get("cases_dir", "~/.ai-triage/cases")
    if not isinstance(cases_dir, str) or not cases_dir.strip():
        errors.append("cases_dir: must be a non-empty string")
        cases_dir = "~/.ai-triage/cases"

    limits = _parse_numbers(_section(data, "limits", errors, required=False), DEFAULT_LIMITS, "limits", int, errors, MAX_LIMITS)
    typesafe = _section(data, "typesafe", errors, required=False)
    model = typesafe.get("model", "jev-latest")
    if not isinstance(model, str) or not model.strip():
        errors.append("typesafe.model: must be a non-empty string")
        model = "jev-latest"
    raw_thresholds = typesafe.get("thresholds") or {}
    if not isinstance(raw_thresholds, dict):
        errors.append("typesafe.thresholds: must be a mapping")
        raw_thresholds = {}
    thresholds = _parse_numbers(raw_thresholds, DEFAULT_THRESHOLDS, "typesafe.thresholds", float, errors)

    if errors:
        raise ConfigError(errors)
    return TriageConfig(
        oneuptime_url=oneuptime_url,
        permission_set=permission_set.strip(),
        accounts=accounts,
        opensearch_clusters=opensearch,
        eks_clusters=eks,
        confluence_space_key=space_key,
        confluence_parent_page_id=parent_page_id,
        slack_default_channel=slack_channel.strip() if slack_channel else None,
        cases_dir=Path(cases_dir).expanduser(),
        limits=limits,
        typesafe_model=model.strip(),
        typesafe_thresholds=thresholds,
    )


def load_config(path: Path) -> TriageConfig:
    if not path.is_file():
        raise ConfigError([f"{path}: file not found"])
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ConfigError([f"{path}: not valid YAML ({exc})"]) from exc
    return parse_config(data)


def default_config_path(skill_dir: Path) -> Path:
    return skill_dir / "config" / CONFIG_FILE_NAME
