# AI Triage Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the safety foundation of the AI Triage skill: validated config and service map, the read-only guard, the AWS permission policy, access verification, preflight, and the installer.

**Architecture:** A personal Claude Code skill installed by copy into `~/.claude/skills/ai-triage/`. A Python package (`scripts/triage/`) holds pure, tested logic; thin command scripts wrap it. One `PreToolUse` hook, declared in the skill's frontmatter, approves validated read commands and blocks everything else that touches AWS, Kubernetes, or OpenSearch.

**Tech Stack:** Python 3.10+ (standard library plus PyYAML 6.0.3), pytest 9.1.1, Bash, AWS CLI v2, `kubectl`, shellcheck (optional lint).

**Spec:** `LLM_Skills/AI_Triage/docs/specs/2026-10-04-ai-triage-design.md`. This plan implements build stage 1 of section 14. It is the first of five plans, one per build stage. Each later plan is written after the one before it is done.

## Global Constraints

- All files live under `LLM_Skills/AI_Triage/`. Every path in this plan is relative to that folder, and every command runs from it.
- Work on the branch `claude-skill`, which the user created for this work. Never commit to `master`. Never push.
- The repository is a public fork. Commit only placeholder account IDs (`111111111111`, `222222222222`) and `example.com` hostnames. Never commit a real `triage-config.yaml`, `service-map.yaml`, or `kubeconfig`.
- Nothing in this plan calls AWS, a cluster, OpenSearch, or OneUptime. Tests use the fake in `tests/fakes.py`. `verify_access.py` is run only by an engineer.
- The skill never changes anything in AWS, Kubernetes, OpenSearch, or OneUptime. No code path may issue a write.
- Every AWS CLI call the skill makes sets `--profile` and `--region` explicitly.
- Triage profile names and kubeconfig context names start with `triage-`.
- The permission set is named `ai-triage-read-only` unless `permission_set` in the config says otherwise.
- The installed location is fixed: `~/.claude/skills/ai-triage/`.
- Python 3.10 or newer. Dependencies are pinned: `PyYAML==6.0.3`, `pytest==9.1.1`.
- Bash scripts start with `set -euo pipefail`, handle errors explicitly, exit with meaningful codes, and print usage text for `--help`.
- Test-first: write the failing test, run it and confirm it fails for the stated reason, then write the code. Do not mark a task done until `./run-tests.sh` passes in full.
- Conventional commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`) with a body that says why. End each commit message with the attribution lines your session provides.
- Do not run the repository's own `npm run lint`, `npm run fix`, or its test suites. This folder is independent of the OneUptime application.
- When spawning a subagent, set its model explicitly: Sonnet for implementation tasks, Opus for task reviews, Fable for the final review.
- Use the `typesafe-ai` skill for development decisions as the user's global rules require: red-phase checks, debugging, and done checks. If it is unavailable, say so before proceeding.

## Review Focus

Five conditions the spec implies and a person would hit. Each is pinned by a named test in the task that owns the code.

1. **A repeated option where the last one wins.** `aws ... --profile triage-x --profile admin` must be blocked, because the AWS CLI and `kubectl` use the last value. Tests: `test_everything_else_is_denied_with_a_reason` in Tasks 5 and 6.
2. **A profile supplied through a shell variable.** `--profile $TRIAGE_PROFILE` cannot be checked and must be blocked. Test: Task 5, same test.
3. **An OpenSearch hostname in different letter case.** `https://OpenSearch.Internal.Example.com` must still be recognised. Test: `test_opensearch_host_is_matched_whatever_its_letter_case` in Task 7.
4. **An account ID written without quotes.** YAML reads it as a number and drops a leading zero. It must be rejected with a message that says to quote it. Test: `test_account_id_must_be_twelve_quoted_digits` in Task 2.
5. **A home folder with a space in its name.** Install, upgrade, and the guard's script recognition must all work. Tests: `test_home_folder_with_a_space_in_its_name` in Task 13 and `test_skill_folder_with_a_space_in_its_path_is_recognised` in Task 7.

## File Structure

```
LLM_Skills/AI_Triage/
  .gitignore                     keeps private config and environments out of git
  README.md                      install, configure, verify, use
  install.sh                     installer and upgrader
  run-tests.sh                   one command to run the suite
  pytest.ini
  requirements-dev.txt
  docs/aws-permissions.md        every permission, why, and setup steps
  docs/verification-notes.md     results of the live check in Task 15
  iam/ai-triage-inline-policy.json
  tools/check_policy_actions.py  manual check of action names against AWS
  skill/ai-triage/
    SKILL.md                     frontmatter with the guard hook; foundation body
    requirements.txt
    config/triage-config.example.yaml
    config/service-map.example.yaml
    scripts/
      guard_hook.sh              hook wrapper; fails closed without Python
      guard_hook.py              hook entry point
      validate_map.py            command: validate config and map
      verify_access.py           command: prove reads work and writes are denied
      preflight.py               command: is a run ready to start
      triage/
        config.py                load and validate the config
        service_map.py           load, validate, and match the service map
        shell_parse.py           split a command line into segments
        verdict.py               allow / deny / ask / pass
        guard_aws.py             rules for one AWS CLI call
        guard_kubectl.py         rules for one kubectl call
        guard.py                 decision for a whole command line
        policy_check.py          static checks on the inline policy
        awscli.py                run one AWS CLI call
        verify.py                identity, read probes, simulator
        preflight.py             readiness checks
  tests/
    conftest.py, fakes.py, test_*.py
```

Each module has one job. The guard is split in four so that the shell splitting, the AWS rules, the `kubectl` rules, and the combined decision can each be read and tested alone.

---

### Task 1: Test harness and public-repository hygiene

**Files:**
- Create: `pytest.ini`
- Create: `requirements-dev.txt`
- Create: `skill/ai-triage/requirements.txt`
- Create: `run-tests.sh`
- Create: `tests/conftest.py`
- Create: `.gitignore`
- Test: `tests/test_repo_hygiene.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `./run-tests.sh [pytest args]`; fixtures `config_data` and `map_data` (fresh `dict` copies of the example files); constants `ROOT`, `SKILL_SRC`, `EXAMPLE_CONFIG`, `EXAMPLE_MAP` in `tests/conftest.py`.

- [ ] **Step 1: Confirm the branch**

```bash
git rev-parse --abbrev-ref HEAD
```

Expected: `claude-skill`. If it prints `master`, stop and report it.

- [ ] **Step 2: Create the harness files**

The harness itself is not reasonably testable before it exists. The hygiene test in step 3 is its first real test.

`pytest.ini`

```ini
[pytest]
testpaths = tests
pythonpath = skill/ai-triage/scripts
```

`skill/ai-triage/requirements.txt`

```text
PyYAML==6.0.3
```

`requirements-dev.txt`

```text
-r skill/ai-triage/requirements.txt
pytest==9.1.1
```

`run-tests.sh`

```bash
#!/usr/bin/env bash
# Run the AI Triage test suite in its own Python environment.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: run-tests.sh [--help] [pytest arguments...]

Creates .venv-dev on first use, installs the pinned test dependencies, lints the
shell scripts when shellcheck is available, and runs pytest.

Examples:
  ./run-tests.sh
  ./run-tests.sh tests/test_guard.py -k kubectl

Exit codes: the exit code of shellcheck or pytest; 1 if setup fails.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv="${root}/.venv-dev"

if [[ ! -x "${venv}/bin/python" ]]; then
  python3 -m venv "${venv}"
fi
"${venv}/bin/python" -m pip install --quiet --disable-pip-version-check -r "${root}/requirements-dev.txt"

# Lint only the shell scripts that exist, so the suite runs while the project is still being built.
shell_scripts=()
for script in "${root}/install.sh" "${root}/run-tests.sh" "${root}/skill/ai-triage/scripts/guard_hook.sh"; do
  if [[ -f "${script}" ]]; then
    shell_scripts+=("${script}")
  fi
done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "${shell_scripts[@]}"
else
  echo "shellcheck not found; skipping the shell lint." >&2
fi

cd "${root}"
exec "${venv}/bin/python" -m pytest "$@"
```

`tests/conftest.py`

```python
"""Shared fixtures."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SKILL_SRC = ROOT / "skill" / "ai-triage"
EXAMPLE_CONFIG = SKILL_SRC / "config" / "triage-config.example.yaml"
EXAMPLE_MAP = SKILL_SRC / "config" / "service-map.example.yaml"


@pytest.fixture
def config_data() -> dict:
    """A fresh, valid config document that a test may mutate."""
    return copy.deepcopy(yaml.safe_load(EXAMPLE_CONFIG.read_text()))


@pytest.fixture
def map_data() -> dict:
    """A fresh, valid service map document that a test may mutate."""
    return copy.deepcopy(yaml.safe_load(EXAMPLE_MAP.read_text()))
```

Then: `chmod +x run-tests.sh`

- [ ] **Step 3: Write the failing hygiene test**

`tests/test_repo_hygiene.py`

```python
"""This folder lives in a public repository. Keep company data out of it."""
import re

from conftest import ROOT, SKILL_SRC

ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
PLACEHOLDER_ACCOUNT_IDS = {"1" * 12, "2" * 12}
SKIPPED_DIRS = {".venv", ".venv-dev", ".pytest_cache", "__pycache__"}
PRIVATE_FILES = ("triage-config.yaml", "service-map.yaml", "kubeconfig")


def text_files():
    for path in ROOT.rglob("*"):
        if path.is_file() and not SKIPPED_DIRS & set(path.relative_to(ROOT).parts):
            try:
                yield path, path.read_text()
            except UnicodeDecodeError:
                continue


def test_only_placeholder_account_ids_appear():
    offenders = {}
    for path, text in text_files():
        found = set(ACCOUNT_ID_RE.findall(text)) - PLACEHOLDER_ACCOUNT_IDS
        if found:
            offenders[str(path.relative_to(ROOT))] = sorted(found)
    assert offenders == {}


def test_private_config_files_are_listed_in_gitignore():
    ignored = (ROOT / ".gitignore").read_text().splitlines()
    for name in PRIVATE_FILES:
        assert f"skill/ai-triage/config/{name}" in ignored, f"{name} must be ignored by git"


def test_no_private_config_file_exists_in_the_source_tree():
    for name in PRIVATE_FILES:
        assert not (SKILL_SRC / "config" / name).exists(), f"{name} must not be created in the repository"
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_repo_hygiene.py`
Expected: FAIL. `test_private_config_files_are_listed_in_gitignore` fails with `FileNotFoundError` for `.gitignore`. The other two tests pass.

- [ ] **Step 5: Add the ignore file**

`.gitignore`

```gitignore
.venv-dev/
.pytest_cache/
__pycache__/
*.pyc
skill/ai-triage/.venv/
skill/ai-triage/config/triage-config.yaml
skill/ai-triage/config/service-map.yaml
skill/ai-triage/config/kubeconfig
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_repo_hygiene.py`
Expected: PASS, 3 passed.

- [ ] **Step 7: Commit**

```bash
git add -A .
git commit -m "chore(ai-triage): add test harness and public-repo hygiene checks" -m "The folder lives in a public fork, so account ids and private config must be kept out from the first commit."
```

### Task 2: Config loader and validator

**Files:**
- Create: `skill/ai-triage/scripts/triage/__init__.py`
- Create: `skill/ai-triage/scripts/triage/config.py`
- Create: `skill/ai-triage/config/triage-config.example.yaml`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: the `config_data` fixture from Task 1.
- Produces: `parse_config(data) -> TriageConfig`, `load_config(path: Path) -> TriageConfig`, `default_config_path(skill_dir: Path) -> Path`, `ConfigError` with `.errors: list[str]`. `TriageConfig` fields: `oneuptime_url`, `permission_set`, `accounts: dict[str, Account]`, `opensearch_clusters`, `eks_clusters`, `confluence_space_key`, `confluence_parent_page_id`, `slack_default_channel`, `cases_dir: Path`, `limits: dict[str, int]`, `typesafe_model`, `typesafe_thresholds`; methods `profiles()`, `opensearch_hosts()`, `kube_contexts()` returning `frozenset[str]`, and `account_for_profile(profile)`. `Account(alias, account_id, profile, regions)`.

- [ ] **Step 1: Write the failing test**

`tests/test_config.py`

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_config.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/__init__.py`

```python
"""Support library for the AI Triage skill."""
```

`skill/ai-triage/scripts/triage/config.py`

```python
"""Load and validate the team config file (triage-config.yaml)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
PROFILE_PREFIX = "triage-"
DEFAULT_PERMISSION_SET = "ai-triage-read-only"
FORBIDDEN_INDEX_PATTERNS = frozenset({"", "*", "_all"})
CONFIG_FILE_NAME = "triage-config.yaml"

DEFAULT_LIMITS = {
    "max_window_hours": 6,
    "logs_insights_max_log_groups": 5,
    "opensearch_max_hits": 50,
    "opensearch_timeout_seconds": 10,
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


def _parse_accounts(raw: dict[str, Any], errors: list[str]) -> dict[str, Account]:
    accounts: dict[str, Account] = {}
    if not raw:
        errors.append("accounts: at least one account is required")
    seen_profiles: set[str] = set()
    for alias, body in raw.items():
        where = f"accounts.{alias}"
        if not isinstance(body, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        raw_account_id = body.get("account_id")
        account_id = raw_account_id if isinstance(raw_account_id, str) else ""
        if not ACCOUNT_ID_RE.match(account_id):
            errors.append(f"{where}.account_id: must be 12 digits written in quotes")
        profile = _text(body, "profile", where, errors)
        if profile and not profile.startswith(PROFILE_PREFIX):
            errors.append(f"{where}.profile: must start with '{PROFILE_PREFIX}'")
        if profile in seen_profiles:
            errors.append(f"{where}.profile: '{profile}' is used by more than one account")
        seen_profiles.add(profile)
        regions = body.get("regions")
        if not isinstance(regions, list) or not regions:
            errors.append(f"{where}.regions: must be a non-empty list")
            regions = []
        for region in regions:
            if not isinstance(region, str) or not REGION_RE.match(region):
                errors.append(f"{where}.regions: '{region}' is not a region name")
        accounts[str(alias)] = Account(str(alias), account_id, profile, tuple(str(r) for r in regions))
    return accounts


def _parse_opensearch(raw: dict[str, Any], accounts: dict[str, Account], errors: list[str]) -> dict[str, OpenSearchCluster]:
    clusters: dict[str, OpenSearchCluster] = {}
    for name, body in raw.items():
        where = f"opensearch_clusters.{name}"
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
            if not isinstance(pattern, str) or pattern.strip() in FORBIDDEN_INDEX_PATTERNS:
                errors.append(f"{where}.allowed_index_patterns: '{pattern}' is too broad")
        time_field = _text(body, "time_field", where, errors)
        clusters[str(name)] = OpenSearchCluster(
            str(name), account, endpoint, parsed.hostname or "", tuple(str(p) for p in patterns), time_field
        )
    return clusters


def _parse_eks(raw: dict[str, Any], accounts: dict[str, Account], errors: list[str]) -> dict[str, EksCluster]:
    clusters: dict[str, EksCluster] = {}
    for name, body in raw.items():
        where = f"eks_clusters.{name}"
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
        if context and not context.startswith(PROFILE_PREFIX):
            errors.append(f"{where}.context: must start with '{PROFILE_PREFIX}'")
        clusters[str(name)] = EksCluster(str(name), account, region, context)
    return clusters


def _parse_numbers(raw: dict[str, Any], defaults: dict[str, Any], where: str, kind: type, errors: list[str]) -> dict[str, Any]:
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
        if kind is float and not 0 <= value <= 1:
            errors.append(f"{where}.{key}: must be between 0 and 1")
            continue
        result[key] = kind(value)
    return result


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
    parent_page_id = str(confluence.get("parent_page_id", "")).strip() if confluence else ""
    if confluence and not parent_page_id:
        errors.append("confluence.parent_page_id: must be set")

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

    limits = _parse_numbers(_section(data, "limits", errors, required=False), DEFAULT_LIMITS, "limits", int, errors)
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
```

`skill/ai-triage/config/triage-config.example.yaml`

```yaml
# Copy to triage-config.yaml and replace every value. This file holds no secrets.
oneuptime:
  url: https://oneuptime.example.com

# Name of the IAM Identity Center permission set the triage profiles use.
permission_set: ai-triage-read-only

accounts:
  prod-main:
    account_id: "111111111111"
    profile: triage-prod-main
    regions: [eu-west-1, us-east-1]
  staging:
    account_id: "222222222222"
    profile: triage-staging
    regions: [eu-west-1]

opensearch_clusters:
  logs-prod:
    account: prod-main
    endpoint: https://opensearch.internal.example.com
    allowed_index_patterns: ["app-logs-*"]
    time_field: "@timestamp"

eks_clusters:
  platform-prod:
    account: prod-main
    region: eu-west-1
    context: triage-platform-prod

confluence:
  space_key: OPS
  parent_page_id: "123456"

slack:
  default_channel: "#incidents"

cases_dir: ~/.ai-triage/cases

limits:
  max_window_hours: 6
  logs_insights_max_log_groups: 5
  opensearch_max_hits: 50
  opensearch_timeout_seconds: 10

typesafe:
  model: jev-latest
  thresholds:   # uncalibrated starting values
    evidence_supports: 0.8
    cause_top_probability: 0.6
    ask_engineer_below: 0.5
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_config.py`
Expected: PASS, 29 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): load and validate the team config" -m "Every later component trusts the config, so all problems are reported at once and unsafe values such as non-triage profiles are rejected."
```

### Task 3: Service map: load, validate, match

**Files:**
- Create: `skill/ai-triage/scripts/triage/service_map.py`
- Create: `skill/ai-triage/scripts/validate_map.py`
- Create: `skill/ai-triage/config/service-map.example.yaml`
- Modify: `tests/test_repo_hygiene.py`
- Test: `tests/test_service_map.py`
- Test: `tests/test_validate_map_cli.py`

**Interfaces:**
- Consumes: `TriageConfig`, `parse_config`, `load_config`, `default_config_path`, `ConfigError` from Task 2.
- Produces: `parse_map(data, config) -> ServiceMap`, `load_map(path, config) -> ServiceMap`, `default_map_path(skill_dir) -> Path`, `MapError` with `.errors`, `MatchKeys.build(monitors=, labels=, hostnames=)`, `match_incident(service_map, incident: MatchKeys) -> MatchResult` where `MatchResult.status` is `"one"`, `"many"`, or `"none"` and `.candidates` is a tuple of `Candidate(service, environment, reasons)`. Command `validate_map.py [--config PATH] [--map PATH]`, exit 0 valid, 1 invalid, 2 usage.

- [ ] **Step 1: Write the failing tests**

`tests/test_service_map.py`

```python
import pytest

from triage.config import parse_config
from triage.service_map import MapError, MatchKeys, load_map, match_incident, parse_map


@pytest.fixture
def config(config_data):
    return parse_config(config_data)


def test_example_map_is_valid(map_data, config):
    smap = parse_map(map_data, config)
    assert set(smap.services) == {"checkout-api", "payments-api"}
    prod = smap.services["checkout-api"].environments["prod"]
    assert prod.account == "prod-main" and prod.depends_on == ("payments-api",)
    assert smap.services["checkout-api"].last_verified == "2026-10-04"


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"].update(account="nope"), "unknown account 'nope'"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"].update(region="us-west-2"), "is not listed for account"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"]["resources"].update(mainframe="x"), "unknown resource key"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"]["resources"]["opensearch"].update(cluster="nope"), "unknown cluster 'nope'"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"]["resources"]["opensearch"].update(index_pattern="other-*"), "outside the allowed patterns"),
        (lambda d: d["services"]["payments-api"]["environments"]["prod"]["resources"]["eks"].update(cluster="nope"), "unknown cluster 'nope'"),
        (lambda d: d["services"]["payments-api"]["environments"]["prod"]["resources"]["eks"].pop("namespace"), "eks.namespace: must be set"),
        (lambda d: d["services"]["checkout-api"]["environments"]["prod"].update(depends_on=["ghost"]), "unknown service 'ghost'"),
        (lambda d: d["services"]["checkout-api"].update(source="guessed"), "source: must be one of"),
        (lambda d: d["services"]["checkout-api"].update(last_verified="yesterday"), "last_verified: must be a date"),
        (lambda d: d["services"]["payments-api"].pop("match"), "needs a match block"),
        (lambda d: d["services"]["payments-api"].update(environments={}), "at least one environment is required"),
        (lambda d: d["services"]["payments-api"]["match"].update(urls=["x"]), "match.urls: unknown key"),
    ],
)
def test_invalid_map_is_rejected(map_data, config, mutate, expected):
    mutate(map_data)
    with pytest.raises(MapError) as excinfo:
        parse_map(map_data, config)
    assert expected in "\n".join(excinfo.value.errors)


def test_environment_match_selects_one_environment(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(monitors=["checkout api"], labels=["Checkout"]))
    assert result.status == "one"
    candidate = result.candidates[0]
    assert (candidate.service, candidate.environment) == ("checkout-api", "prod")
    assert "label:checkout" in candidate.reasons and "monitor:checkout api" in candidate.reasons


def test_service_level_match_alone_is_ambiguous_when_every_environment_has_its_own(map_data, config):
    smap = parse_map(map_data, config)
    assert match_incident(smap, MatchKeys.build(labels=["checkout"])).status == "none"


def test_service_level_match_covers_environments_without_their_own(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(hostnames=["Payments.Example.com."]))
    assert result.status == "one"
    assert (result.candidates[0].service, result.candidates[0].environment) == ("payments-api", "prod")


def test_several_services_matching_is_reported_as_many(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(monitors=["Checkout API", "Payments API"]))
    assert result.status == "many"
    assert {c.service for c in result.candidates} == {"checkout-api", "payments-api"}


def test_no_match(map_data, config):
    smap = parse_map(map_data, config)
    result = match_incident(smap, MatchKeys.build(monitors=["Unknown"]))
    assert result.status == "none" and result.candidates == ()


def test_empty_map_file_is_an_empty_map(tmp_path, config):
    path = tmp_path / "service-map.yaml"
    path.write_text("")
    assert load_map(path, config).services == {}


def test_missing_map_file_is_reported(tmp_path, config):
    with pytest.raises(MapError) as excinfo:
        load_map(tmp_path / "absent.yaml", config)
    assert "file not found" in excinfo.value.errors[0]
```

`tests/test_validate_map_cli.py`

```python
import subprocess
import sys

from conftest import EXAMPLE_CONFIG, EXAMPLE_MAP, SKILL_SRC

SCRIPT = SKILL_SRC / "scripts" / "validate_map.py"


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_valid_files_exit_zero():
    result = run("--config", str(EXAMPLE_CONFIG), "--map", str(EXAMPLE_MAP))
    assert result.returncode == 0
    assert "OK: 2 accounts, 2 services" in result.stdout


def test_invalid_map_exits_one_and_lists_errors(tmp_path):
    bad = tmp_path / "service-map.yaml"
    bad.write_text("services:\n  a:\n    environments: {}\n")
    result = run("--config", str(EXAMPLE_CONFIG), "--map", str(bad))
    assert result.returncode == 1
    assert "Service map is invalid:" in result.stderr
    assert "at least one environment is required" in result.stderr


def test_missing_config_exits_one(tmp_path):
    result = run("--config", str(tmp_path / "none.yaml"), "--map", str(EXAMPLE_MAP))
    assert result.returncode == 1
    assert "Config is invalid:" in result.stderr


def test_unknown_flag_exits_two():
    assert run("--nope").returncode == 2
```

Append this test to the end of `tests/test_repo_hygiene.py`:

```python
def test_example_files_use_the_reserved_example_domain():
    for name in ("triage-config.example.yaml", "service-map.example.yaml"):
        text = (SKILL_SRC / "config" / name).read_text()
        hosts = re.findall(r"[a-z0-9.-]+\.(?:com|net|org|io)\b", text)
        assert hosts and all(host.endswith("example.com") for host in hosts)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `./run-tests.sh tests/test_service_map.py tests/test_validate_map_cli.py tests/test_repo_hygiene.py`
Expected: FAIL. `test_service_map.py` fails at collection with `ModuleNotFoundError: No module named 'triage.service_map'`. The command tests fail because `validate_map.py` does not exist. The new hygiene test fails with `FileNotFoundError` for `service-map.example.yaml`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/service_map.py`

```python
"""Load, validate, and match the service map (service-map.yaml)."""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from triage.config import TriageConfig

MAP_FILE_NAME = "service-map.yaml"
SOURCES = ("confirmed", "discovered")
RESOURCE_KEYS = frozenset(
    {
        "ecs_service",
        "ec2_instances",
        "auto_scaling_group",
        "lambda_functions",
        "eks",
        "load_balancer",
        "api_gateway",
        "cloudfront_distribution",
        "rds",
        "elasticache",
        "dynamodb_tables",
        "efs",
        "sqs_queues",
        "sns_topics",
        "log_groups",
        "opensearch",
    }
)


class MapError(Exception):
    """Raised with every problem found, not just the first."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _normalise(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(str(v).strip().lower().rstrip(".") for v in values if str(v).strip())


@dataclass(frozen=True)
class MatchKeys:
    monitors: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()

    @classmethod
    def build(cls, monitors: Any = (), labels: Any = (), hostnames: Any = ()) -> "MatchKeys":
        return cls(_normalise(monitors), _normalise(labels), _normalise(hostnames))

    def is_empty(self) -> bool:
        return not (self.monitors or self.labels or self.hostnames)

    def hits(self, incident: "MatchKeys") -> tuple[str, ...]:
        """Return one reason per key this block shares with the incident."""
        reasons = [f"monitor:{m}" for m in self.monitors if m in incident.monitors]
        reasons += [f"label:{l}" for l in self.labels if l in incident.labels]
        reasons += [f"hostname:{h}" for h in self.hostnames if h in incident.hostnames]
        return tuple(reasons)


@dataclass(frozen=True)
class Environment:
    name: str
    account: str
    region: str
    resources: dict[str, Any]
    depends_on: tuple[str, ...]
    match: MatchKeys = field(default_factory=MatchKeys)


@dataclass(frozen=True)
class Service:
    name: str
    match: MatchKeys
    environments: dict[str, Environment]
    source: str
    last_verified: str


@dataclass(frozen=True)
class ServiceMap:
    services: dict[str, Service]


@dataclass(frozen=True)
class Candidate:
    service: str
    environment: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MatchResult:
    status: str  # "one" | "many" | "none"
    candidates: tuple[Candidate, ...]


def _parse_match(raw: Any, where: str, errors: list[str]) -> MatchKeys:
    if raw is None:
        return MatchKeys()
    if not isinstance(raw, dict):
        errors.append(f"{where}.match: must be a mapping")
        return MatchKeys()
    for key in raw:
        if key not in ("monitors", "labels", "hostnames"):
            errors.append(f"{where}.match.{key}: unknown key")
    return MatchKeys.build(raw.get("monitors"), raw.get("labels"), raw.get("hostnames"))


def _check_resources(resources: dict[str, Any], where: str, config: TriageConfig, errors: list[str]) -> None:
    for key in resources:
        if key not in RESOURCE_KEYS:
            errors.append(f"{where}.resources.{key}: unknown resource key")
    search = resources.get("opensearch")
    if search is not None:
        if not isinstance(search, dict):
            errors.append(f"{where}.resources.opensearch: must be a mapping")
        else:
            cluster = config.opensearch_clusters.get(str(search.get("cluster")))
            pattern = str(search.get("index_pattern", ""))
            if cluster is None:
                errors.append(f"{where}.resources.opensearch.cluster: unknown cluster '{search.get('cluster')}'")
            elif not any(fnmatchcase(pattern, allowed) for allowed in cluster.allowed_index_patterns):
                errors.append(
                    f"{where}.resources.opensearch.index_pattern: '{pattern}' is outside the allowed patterns"
                )
    eks = resources.get("eks")
    if eks is not None:
        if not isinstance(eks, dict):
            errors.append(f"{where}.resources.eks: must be a mapping")
        else:
            if str(eks.get("cluster")) not in config.eks_clusters:
                errors.append(f"{where}.resources.eks.cluster: unknown cluster '{eks.get('cluster')}'")
            if not str(eks.get("namespace", "")).strip():
                errors.append(f"{where}.resources.eks.namespace: must be set")


def _parse_environment(name: str, raw: Any, where: str, config: TriageConfig, errors: list[str]) -> Environment | None:
    if not isinstance(raw, dict):
        errors.append(f"{where}: must be a mapping")
        return None
    account = str(raw.get("account", ""))
    region = str(raw.get("region", ""))
    if account not in config.accounts:
        errors.append(f"{where}.account: unknown account '{account}'")
    elif region not in config.accounts[account].regions:
        errors.append(f"{where}.region: '{region}' is not listed for account '{account}'")
    resources = raw.get("resources") or {}
    if not isinstance(resources, dict):
        errors.append(f"{where}.resources: must be a mapping")
        resources = {}
    _check_resources(resources, where, config, errors)
    depends_on = raw.get("depends_on") or []
    if not isinstance(depends_on, list):
        errors.append(f"{where}.depends_on: must be a list")
        depends_on = []
    return Environment(
        name=name,
        account=account,
        region=region,
        resources=resources,
        depends_on=tuple(str(d) for d in depends_on),
        match=_parse_match(raw.get("match"), where, errors),
    )


def parse_map(data: Any, config: TriageConfig) -> ServiceMap:
    errors: list[str] = []
    if not isinstance(data, dict) or not isinstance(data.get("services", {}), dict):
        raise MapError(["service map: must be a mapping with a 'services' mapping"])
    services: dict[str, Service] = {}
    for name, raw in (data.get("services") or {}).items():
        where = f"services.{name}"
        if not isinstance(raw, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        match = _parse_match(raw.get("match"), where, errors)
        raw_envs = raw.get("environments")
        if not isinstance(raw_envs, dict) or not raw_envs:
            errors.append(f"{where}.environments: at least one environment is required")
            raw_envs = {}
        environments: dict[str, Environment] = {}
        for env_name, env_raw in raw_envs.items():
            env = _parse_environment(str(env_name), env_raw, f"{where}.environments.{env_name}", config, errors)
            if env is not None:
                environments[str(env_name)] = env
        if match.is_empty() and any(env.match.is_empty() for env in environments.values()):
            errors.append(f"{where}: needs a match block on the service or on every environment")
        source = raw.get("source", "confirmed")
        if source not in SOURCES:
            errors.append(f"{where}.source: must be one of {', '.join(SOURCES)}")
        last_verified = raw.get("last_verified")
        if isinstance(last_verified, datetime.date):
            last_verified = last_verified.isoformat()
        try:
            datetime.date.fromisoformat(str(last_verified))
        except ValueError:
            errors.append(f"{where}.last_verified: must be a date such as 2026-10-04")
        services[str(name)] = Service(str(name), match, environments, str(source), str(last_verified))

    for service in services.values():
        for env in service.environments.values():
            for dependency in env.depends_on:
                if dependency not in services:
                    errors.append(
                        f"services.{service.name}.environments.{env.name}.depends_on: unknown service '{dependency}'"
                    )
    if errors:
        raise MapError(errors)
    return ServiceMap(services)


def load_map(path: Path, config: TriageConfig) -> ServiceMap:
    if not path.is_file():
        raise MapError([f"{path}: file not found"])
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise MapError([f"{path}: not valid YAML ({exc})"]) from exc
    return parse_map(data if data is not None else {"services": {}}, config)


def default_map_path(skill_dir: Path) -> Path:
    return skill_dir / "config" / MAP_FILE_NAME


def match_incident(service_map: ServiceMap, incident: MatchKeys) -> MatchResult:
    """Find the service environments an incident points at.

    An environment with its own match block is chosen only when that block
    hits. Environments without one inherit the service-level match.
    """
    candidates: list[Candidate] = []
    for service in service_map.services.values():
        service_hits = service.match.hits(incident)
        own_hits = {name: env.match.hits(incident) for name, env in service.environments.items()}
        if any(own_hits.values()):
            for name, hits in own_hits.items():
                if hits:
                    candidates.append(Candidate(service.name, name, service_hits + hits))
        elif service_hits:
            for name, env in service.environments.items():
                if env.match.is_empty():
                    candidates.append(Candidate(service.name, name, service_hits))
    status = "none" if not candidates else "one" if len(candidates) == 1 else "many"
    return MatchResult(status, tuple(candidates))
```

`skill/ai-triage/scripts/validate_map.py`

```python
#!/usr/bin/env python3
"""Validate the team config and the service map.

Exit codes: 0 valid, 1 invalid, 2 usage error.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.config import ConfigError, default_config_path, load_config
from triage.service_map import MapError, default_map_path, load_map

SKILL_DIR = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_map", description="Validate triage-config.yaml and service-map.yaml."
    )
    parser.add_argument("--config", type=Path, default=default_config_path(SKILL_DIR), help="path to the config file")
    parser.add_argument("--map", type=Path, default=default_map_path(SKILL_DIR), help="path to the service map")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("Config is invalid:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    try:
        service_map = load_map(args.map, config)
    except MapError as exc:
        print("Service map is invalid:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {len(config.accounts)} accounts, {len(service_map.services)} services")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

`skill/ai-triage/config/service-map.example.yaml`

```yaml
# Copy to service-map.yaml and replace with your services.
# A match block on the service applies to every environment. An environment may
# carry its own match block when monitors differ per environment.
services:
  checkout-api:
    match:
      labels: ["checkout"]
    environments:
      prod:
        match:
          monitors: ["Checkout API"]
          hostnames: ["checkout.example.com"]
        account: prod-main
        region: eu-west-1
        resources:
          ecs_service: checkout/checkout-api
          load_balancer: checkout-prod
          rds: checkout-prod-db
          elasticache: checkout-prod-redis
          log_groups: ["/ecs/checkout-api"]
          opensearch:
            cluster: logs-prod
            index_pattern: "app-logs-checkout-*"
            filter: {service: checkout-api}
        depends_on: ["payments-api"]
      staging:
        match:
          monitors: ["Checkout API (staging)"]
          hostnames: ["checkout.staging.example.com"]
        account: staging
        region: eu-west-1
        resources:
          ecs_service: checkout/checkout-api
          log_groups: ["/ecs/checkout-api"]
    source: confirmed          # confirmed | discovered
    last_verified: 2026-10-04
  payments-api:
    match:
      monitors: ["Payments API"]
      hostnames: ["payments.example.com"]
    environments:
      prod:
        account: prod-main
        region: eu-west-1
        resources:
          eks:
            cluster: platform-prod
            namespace: payments
            workloads: ["deployment/payments-api"]
          dynamodb_tables: ["payments-ledger"]
          sqs_queues: ["payments-events"]
    source: discovered
    last_verified: 2026-10-04
```

Then: `chmod +x skill/ai-triage/scripts/validate_map.py`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `./run-tests.sh tests/test_service_map.py tests/test_validate_map_cli.py tests/test_repo_hygiene.py`
Expected: PASS, 29 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): add the service map with validation and incident matching" -m "The map decides which account and resources a run looks at, so a stale or malformed entry must be caught before a run starts."
```

### Task 4: Shell command splitter

**Files:**
- Create: `skill/ai-triage/scripts/triage/shell_parse.py`
- Test: `tests/test_shell_parse.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `split_command(command: str) -> list[Segment]`; `Segment(argv: tuple[str, ...], env: tuple[str, ...], writes_file: bool, preceded_by: str)`; `Unparseable` raised for multi-line commands, command substitution, process substitution, here-documents, subshells, unbalanced quotes, and a redirect with no target.

- [ ] **Step 1: Write the failing test**

`tests/test_shell_parse.py`

```python
import pytest

from triage.shell_parse import Unparseable, split_command


def argvs(command):
    return [segment.argv for segment in split_command(command)]


def test_single_command():
    [segment] = split_command("aws ecs list-clusters --profile triage-a --region eu-west-1")
    assert segment.argv[:3] == ("aws", "ecs", "list-clusters")
    assert segment.env == () and segment.writes_file is False and segment.preceded_by == ""


def test_pipes_and_lists_are_split_and_remember_their_separator():
    segments = split_command("aws a b | jq . && echo ok ; echo done || true &")
    assert [s.argv for s in segments] == [("aws", "a", "b"), ("jq", "."), ("echo", "ok"), ("echo", "done"), ("true",)]
    assert [s.preceded_by for s in segments] == ["", "|", "&&", ";", "||"]


def test_quoted_operators_stay_inside_their_argument():
    assert argvs("aws logs filter-log-events --filter-pattern '\"ERROR\" | x'") == [
        ("aws", "logs", "filter-log-events", "--filter-pattern", '"ERROR" | x')
    ]


def test_leading_assignments_are_separated_from_argv():
    [segment] = split_command("FOO=1 AWS_PROFILE=admin aws s3 ls")
    assert segment.env == ("FOO=1", "AWS_PROFILE=admin")
    assert segment.argv == ("aws", "s3", "ls")


@pytest.mark.parametrize(
    "command",
    ["aws a b 2>/dev/null", "aws a b > /dev/null 2>&1", "aws a b 2>&1 | jq .", "jq . < input.json"],
)
def test_harmless_redirects_do_not_count_as_writes(command):
    first = split_command(command)[0]
    assert first.writes_file is False
    assert "2" not in first.argv and "/dev/null" not in first.argv


@pytest.mark.parametrize("command", ["aws a b > out.json", "aws a b >> out.json", "aws a b &> all.txt"])
def test_redirect_to_a_file_is_flagged(command):
    assert split_command(command)[0].writes_file is True


def test_line_continuation_is_joined():
    assert argvs("aws ecs \\\n  list-clusters") == [("aws", "ecs", "list-clusters")]


@pytest.mark.parametrize(
    "command",
    [
        "echo $(aws sts get-caller-identity)",
        "echo `aws sts get-caller-identity`",
        "diff <(aws a b) <(aws c d)",
        "cat <<EOF\nhello\nEOF",
        "aws a b\naws c d",
        "(aws a b)",
        "aws a b 'unterminated",
        "aws a b >",
    ],
)
def test_unsupported_shell_features_are_unparseable(command):
    with pytest.raises(Unparseable):
        split_command(command)


def test_empty_command_has_no_segments():
    assert split_command("   ") == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_shell_parse.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.shell_parse'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/shell_parse.py`

```python
"""Split a shell command line into simple command segments.

This is deliberately conservative. Anything it cannot split with confidence
raises Unparseable, and the guard then refuses to auto-approve the command.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

PUNCTUATION = set("();<>|&")
SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&"})
REDIRECTS = frozenset({">", ">>", "<", ">&", "<&", "&>", "&>>", ">|"})
HARMLESS_TARGETS = frozenset({"/dev/null"})
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
UNSUPPORTED_SNIPPETS = ("$(", "`", "<(", ">(", "<<")


class Unparseable(Exception):
    """The command uses shell features this splitter does not model."""


@dataclass(frozen=True)
class Segment:
    argv: tuple[str, ...]
    env: tuple[str, ...]
    writes_file: bool
    preceded_by: str  # the separator before this segment, "" for the first


def _is_operator(token: str) -> bool:
    return bool(token) and all(char in PUNCTUATION for char in token)


def split_command(command: str) -> list[Segment]:
    text = command.replace("\\\n", " ").strip()
    if "\n" in text:
        raise Unparseable("multi-line command")
    for snippet in UNSUPPORTED_SNIPPETS:
        if snippet in text:
            raise Unparseable(f"contains {snippet}")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise Unparseable(str(exc)) from exc

    segments: list[Segment] = []
    words: list[str] = []
    writes_file = False
    preceded_by = ""

    def flush(next_separator: str) -> None:
        nonlocal words, writes_file, preceded_by
        env: list[str] = []
        while words and ASSIGNMENT_RE.match(words[0]):
            env.append(words.pop(0))
        if words or env:
            segments.append(Segment(tuple(words), tuple(env), writes_file, preceded_by))
        words, writes_file, preceded_by = [], False, next_separator

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not _is_operator(token):
            words.append(token)
            index += 1
            continue
        if token in SEPARATORS:
            flush(token)
            index += 1
            continue
        if token in REDIRECTS:
            if index + 1 >= len(tokens) or _is_operator(tokens[index + 1]):
                raise Unparseable("redirect without a target")
            target = tokens[index + 1]
            if words and words[-1] in ("1", "2") and token != "<":
                words.pop()  # a file descriptor number such as the 2 in 2>/dev/null
            duplicates_descriptor = token in (">&", "<&") and (target.isdigit() or target == "-")
            if token != "<" and target not in HARMLESS_TARGETS and not duplicates_descriptor:
                writes_file = True
            index += 2
            continue
        raise Unparseable(f"unsupported operator {token}")
    flush("")
    return segments
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_shell_parse.py`
Expected: PASS, 21 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): split shell command lines for the guard" -m "The guard must judge each command in a pipeline or list separately, and must refuse to auto-approve anything it cannot split with confidence."
```

### Task 5: Guard rules for AWS CLI calls

**Files:**
- Create: `skill/ai-triage/scripts/triage/verdict.py`
- Create: `skill/ai-triage/scripts/triage/guard_aws.py`
- Test: `tests/test_guard_aws.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Verdict(kind: str, reason: str = "")` with kinds `ALLOW`, `DENY`, `ASK`, `PASS`; `strictest(verdicts: list[Verdict]) -> Verdict` (deny beats ask beats pass beats allow); `check_aws(argv: tuple[str, ...], env: tuple[str, ...], profiles: frozenset[str]) -> Verdict`.

- [ ] **Step 1: Write the failing test**

`tests/test_guard_aws.py`

```python
import shlex

import pytest

from triage.guard_aws import check_aws
from triage.verdict import ALLOW, ASK, DENY

PROFILES = frozenset({"triage-prod-main", "triage-staging"})
OK = "--profile triage-prod-main --region eu-west-1"


def verdict(command, env=()):
    return check_aws(tuple(shlex.split(command)), tuple(env), PROFILES)


@pytest.mark.parametrize(
    "command",
    [
        f"aws ecs describe-services --cluster a --services b {OK}",
        f"aws --profile triage-staging --region eu-west-1 --output json rds describe-db-instances",
        f"aws logs filter-log-events --log-group-name /x {OK}",
        f"aws logs start-query --log-group-name /x --start-time 1 --end-time 2 --query-string 'fields @message' {OK}",
        f"aws logs get-query-results --query-id abc {OK}",
        f"aws cloudtrail lookup-events --max-results 5 {OK}",
        f"aws rds download-db-log-file-portion --db-instance-identifier d --log-file-name f {OK}",
        f"aws iam simulate-principal-policy --policy-source-arn arn --action-names ecs:StopTask {OK}",
        f"aws sts get-caller-identity {OK}",
        f"aws lambda get-function-configuration --function-name f {OK}",
        f"aws ssm get-parameter --name /app/url {OK}",
        f"aws ecr batch-get-repository-scanning-configuration --repository-names r {OK}",
        f"aws s3 ls {OK}",
        f"aws ecs describe-services --profile=triage-prod-main --region=eu-west-1 --cluster a",
        f"aws ecs help {OK}",
        "aws --version",
        "aws configure list-profiles",
        f"/usr/local/bin/aws ecs list-clusters {OK}",
    ],
)
def test_reads_with_a_triage_profile_are_allowed(command):
    assert verdict(command).kind == ALLOW


@pytest.mark.parametrize(
    "command, reason",
    [
        ("aws ecs describe-services --cluster a --region eu-west-1", "must set --profile"),
        ("aws ecs describe-services --cluster a --profile admin --region eu-west-1", "not a triage profile"),
        ("aws ecs describe-services --cluster a --profile triage-prod-main", "must set --region"),
        (f"aws ecs update-service --cluster a --service b --desired-count 0 {OK}", "not a known read"),
        (f"aws ecs stop-task --task t {OK}", "not a known read"),
        (f"aws ec2 terminate-instances --instance-ids i-1 {OK}", "not a known read"),
        (f"aws s3 rm s3://bucket/key {OK}", "not a read-only listing"),
        (f"aws s3 cp s3://bucket/key - {OK}", "not a read-only listing"),
        (f"aws secretsmanager get-secret-value --secret-id s {OK}", "returns secrets"),
        (f"aws secretsmanager batch-get-secret-value --secret-id-list s {OK}", "returns secrets"),
        (f"aws ecr get-login-password {OK}", "returns secrets"),
        (f"aws lambda get-function --function-name f {OK}", "returns secrets"),
        (f"aws s3api get-object --bucket b --key k out {OK}", "returns secrets"),
        (f"aws dynamodb get-item --table-name t --key x {OK}", "returns secrets"),
        (f"aws sts get-session-token {OK}", "returns secrets"),
        (f"aws ssm get-parameter --name /app/secret --with-decryption {OK}", "--with-decryption"),
        (f"aws ssm start-session --target i-1 {OK}", "not a known read"),
        (f"aws ecs execute-command --cluster a --task t --command sh {OK}", "not a known read"),
        (f"aws ecs describe-services --debug {OK}", "--debug"),
        ("aws configure set region eu-west-1", "changes local AWS CLI settings"),
        ("aws ecs list-clusters --profile triage-prod-main --profile admin --region eu-west-1", "profile 'admin' is not a triage profile"),
        ("aws ecs list-clusters --profile admin --profile=triage-prod-main --region eu-west-1", "profile 'admin' is not a triage profile"),
        ("aws ecs list-clusters --profile $TRIAGE_PROFILE --region eu-west-1", "is not a triage profile"),
        ("aws sso login --profile triage-prod-main", "sign in yourself"),
    ],
)
def test_everything_else_is_denied_with_a_reason(command, reason):
    result = verdict(command)
    assert result.kind == DENY
    assert reason in result.reason


@pytest.mark.parametrize(
    "command, env",
    [
        (f"aws ecs describe-services {OK}", ("AWS_PROFILE=admin",)),
        (f"aws ecs describe-services --endpoint-url http://localhost:4566 {OK}", ()),
        (f"aws ecs {OK}", ()),
        ("aws", ()),
    ],
)
def test_ambiguous_invocations_ask(command, env):
    assert verdict(command, env).kind == ASK
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_guard_aws.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.guard_aws'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/verdict.py`

```python
"""The outcome of checking one command."""
from __future__ import annotations

from dataclasses import dataclass

ALLOW = "allow"
DENY = "deny"
ASK = "ask"
PASS = "pass"  # no opinion: the normal permission flow decides

# Higher wins when several segments of one command line disagree.
PRECEDENCE = {DENY: 3, ASK: 2, PASS: 1, ALLOW: 0}


@dataclass(frozen=True)
class Verdict:
    kind: str
    reason: str = ""


def strictest(verdicts: list[Verdict]) -> Verdict:
    if not verdicts:
        return Verdict(PASS)
    return max(verdicts, key=lambda verdict: PRECEDENCE[verdict.kind])
```

`skill/ai-triage/scripts/triage/guard_aws.py`

```python
"""Decide whether one AWS CLI invocation is a triage read."""
from __future__ import annotations

from triage.verdict import ALLOW, ASK, DENY, Verdict

VALUE_OPTIONS = frozenset(
    {
        "--profile",
        "--region",
        "--output",
        "--query",
        "--endpoint-url",
        "--color",
        "--ca-bundle",
        "--cli-read-timeout",
        "--cli-connect-timeout",
        "--cli-binary-format",
    }
)
READ_PREFIXES = ("describe-", "list-", "get-", "batch-get-")
READ_EXACT = frozenset(
    {
        ("cloudtrail", "lookup-events"),
        ("logs", "filter-log-events"),
        ("logs", "start-query"),
        ("logs", "stop-query"),
        ("rds", "download-db-log-file-portion"),
        ("iam", "simulate-principal-policy"),
        ("route53", "test-dns-answer"),
        ("s3", "ls"),
    }
)
# Operations that look like reads but return secrets, credentials, or stored data.
DENY_EXACT = frozenset(
    {
        ("secretsmanager", "get-secret-value"),
        ("secretsmanager", "batch-get-secret-value"),
        ("ec2", "get-password-data"),
        ("ecr", "get-login-password"),
        ("ecr", "get-authorization-token"),
        ("ecr", "get-download-url-for-layer"),
        ("ecr", "batch-get-image"),
        ("eks", "get-token"),
        ("lambda", "get-function"),
        ("s3api", "get-object"),
        ("sts", "get-session-token"),
        ("sts", "get-federation-token"),
        ("dynamodb", "get-item"),
        ("dynamodb", "batch-get-item"),
        ("kinesis", "get-records"),
        ("kinesis", "get-shard-iterator"),
        ("codecommit", "get-file"),
        ("codecommit", "get-blob"),
    }
)
LOCAL_READS = frozenset({("configure", "list"), ("configure", "list-profiles")})


def _option_values(argv: tuple[str, ...], name: str) -> list[str]:
    """Every value given for an option. The AWS CLI lets an option repeat and uses the last."""
    values: list[str] = []
    for index, token in enumerate(argv):
        if token == name and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith(name + "="):
            values.append(token.split("=", 1)[1])
    return values


def _service_and_operation(argv: tuple[str, ...]) -> tuple[str | None, str | None]:
    positionals: list[str] = []
    index = 1
    while index < len(argv) and len(positionals) < 2:
        token = argv[index]
        if token.startswith("-"):
            index += 2 if token in VALUE_OPTIONS else 1
            continue
        positionals.append(token)
        index += 1
    positionals += [None, None]
    return positionals[0], positionals[1]


def check_aws(argv: tuple[str, ...], env: tuple[str, ...], profiles: frozenset[str]) -> Verdict:
    if any(assignment.startswith("AWS_") for assignment in env):
        return Verdict(ASK, "AWS_* environment variables are set on the command line")
    if "--debug" in argv:
        return Verdict(DENY, "--debug prints request signing details")
    if _option_values(argv, "--endpoint-url"):
        return Verdict(ASK, "--endpoint-url redirects the request")

    service, operation = _service_and_operation(argv)
    if service is None:
        return Verdict(ALLOW, "version check") if "--version" in argv else Verdict(ASK, "no AWS service given")
    if (service, operation) in LOCAL_READS:
        return Verdict(ALLOW, "reads local AWS CLI settings")
    if service == "configure":
        return Verdict(DENY, "changes local AWS CLI settings")
    if service == "sso":
        return Verdict(DENY, "sign in yourself with: aws sso login --profile <triage profile>")

    given_profiles = _option_values(argv, "--profile")
    if not given_profiles:
        return Verdict(DENY, "every AWS command must set --profile to a triage profile")
    for profile in given_profiles:
        if profile not in profiles:
            return Verdict(DENY, f"profile '{profile}' is not a triage profile")
    if not _option_values(argv, "--region"):
        return Verdict(DENY, "every AWS command must set --region")
    if operation is None:
        return Verdict(ASK, f"no operation given for aws {service}")
    if operation == "help":
        return Verdict(ALLOW, "help text")
    if (service, operation) in DENY_EXACT:
        return Verdict(DENY, f"aws {service} {operation} returns secrets, credentials, or stored data")
    if "--with-decryption" in argv:
        return Verdict(DENY, "--with-decryption reads encrypted values")
    if service == "s3" and operation != "ls":
        return Verdict(DENY, f"aws s3 {operation} is not a read-only listing")
    if (service, operation) in READ_EXACT or operation.startswith(READ_PREFIXES):
        return Verdict(ALLOW, f"aws {service} {operation} is a read")
    return Verdict(DENY, f"aws {service} {operation} is not a known read operation")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_guard_aws.py`
Expected: PASS, 46 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): allow only read AWS calls that use a triage profile" -m "The permission set makes writes impossible, but only if it is the identity in use. This rule set makes sure it is, and also blocks reads that return secrets or stored data."
```

### Task 6: Guard rules for kubectl calls

**Files:**
- Create: `skill/ai-triage/scripts/triage/guard_kubectl.py`
- Test: `tests/test_guard_kubectl.py`

**Interfaces:**
- Consumes: `Verdict`, `ALLOW`, `ASK`, `DENY` from Task 5.
- Produces: `check_kubectl(argv: tuple[str, ...], env: tuple[str, ...], kubeconfig: str, contexts: frozenset[str]) -> Verdict`.

- [ ] **Step 1: Write the failing test**

`tests/test_guard_kubectl.py`

```python
import shlex

import pytest

from triage.guard_kubectl import check_kubectl
from triage.verdict import ALLOW, ASK, DENY

KUBECONFIG = "/home/eng/.claude/skills/ai-triage/config/kubeconfig"
CONTEXTS = frozenset({"triage-platform-prod"})
OK = f"--kubeconfig {KUBECONFIG} --context triage-platform-prod"


def verdict(command, env=()):
    return check_kubectl(tuple(shlex.split(command)), tuple(env), KUBECONFIG, CONTEXTS)


@pytest.mark.parametrize(
    "command",
    [
        f"kubectl {OK} -n payments get pods -o wide",
        f"kubectl {OK} get pods -A",
        f"kubectl {OK} --namespace payments describe deployment payments-api",
        f"kubectl {OK} -n payments logs payments-api-123 --since 30m --tail 200",
        f"kubectl {OK} -n payments logs deploy/payments-api --previous --tail=100",
        f"kubectl {OK} -n payments events --for deployment/payments-api",
        f"kubectl {OK} -n payments rollout status deployment/payments-api",
        f"kubectl {OK} -n payments rollout history deployment/payments-api",
        f"kubectl {OK} -n payments get pods,deployments,events",
        f"kubectl {OK} get namespaces",
        f"kubectl {OK} get nodes -o wide",
        f"kubectl {OK} top nodes",
        f"kubectl {OK} -n payments top pods",
        f"kubectl {OK} auth can-i list pods -n payments",
        f"kubectl {OK} version",
        f"kubectl {OK} api-resources",
        f"kubectl --kubeconfig={KUBECONFIG} --context=triage-platform-prod -n payments get configmap app-config -o yaml",
    ],
)
def test_bounded_reads_with_the_triage_kubeconfig_are_allowed(command):
    assert verdict(command).kind == ALLOW


@pytest.mark.parametrize(
    "command, reason",
    [
        ("kubectl --context triage-platform-prod -n payments get pods", "must set --kubeconfig"),
        ("kubectl --kubeconfig /home/eng/.kube/config --context triage-platform-prod -n payments get pods", "must use the triage kubeconfig"),
        (f"kubectl --kubeconfig {KUBECONFIG} -n payments get pods", "must set --context"),
        (f"kubectl --kubeconfig {KUBECONFIG} --context admin-prod -n payments get pods", "not a triage context"),
        (f"kubectl {OK} get pods", "set a namespace"),
        (f"kubectl {OK} --context admin-prod -n payments get pods", "not a triage context"),
        (f"kubectl {OK} --kubeconfig=/home/eng/.kube/config -n payments get pods", "must use the triage kubeconfig"),
        (f"kubectl {OK} -n payments delete pod p", "kubectl delete is not a read"),
        (f"kubectl {OK} -n payments apply -f manifest.yaml", "kubectl apply is not a read"),
        (f"kubectl {OK} -n payments exec -it p -- sh", "kubectl exec is not a read"),
        (f"kubectl {OK} -n payments port-forward svc/x 8080:80", "kubectl port-forward is not a read"),
        (f"kubectl {OK} -n payments scale deployment/x --replicas=0", "kubectl scale is not a read"),
        (f"kubectl {OK} -n payments edit deployment x", "kubectl edit is not a read"),
        (f"kubectl {OK} -n payments rollout restart deployment/x", "kubectl rollout restart is not a read"),
        (f"kubectl {OK} -n payments rollout undo deployment/x", "kubectl rollout undo is not a read"),
        (f"kubectl {OK} config view", "kubectl config is not a read"),
        (f"kubectl {OK} -n payments get secrets", "secrets is not allowed"),
        (f"kubectl {OK} -n payments get secret/db -o yaml", "secrets is not allowed"),
        (f"kubectl {OK} -n payments get pods,secrets", "secrets is not allowed"),
        (f"kubectl {OK} -n payments describe secret db", "secrets is not allowed"),
        (f"kubectl {OK} -n payments logs p", "must be bounded"),
        (f"kubectl {OK} -n payments logs p --tail 10 -f", "never ends"),
        (f"kubectl {OK} -n payments get pods -w", "never ends"),
        (f"kubectl {OK} get --raw /api/v1/namespaces/payments/secrets", "--raw is not allowed"),
        (f"kubectl {OK} -n payments get pods --as system:admin", "--as is not allowed"),
        (f"kubectl {OK} -n payments get pods --token abc", "--token is not allowed"),
    ],
)
def test_everything_else_is_denied_with_a_reason(command, reason):
    result = verdict(command)
    assert result.kind == DENY
    assert reason in result.reason


def test_kubeconfig_environment_override_asks():
    assert verdict(f"kubectl {OK} -n payments get pods", env=("KUBECONFIG=/tmp/other",)).kind == ASK


def test_no_verb_asks():
    assert verdict(f"kubectl {OK}").kind == ASK


def test_home_relative_kubeconfig_is_accepted(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    command = "kubectl --kubeconfig ~/.claude/skills/ai-triage/config/kubeconfig --context triage-platform-prod -n p get pods"
    assert verdict(command).kind == ALLOW
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_guard_kubectl.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.guard_kubectl'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/guard_kubectl.py`

```python
"""Decide whether one kubectl invocation is a triage read."""
from __future__ import annotations

import os

from triage.verdict import ALLOW, ASK, DENY, Verdict

VALUE_OPTIONS = frozenset(
    {
        "--kubeconfig",
        "--context",
        "-n",
        "--namespace",
        "--cluster",
        "--user",
        "--request-timeout",
        "-o",
        "--output",
        "-l",
        "--selector",
        "--field-selector",
        "--sort-by",
        "--since",
        "--since-time",
        "--tail",
        "-c",
        "--container",
        "--limit-bytes",
        "--chunk-size",
        "--max-log-requests",
    }
)
FORBIDDEN_OPTIONS = ("--as", "--as-group", "--token", "--server", "-s", "--raw", "--insecure-skip-tls-verify")
UNBOUNDED_OPTIONS = ("-f", "--follow", "-w", "--watch", "--watch-only")
LOG_BOUNDS = ("--since", "--since-time", "--tail", "--limit-bytes")
READ_VERBS = frozenset({"get", "describe", "logs", "events", "top", "version", "api-resources", "api-versions", "explain"})
READ_SUBCOMMANDS = {"rollout": frozenset({"status", "history"}), "auth": frozenset({"can-i", "whoami"})}
NAMESPACED_VERBS = frozenset({"get", "describe", "logs", "events", "top", "rollout"})
CLUSTER_SCOPED = frozenset(
    {
        "namespaces", "namespace", "ns",
        "nodes", "node", "no",
        "persistentvolumes", "persistentvolume", "pv",
        "storageclasses", "storageclass", "sc",
        "customresourcedefinitions", "customresourcedefinition", "crd", "crds",
        "clusterroles", "clusterrolebindings", "ingressclasses", "priorityclasses",
    }
)
SECRET_NAMES = frozenset({"secret", "secrets"})


def _has_option(argv: tuple[str, ...], names: tuple[str, ...]) -> str | None:
    for token in argv[1:]:
        for name in names:
            if token == name or token.startswith(name + "="):
                return name
    return None


def _option_values(argv: tuple[str, ...], name: str) -> list[str]:
    """Every value given for an option. kubectl lets an option repeat and uses the last."""
    values: list[str] = []
    for index, token in enumerate(argv):
        if token == name and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith(name + "="):
            values.append(token.split("=", 1)[1])
    return values


def _positionals(argv: tuple[str, ...]) -> list[str]:
    result: list[str] = []
    index = 1
    while index < len(argv):
        token = argv[index]
        if token.startswith("-"):
            index += 2 if token in VALUE_OPTIONS else 1
            continue
        result.append(token)
        index += 1
    return result


def _resource_kinds(arguments: list[str]) -> set[str]:
    """Resource kinds named by `get pods,secrets` or `describe secret/x`."""
    kinds: set[str] = set()
    for argument in arguments:
        for part in argument.split(","):
            kinds.add(part.split("/", 1)[0].split(".", 1)[0].lower())
    return kinds


def check_kubectl(argv: tuple[str, ...], env: tuple[str, ...], kubeconfig: str, contexts: frozenset[str]) -> Verdict:
    if any(assignment.startswith("KUBECONFIG=") for assignment in env):
        return Verdict(ASK, "KUBECONFIG is set on the command line")
    forbidden = _has_option(argv, FORBIDDEN_OPTIONS)
    if forbidden:
        return Verdict(DENY, f"kubectl {forbidden} is not allowed during triage")

    given_kubeconfigs = _option_values(argv, "--kubeconfig")
    if not given_kubeconfigs:
        return Verdict(DENY, f"every kubectl command must set --kubeconfig {kubeconfig}")
    for given in given_kubeconfigs:
        if os.path.normpath(os.path.expanduser(given)) != os.path.normpath(kubeconfig):
            return Verdict(DENY, "kubectl must use the triage kubeconfig, not another one")
    given_contexts = _option_values(argv, "--context")
    if not given_contexts:
        return Verdict(DENY, "every kubectl command must set --context to a triage context")
    for context in given_contexts:
        if context not in contexts:
            return Verdict(DENY, f"context '{context}' is not a triage context")

    positionals = _positionals(argv)
    if not positionals:
        return Verdict(ASK, "no kubectl verb given")
    verb, rest = positionals[0], positionals[1:]
    if verb in READ_SUBCOMMANDS:
        if not rest or rest[0] not in READ_SUBCOMMANDS[verb]:
            return Verdict(DENY, f"kubectl {verb} {rest[0] if rest else ''} is not a read".rstrip())
        rest = rest[1:]
    elif verb not in READ_VERBS:
        return Verdict(DENY, f"kubectl {verb} is not a read")

    unbounded = _has_option(argv, UNBOUNDED_OPTIONS)
    if unbounded:
        return Verdict(DENY, f"kubectl {unbounded} never ends; bound the output instead")
    if verb == "logs" and _has_option(argv, LOG_BOUNDS) is None:
        return Verdict(DENY, "kubectl logs must be bounded with --since, --since-time, or --tail")
    kinds = _resource_kinds(rest[:1]) if verb in ("get", "describe") else set()
    if kinds & SECRET_NAMES:
        return Verdict(DENY, "reading Kubernetes secrets is not allowed")

    has_namespace = _has_option(argv, ("-n", "--namespace", "-A", "--all-namespaces")) is not None
    cluster_scoped = bool(kinds) and kinds <= CLUSTER_SCOPED
    if verb == "top" and rest[:1] and rest[0] in CLUSTER_SCOPED:
        cluster_scoped = True
    if verb in NAMESPACED_VERBS and not has_namespace and not cluster_scoped:
        return Verdict(DENY, "set a namespace with -n <namespace> or -A")
    return Verdict(ALLOW, f"kubectl {verb} is a read")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_guard_kubectl.py`
Expected: PASS, 46 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): allow only bounded read kubectl calls on triage contexts" -m "The EKS view policy blocks writes inside the cluster, but the engineer's own kubeconfig may hold broader contexts. This rule set keeps a run on the triage kubeconfig."
```

### Task 7: Guard decision for a whole command line

**Files:**
- Create: `skill/ai-triage/scripts/triage/guard.py`
- Test: `tests/test_guard.py`

**Interfaces:**
- Consumes: `split_command`, `Segment`, `Unparseable` (Task 4); `check_aws` (Task 5); `check_kubectl` (Task 6); `Verdict`, `strictest` (Task 5); `TriageConfig` (Task 2).
- Produces: `GuardContext(profiles, kubeconfig, kube_contexts, opensearch_hosts, skill_dir)`; `context_from_config(config, skill_dir: Path) -> GuardContext`; `decide(command: str, context: GuardContext | None, context_error: str = "") -> Verdict`; `is_sensitive(command: str, hosts=frozenset()) -> bool`; constant `KUBECONFIG_NAME = "kubeconfig"`. The OpenSearch tool that Stage 2 adds must be named `opensearch_query.py`.

- [ ] **Step 1: Write the failing test**

`tests/test_guard.py`

```python
import pytest

from triage.config import parse_config
from triage.guard import GuardContext, context_from_config, decide
from triage.verdict import ALLOW, ASK, DENY, PASS

SKILL = "/home/eng/.claude/skills/ai-triage"
PY = f"{SKILL}/.venv/bin/python"
CONTEXT = GuardContext(
    profiles=frozenset({"triage-prod-main"}),
    kubeconfig=f"{SKILL}/config/kubeconfig",
    kube_contexts=frozenset({"triage-platform-prod"}),
    opensearch_hosts=frozenset({"opensearch.internal.example.com"}),
    skill_dir=SKILL,
)
AWS_OK = "--profile triage-prod-main --region eu-west-1"
KUBE_OK = f"--kubeconfig {SKILL}/config/kubeconfig --context triage-platform-prod -n payments"


def kind(command, context=CONTEXT):
    return decide(command, context).kind


@pytest.mark.parametrize(
    "command",
    [
        f"aws ecs describe-services --cluster a --services b {AWS_OK}",
        f"aws ecs describe-services --cluster a {AWS_OK} | jq '.services[0].events[:5]'",
        f"aws ecs list-tasks --cluster a {AWS_OK} 2>/dev/null | head -20",
        f"aws ecs list-clusters {AWS_OK} && aws rds describe-db-instances {AWS_OK}",
        f"kubectl {KUBE_OK} get pods -o wide | grep -v Running",
        f"{PY} {SKILL}/scripts/preflight.py --json",
        f"{PY} {SKILL}/scripts/opensearch_query.py --cluster logs-prod health",
        f'"{PY}" "{SKILL}/scripts/validate_map.py"',
    ],
)
def test_validated_reads_are_approved(command):
    assert kind(command) == ALLOW


@pytest.mark.parametrize(
    "command",
    [
        "aws ecs describe-services --cluster a --profile admin --region eu-west-1",
        f"aws ecs list-clusters {AWS_OK} && aws ecs stop-task --task t {AWS_OK}",
        f"aws ecs list-clusters {AWS_OK}; aws s3 rm s3://b/k {AWS_OK}",
        f"kubectl {KUBE_OK} delete pod p",
        "curl -s https://opensearch.internal.example.com/_cat/indices",
        "curl -XDELETE https://opensearch.internal.example.com/app-logs-2026",
        f"{PY} {SKILL}/scripts/preflight.py https://opensearch.internal.example.com",
        "python3 -c \"import urllib.request as u; u.urlopen('http://opensearch.internal.example.com/_search')\"",
    ],
)
def test_writes_wrong_identities_and_side_routes_are_blocked(command):
    assert kind(command) == DENY


@pytest.mark.parametrize(
    "command",
    [
        f"echo $(aws sts get-caller-identity {AWS_OK})",
        f"bash -c 'aws ecs list-clusters {AWS_OK}'",
        f"xargs aws ecs describe-tasks {AWS_OK}",
        "cat ~/.aws/config",
        f"aws ecs list-clusters {AWS_OK}\naws ecs list-services {AWS_OK}",
        f"AWS_PROFILE=admin aws ecs list-clusters {AWS_OK}",
    ],
)
def test_commands_the_guard_cannot_check_force_a_prompt(command):
    assert kind(command) == ASK


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status",
        "npm test",
        "echo $(date)",
        f"aws ecs list-clusters {AWS_OK} > clusters.json",
        f"aws ecs list-clusters {AWS_OK} | tee clusters.json",
        f"aws ecs list-clusters {AWS_OK} | xargs rm -rf",
        f"aws ecs list-clusters {AWS_OK}; grep -r password /etc",
        f"/usr/bin/python3 {SKILL}/scripts/preflight.py",
        f"{PY} /tmp/other.py",
        f"{PY} {SKILL}/scripts/../../evil.py",
    ],
)
def test_unrelated_or_mixed_commands_fall_through_to_the_normal_flow(command):
    assert kind(command) == PASS


def test_opensearch_host_is_matched_whatever_its_letter_case():
    assert kind("curl -s https://OpenSearch.Internal.Example.com/_cat/indices") == DENY


def test_absolute_path_to_aws_is_checked_like_aws():
    assert kind(f"/usr/local/bin/aws ecs list-clusters {AWS_OK}") == ALLOW
    assert kind(f"/usr/local/bin/aws ecs stop-task --task t {AWS_OK}") == DENY


def test_skill_folder_with_a_space_in_its_path_is_recognised():
    skill = "/Users/First Last/.claude/skills/ai-triage"
    context = GuardContext(
        profiles=CONTEXT.profiles,
        kubeconfig=f"{skill}/config/kubeconfig",
        kube_contexts=CONTEXT.kube_contexts,
        opensearch_hosts=CONTEXT.opensearch_hosts,
        skill_dir=skill,
    )
    assert kind(f'"{skill}/.venv/bin/python" "{skill}/scripts/preflight.py" --json', context) == ALLOW
    kubectl = f'kubectl --kubeconfig "{skill}/config/kubeconfig" --context triage-platform-prod -n payments get pods'
    assert kind(kubectl, context) == ALLOW


def test_deny_outranks_ask_and_reason_names_the_problem():
    verdict = decide(f"cat ~/.aws/config; aws ecs stop-task --task t {AWS_OK}", CONTEXT)
    assert verdict.kind == DENY and "not a known read" in verdict.reason


def test_without_a_valid_config_aws_and_kubectl_are_denied():
    verdict = decide(f"aws ecs list-clusters {AWS_OK}", None, "config file not found")
    assert verdict.kind == DENY and "config file not found" in verdict.reason
    assert decide("kubectl get pods", None, "x").kind == DENY
    assert decide("ls -la", None, "x").kind == PASS


def test_context_is_built_from_config(config_data, tmp_path):
    context = context_from_config(parse_config(config_data), tmp_path)
    assert context.profiles == frozenset({"triage-prod-main", "triage-staging"})
    assert context.kubeconfig == str(tmp_path / "config" / "kubeconfig")
    assert context.kube_contexts == frozenset({"triage-platform-prod"})
    assert context.opensearch_hosts == frozenset({"opensearch.internal.example.com"})


def test_home_relative_script_paths_are_recognised(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    command = '"$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/preflight.py"'
    assert kind(command) == ALLOW
    assert kind("~/.claude/skills/ai-triage/.venv/bin/python ~/.claude/skills/ai-triage/scripts/preflight.py") == ALLOW
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_guard.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.guard'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/guard.py`

```python
"""Decide what to do with one shell command line during a triage session."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from triage.config import TriageConfig
from triage.guard_aws import check_aws
from triage.guard_kubectl import check_kubectl
from triage.shell_parse import Segment, Unparseable, split_command
from triage.verdict import ALLOW, ASK, DENY, PASS, Verdict, strictest

SENSITIVE_WORD_RE = re.compile(r"(?<![A-Za-z0-9_])(aws|kubectl)(?![A-Za-z0-9_])")
# Filters that only transform what is piped into them.
PIPE_FILTERS = frozenset({"jq", "head", "tail", "grep", "sort", "uniq", "wc", "cut", "tr", "column"})
OPENSEARCH_SCRIPT = "opensearch_query.py"
KUBECONFIG_NAME = "kubeconfig"


@dataclass(frozen=True)
class GuardContext:
    profiles: frozenset[str]
    kubeconfig: str
    kube_contexts: frozenset[str]
    opensearch_hosts: frozenset[str]
    skill_dir: str


def context_from_config(config: TriageConfig, skill_dir: Path) -> GuardContext:
    return GuardContext(
        profiles=config.profiles(),
        kubeconfig=str(skill_dir / "config" / KUBECONFIG_NAME),
        kube_contexts=config.kube_contexts(),
        opensearch_hosts=config.opensearch_hosts(),
        skill_dir=str(skill_dir),
    )


def _expand(token: str) -> str:
    home = os.path.expanduser("~")
    return os.path.normpath(os.path.expanduser(token.replace("${HOME}", home).replace("$HOME", home)))


def _is_command(word: str, name: str) -> bool:
    return word == name or word.endswith("/" + name)


def _own_script(argv: tuple[str, ...], context: GuardContext) -> str | None:
    """Return the script name when argv runs a skill script with the skill's Python."""
    if len(argv) < 2:
        return None
    interpreter, script = _expand(argv[0]), _expand(argv[1])
    scripts_dir = os.path.join(context.skill_dir, "scripts")
    if interpreter != os.path.join(context.skill_dir, ".venv", "bin", "python"):
        return None
    if os.path.dirname(script) != scripts_dir or not script.endswith(".py"):
        return None
    return os.path.basename(script)


def _mentions_host(text: str, hosts: frozenset[str]) -> bool:
    lowered = text.lower()
    return any(host and host.lower() in lowered for host in hosts)


def is_sensitive(command: str, hosts: frozenset[str] = frozenset()) -> bool:
    return bool(SENSITIVE_WORD_RE.search(command)) or _mentions_host(command, hosts)


def _check_segment(segment: Segment, context: GuardContext) -> Verdict:
    if not segment.argv:
        return Verdict(PASS)
    text = " ".join(segment.env + segment.argv)
    own_script = _own_script(segment.argv, context)
    if _mentions_host(text, context.opensearch_hosts):
        if own_script == OPENSEARCH_SCRIPT:
            return Verdict(ALLOW, "OpenSearch query through the triage tool")
        return Verdict(DENY, "OpenSearch clusters may only be reached through the opensearch_query tool")
    if own_script is not None:
        return Verdict(ALLOW, f"triage script {own_script}")
    command = segment.argv[0]
    if _is_command(command, "aws"):
        return check_aws(segment.argv, segment.env, context.profiles)
    if _is_command(command, "kubectl"):
        return check_kubectl(segment.argv, segment.env, context.kubeconfig, context.kube_contexts)
    if SENSITIVE_WORD_RE.search(text):
        return Verdict(ASK, "aws or kubectl is used indirectly, which the guard cannot check")
    if command in PIPE_FILTERS and segment.preceded_by == "|":
        return Verdict(ALLOW, f"{command} filters piped output")
    return Verdict(PASS)


def decide(command: str, context: GuardContext | None, context_error: str = "") -> Verdict:
    """Return allow, deny, ask, or pass for a whole command line."""
    if context is None:
        if is_sensitive(command):
            return Verdict(DENY, f"the triage guard has no valid config ({context_error}); fix it before running this")
        return Verdict(PASS)
    try:
        segments = split_command(command)
    except Unparseable as exc:
        if is_sensitive(command, context.opensearch_hosts):
            return Verdict(ASK, f"the guard cannot check this command ({exc})")
        return Verdict(PASS)
    verdicts: list[Verdict] = []
    for segment in segments:
        verdict = _check_segment(segment, context)
        if verdict.kind == ALLOW and segment.writes_file:
            verdict = Verdict(PASS)  # writing a local file goes through the normal permission flow
        verdicts.append(verdict)
    return strictest(verdicts)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_guard.py`
Expected: PASS, 40 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): decide allow, deny, ask, or pass for a command line" -m "A pipeline is only as safe as its riskiest part, so the strictest verdict wins, and anything that writes a file or cannot be checked is never auto-approved."
```

### Task 8: Hook entry point, wrapper, and skill skeleton

**Files:**
- Create: `skill/ai-triage/scripts/guard_hook.py`
- Create: `skill/ai-triage/scripts/guard_hook.sh`
- Create: `skill/ai-triage/SKILL.md`
- Test: `tests/test_guard_hook.py`

**Interfaces:**
- Consumes: `decide`, `context_from_config`, `is_sensitive` (Task 7); `load_config`, `default_config_path`, `ConfigError` (Task 2); `Verdict`, `DENY`, `PASS` (Task 5).
- Produces: `guard_hook.evaluate(stdin_text: str, skill_dir: Path) -> str` returning the hook's JSON output or an empty string; `guard_hook.sh`, which reads the hook payload on stdin, always exits 0, and honours `AI_TRIAGE_PYTHON` to override the interpreter in tests. Hook output shape: `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow" | "deny" | "ask", "permissionDecisionReason": "AI Triage guard: ..."}}`.

- [ ] **Step 1: Write the failing test**

`tests/test_guard_hook.py`

```python
import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import EXAMPLE_CONFIG, SKILL_SRC

import guard_hook

AWS_OK = "--profile triage-prod-main --region eu-west-1"


def payload(command, tool="Bash"):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": command}})


@pytest.fixture
def skill_dir(tmp_path):
    """A skill folder with a valid config, as the installer would leave it."""
    (tmp_path / "config").mkdir()
    shutil.copy(EXAMPLE_CONFIG, tmp_path / "config" / "triage-config.yaml")
    return tmp_path


def decision(output):
    return json.loads(output)["hookSpecificOutput"]


def test_allowed_read_prints_an_allow_decision(skill_dir):
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), skill_dir))
    assert result["hookEventName"] == "PreToolUse"
    assert result["permissionDecision"] == "allow"
    assert result["permissionDecisionReason"].startswith("AI Triage guard: ")


def test_write_prints_a_deny_decision(skill_dir):
    result = decision(guard_hook.evaluate(payload(f"aws ecs stop-task --task t {AWS_OK}"), skill_dir))
    assert result["permissionDecision"] == "deny"


def test_unchecked_command_prints_an_ask_decision(skill_dir):
    result = decision(guard_hook.evaluate(payload(f"bash -c 'aws ecs list-clusters {AWS_OK}'"), skill_dir))
    assert result["permissionDecision"] == "ask"


def test_unrelated_command_prints_nothing(skill_dir):
    assert guard_hook.evaluate(payload("ls -la"), skill_dir) == ""


def test_other_tools_are_ignored(skill_dir):
    assert guard_hook.evaluate(payload("aws ecs stop-task", tool="Read"), skill_dir) == ""


def test_missing_config_denies_aws_but_not_other_commands(tmp_path):
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), tmp_path))
    assert result["permissionDecision"] == "deny"
    assert "no valid config" in result["permissionDecisionReason"]
    assert guard_hook.evaluate(payload("ls"), tmp_path) == ""


def test_invalid_config_denies_aws(skill_dir):
    path = skill_dir / "config" / "triage-config.yaml"
    data = yaml.safe_load(path.read_text())
    data["accounts"]["prod-main"]["profile"] = "admin"
    path.write_text(yaml.safe_dump(data))
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), skill_dir))
    assert result["permissionDecision"] == "deny"


def test_unreadable_input_denies_only_when_it_mentions_aws_or_kubectl(skill_dir):
    assert decision(guard_hook.evaluate("not json aws ecs stop-task", skill_dir))["permissionDecision"] == "deny"
    assert guard_hook.evaluate("not json at all", skill_dir) == ""


def test_internal_error_fails_closed(skill_dir, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(guard_hook, "decide", boom)
    result = decision(guard_hook.evaluate(payload(f"aws ecs list-clusters {AWS_OK}"), skill_dir))
    assert result["permissionDecision"] == "deny" and "internal error" in result["permissionDecisionReason"]
    assert guard_hook.evaluate(payload("ls"), skill_dir) == ""


WRAPPER = SKILL_SRC / "scripts" / "guard_hook.sh"


def run_wrapper(stdin, python_bin):
    env = dict(os.environ, AI_TRIAGE_PYTHON=str(python_bin))
    return subprocess.run(["bash", str(WRAPPER)], input=stdin, capture_output=True, text=True, env=env)


def test_wrapper_runs_the_python_guard():
    # The source tree has no real config, so an aws command is denied for that reason.
    result = run_wrapper(payload(f"aws ecs list-clusters {AWS_OK}"), sys.executable)
    assert result.returncode == 0
    assert decision(result.stdout)["permissionDecision"] == "deny"
    assert "no valid config" in decision(result.stdout)["permissionDecisionReason"]


def test_wrapper_without_python_denies_sensitive_commands(tmp_path):
    result = run_wrapper(payload("kubectl get pods"), tmp_path / "missing-python")
    assert result.returncode == 0
    assert decision(result.stdout)["permissionDecision"] == "deny"
    assert "not installed correctly" in decision(result.stdout)["permissionDecisionReason"]


def test_wrapper_without_python_stays_silent_for_other_commands(tmp_path):
    result = run_wrapper(payload("ls -la"), tmp_path / "missing-python")
    assert result.returncode == 0 and result.stdout == ""


def test_wrapper_denies_when_the_python_guard_crashes(tmp_path):
    broken = tmp_path / "python"
    broken.write_text("#!/usr/bin/env bash\nexit 1\n")
    broken.chmod(0o755)
    result = run_wrapper(payload(f"aws ecs list-clusters {AWS_OK}"), broken)
    assert result.returncode == 0
    assert "failed to run" in decision(result.stdout)["permissionDecisionReason"]


def test_wrapper_help():
    result = subprocess.run(["bash", str(WRAPPER), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.startswith("Usage: guard_hook.sh")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_guard_hook.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'guard_hook'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/guard_hook.py`

```python
#!/usr/bin/env python3
"""PreToolUse hook entry point for the AI Triage guard.

Reads the hook input JSON on stdin and prints a permission decision, or
nothing when the guard has no opinion. It never exits non-zero: any internal
error becomes a deny for commands that touch aws or kubectl.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from triage.config import ConfigError, default_config_path, load_config
from triage.guard import context_from_config, decide, is_sensitive
from triage.verdict import DENY, PASS, Verdict

SKILL_DIR = Path(__file__).resolve().parent.parent


def render(verdict: Verdict) -> str:
    if verdict.kind == PASS:
        return ""
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": verdict.kind,
                "permissionDecisionReason": f"AI Triage guard: {verdict.reason}",
            }
        }
    )


def evaluate(stdin_text: str, skill_dir: Path) -> str:
    try:
        payload = json.loads(stdin_text)
    except json.JSONDecodeError:
        return render(Verdict(DENY, "unreadable hook input") if is_sensitive(stdin_text) else Verdict(PASS))
    if payload.get("tool_name") != "Bash":
        return ""
    command = str((payload.get("tool_input") or {}).get("command", ""))
    try:
        try:
            context, error = context_from_config(load_config(default_config_path(skill_dir)), skill_dir), ""
        except ConfigError as exc:
            context, error = None, exc.errors[0]
        return render(decide(command, context, error))
    except Exception as exc:  # fail closed for anything that touches aws or kubectl
        return render(Verdict(DENY, f"internal error ({exc})") if is_sensitive(command) else Verdict(PASS))


def main() -> int:
    output = evaluate(sys.stdin.read(), SKILL_DIR)
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

`skill/ai-triage/scripts/guard_hook.sh`

```bash
#!/usr/bin/env bash
# PreToolUse hook wrapper for the AI Triage guard.
# Runs guard_hook.py with the skill's own Python. If that Python is missing or
# the script fails, commands that mention aws or kubectl are denied.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: guard_hook.sh [--help]

Reads a Claude Code PreToolUse hook payload on stdin and prints a permission
decision as JSON. Prints nothing when the guard has no opinion.
Always exits 0.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

skill_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${AI_TRIAGE_PYTHON:-${skill_dir}/.venv/bin/python}"
payload="$(cat)"

deny_if_sensitive() {
  local reason="$1"
  if printf '%s' "${payload}" | grep -Eq '(^|[^A-Za-z0-9_])(aws|kubectl)([^A-Za-z0-9_]|$)'; then
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"AI Triage guard: %s"}}\n' "${reason}"
  fi
}

if [[ ! -x "${python_bin}" ]]; then
  deny_if_sensitive "the skill is not installed correctly (no Python environment). Run install.sh again."
  exit 0
fi

if output="$(printf '%s' "${payload}" | "${python_bin}" "${skill_dir}/scripts/guard_hook.py" 2>/dev/null)"; then
  if [[ -n "${output}" ]]; then
    printf '%s\n' "${output}"
  fi
else
  deny_if_sensitive "the guard failed to run. Run install.sh again."
fi
exit 0
```

`skill/ai-triage/SKILL.md`

````markdown
---
name: ai-triage
description: Triage a OneUptime incident against AWS, EKS, and OpenSearch using read-only access. This build contains the foundation only (config, guard, access checks); the triage method is not included yet.
argument-hint: "[incident number or URL]"
disable-model-invocation: true
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "\"$HOME/.claude/skills/ai-triage/scripts/guard_hook.sh\""
          timeout: 10
---

# AI Triage (foundation build)

This build installs the safety foundation. It cannot triage an incident yet.

Invoking this skill turns on the triage guard for the rest of the session. The
guard approves read-only AWS and Kubernetes commands that use a triage profile
or the triage kubeconfig, and blocks every other AWS or Kubernetes command.
Start a new session to work with your everyday profiles again.

## What to do when invoked

1. Run the preflight check and show its output:

   ```bash
   "$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/preflight.py"
   ```

2. If a sign-in session has expired, tell the engineer to run the
   `aws sso login --profile <name>` command that preflight printed. Do not try
   to sign in yourself.
3. Tell the engineer that the triage method is not part of this build.

## Rules that already apply

- Every AWS command sets `--profile` to a triage profile and sets `--region`.
- Every `kubectl` command sets `--kubeconfig` to the skill's kubeconfig,
  `--context` to a triage context, and a namespace.
- Never change anything in AWS, Kubernetes, OpenSearch, or OneUptime.
- Never print or store secret values.
````

Then: `chmod +x skill/ai-triage/scripts/guard_hook.py skill/ai-triage/scripts/guard_hook.sh`

Why the hook command uses `$HOME` and a fixed path: the Claude Code docs list `${CLAUDE_SKILL_DIR}` as substituted in a skill's body and in `allowed-tools`, but not in hook commands. The install location is fixed, so a shell-form command with `$HOME` is reliable.

Why `disable-model-invocation: true`: this build cannot triage. The flag keeps Claude from loading the skill on its own until the method arrives in Stage 3.

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_guard_hook.py`
Expected: PASS, 14 passed. shellcheck reports nothing for `guard_hook.sh`.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): wire the guard into a PreToolUse hook that fails closed" -m "A hook that crashes is treated by Claude Code as a non-blocking error, which would let commands through. The wrapper and entry point turn every failure into a deny for AWS and kubectl commands."
```

### Task 9: Inline policy and its static checks

**Files:**
- Create: `iam/ai-triage-inline-policy.json`
- Create: `skill/ai-triage/scripts/triage/policy_check.py`
- Create: `tools/check_policy_actions.py`
- Test: `tests/test_policy.py`

**Interfaces:**
- Consumes: `ROOT` from `tests/conftest.py`.
- Produces: `check_policy(document, raw_text: str) -> list[str]` (empty list means acceptable); constants `REQUIRED_DENIES` and `FORBIDDEN_ALLOWS`; the policy file; the manual tool `tools/check_policy_actions.py [--policy PATH]`, exit 0 all actions exist, 1 unknown actions, 2 usage or network error.

- [ ] **Step 1: Write the failing test**

`tests/test_policy.py`

```python
import copy
import json

import pytest

from conftest import ROOT
from triage.policy_check import check_policy

POLICY_PATH = ROOT / "iam" / "ai-triage-inline-policy.json"


@pytest.fixture
def policy():
    return json.loads(POLICY_PATH.read_text())


def problems(document):
    return check_policy(document, json.dumps(document, indent=2))


def test_shipped_policy_has_no_problems():
    raw = POLICY_PATH.read_text()
    assert check_policy(json.loads(raw), raw) == []


def test_shipped_policy_covers_the_documented_areas(policy):
    allowed = {a for s in policy["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
    for action in (
        "logs:GetLogEvents",
        "logs:StartQuery",
        "cloudwatch:DescribeAlarmHistory",
        "ecr:DescribeImages",
        "rds:DownloadDBLogFilePortion",
        "es:DescribeDomain",
        "lambda:GetFunctionConfiguration",
        "elasticfilesystem:DescribeMountTargets",
        "config:GetResourceConfigHistory",
        "iam:SimulatePrincipalPolicy",
        "ssm:GetParameter",
        "secretsmanager:DescribeSecret",
    ):
        assert action in allowed


def allow(policy, *actions):
    document = copy.deepcopy(policy)
    document["Statement"][0]["Action"].extend(actions)
    return document


@pytest.mark.parametrize(
    "action, expected",
    [
        ("ecs:UpdateService", "'ecs:UpdateService' is not a read action"),
        ("ec2:TerminateInstances", "is not a read action"),
        ("s3:PutObject", "is not a read action"),
        ("s3:GetObject", "'s3:GetObject' must never be granted"),
        ("secretsmanager:GetSecretValue", "must never be granted"),
        ("lambda:GetFunction", "must never be granted"),
        ("logs:Get*", "uses a wildcard"),
        ("ecs:*", "uses a wildcard"),
        ("nonsense", "is not a service:Action pair"),
    ],
)
def test_bad_allow_actions_are_reported(policy, action, expected):
    assert any(expected in problem for problem in problems(allow(policy, action)))


def test_missing_required_deny_is_reported(policy):
    document = copy.deepcopy(policy)
    deny = next(s for s in document["Statement"] if s["Effect"] == "Deny")
    deny["Action"].remove("kms:Decrypt")
    assert "missing explicit deny for 'kms:Decrypt'" in problems(document)


def test_scoped_deny_is_reported(policy):
    document = copy.deepcopy(policy)
    deny = next(s for s in document["Statement"] if s["Effect"] == "Deny")
    deny["Resource"] = "arn:aws:kms:*:*:key/abc"
    assert any("a Deny must apply to every resource" in p for p in problems(document))


def test_duplicate_sid_and_not_action_are_reported(policy):
    document = copy.deepcopy(policy)
    document["Statement"][1]["Sid"] = document["Statement"][0]["Sid"]
    document["Statement"][2]["NotAction"] = ["iam:*"]
    found = problems(document)
    assert any("needs a unique Sid" in p for p in found)
    assert any("NotAction and NotResource are not allowed" in p for p in found)


def test_size_limit_is_enforced(policy):
    document = allow(policy, *[f"ec2:DescribeSomethingVeryLongNumber{i:05d}" for i in range(400)])
    assert any("non-whitespace bytes" in p for p in problems(document))


def test_account_id_is_reported(policy):
    document = copy.deepcopy(policy)
    document["Statement"][0]["Resource"] = "arn:aws:logs:eu-west-1:" + "9" * 12 + ":*"
    assert "policy contains an account id" in problems(document)


@pytest.mark.parametrize("document", [None, [], {"Version": "2008-10-17", "Statement": []}, {"Version": "2012-10-17"}])
def test_malformed_documents_are_reported(document):
    assert check_policy(document, json.dumps(document)) != []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_policy.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.policy_check'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/policy_check.py`

```python
"""Static checks on the inline policy of the triage permission set."""
from __future__ import annotations

import re
from typing import Any

MAX_BYTES = 32768
MAX_NON_WHITESPACE_BYTES = 10240
READ_NAME_PREFIXES = ("Describe", "Get", "List", "BatchGet", "Lookup", "Filter", "Download", "Simulate")
# Actions that are reads despite their names.
READ_EXCEPTIONS = frozenset({"logs:StartQuery", "logs:StopQuery", "apigateway:GET"})
# Never grant these, even though some of them look like reads.
FORBIDDEN_ALLOWS = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "kms:Decrypt",
        "ssm:StartSession",
        "ssm:SendCommand",
        "ecs:ExecuteCommand",
        "ec2:GetPasswordData",
        "lambda:GetFunction",
        "s3:GetObject",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetAuthorizationToken",
        "kinesis:GetRecords",
        "sts:GetSessionToken",
        "sts:GetFederationToken",
    }
)
REQUIRED_DENIES = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "kms:Decrypt",
        "ssm:StartSession",
        "ssm:SendCommand",
        "ecs:ExecuteCommand",
        "ec2:GetPasswordData",
        "ec2-instance-connect:*",
        "rds-data:*",
        "rds-db:connect",
    }
)
ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def check_policy(document: Any, raw_text: str) -> list[str]:
    """Return every problem found. An empty list means the policy is acceptable."""
    problems: list[str] = []
    size = len(raw_text.encode())
    compact = len(re.sub(r"\s", "", raw_text).encode())
    if size > MAX_BYTES:
        problems.append(f"policy is {size} bytes, over the {MAX_BYTES} byte limit")
    if compact > MAX_NON_WHITESPACE_BYTES:
        problems.append(f"policy has {compact} non-whitespace bytes, over the {MAX_NON_WHITESPACE_BYTES} limit")
    if ACCOUNT_ID_RE.search(raw_text):
        problems.append("policy contains an account id")
    if not isinstance(document, dict) or document.get("Version") != "2012-10-17":
        return problems + ["policy must be an object with Version 2012-10-17"]
    statements = document.get("Statement")
    if not isinstance(statements, list) or not statements:
        return problems + ["policy must have a non-empty Statement list"]

    sids: set[str] = set()
    denied: set[str] = set()
    for index, statement in enumerate(statements):
        sid = statement.get("Sid") if isinstance(statement, dict) else None
        where = f"statement {sid or index}"
        if not isinstance(statement, dict):
            problems.append(f"{where}: must be an object")
            continue
        if not sid or sid in sids:
            problems.append(f"{where}: needs a unique Sid")
        sids.add(sid)
        if "NotAction" in statement or "NotResource" in statement:
            problems.append(f"{where}: NotAction and NotResource are not allowed")
        effect = statement.get("Effect")
        actions = [str(action) for action in _as_list(statement.get("Action", []))]
        if not actions:
            problems.append(f"{where}: needs at least one Action")
        if effect == "Deny":
            denied.update(actions)
            if _as_list(statement.get("Resource")) != ["*"]:
                problems.append(f"{where}: a Deny must apply to every resource")
            continue
        if effect != "Allow":
            problems.append(f"{where}: Effect must be Allow or Deny")
            continue
        for action in actions:
            service, _, name = action.partition(":")
            if not service or not name:
                problems.append(f"{where}: '{action}' is not a service:Action pair")
            elif "*" in action:
                problems.append(f"{where}: '{action}' uses a wildcard")
            elif action in FORBIDDEN_ALLOWS:
                problems.append(f"{where}: '{action}' must never be granted")
            elif action not in READ_EXCEPTIONS and not name.startswith(READ_NAME_PREFIXES):
                problems.append(f"{where}: '{action}' is not a read action")
    for action in sorted(REQUIRED_DENIES - denied):
        problems.append(f"missing explicit deny for '{action}'")
    return problems
```

`iam/ai-triage-inline-policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TriageObservability",
      "Effect": "Allow",
      "Action": [
        "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery", "logs:StopQuery",
        "logs:GetQueryResults", "logs:GetLogRecord", "logs:GetLogGroupFields",
        "cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory", "cloudwatch:DescribeAlarmsForMetric",
        "health:DescribeEvents", "health:DescribeEventDetails", "health:DescribeAffectedEntities",
        "tag:GetResources", "tag:GetTagKeys", "tag:GetTagValues",
        "servicequotas:ListServiceQuotas", "servicequotas:GetServiceQuota"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TriageCompute",
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeImages", "ecr:DescribeImageScanFindings",
        "ec2:GetConsoleOutput",
        "application-autoscaling:DescribeScalableTargets", "application-autoscaling:DescribeScalingActivities",
        "application-autoscaling:DescribeScalingPolicies",
        "lambda:GetFunctionConfiguration", "lambda:GetFunctionConcurrency", "lambda:GetFunctionEventInvokeConfig",
        "lambda:GetEventSourceMapping", "lambda:GetFunctionUrlConfig", "lambda:GetAlias", "lambda:GetAccountSettings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TriageDataStores",
      "Effect": "Allow",
      "Action": [
        "rds:DownloadDBLogFilePortion",
        "pi:GetResourceMetrics", "pi:DescribeDimensionKeys", "pi:GetDimensionKeyDetails", "pi:GetResourceMetadata",
        "pi:ListAvailableResourceDimensions", "pi:ListAvailableResourceMetrics",
        "es:DescribeDomain", "es:DescribeDomains", "es:DescribeDomainConfig", "es:DescribeDomainHealth",
        "es:DescribeDomainNodes", "es:DescribeDomainChangeProgress", "es:ListTags",
        "elasticfilesystem:DescribeMountTargets", "elasticfilesystem:DescribeMountTargetSecurityGroups",
        "elasticfilesystem:DescribeAccessPoints", "elasticfilesystem:DescribeFileSystemPolicy",
        "elasticfilesystem:DescribeLifecycleConfiguration",
        "sns:GetTopicAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TriageEdge",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeRules", "elasticloadbalancing:DescribeTargetGroupAttributes",
        "elasticloadbalancing:DescribeListenerCertificates", "elasticloadbalancing:DescribeTags",
        "acm:DescribeCertificate",
        "cloudfront:GetDistribution", "cloudfront:GetDistributionConfig",
        "wafv2:GetWebACL", "wafv2:GetWebACLForResource", "wafv2:GetRuleGroup", "wafv2:GetSampledRequests"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TriageApiGatewayRead",
      "Effect": "Allow",
      "Action": ["apigateway:GET"],
      "Resource": [
        "arn:aws:apigateway:*::/restapis/*", "arn:aws:apigateway:*::/apis/*", "arn:aws:apigateway:*::/account",
        "arn:aws:apigateway:*::/usageplans", "arn:aws:apigateway:*::/usageplans/*", "arn:aws:apigateway:*::/domainnames/*"
      ]
    },
    {
      "Sid": "TriageChangesAndConfig",
      "Effect": "Allow",
      "Action": [
        "cloudformation:DescribeStackEvents", "cloudformation:DescribeStackResources",
        "codepipeline:GetPipelineState", "codepipeline:GetPipelineExecution", "codepipeline:ListPipelineExecutions",
        "codepipeline:ListActionExecutions", "codebuild:BatchGetBuilds",
        "config:GetResourceConfigHistory", "config:BatchGetResourceConfig",
        "ssm:DescribeParameters", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TriageAccessDiagnosis",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole", "iam:GetRolePolicy", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:SimulatePrincipalPolicy",
        "kms:DescribeKey", "kms:GetKeyPolicy",
        "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenySecretsAndInteractiveAccess",
      "Effect": "Deny",
      "Action": [
        "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue",
        "kms:Decrypt",
        "ssm:StartSession", "ssm:SendCommand",
        "ecs:ExecuteCommand",
        "ec2:GetPasswordData", "ec2-instance-connect:*",
        "rds-data:*", "rds-db:connect"
      ],
      "Resource": "*"
    }
  ]
}
```

`tools/check_policy_actions.py`

```python
#!/usr/bin/env python3
"""Check every action in the inline policy against the AWS Service Reference.

This needs network access, so it is a manual tool and not part of the test
suite. Run it after editing iam/ai-triage-inline-policy.json.

Exit codes: 0 all actions exist, 1 unknown actions found, 2 usage or network error.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

INDEX_URL = "https://servicereference.us-east-1.amazonaws.com/"
DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "iam" / "ai-triage-inline-policy.json"


def fetch(url: str) -> object:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_policy_actions", description=__doc__.splitlines()[0])
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="path to the inline policy JSON")
    args = parser.parse_args(argv)
    policy = json.loads(args.policy.read_text())
    try:
        service_urls = {entry["service"]: entry["url"] for entry in fetch(INDEX_URL)}
        known: dict[str, set[str]] = {}
        unknown: list[str] = []
        checked = 0
        for statement in policy["Statement"]:
            actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            for action in actions:
                service, _, name = action.partition(":")
                checked += 1
                if service not in service_urls:
                    unknown.append(f"{action} (unknown service)")
                    continue
                if service not in known:
                    known[service] = {entry["Name"] for entry in fetch(service_urls[service])["Actions"]}
                if name != "*" and name not in known[service]:
                    unknown.append(action)
    except (urllib.error.URLError, TimeoutError, KeyError) as exc:
        print(f"Could not read the AWS Service Reference: {exc}", file=sys.stderr)
        return 2
    if unknown:
        print("Unknown actions:", file=sys.stderr)
        for action in unknown:
            print(f"  - {action}", file=sys.stderr)
        return 1
    print(f"OK: {checked} actions exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Then: `chmod +x tools/check_policy_actions.py`

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_policy.py`
Expected: PASS, 20 passed.

- [ ] **Step 5: Check the action names against AWS**

This step needs network access and calls only AWS's public service reference. It is not part of the test suite.

Run: `python3 tools/check_policy_actions.py`
Expected: `OK: 95 actions exist`. If AWS has renamed an action since 2026-10-04, fix the policy file and rerun steps 4 and 5.

- [ ] **Step 6: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): add the read-only inline policy with static checks" -m "The policy is the real read-only guarantee. The checks stop a write action, a wildcard, or a secret-reading action from ever being added to it."
```

### Task 10: AWS CLI wrapper and the test fake

**Files:**
- Create: `skill/ai-triage/scripts/triage/awscli.py`
- Create: `tests/fakes.py`
- Test: `tests/test_awscli.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `run_aws(service, operation, args=(), *, profile, region, runner=subprocess_runner, timeout=60) -> AwsResult`; `AwsResult(ok, data, error_code, error_message, argv)`; type `Runner = Callable[[list[str], int], tuple[int, str, str]]`; error code constants `SSO_EXPIRED = "SsoSessionExpired"`, `CLI_MISSING`, `TIMEOUT`, `BAD_OUTPUT`, `UNKNOWN`. In tests: `FakeAws(answers, default=None)` with `.calls` and `.called(service, operation)`, `access_denied(action)`, `SSO_EXPIRED_ERROR`.

- [ ] **Step 1: Write the failing test and the fake**

`tests/fakes.py`

```python
"""A scripted stand-in for the AWS CLI, used by the tests."""
from __future__ import annotations

import json


class FakeAws:
    """Answers `aws <service> <operation>` calls from a table.

    Keys are "service operation" or "profile service operation"; the more
    specific key wins. Values are a JSON-serialisable result, or an
    (exit code, stderr) tuple for a failure.
    """

    def __init__(self, answers: dict[str, object], default: object = None):
        self.answers = answers
        self.default = {} if default is None else default
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        self.calls.append(argv)
        profile = argv[argv.index("--profile") + 1]
        key = f"{argv[1]} {argv[2]}"
        answer = self.answers.get(f"{profile} {key}", self.answers.get(key, self.default))
        if isinstance(answer, tuple):
            return answer[0], "", answer[1]
        return 0, json.dumps(answer), ""

    def called(self, service: str, operation: str) -> list[list[str]]:
        return [argv for argv in self.calls if argv[1:3] == [service, operation]]


def access_denied(action: str) -> tuple[int, str]:
    return 254, f"An error occurred (AccessDeniedException) when calling the {action} operation: not authorized"


SSO_EXPIRED_ERROR = (255, "Error loading SSO Token: Token for my-sso does not exist")
```

`tests/test_awscli.py`

```python
import subprocess

from triage.awscli import AwsResult, run_aws


def runner_returning(code, stdout="", stderr=""):
    def runner(argv, timeout):
        runner.argv, runner.timeout = argv, timeout
        return code, stdout, stderr

    return runner


def test_profile_region_and_json_output_are_always_passed():
    runner = runner_returning(0, '{"clusterArns": []}')
    result = run_aws("ecs", "list-clusters", ["--max-items", "1"], profile="triage-a", region="eu-west-1", runner=runner)
    assert runner.argv == [
        "aws", "ecs", "list-clusters", "--max-items", "1",
        "--profile", "triage-a", "--region", "eu-west-1", "--output", "json", "--no-cli-pager",
    ]
    assert result == AwsResult(True, {"clusterArns": []}, None, None, tuple(runner.argv))


def test_empty_output_is_success_without_data():
    result = run_aws("logs", "stop-query", profile="p", region="r", runner=runner_returning(0, "  \n"))
    assert result.ok and result.data is None


def test_service_error_code_is_extracted():
    stderr = "An error occurred (AccessDeniedException) when calling the ListClusters operation: no"
    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner_returning(254, "", stderr))
    assert not result.ok and result.error_code == "AccessDeniedException" and "ListClusters" in result.error_message


def test_expired_sign_in_is_recognised():
    stderr = "Error loading SSO Token: Token for my-sso does not exist"
    result = run_aws("sts", "get-caller-identity", profile="p", region="r", runner=runner_returning(255, "", stderr))
    assert result.error_code == "SsoSessionExpired"


def test_unrecognised_failure_is_unknown():
    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner_returning(1, "", "boom"))
    assert result.error_code == "Unknown" and result.error_message == "boom"


def test_non_json_output_is_a_failure():
    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner_returning(0, "not json"))
    assert not result.ok and result.error_code == "UnreadableOutput"


def test_missing_cli_is_reported():
    def runner(argv, timeout):
        raise FileNotFoundError("aws")

    assert run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner).error_code == "AwsCliMissing"


def test_timeout_is_reported():
    def runner(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner, timeout=5)
    assert result.error_code == "Timeout" and "5 seconds" in result.error_message
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_awscli.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.awscli'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/awscli.py`

```python
"""Run one read-only AWS CLI call with an explicit profile and region."""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Sequence

SSO_EXPIRED = "SsoSessionExpired"
CLI_MISSING = "AwsCliMissing"
TIMEOUT = "Timeout"
BAD_OUTPUT = "UnreadableOutput"
UNKNOWN = "Unknown"

ERROR_CODE_RE = re.compile(r"An error occurred \((\w+)\)")
SSO_EXPIRED_MARKERS = (
    "Error loading SSO Token",
    "Token has expired",
    "SSO session associated with this profile has expired",
    "The SSO session associated with this profile is invalid",
    "Error when retrieving token from sso",
)

# A runner takes the full argv and a timeout, and returns (exit code, stdout, stderr).
Runner = Callable[[list[str], int], tuple[int, str, str]]


@dataclass(frozen=True)
class AwsResult:
    ok: bool
    data: Any
    error_code: str | None
    error_message: str | None
    argv: tuple[str, ...]


def subprocess_runner(argv: list[str], timeout: int) -> tuple[int, str, str]:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return completed.returncode, completed.stdout, completed.stderr


def run_aws(
    service: str,
    operation: str,
    args: Sequence[str] = (),
    *,
    profile: str,
    region: str,
    runner: Runner = subprocess_runner,
    timeout: int = 60,
) -> AwsResult:
    argv = ["aws", service, operation, *args, "--profile", profile, "--region", region, "--output", "json", "--no-cli-pager"]
    frozen = tuple(argv)
    try:
        code, stdout, stderr = runner(argv, timeout)
    except FileNotFoundError:
        return AwsResult(False, None, CLI_MISSING, "the aws command was not found", frozen)
    except subprocess.TimeoutExpired:
        return AwsResult(False, None, TIMEOUT, f"no answer within {timeout} seconds", frozen)
    if code != 0:
        message = stderr.strip()
        if any(marker in message for marker in SSO_EXPIRED_MARKERS):
            return AwsResult(False, None, SSO_EXPIRED, message, frozen)
        match = ERROR_CODE_RE.search(message)
        return AwsResult(False, None, match.group(1) if match else UNKNOWN, message, frozen)
    if not stdout.strip():
        return AwsResult(True, None, None, None, frozen)
    try:
        return AwsResult(True, json.loads(stdout), None, None, frozen)
    except json.JSONDecodeError:
        return AwsResult(False, None, BAD_OUTPUT, "the aws command did not print JSON", frozen)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_awscli.py`
Expected: PASS, 8 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): add one way to call the AWS CLI with explicit profile and region" -m "Every collector will go through this function, so the profile and region can never be left to defaults and an expired sign-in is recognised in one place."
```

### Task 11: Access verification

**Files:**
- Create: `skill/ai-triage/scripts/triage/verify.py`
- Create: `skill/ai-triage/scripts/verify_access.py`
- Test: `tests/test_verify.py`

**Interfaces:**
- Consumes: `run_aws`, `Runner`, `subprocess_runner`, `SSO_EXPIRED` (Task 10); `Account`, `TriageConfig`, `load_config`, `default_config_path`, `ConfigError` (Task 2); `FakeAws`, `access_denied`, `SSO_EXPIRED_ERROR` (Task 10).
- Produces: `check_identity(account, permission_set, runner) -> tuple[CheckResult, str | None]` (the second value is the role name, or `None` on failure); `verify_account(account, permission_set, runner) -> list[CheckResult]`; `verify_all(config, aliases=(), runner=) -> list[CheckResult]`; `render_table(results) -> str`; `exit_code(results) -> int`; `CheckResult(account, name, status, detail)`; status constants `PASSED`, `FAILED`, `SKIPPED`, `EXPIRED`. Command `verify_access.py [--config PATH] [--account ALIAS ...]`, exit 0 passed, 1 failed, 2 usage or config error, 3 sign-in expired.

- [ ] **Step 1: Write the failing test**

`tests/test_verify.py`

```python
import pytest

from fakes import SSO_EXPIRED_ERROR, FakeAws, access_denied
from triage.config import parse_config
from triage.verify import (
    EXPIRED,
    FAILED,
    PASSED,
    SIMULATED_READS,
    SIMULATED_WRITES,
    SKIPPED,
    exit_code,
    render_table,
    verify_account,
    verify_all,
)

ROLE = "AWSReservedSSO_ai-triage-read-only_0123456789abcdef"
ROLE_ARN = f"arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/eu-west-1/{ROLE}"


def identity(account_id="111111111111", role=ROLE):
    return {"Account": account_id, "Arn": f"arn:aws:sts::{account_id}:assumed-role/{role}/engineer@example.com"}


def simulation(overrides=None):
    decisions = {action: "allowed" for action in SIMULATED_READS}
    decisions.update({action: "implicitDeny" for action in SIMULATED_WRITES})
    decisions["kms:Decrypt"] = "explicitDeny"
    decisions.update(overrides or {})
    return {"EvaluationResults": [{"EvalActionName": a, "EvalDecision": d} for a, d in decisions.items()]}


def healthy(**extra):
    answers = {
        "sts get-caller-identity": identity(),
        "iam list-roles": {"Roles": [{"RoleName": ROLE, "Arn": ROLE_ARN}]},
        "iam simulate-principal-policy": simulation(),
    }
    answers.update(extra)
    return FakeAws(answers)


@pytest.fixture
def account(config_data):
    return parse_config(config_data).accounts["prod-main"]


def by_name(results):
    return {result.name: result for result in results}


def test_healthy_account_passes_every_check(account):
    fake = healthy()
    results = verify_account(account, "ai-triage-read-only", fake)
    assert {r.status for r in results} == {PASSED}
    assert exit_code(results) == 0
    assert by_name(results)["Identity"].detail == ROLE
    assert all("--profile" in argv and "--region" in argv for argv in fake.calls)


def test_simulator_is_asked_about_the_role_behind_the_profile(account):
    fake = healthy()
    verify_account(account, "ai-triage-read-only", fake)
    [argv] = fake.called("iam", "simulate-principal-policy")
    assert argv[argv.index("--policy-source-arn") + 1] == ROLE_ARN
    assert "ecs:UpdateService" in argv and "logs:GetLogEvents" in argv


def test_no_write_operation_is_ever_called(account):
    fake = healthy()
    verify_account(account, "ai-triage-read-only", fake)
    read_starts = ("describe-", "list-", "get-", "lookup-", "simulate-")
    assert all(argv[2].startswith(read_starts) for argv in fake.calls)


def test_wrong_account_stops_after_identity(account):
    fake = healthy(**{"sts get-caller-identity": identity(account_id="222222222222")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert len(results) == 1 and results[0].status == FAILED
    assert "different account" in results[0].detail


def test_wrong_permission_set_stops_after_identity(account):
    fake = healthy(**{"sts get-caller-identity": identity(role="AWSReservedSSO_AdministratorAccess_abc")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert len(results) == 1 and "does not use the ai-triage-read-only permission set" in results[0].detail


def test_expired_sign_in_is_reported_with_its_own_exit_code(account):
    fake = healthy(**{"sts get-caller-identity": SSO_EXPIRED_ERROR})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert results[0].status == EXPIRED and exit_code(results) == 3


def test_denied_read_fails(account):
    fake = healthy(**{"cloudwatch describe-alarms": access_denied("DescribeAlarms")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Read: Alarms"].status == FAILED
    assert by_name(results)["Read: Alarms"].detail == "AccessDeniedException"
    assert exit_code(results) == 1


def test_health_without_a_support_plan_is_skipped_not_failed(account):
    error = (254, "An error occurred (SubscriptionRequiredException) when calling the DescribeEvents operation")
    results = verify_account(account, "ai-triage-read-only", healthy(**{"health describe-events": error}))
    assert by_name(results)["Read: AWS Health"].status == SKIPPED
    assert exit_code(results) == 0


def test_health_is_queried_in_its_home_region(account):
    fake = healthy()
    verify_account(account, "ai-triage-read-only", fake)
    [argv] = fake.called("health", "describe-events")
    assert argv[argv.index("--region") + 1] == "us-east-1"


def test_an_allowed_write_fails(account):
    fake = healthy(**{"iam simulate-principal-policy": simulation({"ecs:UpdateService": "allowed"})})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Denied: ecs:UpdateService"].status == FAILED
    assert exit_code(results) == 1


def test_a_denied_read_in_the_simulator_fails(account):
    fake = healthy(**{"iam simulate-principal-policy": simulation({"logs:GetLogEvents": "implicitDeny"})})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Allowed: logs:GetLogEvents"].status == FAILED


def test_missing_simulator_answer_fails(account):
    fake = healthy(**{"iam simulate-principal-policy": {"EvaluationResults": []}})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Denied: kms:Decrypt"].detail == "no answer"
    assert by_name(results)["Denied: kms:Decrypt"].status == FAILED


def test_role_not_found_fails_the_simulator_check(account):
    fake = healthy(**{"iam list-roles": {"Roles": []}})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Simulator"].status == FAILED


def test_simulator_denied_fails_the_simulator_check(account):
    fake = healthy(**{"iam simulate-principal-policy": access_denied("SimulatePrincipalPolicy")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Simulator"].detail == "AccessDeniedException"


def test_verify_all_covers_every_account_or_only_the_named_ones(config_data):
    config = parse_config(config_data)
    fake = FakeAws(
        {
            "triage-prod-main sts get-caller-identity": identity(),
            "triage-staging sts get-caller-identity": identity(account_id="222222222222"),
            "iam list-roles": {"Roles": [{"RoleName": ROLE, "Arn": ROLE_ARN}]},
            "iam simulate-principal-policy": simulation(),
        }
    )
    assert {r.account for r in verify_all(config, runner=fake)} == {"prod-main", "staging"}
    assert {r.account for r in verify_all(config, ["staging"], runner=fake)} == {"staging"}


def test_table_lists_every_result(account):
    table = render_table(verify_account(account, "ai-triage-read-only", healthy()))
    lines = table.splitlines()
    assert lines[0].split() == ["ACCOUNT", "CHECK", "RESULT", "DETAIL"]
    assert any("Denied: ecs:UpdateService" in line and "pass" in line for line in lines)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_verify.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.verify'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/verify.py`

```python
"""Prove that a triage profile can read what triage needs and cannot write."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from triage.awscli import SSO_EXPIRED, Runner, run_aws, subprocess_runner
from triage.config import Account, TriageConfig

PASSED = "pass"
FAILED = "fail"
SKIPPED = "skipped"
EXPIRED = "expired"

SSO_ROLE_PATH = "/aws-reserved/sso.amazonaws.com/"
SSO_ROLE_PREFIX = "AWSReservedSSO_"


@dataclass(frozen=True)
class Probe:
    name: str
    service: str
    operation: str
    args: tuple[str, ...] = ()
    region: str | None = None  # a fixed region for services that live in one place
    skip_on: tuple[str, ...] = ()  # error codes that mean "not available here", not "denied"


# Calls that need no resource identifier, one per permission area.
READ_PROBES: tuple[Probe, ...] = (
    Probe("ECS", "ecs", "list-clusters", ("--max-items", "1")),
    Probe("EC2", "ec2", "describe-instances", ("--max-items", "1")),
    Probe("ECR", "ecr", "describe-repositories", ("--max-items", "1")),
    Probe("EKS", "eks", "list-clusters", ("--max-items", "1")),
    Probe("Lambda settings", "lambda", "get-account-settings"),
    Probe("Auto Scaling", "autoscaling", "describe-auto-scaling-groups", ("--max-items", "1")),
    Probe("Service scaling", "application-autoscaling", "describe-scalable-targets", ("--service-namespace", "ecs", "--max-items", "1")),
    Probe("RDS", "rds", "describe-db-instances", ("--max-items", "1")),
    Probe("ElastiCache", "elasticache", "describe-cache-clusters", ("--max-items", "1")),
    Probe("OpenSearch domains", "opensearch", "list-domain-names"),
    Probe("DynamoDB", "dynamodb", "list-tables", ("--max-items", "1")),
    Probe("EFS access points", "efs", "describe-access-points", ("--max-items", "1")),
    Probe("SQS", "sqs", "list-queues", ("--max-items", "1")),
    Probe("Load balancers", "elbv2", "describe-load-balancers", ("--max-items", "1")),
    Probe("Log groups", "logs", "describe-log-groups", ("--max-items", "1")),
    Probe("Alarms", "cloudwatch", "describe-alarms", ("--max-items", "1")),
    Probe("CloudTrail events", "cloudtrail", "lookup-events", ("--max-items", "1")),
    Probe("Tag search", "resourcegroupstaggingapi", "get-resources", ("--max-items", "1")),
    Probe("Service quotas", "service-quotas", "list-service-quotas", ("--service-code", "ecs", "--max-items", "1")),
    Probe("Parameter Store", "ssm", "describe-parameters", ("--max-items", "1")),
    Probe("Secrets metadata", "secretsmanager", "list-secrets", ("--max-items", "1")),
    Probe("AWS Health", "health", "describe-events", ("--max-items", "1"), region="us-east-1", skip_on=("SubscriptionRequiredException",)),
)

# The simulator must answer "allowed" for each of these.
SIMULATED_READS: tuple[str, ...] = (
    "logs:GetLogEvents",
    "logs:StartQuery",
    "ecs:DescribeServices",
    "ecr:DescribeImages",
    "rds:DownloadDBLogFilePortion",
    "es:DescribeDomain",
    "lambda:GetFunctionConfiguration",
    "cloudformation:DescribeStackEvents",
    "config:GetResourceConfigHistory",
    "cloudtrail:LookupEvents",
)
# The simulator must not answer "allowed" for any of these.
SIMULATED_WRITES: tuple[str, ...] = (
    "ecs:UpdateService",
    "ecs:StopTask",
    "ecs:ExecuteCommand",
    "ec2:TerminateInstances",
    "ec2:StopInstances",
    "rds:DeleteDBInstance",
    "rds:RebootDBInstance",
    "elasticache:DeleteCacheCluster",
    "es:DeleteDomain",
    "lambda:UpdateFunctionCode",
    "eks:DeleteCluster",
    "dynamodb:DeleteTable",
    "sqs:DeleteQueue",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:GetObject",
    "logs:DeleteLogGroup",
    "iam:CreateUser",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "ssm:StartSession",
)


@dataclass(frozen=True)
class CheckResult:
    account: str
    name: str
    status: str
    detail: str = ""


def _role_name(caller_arn: str) -> str | None:
    """arn:aws:sts::<id>:assumed-role/<role name>/<session> -> <role name>."""
    parts = caller_arn.split(":", 5)
    if len(parts) != 6 or not parts[5].startswith("assumed-role/"):
        return None
    return parts[5].split("/")[1]


def check_identity(account: Account, permission_set: str, runner: Runner) -> tuple[CheckResult, str | None]:
    """Confirm the profile lands in the right account with the triage permission set."""
    region = account.regions[0]
    result = run_aws("sts", "get-caller-identity", profile=account.profile, region=region, runner=runner)
    if not result.ok:
        status = EXPIRED if result.error_code == SSO_EXPIRED else FAILED
        return CheckResult(account.alias, "Identity", status, result.error_message or result.error_code or ""), None
    data = result.data or {}
    if data.get("Account") != account.account_id:
        return CheckResult(account.alias, "Identity", FAILED, f"profile {account.profile} signs in to a different account"), None
    role_name = _role_name(str(data.get("Arn", "")))
    expected_prefix = f"{SSO_ROLE_PREFIX}{permission_set}_"
    if role_name is None or not role_name.startswith(expected_prefix):
        return CheckResult(account.alias, "Identity", FAILED, f"profile {account.profile} does not use the {permission_set} permission set"), None
    return CheckResult(account.alias, "Identity", PASSED, role_name), role_name


def run_read_probes(account: Account, runner: Runner, probes: Sequence[Probe] = READ_PROBES) -> list[CheckResult]:
    results: list[CheckResult] = []
    for probe in probes:
        region = probe.region or account.regions[0]
        result = run_aws(probe.service, probe.operation, probe.args, profile=account.profile, region=region, runner=runner)
        if result.ok:
            results.append(CheckResult(account.alias, f"Read: {probe.name}", PASSED))
        elif result.error_code in probe.skip_on:
            results.append(CheckResult(account.alias, f"Read: {probe.name}", SKIPPED, f"not available ({result.error_code})"))
        else:
            results.append(CheckResult(account.alias, f"Read: {probe.name}", FAILED, result.error_code or "failed"))
    return results


def run_simulation(account: Account, role_name: str, runner: Runner) -> list[CheckResult]:
    """Ask the IAM policy simulator about sample reads and writes. Nothing is attempted."""
    region = account.regions[0]
    roles = run_aws(
        "iam", "list-roles", ("--path-prefix", SSO_ROLE_PATH), profile=account.profile, region=region, runner=runner
    )
    arn = next((r.get("Arn") for r in (roles.data or {}).get("Roles", []) if r.get("RoleName") == role_name), None) if roles.ok else None
    if arn is None:
        return [CheckResult(account.alias, "Simulator", FAILED, "could not find the role behind the triage profile")]
    actions = SIMULATED_READS + SIMULATED_WRITES
    simulation = run_aws(
        "iam",
        "simulate-principal-policy",
        ("--policy-source-arn", arn, "--action-names", *actions),
        profile=account.profile,
        region=region,
        runner=runner,
    )
    if not simulation.ok:
        return [CheckResult(account.alias, "Simulator", FAILED, simulation.error_code or "failed")]
    decisions = {
        entry.get("EvalActionName"): entry.get("EvalDecision")
        for entry in (simulation.data or {}).get("EvaluationResults", [])
    }
    results: list[CheckResult] = []
    for action in SIMULATED_READS:
        decision = decisions.get(action, "no answer")
        status = PASSED if decision == "allowed" else FAILED
        results.append(CheckResult(account.alias, f"Allowed: {action}", status, "" if status == PASSED else decision))
    for action in SIMULATED_WRITES:
        decision = decisions.get(action, "no answer")
        status = PASSED if decision in ("implicitDeny", "explicitDeny") else FAILED
        results.append(CheckResult(account.alias, f"Denied: {action}", status, "" if status == PASSED else decision))
    return results


def verify_account(account: Account, permission_set: str, runner: Runner = subprocess_runner) -> list[CheckResult]:
    identity, role_name = check_identity(account, permission_set, runner)
    if role_name is None:
        return [identity]
    return [identity, *run_read_probes(account, runner), *run_simulation(account, role_name, runner)]


def verify_all(config: TriageConfig, aliases: Sequence[str] = (), runner: Runner = subprocess_runner) -> list[CheckResult]:
    results: list[CheckResult] = []
    for alias, account in config.accounts.items():
        if aliases and alias not in aliases:
            continue
        results.extend(verify_account(account, config.permission_set, runner))
    return results


def render_table(results: Sequence[CheckResult]) -> str:
    width_account = max([len("ACCOUNT"), *(len(r.account) for r in results)])
    width_name = max([len("CHECK"), *(len(r.name) for r in results)])
    lines = [f"{'ACCOUNT':<{width_account}}  {'CHECK':<{width_name}}  RESULT   DETAIL"]
    for r in results:
        lines.append(f"{r.account:<{width_account}}  {r.name:<{width_name}}  {r.status:<7}  {r.detail}".rstrip())
    return "\n".join(lines)


def exit_code(results: Sequence[CheckResult]) -> int:
    """0 all good, 1 something failed, 3 a sign-in session has expired."""
    statuses = {r.status for r in results}
    if FAILED in statuses:
        return 1
    if EXPIRED in statuses:
        return 3
    return 0
```

`skill/ai-triage/scripts/verify_access.py`

```python
#!/usr/bin/env python3
"""Check that each triage profile can read what triage needs and cannot write.

Reads are proven by harmless list and describe calls. Writes are checked with
the IAM policy simulator, so no write is ever attempted.

Exit codes: 0 all checks passed, 1 a check failed, 2 usage or config error,
3 a sign-in session has expired.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.config import ConfigError, default_config_path, load_config
from triage.verify import EXPIRED, exit_code, render_table, verify_all

SKILL_DIR = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_access", description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, default=default_config_path(SKILL_DIR), help="path to the config file")
    parser.add_argument("--account", action="append", default=[], metavar="ALIAS", help="check only this account; repeatable")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("Config is invalid:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return 2
    unknown = [alias for alias in args.account if alias not in config.accounts]
    if unknown:
        print(f"Unknown account: {', '.join(unknown)}", file=sys.stderr)
        return 2
    results = verify_all(config, args.account)
    print(render_table(results))
    for result in results:
        if result.status == EXPIRED:
            profile = config.accounts[result.account].profile
            print(f"\nSign-in expired. Run: aws sso login --profile {profile}", file=sys.stderr)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
```

Then: `chmod +x skill/ai-triage/scripts/verify_access.py`

Every probe command and its options were checked on 2026-10-04 to parse in AWS CLI 2.34.4 using `--generate-cli-skeleton`, which makes no AWS call.

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_verify.py`
Expected: PASS, 16 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): verify that triage access can read and cannot write" -m "An engineer needs proof that the permission set works in every account. Writes are checked with the policy simulator so that nothing is ever attempted."
```

### Task 12: Preflight

**Files:**
- Create: `skill/ai-triage/scripts/triage/preflight.py`
- Create: `skill/ai-triage/scripts/preflight.py`
- Test: `tests/test_preflight.py`

**Interfaces:**
- Consumes: `check_identity`, `PASSED`, `EXPIRED` (Task 11); `load_config`, `default_config_path`, `ConfigError`, `TriageConfig` (Task 2); `load_map`, `default_map_path`, `MapError` (Task 3); `KUBECONFIG_NAME` (Task 7); `Runner`, `subprocess_runner` (Task 10).
- Produces: `run_preflight(skill_dir: Path, accounts=(), *, runner=, env=, which=) -> list[Check]`; `Check(name, status, detail, fix)`; status constants `OK`, `WARN`, `FAIL`, `SIGN_IN`; `exit_code(checks) -> int`; `render_text(checks) -> str`; `as_dicts(checks) -> list[dict]`. Command `preflight.py [--account ALIAS ...] [--json]`, exit 0 ready, 1 failed, 2 usage, 3 only a sign-in is needed. JSON shape: `{"exit_code": int, "checks": [{"name", "status", "detail", "fix"}]}`.

- [ ] **Step 1: Write the failing test**

`tests/test_preflight.py`

```python
import json
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import EXAMPLE_CONFIG, EXAMPLE_MAP, SKILL_SRC
from fakes import SSO_EXPIRED_ERROR, FakeAws
from triage.preflight import FAIL, OK, SIGN_IN, WARN, exit_code, render_text, run_preflight

ROLE = "AWSReservedSSO_ai-triage-read-only_0123456789abcdef"


def identity(account_id):
    return {"Account": account_id, "Arn": f"arn:aws:sts::{account_id}:assumed-role/{ROLE}/engineer@example.com"}


@pytest.fixture
def skill_dir(tmp_path):
    """A skill folder as the installer leaves it, with cases kept inside tmp_path."""
    config_dir = tmp_path / "skill" / "config"
    config_dir.mkdir(parents=True)
    data = yaml.safe_load(EXAMPLE_CONFIG.read_text())
    data["cases_dir"] = str(tmp_path / "cases")
    (config_dir / "triage-config.yaml").write_text(yaml.safe_dump(data))
    shutil.copy(EXAMPLE_MAP, config_dir / "service-map.yaml")
    (config_dir / "kubeconfig").write_text("apiVersion: v1\nkind: Config\n")
    return tmp_path / "skill"


def signed_in():
    return FakeAws(
        {
            "triage-prod-main sts get-caller-identity": identity("111111111111"),
            "triage-staging sts get-caller-identity": identity("222222222222"),
        }
    )


def run(skill_dir, accounts=(), runner=None, env=None, missing=()):
    return run_preflight(
        skill_dir,
        accounts,
        runner=runner or signed_in(),
        env={"TYPESAFE_API_KEY": "set"} if env is None else env,
        which=lambda name: None if name in missing else f"/usr/bin/{name}",
    )


def by_name(checks):
    return {check.name: check for check in checks}


def test_everything_ready(skill_dir, tmp_path):
    checks = run(skill_dir)
    assert {check.status for check in checks} == {OK}
    assert exit_code(checks) == 0
    assert (tmp_path / "cases").is_dir()
    assert by_name(checks)["Config"].detail == "2 accounts"
    assert by_name(checks)["Service map"].detail == "2 services"


def test_missing_config_stops_early(tmp_path):
    checks = run(tmp_path)
    assert [check.name for check in checks] == ["Config"]
    assert checks[0].status == FAIL and exit_code(checks) == 1


def test_invalid_map_fails_but_other_checks_still_run(skill_dir):
    (skill_dir / "config" / "service-map.yaml").write_text("services:\n  a:\n    environments: {}\n")
    checks = by_name(run(skill_dir))
    assert checks["Service map"].status == FAIL
    assert checks["Sign-in: prod-main"].status == OK


def test_expired_sign_in_gives_the_login_command(skill_dir):
    runner = signed_in()
    runner.answers["triage-staging sts get-caller-identity"] = SSO_EXPIRED_ERROR
    checks = run(skill_dir, runner=runner)
    staging = by_name(checks)["Sign-in: staging"]
    assert staging.status == SIGN_IN
    assert staging.fix == "aws sso login --profile triage-staging"
    assert exit_code(checks) == 3


def test_wrong_account_is_a_failure(skill_dir):
    runner = signed_in()
    runner.answers["triage-staging sts get-caller-identity"] = identity("111111111111")
    checks = run(skill_dir, runner=runner)
    assert by_name(checks)["Sign-in: staging"].status == FAIL and exit_code(checks) == 1


def test_only_named_accounts_are_signed_in_checked(skill_dir):
    runner = signed_in()
    checks = by_name(run(skill_dir, ["prod-main"], runner=runner))
    assert "Sign-in: prod-main" in checks and "Sign-in: staging" not in checks
    assert all("triage-prod-main" in argv for argv in runner.calls)


def test_unknown_account_fails(skill_dir):
    checks = run(skill_dir, ["nope"])
    assert by_name(checks)["Accounts"].status == FAIL


def test_missing_aws_cli_fails_without_calling_it(skill_dir):
    runner = signed_in()
    checks = by_name(run(skill_dir, runner=runner, missing=("aws",)))
    assert checks["AWS CLI"].status == FAIL and runner.calls == []


def test_missing_kubectl_or_kubeconfig_fails_when_clusters_are_configured(skill_dir):
    assert by_name(run(skill_dir, missing=("kubectl",)))["kubectl"].status == FAIL
    (skill_dir / "config" / "kubeconfig").unlink()
    assert "kubeconfig does not exist" in by_name(run(skill_dir))["kubectl"].detail


def test_kubectl_is_not_checked_without_clusters(skill_dir):
    path = skill_dir / "config" / "triage-config.yaml"
    data = yaml.safe_load(path.read_text())
    data.pop("eks_clusters")
    path.write_text(yaml.safe_dump(data))
    (skill_dir / "config" / "service-map.yaml").write_text("services: {}\n")
    assert "kubectl" not in by_name(run(skill_dir, missing=("kubectl",)))


def test_missing_typesafe_key_is_a_warning_not_a_failure(skill_dir):
    checks = run(skill_dir, env={})
    assert by_name(checks)["TypeSafe key"].status == WARN
    assert exit_code(checks) == 0


def test_unwritable_cases_folder_fails(skill_dir, tmp_path):
    (tmp_path / "cases").write_text("a file where the folder should be")
    assert by_name(run(skill_dir))["Cases folder"].status == FAIL


def test_text_output_shows_fixes_only_for_problems(skill_dir):
    runner = signed_in()
    runner.answers["triage-staging sts get-caller-identity"] = SSO_EXPIRED_ERROR
    text = render_text(run(skill_dir, runner=runner))
    assert "[sign-in] Sign-in: staging" in text
    assert "fix: aws sso login --profile triage-staging" in text
    assert text.count("fix:") == 1


def test_cli_reports_a_missing_config_as_json(tmp_path):
    script = SKILL_SRC / "scripts" / "preflight.py"
    result = subprocess.run(
        [sys.executable, str(script), "--json", "--skill-dir", str(tmp_path)], capture_output=True, text=True
    )
    assert result.returncode == 1
    body = json.loads(result.stdout)
    assert body["exit_code"] == 1 and body["checks"][0]["name"] == "Config"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_preflight.py`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'triage.preflight'`.

- [ ] **Step 3: Write the implementation**

`skill/ai-triage/scripts/triage/preflight.py`

```python
"""Check that everything a triage run needs is in place before it starts."""
from __future__ import annotations

import os
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from triage.awscli import Runner, subprocess_runner
from triage.config import ConfigError, TriageConfig, default_config_path, load_config
from triage.guard import KUBECONFIG_NAME
from triage.service_map import MapError, default_map_path, load_map
from triage.verify import EXPIRED, PASSED, check_identity

OK = "ok"
WARN = "warn"
FAIL = "fail"
SIGN_IN = "sign-in"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str = ""
    fix: str = ""


def _load(skill_dir: Path) -> tuple[TriageConfig | None, list[Check]]:
    try:
        config = load_config(default_config_path(skill_dir))
    except ConfigError as exc:
        return None, [Check("Config", FAIL, "; ".join(exc.errors), "Edit config/triage-config.yaml in the skill folder.")]
    checks = [Check("Config", OK, f"{len(config.accounts)} accounts")]
    try:
        service_map = load_map(default_map_path(skill_dir), config)
        checks.append(Check("Service map", OK, f"{len(service_map.services)} services"))
    except MapError as exc:
        checks.append(Check("Service map", FAIL, "; ".join(exc.errors), "Edit config/service-map.yaml in the skill folder."))
    return config, checks


def run_preflight(
    skill_dir: Path,
    accounts: Sequence[str] = (),
    *,
    runner: Runner = subprocess_runner,
    env: Mapping[str, str] = os.environ,
    which: Callable[[str], str | None] = shutil.which,
) -> list[Check]:
    config, checks = _load(skill_dir)
    if config is None:
        return checks
    unknown = [alias for alias in accounts if alias not in config.accounts]
    if unknown:
        checks.append(Check("Accounts", FAIL, f"unknown account: {', '.join(unknown)}"))
        return checks

    if which("aws") is None:
        checks.append(Check("AWS CLI", FAIL, "the aws command was not found", "Install AWS CLI version 2."))
    else:
        checks.append(Check("AWS CLI", OK))
        for alias, account in config.accounts.items():
            if accounts and alias not in accounts:
                continue
            identity, _ = check_identity(account, config.permission_set, runner)
            name = f"Sign-in: {alias}"
            if identity.status == PASSED:
                checks.append(Check(name, OK, identity.detail))
            elif identity.status == EXPIRED:
                checks.append(Check(name, SIGN_IN, "the sign-in session has expired", f"aws sso login --profile {account.profile}"))
            else:
                checks.append(Check(name, FAIL, identity.detail, f"Check the profile {account.profile} in your AWS config."))

    if config.eks_clusters:
        kubeconfig = skill_dir / "config" / KUBECONFIG_NAME
        if which("kubectl") is None:
            checks.append(Check("kubectl", FAIL, "the kubectl command was not found", "Install kubectl."))
        elif not kubeconfig.is_file():
            checks.append(Check("kubectl", FAIL, "the triage kubeconfig does not exist", "Create it with the commands in the README."))
        else:
            checks.append(Check("kubectl", OK))

    try:
        config.cases_dir.mkdir(parents=True, exist_ok=True)
        writable = os.access(config.cases_dir, os.W_OK)
    except OSError:
        writable = False
    if writable:
        checks.append(Check("Cases folder", OK, str(config.cases_dir)))
    else:
        checks.append(Check("Cases folder", FAIL, f"cannot write to {config.cases_dir}", "Fix cases_dir in the config."))

    if env.get("TYPESAFE_API_KEY"):
        checks.append(Check("TypeSafe key", OK))
    else:
        checks.append(
            Check("TypeSafe key", WARN, "TYPESAFE_API_KEY is not set; causes will be capped at 'probable'", "Export TYPESAFE_API_KEY in your shell profile.")
        )
    return checks


def exit_code(checks: Sequence[Check]) -> int:
    """0 ready (warnings allowed), 1 something failed, 3 only sign-in is needed."""
    statuses = {check.status for check in checks}
    if FAIL in statuses:
        return 1
    if SIGN_IN in statuses:
        return 3
    return 0


def render_text(checks: Sequence[Check]) -> str:
    lines = []
    for check in checks:
        line = f"[{check.status:<7}] {check.name}"
        if check.detail:
            line += f": {check.detail}"
        lines.append(line)
        if check.fix and check.status != OK:
            lines.append(f"          fix: {check.fix}")
    return "\n".join(lines)


def as_dicts(checks: Sequence[Check]) -> list[dict[str, str]]:
    return [asdict(check) for check in checks]
```

`skill/ai-triage/scripts/preflight.py`

```python
#!/usr/bin/env python3
"""Check that a triage run can start: config, service map, sign-in, tools.

Exit codes: 0 ready, 1 a check failed, 2 usage error, 3 only a sign-in is needed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from triage.preflight import as_dicts, exit_code, render_text, run_preflight

SKILL_DIR = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="preflight", description=__doc__.split("\n\n")[0])
    parser.add_argument("--account", action="append", default=[], metavar="ALIAS", help="check sign-in only for this account; repeatable")
    parser.add_argument("--json", action="store_true", help="print the checks as JSON")
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    checks = run_preflight(args.skill_dir, args.account)
    code = exit_code(checks)
    if args.json:
        print(json.dumps({"exit_code": code, "checks": as_dicts(checks)}, indent=2))
    else:
        print(render_text(checks))
    return code


if __name__ == "__main__":
    sys.exit(main())
```

Then: `chmod +x skill/ai-triage/scripts/preflight.py`

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_preflight.py`
Expected: PASS, 14 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): add the preflight check" -m "An expired sign-in is the one thing a person must fix, so it is detected before any unattended work begins and reported with the exact command to run."
```

### Task 13: Installer

**Files:**
- Create: `install.sh`
- Test: `tests/test_install.py`

**Interfaces:**
- Consumes: the `skill/ai-triage/` tree from Tasks 2 to 12.
- Produces: `install.sh [--dry-run] [--help]`, exit 0 done, 1 failure, 2 usage, 3 missing prerequisite. Installs to `$HOME/.claude/skills/ai-triage`, backs up `config/` to `$HOME/.ai-triage/backups/<timestamp>/` before an upgrade, honours `AI_TRIAGE_SKIP_VENV=1`.

- [ ] **Step 1: Write the failing test**

`tests/test_install.py`

```python
import os
import subprocess
import sys

import pytest

from conftest import ROOT

INSTALL = ROOT / "install.sh"


def stub(path, body):
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


@pytest.fixture
def sandbox(tmp_path):
    """A fake HOME and a PATH holding stub aws, python3, and kubectl commands."""
    home, bin_dir = tmp_path / "home", tmp_path / "bin"
    home.mkdir()
    bin_dir.mkdir()
    stub(bin_dir / "aws", 'echo "aws-cli/2.34.4 Python/3.13.11 Darwin/27.0.0"')
    stub(bin_dir / "python3", f'exec "{sys.executable}" "$@"')
    stub(bin_dir / "kubectl", "exit 0")
    return home, bin_dir


def install(sandbox, *args, skip_venv=True):
    home, bin_dir = sandbox
    env = {"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin"}
    if skip_venv:
        env["AI_TRIAGE_SKIP_VENV"] = "1"
    return subprocess.run(["bash", str(INSTALL), *args], capture_output=True, text=True, env=env)


def dest(sandbox):
    return sandbox[0] / ".claude" / "skills" / "ai-triage"


def test_help(sandbox):
    result = install(sandbox, "--help")
    assert result.returncode == 0 and result.stdout.startswith("Usage: install.sh")


def test_unknown_option_is_a_usage_error(sandbox):
    result = install(sandbox, "--force")
    assert result.returncode == 2 and "Unknown option: --force" in result.stderr


def test_dry_run_changes_nothing(sandbox):
    result = install(sandbox, "--dry-run", skip_venv=False)
    assert result.returncode == 0
    assert "[dry-run] Nothing was changed." in result.stdout
    assert "-m pip install" in result.stdout
    assert not (sandbox[0] / ".claude").exists()
    assert not (sandbox[0] / ".ai-triage").exists()


def test_fresh_install_creates_the_skill_and_config(sandbox):
    result = install(sandbox)
    assert result.returncode == 0, result.stderr
    target = dest(sandbox)
    assert (target / "SKILL.md").is_file()
    assert os.access(target / "scripts" / "guard_hook.sh", os.X_OK)
    assert (target / "scripts" / "triage" / "guard.py").is_file()
    for name in ("triage-config", "service-map"):
        example = (target / "config" / f"{name}.example.yaml").read_text()
        assert (target / "config" / f"{name}.yaml").read_text() == example
    assert "Next steps:" in result.stdout
    assert not list(target.rglob("__pycache__"))


def test_upgrade_keeps_config_and_backs_it_up(sandbox):
    assert install(sandbox).returncode == 0
    target = dest(sandbox)
    (target / "config" / "triage-config.yaml").write_text("mine: true\n")
    (target / "config" / "service-map.yaml").write_text("services: {}\n")
    (target / "config" / "kubeconfig").write_text("kind: Config\n")
    (target / "scripts" / "stale.py").write_text("# left over from an old version\n")

    result = install(sandbox)

    assert result.returncode == 0, result.stderr
    assert (target / "config" / "triage-config.yaml").read_text() == "mine: true\n"
    assert (target / "config" / "service-map.yaml").read_text() == "services: {}\n"
    assert (target / "config" / "kubeconfig").read_text() == "kind: Config\n"
    assert not (target / "scripts" / "stale.py").exists()
    assert "Kept your existing triage-config.yaml" in result.stdout
    backups = list((sandbox[0] / ".ai-triage" / "backups").iterdir())
    assert len(backups) == 1
    assert (backups[0] / "config" / "triage-config.yaml").read_text() == "mine: true\n"


def test_home_folder_with_a_space_in_its_name(sandbox, tmp_path):
    home = tmp_path / "First Last"
    home.mkdir()
    spaced = (home, sandbox[1])
    assert install(spaced).returncode == 0
    (dest(spaced) / "config" / "triage-config.yaml").write_text("mine: true\n")
    result = install(spaced)
    assert result.returncode == 0, result.stderr
    assert (dest(spaced) / "config" / "triage-config.yaml").read_text() == "mine: true\n"
    assert len(list((home / ".ai-triage" / "backups").iterdir())) == 1


def test_missing_aws_cli_is_a_prerequisite_error(sandbox):
    (sandbox[1] / "aws").unlink()
    result = install(sandbox)
    assert result.returncode == 3 and "the aws command was not found" in result.stderr
    assert not dest(sandbox).exists()


def test_old_aws_cli_is_a_prerequisite_error(sandbox):
    stub(sandbox[1] / "aws", 'echo "aws-cli/1.32.0 Python/3.11"')
    result = install(sandbox)
    assert result.returncode == 3 and "AWS CLI version 2 is required" in result.stderr


def test_old_python_is_a_prerequisite_error(sandbox):
    stub(sandbox[1] / "python3", "exit 1")
    result = install(sandbox)
    assert result.returncode == 3 and "Python 3.10 or newer is required" in result.stderr


def test_missing_kubectl_is_only_a_warning(sandbox):
    (sandbox[1] / "kubectl").unlink()
    result = install(sandbox)
    assert result.returncode == 0 and "Warning: kubectl was not found" in result.stdout
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_install.py`
Expected: FAIL. Every test fails because `install.sh` does not exist, so `bash` exits 127.

- [ ] **Step 3: Write the implementation**

`install.sh`

```bash
#!/usr/bin/env bash
# Install or upgrade the AI Triage skill into ~/.claude/skills/ai-triage.
set -euo pipefail

readonly EXIT_FAILURE=1
readonly EXIT_USAGE=2
readonly EXIT_PREREQUISITE=3

usage() {
  cat <<'USAGE'
Usage: install.sh [--dry-run] [--help]

Installs or upgrades the AI Triage skill in ~/.claude/skills/ai-triage.

  --dry-run   Print every step without changing anything.
  --help      Show this text.

An upgrade replaces the skill's code and keeps your config, service map, and
kubeconfig. They are backed up to ~/.ai-triage/backups/<timestamp>/ first.

Environment:
  AI_TRIAGE_SKIP_VENV=1   Do not create the Python environment (used by tests).

Exit codes: 0 done, 1 failure, 2 usage error, 3 missing prerequisite.
USAGE
}

dry_run=0
while (($# > 0)); do
  case "$1" in
    --dry-run) dry_run=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit "${EXIT_USAGE}"
      ;;
  esac
  shift
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${script_dir}/skill/ai-triage"
dest_dir="${HOME}/.claude/skills/ai-triage"
backup_root="${HOME}/.ai-triage/backups"

log() { printf '%s\n' "$*"; }

fail() {
  local code="$1"
  shift
  printf 'Error: %s\n' "$*" >&2
  exit "${code}"
}

run() {
  if ((dry_run)); then
    log "[dry-run] $*"
  else
    "$@"
  fi
}

check_prerequisites() {
  [[ -f "${source_dir}/SKILL.md" ]] || fail "${EXIT_FAILURE}" "skill source not found at ${source_dir}"
  command -v aws >/dev/null 2>&1 || fail "${EXIT_PREREQUISITE}" "the aws command was not found. Install AWS CLI version 2."
  local aws_version
  aws_version="$(aws --version 2>&1)"
  [[ "${aws_version}" == aws-cli/2.* ]] || fail "${EXIT_PREREQUISITE}" "AWS CLI version 2 is required, found: ${aws_version}"
  command -v python3 >/dev/null 2>&1 || fail "${EXIT_PREREQUISITE}" "python3 was not found. Install Python 3.10 or newer."
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' ||
    fail "${EXIT_PREREQUISITE}" "Python 3.10 or newer is required."
  if ! command -v kubectl >/dev/null 2>&1; then
    log "Warning: kubectl was not found. It is needed only if you configure EKS clusters."
  fi
}

backup_config() {
  [[ -d "${dest_dir}/config" ]] || return 0
  local backup_dir
  backup_dir="${backup_root}/$(date +%Y%m%d-%H%M%S)"
  run mkdir -p "${backup_dir}"
  run cp -R "${dest_dir}/config" "${backup_dir}/config"
  log "Backed up your config to ${backup_dir}"
}

copy_code() {
  run mkdir -p "${dest_dir}"
  local path name
  for path in "${source_dir}"/*; do
    name="$(basename "${path}")"
    [[ "${name}" == "config" ]] && continue
    run rm -rf "${dest_dir:?}/${name}"
    run cp -R "${path}" "${dest_dir}/${name}"
  done
  if ((!dry_run)); then
    find "${dest_dir}/scripts" -type d -name '__pycache__' -prune -exec rm -rf {} +
  fi
}

install_config() {
  run mkdir -p "${dest_dir}/config"
  local name
  for name in triage-config service-map; do
    run cp "${source_dir}/config/${name}.example.yaml" "${dest_dir}/config/${name}.example.yaml"
    if [[ -f "${dest_dir}/config/${name}.yaml" ]]; then
      log "Kept your existing ${name}.yaml"
    else
      run cp "${source_dir}/config/${name}.example.yaml" "${dest_dir}/config/${name}.yaml"
      log "Created ${name}.yaml from the example. Edit it before the first run."
    fi
  done
}

install_python_environment() {
  if [[ "${AI_TRIAGE_SKIP_VENV:-0}" == "1" ]]; then
    log "Skipping the Python environment (AI_TRIAGE_SKIP_VENV=1)."
    return 0
  fi
  if [[ ! -x "${dest_dir}/.venv/bin/python" ]]; then
    run python3 -m venv "${dest_dir}/.venv"
  fi
  run "${dest_dir}/.venv/bin/python" -m pip install --quiet --disable-pip-version-check -r "${dest_dir}/requirements.txt"
}

print_next_steps() {
  cat <<NEXT

Installed in ${dest_dir}

Next steps:

1. Edit ${dest_dir}/config/triage-config.yaml and service-map.yaml.

2. Add one profile per account to ~/.aws/config:

     [profile triage-<account-alias>]
     sso_session = <your sso session name>
     sso_account_id = <account id>
     sso_role_name = ai-triage-read-only
     region = <region>

3. For each EKS cluster, add a context to the skill's own kubeconfig:

     aws eks update-kubeconfig --name <cluster> --alias triage-<cluster> \\
       --kubeconfig ${dest_dir}/config/kubeconfig \\
       --profile triage-<account-alias> --region <region>

4. Connect OneUptime as read only, then Confluence and Slack:

     claude mcp add --transport http oneuptime <your OneUptime URL>/mcp

5. Install the TypeSafe plugin and set TYPESAFE_API_KEY in your shell profile:

     claude plugin marketplace add typesafe-ai/skills
     claude plugin install typesafe@typesafe-ai

6. Check your setup:

     ${dest_dir}/.venv/bin/python ${dest_dir}/scripts/validate_map.py
     ${dest_dir}/.venv/bin/python ${dest_dir}/scripts/verify_access.py

See README.md and docs/aws-permissions.md for details.
NEXT
}

check_prerequisites
backup_config
copy_code
install_config
install_python_environment
if ((dry_run)); then
  log "[dry-run] Nothing was changed."
else
  print_next_steps
fi
```

Then: `chmod +x install.sh`

The `rm -rf` in `copy_code` removes only named entries inside the skill folder, never `config/`, and `${dest_dir:?}` aborts if the variable is ever empty.

- [ ] **Step 4: Run the test to verify it passes**

Run: `./run-tests.sh tests/test_install.py`
Expected: PASS, 10 passed. shellcheck reports nothing for `install.sh`.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "feat(ai-triage): add the installer" -m "Config and the service map live in the installed folder, so an upgrade must replace code without touching them and must keep a backup."
```

### Task 14: Permissions document and README

**Files:**
- Create: `docs/aws-permissions.md`
- Create: `README.md`
- Test: `tests/test_docs.py`

**Interfaces:**
- Consumes: `REQUIRED_DENIES` (Task 9); the policy file (Task 9).
- Produces: the two documents. The test keeps the permissions document in step with the policy file.

- [ ] **Step 1: Write the failing test**

`tests/test_docs.py`

```python
"""The permissions document must describe exactly what the policy grants."""
import json
import re

from conftest import ROOT
from triage.policy_check import REQUIRED_DENIES

DOC = ROOT / "docs" / "aws-permissions.md"
POLICY = ROOT / "iam" / "ai-triage-inline-policy.json"
README = ROOT / "README.md"


def statements(effect):
    return [s for s in json.loads(POLICY.read_text())["Statement"] if s["Effect"] == effect]


def test_every_granted_action_is_documented():
    text = DOC.read_text()
    missing = [
        action
        for statement in statements("Allow")
        for action in statement["Action"]
        if not re.search(rf"`(?:{re.escape(action)}|{re.escape(action.split(':', 1)[1])})`", text)
    ]
    assert missing == []


def test_every_explicit_deny_is_documented():
    text = DOC.read_text()
    assert [action for action in sorted(REQUIRED_DENIES) if f"`{action}`" not in text] == []


def test_documents_name_the_policies_they_were_checked_against():
    text = DOC.read_text()
    assert "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess" in text
    assert "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy" in text
    assert re.search(r"`ViewOnlyAccess` version \d+", text)


def test_readme_covers_the_required_sections():
    text = README.read_text()
    for heading in ("## Prerequisites", "## Install", "## Configure", "## Verify", "## Use", "## Upgrade", "## Uninstall", "## Troubleshooting"):
        assert heading in text
    for script in ("validate_map.py", "preflight.py", "verify_access.py", "install.sh"):
        assert script in text
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./run-tests.sh tests/test_docs.py`
Expected: FAIL. All four tests fail with `FileNotFoundError`.

- [ ] **Step 3: Write the documents**

`docs/aws-permissions.md`

````markdown
# AI Triage: access and permissions

This document lists every permission the AI Triage skill needs, why it needs it,
and how to set it up. The skill only reads. It never changes anything in AWS,
Kubernetes, OpenSearch, or OneUptime.

## How read-only is guaranteed

| System | What enforces read-only | Strength |
|---|---|---|
| AWS | The `ai-triage-read-only` permission set. It grants read actions only and explicitly denies secret values and interactive access. | Enforced by AWS |
| Kubernetes (EKS) | An access entry tied to the AWS access policy `AmazonEKSViewPolicy`. | Enforced by the cluster |
| OpenSearch | The skill's query tool allows only a fixed list of read operations, and the guard blocks every other route to the cluster. | Convention only: the cluster has no login |
| OneUptime | The MCP connection is authorised as read only. | Enforced by OneUptime |

On the engineer's machine, a guard hook makes sure these identities are the ones
in use. It blocks any AWS command that does not use a triage profile, and any
`kubectl` command that does not use the skill's own kubeconfig.

## 1. AWS permission set

### Create it

Do this once, in IAM Identity Center, from the management or delegated
administrator account.

1. Create a permission set named `ai-triage-read-only`. A session duration of two
   hours suits a triage run.
2. Attach the AWS managed policy `ViewOnlyAccess`
   (`arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`).
3. Add the contents of [`iam/ai-triage-inline-policy.json`](../iam/ai-triage-inline-policy.json)
   as the inline policy.
4. Assign the permission set to your on-call group in every account the skill
   should cover.

If you use a different name, set `permission_set` in `triage-config.yaml` to match.
The skill refuses to run with a profile that uses any other permission set.

### Why this composition

The AWS managed `ViewOnlyAccess` policy covers most describe and list calls but
leaves out content such as log events. `ReadOnlyAccess` goes too far the other
way: it allows reading S3 objects, DynamoDB items, queue messages, and source
code. The permission set therefore starts from `ViewOnlyAccess` and adds a short,
explicit list. A missing permission shows up as an access-denied error, which the
skill records in the report's coverage notes.

Checked on 2026-10-04 against `ViewOnlyAccess` version 46 and `ReadOnlyAccess`
version 190. AWS changes these policies over time. Re-run
`tools/check_policy_actions.py` and `verify_access.py` after AWS updates them.

### What `ViewOnlyAccess` already provides

ECS describe and list, EC2 describe, EKS describe and list, RDS describe including
events, ElastiCache describe, load balancer basics and target health, CloudWatch
metrics, CloudTrail event lookup, Route 53, EC2 Auto Scaling, VPC networking
describes, SQS queue attributes, DynamoDB table metadata, and API Gateway `GET` on
the common resource paths.

### What the inline policy adds

| Area | Actions | Why triage needs it | Sensitivity |
|---|---|---|---|
| CloudWatch Logs | `logs:GetLogEvents`, `FilterLogEvents`, `StartQuery`, `StopQuery`, `GetQueryResults`, `GetLogRecord`, `GetLogGroupFields` | Application and platform errors | High: log content |
| CloudWatch alarms | `cloudwatch:DescribeAlarms`, `DescribeAlarmHistory`, `DescribeAlarmsForMetric` | What fired and when | Low |
| AWS Health | `health:DescribeEvents`, `DescribeEventDetails`, `DescribeAffectedEntities` | AWS-side incidents | Low |
| Tagging | `tag:GetResources`, `GetTagKeys`, `GetTagValues` | Finding resources by tag | Low |
| Service Quotas | `servicequotas:ListServiceQuotas`, `GetServiceQuota` | Limit exhaustion | Low |
| ECR | `ecr:DescribeImages`, `DescribeImageScanFindings` | Which image is deployed and when it was pushed | Low |
| EC2 | `ec2:GetConsoleOutput` | Boot failures | Medium |
| Application Auto Scaling | `application-autoscaling:DescribeScalableTargets`, `DescribeScalingActivities`, `DescribeScalingPolicies` | Service scaling history | Low |
| Lambda | `lambda:GetFunctionConfiguration`, `GetFunctionConcurrency`, `GetFunctionEventInvokeConfig`, `GetEventSourceMapping`, `GetFunctionUrlConfig`, `GetAlias`, `GetAccountSettings` | Settings, limits, event sources | Medium: environment values |
| RDS | `rds:DownloadDBLogFilePortion` | Database error and slow query logs | High: logs may hold query text |
| Performance Insights | `pi:GetResourceMetrics`, `DescribeDimensionKeys`, `GetDimensionKeyDetails`, `GetResourceMetadata`, `ListAvailableResourceDimensions`, `ListAvailableResourceMetrics` | Database load and top queries | Medium: query text |
| OpenSearch domains | `es:DescribeDomain`, `DescribeDomains`, `DescribeDomainConfig`, `DescribeDomainHealth`, `DescribeDomainNodes`, `DescribeDomainChangeProgress`, `ListTags` | Domain state and configuration changes | Low |
| EFS | `elasticfilesystem:DescribeMountTargets`, `DescribeMountTargetSecurityGroups`, `DescribeAccessPoints`, `DescribeFileSystemPolicy`, `DescribeLifecycleConfiguration` | Mount and access failures | Low |
| SNS | `sns:GetTopicAttributes` | Delivery policy and failures | Low |
| Load balancing | `elasticloadbalancing:DescribeRules`, `DescribeTargetGroupAttributes`, `DescribeListenerCertificates`, `DescribeTags` | Routing and health check settings | Low |
| ACM | `acm:DescribeCertificate` | Certificate expiry | Low |
| CloudFront | `cloudfront:GetDistribution`, `GetDistributionConfig` | Origins and behaviors | Low |
| WAF | `wafv2:GetWebACL`, `GetWebACLForResource`, `GetRuleGroup`, `GetSampledRequests` | Which rule blocked traffic | High: sampled requests |
| API Gateway | `apigateway:GET` on REST and HTTP APIs, usage plans, account settings, domain names | Stages, integrations, throttling | Low |
| CloudFormation | `cloudformation:DescribeStackEvents`, `DescribeStackResources` | What a stack update changed | Low |
| CodePipeline, CodeBuild | `codepipeline:GetPipelineState`, `GetPipelineExecution`, `ListPipelineExecutions`, `ListActionExecutions`, `codebuild:BatchGetBuilds` | Correlate releases with the incident | Low |
| AWS Config | `config:GetResourceConfigHistory`, `BatchGetResourceConfig` | What changed on one resource, and when | Medium: configuration values |
| Parameter Store | `ssm:DescribeParameters`, `GetParameter`, `GetParameters`, `GetParametersByPath` | Configuration the application points at | Medium: plain values |
| IAM | `iam:GetRole`, `GetRolePolicy`, `GetPolicy`, `GetPolicyVersion`, `SimulatePrincipalPolicy` | Diagnose access-denied incidents; power the verify script | Low |
| KMS | `kms:DescribeKey`, `GetKeyPolicy` | Key state and key access | Low |
| Secrets Manager | `secretsmanager:DescribeSecret`, `ListSecrets` | Rotation status only | Low |

### Sensitive data decisions

- **Log content** is readable for every log group. Triage is not possible without it.
- **Parameter Store** plain values are readable. Encrypted values are not, because
  decryption is not granted.
- **Secrets Manager** exposes metadata only. Secret values are explicitly denied.
- **ECS task definitions and Lambda configuration** may contain plaintext
  environment values. The skill's collectors redact secret-looking values before
  they reach the model or any report.
- **WAF sampled requests** are readable. Client addresses and headers are redacted.
- **DynamoDB** exposes table metadata and metrics only. Items cannot be read.
- **S3 objects** cannot be read. See the optional exception below.
- **Lambda code** cannot be downloaded.

### Explicit denies

These are denied outright, so they stay blocked even if someone later attaches a
broader policy to the permission set:

`secretsmanager:GetSecretValue`, `secretsmanager:BatchGetSecretValue`,
`kms:Decrypt`, `ssm:StartSession`, `ssm:SendCommand`, `ecs:ExecuteCommand`,
`ec2:GetPasswordData`, `ec2-instance-connect:*`, `rds-data:*`, `rds-db:connect`.

### Optional: load balancer access logs in S3

Off by default. To let triage read load balancer access logs, add this statement
to the inline policy of your permission set, naming only the log buckets. Keep it
out of the copy in this repository.

```json
{
  "Sid": "TriageLoadBalancerAccessLogs",
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::<your-load-balancer-log-bucket>/*"]
}
```

### Cost

Read-only is not free. CloudWatch Logs Insights bills by the volume of data
scanned. The skill always bounds the time window and the number of log groups,
using `limits` in `triage-config.yaml`.

## 2. AWS CLI profiles

Each engineer adds one profile per account to `~/.aws/config`. The name must start
with `triage-` and match the `profile` value for that account in
`triage-config.yaml`.

```ini
[profile triage-prod-main]
sso_session = <your sso session name>
sso_account_id = <account id>
sso_role_name = ai-triage-read-only
region = eu-west-1
```

Sign in with `aws sso login --profile triage-prod-main`. The skill never signs in
for you. When a session expires, it stops and prints this command.

## 3. Kubernetes access for EKS

The AWS API sees a cluster only from outside. To see pods, events, and logs, the
triage role needs read access to the Kubernetes API. An administrator sets this up
once per cluster. The cluster's authentication mode must be `API` or
`API_AND_CONFIG_MAP`.

Find the role that the permission set created in the cluster's account:

```bash
aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/ \
  --query "Roles[?starts_with(RoleName, 'AWSReservedSSO_ai-triage-read-only_')].Arn" \
  --output text --profile <admin profile> --region <region>
```

Create the access entry and attach the view policy. Use the role ARN exactly as
printed, including its path.

```bash
aws eks create-access-entry --cluster-name <cluster> --principal-arn <role arn> \
  --type STANDARD --profile <admin profile> --region <region>

aws eks associate-access-policy --cluster-name <cluster> --principal-arn <role arn> \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy \
  --access-scope type=cluster --profile <admin profile> --region <region>
```

These two commands change the cluster's access configuration. An administrator
runs them. The skill never does.

### What the view policy allows

Checked on 2026-10-04. `get`, `list`, and `watch` on pods, pod logs, events,
deployments, replica sets, stateful sets, daemon sets, jobs, cron jobs, services,
endpoints, ingresses, network policies, config maps, persistent volume claims,
autoscalers, disruption budgets, quotas, and namespaces.

It does not include secrets. It also does not include nodes or the metrics API.
Without the optional role below, node health comes from the AWS side: node group
health, EC2 instance status, and Container Insights.

### Optional: nodes and metrics

To let triage read node state and resource usage from inside the cluster, apply
this manifest and add the group to the access entry.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ai-triage-nodes-read
  labels:
    app: ai-triage
    owner: platform
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["metrics.k8s.io"]
    resources: ["nodes", "pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ai-triage-nodes-read
  labels:
    app: ai-triage
    owner: platform
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ai-triage-nodes-read
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: ai-triage-nodes
```

```bash
aws eks update-access-entry --cluster-name <cluster> --principal-arn <role arn> \
  --kubernetes-groups ai-triage-nodes --profile <admin profile> --region <region>
```

### The skill's own kubeconfig

The skill uses a separate kubeconfig that holds only triage contexts. It never
reads `~/.kube/config`, so your everyday cluster access is not reachable from a
triage run. Each engineer creates the contexts once:

```bash
aws eks update-kubeconfig --name <cluster> --alias triage-<cluster> \
  --kubeconfig ~/.claude/skills/ai-triage/config/kubeconfig \
  --profile triage-<account-alias> --region <region>
```

The alias must match the `context` value for that cluster in `triage-config.yaml`.

During a run, only these `kubectl` verbs are allowed: `get`, `describe`, `logs`,
`events`, `top`, `rollout status`, `rollout history`, `auth can-i`,
`api-resources`, `api-versions`, `explain`, and `version`. Reading secrets,
following logs without a bound, and every changing verb are blocked.

## 4. OpenSearch

The cluster is reachable on the network without a login. Nothing on the server
side stops a write. Read-only therefore rests on two things on the engineer's
machine:

- **The query tool** allows a fixed list of read operations: search, count,
  mappings, settings, and the health and statistics endpoints. Everything else is
  refused.
- **The guard** blocks any command that addresses a configured cluster without
  going through the tool. It matches the cluster's hostname. A cluster reached by
  IP address is not recognised, so always configure and use the hostname.

This is a strong convention, not a hard boundary. Turning on fine-grained access
control and giving the skill a read-only user would close the gap.

Every query has a mandatory time range, a result cap, and a timeout, because a
heavy query against a struggling cluster can make an incident worse.

## 5. OneUptime

Connect the OneUptime MCP server by signing in, and choose **read only** when
authorising. The skill uses only the `get_`, `list_`, and `count_` tools.

## 6. Verify your setup

```bash
~/.claude/skills/ai-triage/.venv/bin/python ~/.claude/skills/ai-triage/scripts/verify_access.py
```

For every configured account this checks three things:

1. **Identity.** The profile signs in to the expected account with the triage
   permission set.
2. **Reads.** One harmless list or describe call per permission area succeeds.
3. **Writes are denied.** The IAM policy simulator is asked about a sample of
   write actions. Nothing is attempted against your resources.

The simulator evaluates the role's own policies. It does not evaluate service
control policies or resource policies, so treat it as a check on the permission
set and not as a full audit.

AWS Health needs a Business or Enterprise support plan. Without one, that check is
reported as skipped.
````

`README.md`

````markdown
# AI Triage

A Claude Code skill that triages a OneUptime incident. You point Claude at an
incident, and it investigates on its own using read-only access to AWS, EKS, and
OpenSearch. It finds the likely root cause and writes a detailed remediation work
order. It never changes anything.

## Status

This is the **foundation build**. It installs the safety layer and the setup
checks:

- the config file and service map, with validation
- the guard that keeps every AWS and Kubernetes command read-only
- the AWS permission policy and the script that verifies your access
- the preflight check and the installer

The triage method, the evidence collectors, the confidence checks, and publishing
to Confluence and Slack arrive in later builds. See
[the design](docs/specs/2026-10-04-ai-triage-design.md).

## Prerequisites

- Claude Code
- AWS CLI version 2
- Python 3.10 or newer
- `kubectl`, only if you configure EKS clusters
- The `ai-triage-read-only` permission set assigned to you in each account. See
  [docs/aws-permissions.md](docs/aws-permissions.md).

## Install

```bash
cd LLM_Skills/AI_Triage
./install.sh --dry-run   # shows every step, changes nothing
./install.sh
```

The skill is copied to `~/.claude/skills/ai-triage/`. The installer does not edit
your AWS config or your Claude Code settings.

## Configure

All of your settings live in `~/.claude/skills/ai-triage/config/`. This folder is
on your machine only. Never copy these files into this repository, which is public.

1. **`triage-config.yaml`.** Your OneUptime address, AWS accounts, OpenSearch
   clusters, EKS clusters, Confluence target, and Slack channel. It holds no
   secrets.
2. **`service-map.yaml`.** Which OneUptime monitors, labels, and hostnames belong
   to which service, and where each environment of that service runs.
3. **AWS profiles.** One profile per account in `~/.aws/config`, named
   `triage-<account-alias>`. See [docs/aws-permissions.md](docs/aws-permissions.md).
4. **Kubeconfig.** One context per EKS cluster in the skill's own kubeconfig. The
   command is in [docs/aws-permissions.md](docs/aws-permissions.md).
5. **Connectors.** Connect OneUptime as read only, then Confluence and Slack:

   ```bash
   claude mcp add --transport http oneuptime <your OneUptime URL>/mcp
   ```

6. **TypeSafe.** Install the plugin and set `TYPESAFE_API_KEY` in your shell
   profile. Without the key the skill still runs, but it cannot label a cause
   higher than "probable".

   ```bash
   claude plugin marketplace add typesafe-ai/skills
   claude plugin install typesafe@typesafe-ai
   ```

## Verify

```bash
cd ~/.claude/skills/ai-triage
.venv/bin/python scripts/validate_map.py    # config and service map are well formed
.venv/bin/python scripts/preflight.py       # sign-in, tools, folders
.venv/bin/python scripts/verify_access.py   # reads work, writes are denied
```

| Script | Exit 0 | Exit 1 | Exit 2 | Exit 3 |
|---|---|---|---|---|
| `validate_map.py` | valid | invalid | usage error | |
| `preflight.py` | ready | a check failed | usage error | only a sign-in is needed |
| `verify_access.py` | all passed | a check failed | usage or config error | a sign-in expired |

When a sign-in has expired, run the `aws sso login --profile <name>` command that
the script prints.

## Use

In Claude Code:

```
/ai-triage
```

In this build the skill runs the preflight check and turns on the guard.

## The guard

Invoking the skill turns on a guard for the rest of that Claude Code session.

- **Approved without a prompt:** read-only AWS commands that use a triage profile
  and set a region, read-only `kubectl` commands that use the skill's kubeconfig
  with a triage context and a namespace, and the skill's own scripts.
- **Blocked:** every other AWS or `kubectl` command, including reads with your
  everyday profiles, and any direct call to a configured OpenSearch cluster.
- **Asked about:** commands the guard cannot check, such as `bash -c "aws ..."`.
- **Left alone:** everything unrelated. Your normal permission settings apply.

To work with your everyday AWS profiles again, start a new session.

## Upgrade

Pull the repository and run `./install.sh` again. Your config, service map, and
kubeconfig are kept, and a copy is saved under `~/.ai-triage/backups/` first.

## Uninstall

Remove `~/.claude/skills/ai-triage/` and the `triage-*` profiles in
`~/.aws/config`. Case files and backups live under `~/.ai-triage/`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| "the triage guard has no valid config" | `triage-config.yaml` is missing or invalid. Run `validate_map.py` and fix what it lists. |
| "profile 'x' is not a triage profile" | The command used a profile that is not in `triage-config.yaml`. Triage commands must use a `triage-` profile. |
| "the skill is not installed correctly" | The Python environment is missing. Run `./install.sh` again. |
| `verify_access.py` reports "does not use the ai-triage-read-only permission set" | The profile's `sso_role_name` points at another permission set. |
| A read check fails with `AccessDeniedException` | The inline policy is missing or out of date in that account. |

## Develop

```bash
cd LLM_Skills/AI_Triage
./run-tests.sh                 # whole suite
./run-tests.sh tests/test_guard.py -k kubectl
python3 tools/check_policy_actions.py   # needs network; run after editing the policy
```

The tests never call AWS. `verify_access.py` is the only thing that does, and you
run it yourself.
````

- [ ] **Step 4: Run the whole suite**

Run: `./run-tests.sh`
Expected: PASS, 297 passed.

- [ ] **Step 5: Commit**

```bash
git add -A .
git commit -m "docs(ai-triage): document permissions, setup, and usage" -m "Someone other than the author must be able to grant the access and install the skill from these two documents alone."
```

### Task 15: Live check in Claude Code

**Files:**
- Create: `docs/verification-notes.md`

**Interfaces:**
- Consumes: everything above.
- Produces: a recorded answer to whether the skill's hook also covers subagents. The Stage 3 plan depends on it.

This task needs a person. It installs into the engineer's real home folder and runs an interactive Claude Code session, so it cannot be done by a subagent and it is not automated. Ask the engineer before starting, and show them each command first.

The Claude Code docs state that hooks from settings files and plugins run inside subagents. They do not say the same for hooks declared in a skill's frontmatter. This task finds out.

- [ ] **Step 1: Install**

```bash
./install.sh --dry-run
./install.sh
```

Expected: the dry run lists the steps, and the real run ends with "Next steps:".

- [ ] **Step 2: Give the guard a valid config**

Edit `~/.claude/skills/ai-triage/config/triage-config.yaml` so it has at least one real account with its `triage-` profile. Then:

```bash
~/.claude/skills/ai-triage/.venv/bin/python ~/.claude/skills/ai-triage/scripts/validate_map.py
```

Expected: `OK: ...`. If the service map still holds the example services, replace its content with `services: {}`.

- [ ] **Step 3: Check the hook in the main session**

Start a new Claude Code session, run `/ai-triage`, then ask Claude to run each command below and note what happens.

| Command | Expected |
|---|---|
| `aws sts get-caller-identity --profile <triage profile> --region <region>` | Runs with no permission prompt |
| `aws sts get-caller-identity --profile <everyday profile> --region <region>` | Blocked, reason mentions "not a triage profile" |
| `aws ecs stop-task --task x --profile <triage profile> --region <region>` | Blocked, reason mentions "not a known read" |
| `bash -c "aws sts get-caller-identity --profile <triage profile> --region <region>"` | A permission prompt appears |
| `ls` | Unaffected |

- [ ] **Step 4: Check the hook inside a subagent**

In the same session, ask Claude to spawn a subagent, with its model set explicitly to Sonnet, that runs the second and third commands from the table. Note whether they are blocked.

- [ ] **Step 5: Check that the hook survives a later turn**

Send any other message, then ask Claude to run the first command again. Expected: it still runs with no prompt, because skill hooks stay registered for the rest of the session.

- [ ] **Step 6: Record the results**

Create `docs/verification-notes.md` with the real results in place of each `<...>`:

```markdown
# Live verification notes

Date: <date>
Claude Code version: <output of `claude --version`>

| Check | Result |
|---|---|
| Read with a triage profile runs without a prompt | <yes / no> |
| Read with an everyday profile is blocked | <yes / no> |
| Write with a triage profile is blocked | <yes / no> |
| Indirect call through `bash -c` asks | <yes / no> |
| Unrelated command is unaffected | <yes / no> |
| Hook still active on a later turn | <yes / no> |
| Hook blocks the same commands inside a subagent | <yes / no> |

## Consequence for Stage 3

<If the hook covers subagents: parallel analysts run as subagents, as the spec
describes. If it does not: either the analysts run in the main session one after
another, or the installer registers the hook in the user's settings with their
consent. State which was observed and which option is chosen.>
```

This file is a record template, so its angle-bracket fields are filled in by the person running the check.

- [ ] **Step 7: Run verify_access against real accounts**

```bash
~/.claude/skills/ai-triage/.venv/bin/python ~/.claude/skills/ai-triage/scripts/verify_access.py
```

Expected: every row is `pass`, or `skipped` for AWS Health without a support plan. This is the first time the probes and the simulator meet real AWS. If a row fails, record it in the notes and fix the cause before Stage 2: a missing permission is fixed in the permission set, a wrong command is fixed in `verify.py` with a test.

- [ ] **Step 8: Commit**

```bash
git add -A docs/verification-notes.md
git commit -m "docs(ai-triage): record the live check of the guard hook" -m "Stage 3 needs to know whether the hook covers subagents before it decides how the analysts run."
```

---

## After this plan

Four plans follow, each written when the one before it is done.

| Plan | Scope |
|---|---|
| 2. Evidence | Collectors for each service, source redaction, and the `opensearch_query.py` tool with its read list and limits |
| 3. Method | The full `SKILL.md`, the 21 playbooks, the analyst prompts, the case file, the report, and the work order with its validator. Depends on the result recorded in Task 15 |
| 4. Judgments | The reviewed TypeSafe question set, the judge script, and the composition rules |
| 5. Publishing | The redaction audit, Confluence, Slack, and service map suggestions |

