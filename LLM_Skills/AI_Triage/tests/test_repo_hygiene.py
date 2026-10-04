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


def test_example_files_use_the_reserved_example_domain():
    for name in ("triage-config.example.yaml", "service-map.example.yaml"):
        text = (SKILL_SRC / "config" / name).read_text()
        hosts = re.findall(r"[a-z0-9.-]+\.(?:com|net|org|io)\b", text)
        assert hosts and all(host.endswith("example.com") for host in hosts)
