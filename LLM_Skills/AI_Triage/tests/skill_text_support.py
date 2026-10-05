"""Shared helpers for the tests that check the skill's Markdown instructions against the code and the guard."""
from __future__ import annotations

import copy
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

from conftest import EXAMPLE_CONFIG, SKILL_SRC
from triage.config import parse_config
from triage.guard import GuardContext, context_from_config, decide
from triage.verdict import ALLOW

SCRIPTS_DIR = SKILL_SRC / "scripts"
PLAYBOOKS_DIR = SKILL_SRC / "playbooks"
FAKE_HOME = "/home/eng"
FAKE_SKILL_DIR = Path(FAKE_HOME) / ".claude" / "skills" / "ai-triage"
EXAMPLE_NAMESPACE = "payments"  # the config has no namespaces; any plain name will do
SECRET_OPERATIONS = (
    "get-secret-value", "decrypt", "get-password-data", "get-authorization-token", "get-login-password",
)

PLACEHOLDER_RE = re.compile(r"<([^<>]+)>")
FENCE_RE = re.compile(r"^```")
_SHAPES = (  # (words that must all appear in the placeholder name, replacement), first match wins
    (("arn",), "arn:aws:example:eu-west-1:111111111111:resource/example-name"),
    (("account", "id"), "111111111111"),
    (("task", "id"), "0123456789abcdef0123456789abcdef"),
    (("instance", "id"), "i-0123456789abcdef0"),
    (("security", "group", "id"), "sg-0123456789abcdef0"),
    (("subnet", "id"), "subnet-0123456789abcdef0"),
    (("vpc", "id"), "vpc-0123456789abcdef0"),
    (("start",), "2026-10-04T10:00:00Z"),
    (("end",), "2026-10-04T12:00:00Z"),
    (("time",), "2026-10-04T10:00:00Z"),
    (("epoch",), "1790000000"),
    (("revision",), "7"),
    (("count",), "20"),
    (("port",), "5432"),
    (("limit",), "20"),
)


def read(path: Path) -> str:
    return path.read_text()


def example_config():
    return parse_config(copy.deepcopy(yaml.safe_load(EXAMPLE_CONFIG.read_text())))


def make_guard_context() -> tuple[GuardContext, dict[str, str]]:
    """A guard context for the example config, and the values that fill the common placeholders."""
    config = example_config()
    account = next(iter(config.accounts.values()))
    eks = next(iter(config.eks_clusters.values()))
    values = {
        "triage profile": account.profile,
        "region": account.regions[0],
        "triage context": eks.context,
        "namespace": EXAMPLE_NAMESPACE,
        # reading.md's generic form: a real read operation, a JMESPath and a jq filter that parse
        "service": "ecs",
        "operation": "describe-clusters",
        "jmespath": "clusters[].clusterName",
        "filter": ".[]",
    }
    return context_from_config(config, FAKE_SKILL_DIR), values


def fill_placeholders(command: str, values: dict[str, str]) -> str:
    """Replace every <...>: the table first, then the shape table, then one rule (lower-case words with dashes)."""
    def replace(match: re.Match) -> str:
        name = match.group(1).strip().lower()
        if name in values:
            return values[name]
        words = re.findall(r"[a-z0-9]+", name)
        for needles, replacement in _SHAPES:
            if all(needle in words for needle in needles):
                return replacement
        return "example-" + "-".join(words) if words else "example"
    return PLACEHOLDER_RE.sub(replace, command)


def guard_kind_and_reason(command: str, monkeypatch) -> tuple[str, str]:
    context, values = make_guard_context()
    monkeypatch.setenv("HOME", FAKE_HOME)
    verdict = decide(fill_placeholders(command, values), context)
    return verdict.kind, getattr(verdict, "reason", "")


def fenced_commands(text: str, prefixes: tuple[str, ...] = ("aws ", "kubectl ")) -> list[tuple[int, str]]:
    """(line number, command) for each line in a fenced code block that starts with one of the prefixes."""
    found, inside = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(line):
            inside = not inside
        elif inside and line.startswith(prefixes):
            found.append((number, line.strip()))
    return found


def is_secret_operation(command: str) -> bool:
    words = command.split()
    if any(word in SECRET_OPERATIONS for word in words):
        return True
    return "--with-decryption" in words and any(word.startswith("get-parameter") for word in words)


_HELP_CACHE: dict[tuple[str, str], tuple[int, str]] = {}


def script_accepts(script: str, subcommand: str) -> tuple[bool, str]:
    """True when `<script>.py <subcommand> --help` exits 0 (argparse rejects an unknown subcommand). No AWS call."""
    key = (script, subcommand)
    if key not in _HELP_CACHE:
        env = {**os.environ, "PYTHONPATH": str(SCRIPTS_DIR), "PYTHONDONTWRITEBYTECODE": "1"}
        argv = [sys.executable, str(SCRIPTS_DIR / f"{script}.py")] + ([subcommand] if subcommand else []) + ["--help"]
        done = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
        _HELP_CACHE[key] = (done.returncode, done.stderr.strip().splitlines()[-1] if done.stderr.strip() else "")
    code, message = _HELP_CACHE[key]
    return code == 0, message


RUN_RE = re.compile(r"`run ([A-Za-z_][A-Za-z0-9_]*)(?: ([a-z][a-z-]*))?")


def run_references(text: str) -> list[tuple[int, str, str]]:
    """(line, script, subcommand or "") for each `run <script> [subcommand]` written in backticks."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in RUN_RE.finditer(line):
            found.append((number, match.group(1), match.group(2) or ""))
    return found
