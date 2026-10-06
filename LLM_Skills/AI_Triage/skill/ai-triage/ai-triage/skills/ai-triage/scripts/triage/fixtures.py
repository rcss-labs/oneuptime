"""Replay mode: answer every AWS, kubectl, and OpenSearch call from canned files.

When AI_TRIAGE_FIXTURES names a folder, the commands use these answers instead of the real tools.
A bad folder is an error. It never falls back to a real call.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from triage.awscli import Runner
from triage.opensearch.client import Transport

FIXTURE_ENV = "AI_TRIAGE_FIXTURES"
LOG_ENV = "AI_TRIAGE_FIXTURE_LOG"
KUBECTL_SKIPPED_WITH_VALUE = ("--kubeconfig", "--context", "-n", "--namespace")
KUBECTL_SKIPPED_ALONE = ("-A",)


class FixtureError(Exception):
    """The replay folder is missing or one of its files is unusable."""


def fixture_dir(env: Mapping[str, str] = os.environ) -> Path | None:
    value = env.get(FIXTURE_ENV, "")
    if not value:
        return None
    directory = Path(value)
    if not directory.is_dir():
        raise FixtureError(f"{FIXTURE_ENV} is set to {value}, which is not a directory")
    return directory


def replay_banner(directory: Path) -> str:
    return f"REPLAY MODE: answers come from {directory}; nothing is called."


def _load_entries(directory: Path, name: str, required_key: str) -> list[dict[str, Any]]:
    path = directory / name
    if not path.is_file():
        return []
    try:
        entries = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise FixtureError(f"cannot read {path}: {error}") from error
    if not isinstance(entries, list) or not all(isinstance(entry, dict) and required_key in entry for entry in entries):
        raise FixtureError(f"{path} must be a list of entries that each have '{required_key}'")
    return entries


def _log(record: dict[str, Any]) -> None:
    log_path = os.environ.get(LOG_ENV)
    if log_path:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


def _kubectl_words(argv: Sequence[str]) -> list[str]:
    """The verb and first argument, once the scope options are skipped."""
    words: list[str] = []
    index = 1
    while index < len(argv) and len(words) < 2:
        token = argv[index]
        if token in KUBECTL_SKIPPED_WITH_VALUE:
            index += 2
            continue
        if token not in KUBECTL_SKIPPED_ALONE:
            words.append(token)
        index += 1
    return words


class FixtureRunner:
    """A Runner that answers aws and kubectl argvs from aws.json and kubectl.json."""

    def __init__(self, directory: Path):
        self._aws = _load_entries(directory, "aws.json", "match")
        self._kubectl = _load_entries(directory, "kubectl.json", "match")

    def __call__(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        program = argv[0] if argv else ""
        if program == "aws":
            _log({"tool": "aws", "argv": list(argv)})
            entry = self._find(self._aws, list(argv[1:3]), argv)
            if entry is None:
                return 0, "{}", ""
            if "error" in entry:
                return int(entry["error"]["code"]), "", entry["error"]["stderr"]
            return 0, json.dumps(entry.get("result", {})), ""
        if program == "kubectl":
            _log({"tool": "kubectl", "argv": list(argv)})
            entry = self._find(self._kubectl, _kubectl_words(argv), argv)
            if entry is None:
                return 0, "", ""
            if "error" in entry:
                return int(entry["error"]["code"]), "", entry["error"]["stderr"]
            return 0, entry.get("stdout", ""), ""
        raise FixtureError(f"replay mode answers only aws and kubectl calls, not {program or 'an empty command'}")

    @staticmethod
    def _find(entries: list[dict[str, Any]], words: list[str], argv: Sequence[str]) -> dict[str, Any] | None:
        for entry in entries:
            if entry["match"] != words:
                continue
            if all(any(needle in element for element in argv) for needle in entry.get("contains", [])):
                return entry
        return None


def fixture_transport(directory: Path) -> Transport:
    entries = _load_entries(directory, "opensearch.json", "path_contains")

    def transport(method: str, url: str, body: "bytes | None", timeout_seconds: int, verify_tls: bool, ca_bundle: "str | None") -> tuple[int, str]:
        _log({"tool": "opensearch", "method": method, "url": url})
        for entry in entries:
            if entry.get("method", method).upper() == method.upper() and entry["path_contains"] in url:
                answer = entry.get("body", {})
                return int(entry.get("status", 200)), answer if isinstance(answer, str) else json.dumps(answer)
        return 404, json.dumps({"error": "no fixture"})

    return transport


def runner_from_env(env: Mapping[str, str] = os.environ) -> Runner | None:
    directory = fixture_dir(env)
    return FixtureRunner(directory) if directory else None


def kube_runner_from_env(env: Mapping[str, str] = os.environ) -> Runner | None:
    return runner_from_env(env)


def transport_from_env(env: Mapping[str, str] = os.environ) -> Transport | None:
    directory = fixture_dir(env)
    return fixture_transport(directory) if directory else None
