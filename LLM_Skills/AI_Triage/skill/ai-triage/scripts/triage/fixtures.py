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
AWS_HOUSEKEEPING_WITH_VALUE = ("--profile", "--region", "--output")
AWS_HOUSEKEEPING_ALONE = ("--no-cli-pager",)
MISS_EXIT_CODE = 255


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


# Each file is read and checked once per process, whoever asks for it.
_ENTRY_CACHE: dict[Path, list[dict[str, Any]]] = {}


def _is_text_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _entry_problem(kind: str, entry: Any) -> str | None:
    """What is wrong with one entry, or None."""
    if not isinstance(entry, dict):
        return "is not an object"
    if kind == "opensearch":
        if not isinstance(entry.get("path_contains"), str):
            return "needs a text 'path_contains'"
        if "method" in entry and not isinstance(entry["method"], str):
            return "has a 'method' that is not text"
        if "status" in entry and not _is_int(entry["status"]):
            return "has a 'status' that is not a whole number"
        return None
    if not _is_text_list(entry.get("match")) or not entry["match"]:
        return "needs 'match' as a list of words"
    if "contains" in entry and not _is_text_list(entry["contains"]):
        return "has a 'contains' that is not a list of text"
    if "error" in entry:
        error = entry["error"]
        if not (isinstance(error, dict) and _is_int(error.get("code")) and isinstance(error.get("stderr"), str)):
            return "has an 'error' that needs a whole-number 'code' and a text 'stderr'"
    if kind == "kubectl" and "stdout" in entry and not isinstance(entry["stdout"], str):
        return "has a 'stdout' that is not text"
    return None


def _load_entries(directory: Path, name: str, kind: str) -> list[dict[str, Any]]:
    path = (directory / name).resolve()
    if path in _ENTRY_CACHE:
        return _ENTRY_CACHE[path]
    if not path.is_file():
        return []
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise FixtureError(f"cannot read {path}: {error}") from error
    if not isinstance(entries, list):
        raise FixtureError(f"{path} must be a list of entries")
    for index, entry in enumerate(entries):
        problem = _entry_problem(kind, entry)
        if problem:
            raise FixtureError(f"{name} entry {index} {problem} ({path})")
    _ENTRY_CACHE[path] = entries
    return entries


def _log(record: dict[str, Any]) -> None:
    """One line per call: what was asked and which entry answered. Nothing from the answer."""
    log_path = os.environ.get(LOG_ENV)
    if log_path:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


def _kubectl_split(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """The verb and first argument, and the remaining words, once the scope options are skipped."""
    tokens: list[str] = []
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in KUBECTL_SKIPPED_WITH_VALUE:
            index += 2
            continue
        if token not in KUBECTL_SKIPPED_ALONE:
            tokens.append(token)
        index += 1
    return tokens[:2], tokens[2:]


def _aws_rest(argv: Sequence[str]) -> list[str]:
    """The arguments after the operation, without the profile, region, and output housekeeping."""
    rest: list[str] = []
    index = 3
    while index < len(argv):
        token = argv[index]
        if token in AWS_HOUSEKEEPING_WITH_VALUE:
            index += 2
            continue
        if token not in AWS_HOUSEKEEPING_ALONE:
            rest.append(token)
        index += 1
    return rest


def _miss(asked: Sequence[str]) -> tuple[int, str, str]:
    return MISS_EXIT_CODE, "", f"replay: no recorded answer for {' '.join(asked)}"


class FixtureRunner:
    """A Runner that answers aws and kubectl argvs from aws.json and kubectl.json.

    A call with no recorded answer fails. A scenario that wants an empty answer records one.
    """

    def __init__(self, directory: Path):
        self._aws = _load_entries(directory, "aws.json", "aws")
        self._kubectl = _load_entries(directory, "kubectl.json", "kubectl")

    def __call__(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        program = argv[0] if argv else ""
        if program == "aws":
            words, rest = list(argv[1:3]), _aws_rest(argv)
            index = self._find(self._aws, words, argv)
            _log({"tool": "aws", "service": words[0] if words else "", "operation": words[1] if len(words) > 1 else "",
                  "entry": index, "argv": list(argv)})
            if index is None:
                return _miss([*words, *rest])
            entry = self._aws[index]
            if "error" in entry:
                return int(entry["error"]["code"]), "", entry["error"]["stderr"]
            return 0, json.dumps(entry.get("result", {})), ""
        if program == "kubectl":
            words, rest = _kubectl_split(argv)
            index = self._find(self._kubectl, words, argv)
            _log({"tool": "kubectl", "service": "kubectl", "operation": " ".join(words), "entry": index, "argv": list(argv)})
            if index is None:
                return _miss(["kubectl", *words, *rest])
            entry = self._kubectl[index]
            if "error" in entry:
                return int(entry["error"]["code"]), "", entry["error"]["stderr"]
            return 0, entry.get("stdout", ""), ""
        raise FixtureError(f"replay mode answers only aws and kubectl calls, not {program or 'an empty command'}")

    @staticmethod
    def _find(entries: list[dict[str, Any]], words: list[str], argv: Sequence[str]) -> int | None:
        for index, entry in enumerate(entries):
            if entry["match"] != words:
                continue
            if all(any(needle in element for element in argv) for needle in entry.get("contains", [])):
                return index
        return None


def fixture_transport(directory: Path) -> Transport:
    entries = _load_entries(directory, "opensearch.json", "opensearch")

    def transport(method: str, url: str, body: "bytes | None", timeout_seconds: int, verify_tls: bool, ca_bundle: "str | None") -> tuple[int, str]:
        for index, entry in enumerate(entries):
            if entry.get("method", method).upper() == method.upper() and entry["path_contains"] in url:
                _log({"tool": "opensearch", "service": "opensearch", "operation": method, "entry": index, "method": method, "url": url})
                answer = entry.get("body", {})
                return int(entry.get("status", 200)), answer if isinstance(answer, str) else json.dumps(answer)
        _log({"tool": "opensearch", "service": "opensearch", "operation": method, "entry": None, "method": method, "url": url})
        return 404, f"replay: no recorded answer for {method} {url}"

    return transport


def runner_from_env(env: Mapping[str, str] = os.environ) -> Runner | None:
    directory = fixture_dir(env)
    return FixtureRunner(directory) if directory else None


def kube_runner_from_env(env: Mapping[str, str] = os.environ) -> Runner | None:
    return runner_from_env(env)


def transport_from_env(env: Mapping[str, str] = os.environ) -> Transport | None:
    directory = fixture_dir(env)
    return fixture_transport(directory) if directory else None
