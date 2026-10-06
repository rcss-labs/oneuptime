"""The guard reads `run.py <command>` exactly as it read the per-command scripts that run.py replaced.

guard_respelling_table.json holds every own-script command line that the guard, hook, skill-text, case and replay
pipeline tests decided before the scripts became commands of run.py (temporary folders rewritten under /home/eng),
with the verdict the guard gave it then, and the verdict it gave the same line naming a script it did not know.
The new spelling must get the same verdict; the old spelling must now get the unknown-script verdict.
"""
import json
import re
from pathlib import Path

import pytest

from triage.guard import GuardContext, decide
from triage.verdict import PASS

TABLE = json.loads((Path(__file__).parent / "guard_respelling_table.json").read_text())
COMMANDS = ("case", "collect", "discover", "findings", "judge", "map_suggest", "opensearch_query", "preflight",
            "publish", "report", "timeline", "validate_map", "verify_access")
OLD_SCRIPT_RE = re.compile(rf"(?<![A-Za-z0-9_])({'|'.join(COMMANDS)})\.py")
OLD_PATH_RE = re.compile(rf"(?<=/)({'|'.join(COMMANDS)})\.py([\"']?)")
HOME = "/home/eng"
SKILL = f"{HOME}/.claude/skills/ai-triage"
PY = f"{SKILL}/.venv/bin/python"


def respelled(command: str) -> str:
    """scripts/<name>.py becomes scripts/run.py <name>, keeping any closing quote on the path word."""
    return OLD_PATH_RE.sub(lambda match: f"run.py{match.group(2)} {match.group(1)}", command)


def reason_respelled(reason: str) -> str:
    return OLD_SCRIPT_RE.sub(lambda match: f"run.py {match.group(1)}", reason)


def context(row) -> GuardContext:
    skill = row["skill_dir"]
    return GuardContext(profiles=frozenset({"triage-prod-main"}), kubeconfig=f"{skill}/config/kubeconfig",
                        kube_contexts=frozenset({"triage-platform-prod"}),
                        opensearch_hosts=frozenset({"opensearch.internal.example.com"}), skill_dir=skill,
                        cases_dir=row["cases_dir"])


@pytest.fixture(autouse=True)
def home(monkeypatch):
    monkeypatch.setenv("HOME", HOME)


def test_the_table_covers_every_command_and_every_verdict():
    assert {match for row in TABLE for match in OLD_SCRIPT_RE.findall(row["command"])} == set(COMMANDS)
    assert {row["kind"] for row in TABLE} == {"allow", "ask", "deny", "pass"}


@pytest.mark.parametrize("row", TABLE, ids=lambda row: row["command"][-90:])
def test_the_new_spelling_gets_the_verdict_the_old_one_got(row):
    verdict = decide(respelled(row["command"]), context(row), cwd=row["cwd"])
    assert (verdict.kind, verdict.reason) == (row["kind"], reason_respelled(row["reason"]))


@pytest.mark.parametrize("row", TABLE, ids=lambda row: row["command"][-90:])
def test_the_old_spelling_gets_the_unknown_script_verdict(row):
    verdict = decide(row["command"], context(row), cwd=row["cwd"])
    assert (verdict.kind, verdict.reason) == (row["unknown_kind"], row["unknown_reason"])


ROW = {"skill_dir": SKILL, "cases_dir": ""}


@pytest.mark.parametrize("command", [
    f"{PY} {SKILL}/scripts/run.py",
    f"{PY} {SKILL}/scripts/run.py --help",
    f"{PY} {SKILL}/scripts/run.py nosuch --json",
    f"{PY} {SKILL}/scripts/run.py guard_hook",
    f"{PY} {SKILL}/scripts/run.py ca init --incident i.json",
    f"{PY} {SKILL}/scripts/run.py Case show --case-dir c",
    f"{PY} {SKILL}/scripts/run.py case.py show --case-dir c",
    f"{PY} {SKILL}/scripts/run.py --skill-dir /tmp/other case show --case-dir c",
    f"{PY} /tmp/scripts/run.py case show --case-dir c",
    f"{PY} {SKILL}/scripts/triage/run.py case show --case-dir c",
    f"{PY} {SKILL}/run.py case show --case-dir c",
    f"{PY} ./scripts/run.py case show --case-dir c",
    f"/usr/bin/python3 {SKILL}/scripts/run.py case show --case-dir c",
    f"{PY} {SKILL}/scripts/../scripts/run.py case show --case-dir c",
])
def test_an_unknown_or_missing_command_or_a_run_py_elsewhere_is_an_unknown_script(command):
    assert decide(command, context(ROW)).kind == PASS
    assert decide(command, context(ROW)) == decide(command.replace("run.py", "not_a_command.py"), context(ROW))
