"""The service playbooks must have the fixed structure and give commands that exist and that the guard approves."""
from __future__ import annotations

import re

import pytest

from conftest import SKILL_SRC
from skill_text_support import (
    FENCE_RE, PLAYBOOKS_DIR, fenced_commands, fill_placeholders, guard_kind_and_reason, is_secret_operation,
    make_guard_context, script_accepts,
)
from triage.collectors import all_collectors
from triage.verdict import ALLOW

HEADINGS = ["When to open", "Collect", "What the facts mean", "Common causes", "Compare with", "Follow a lead"]
MIN_LINES, MAX_LINES = 40, 130
PLAYBOOKS = sorted(PLAYBOOKS_DIR.glob("*.md"))
IDS = [path.stem for path in PLAYBOOKS]
COLLECT_RE = re.compile(r"`run collect ([a-z0-9_]+)([^`]*)`")
OPENSEARCH_RE = re.compile(r"`run opensearch_query(?: ([a-z][a-z-]*))?")
TARGET_RE = re.compile(r"--target ([A-Za-z_]+)=")


def lines_outside_fences(text: str) -> list[tuple[int, str]]:
    result, inside = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(line):
            inside = not inside
        elif not inside:
            result.append((number, line))
    return result


def section(text: str, heading: str) -> str:
    body, active = [], False
    for _, line in lines_outside_fences(text):
        if line.startswith("## "):
            active = line[3:].strip() == heading
        elif active:
            body.append(line)
    return "\n".join(body)


def test_there_are_playbooks():
    assert PLAYBOOKS, "no playbooks found under skill/ai-triage/playbooks/"


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_structure_and_length(path):
    text = path.read_text()
    lines = text.splitlines()
    outside = lines_outside_fences(text)
    titles = [line for _, line in outside if line.startswith("# ")]
    assert len(titles) == 1 and re.fullmatch(r"# \S.* playbook", titles[0]) and lines[0] == titles[0], (
        f"{path.name}: the first line must be the only title, `# <Something> playbook`; found {titles}"
    )
    assert [line[3:].strip() for _, line in outside if line.startswith("## ")] == HEADINGS, (
        f"{path.name}: level-2 headings must be exactly {HEADINGS}"
    )
    assert MIN_LINES <= len(lines) <= MAX_LINES, f"{path.name}: {len(lines)} lines, want {MIN_LINES} to {MAX_LINES}"


def declared_targets(collector) -> set[str]:
    return set(collector.required) | set(collector.optional) | set(collector.one_of)


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_collect_commands_name_real_collectors_and_target_keys(path):
    collectors = all_collectors()
    problems = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        for match in COLLECT_RE.finditer(line):
            name, rest = match.group(1), match.group(2)
            if name not in collectors:
                problems.append(f"{path.name}:{number}: no collector named {name}")
                continue
            for key in TARGET_RE.findall(rest):
                if key not in declared_targets(collectors[name]):
                    problems.append(
                        f"{path.name}:{number}: collector {name} has no target key {key} "
                        f"(declares {sorted(declared_targets(collectors[name]))})"
                    )
        for match in OPENSEARCH_RE.finditer(line):
            subcommand = match.group(1)
            if subcommand is None:
                continue
            ok, message = script_accepts("opensearch_query", subcommand)
            if not ok:
                problems.append(f"{path.name}:{number}: opensearch_query has no subcommand {subcommand}: {message}")
    assert not problems, "\n" + "\n".join(problems)


def follow_a_lead_commands(path) -> list[tuple[int, str]]:
    text = path.read_text()
    start = next((n for n, line in enumerate(text.splitlines(), start=1) if line.strip() == "## Follow a lead"), None)
    if start is None:
        return []
    body = "\n".join(text.splitlines()[start:])
    found = fenced_commands(f"\n{body}")  # line numbers are offset by one; fixed below
    return [(number + start - 1, command) for number, command in found]


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_follow_a_lead_commands_get_allow_from_the_guard(path, monkeypatch):
    commands = follow_a_lead_commands(path)
    assert commands, f"{path.name}: no aws or kubectl command in a fenced block under Follow a lead"
    _, values = make_guard_context()
    problems = []
    for number, command in commands:
        kind, reason = guard_kind_and_reason(command, monkeypatch)
        if kind != ALLOW:
            problems.append(
                f"{path.name}:{number}: guard says {kind}: {reason}\n    command: {fill_placeholders(command, values)}"
            )
    assert not problems, "\n" + "\n".join(problems)


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_follow_a_lead_commands_never_return_secret_material(path):
    offenders = [f"{path.name}:{n}: {c}" for n, c in follow_a_lead_commands(path) if is_secret_operation(c)]
    assert not offenders, "\n" + "\n".join(offenders)


NON_PLAYBOOK_NAMES = {
    "skill", "readme", "agents", "claude", "reading", "formats", "case", "report", "work-order", "checked",
    "summary", "questions", "analyst-common", "redaction-audit",
}


def referenced_playbooks() -> list[tuple[str, str]]:
    """(file that refers, playbook name) for every playbook another playbook or SKILL.md refers to by file name."""
    found = []
    for source in [SKILL_SRC / "SKILL.md", *PLAYBOOKS]:
        for name in re.findall(r"playbooks/([A-Za-z0-9_-]+)\.md", source.read_text()):
            found.append((source.name, name))
        if source in PLAYBOOKS:
            for name in re.findall(r"`([a-z0-9_-]+)\.md`", source.read_text()):
                if name not in NON_PLAYBOOK_NAMES and not name.startswith("analyst-"):
                    found.append((source.name, name))
    return found


def test_every_referenced_playbook_exists():
    existing = {path.stem for path in PLAYBOOKS}
    missing = sorted({f"{source} refers to playbooks/{name}.md" for source, name in referenced_playbooks() if name not in existing})
    assert not missing, "\n" + "\n".join(missing)


def mentioned_collectors(path, names: set[str]) -> set[str]:
    """Collectors a playbook covers: its own name, `run collect <name>`, and backticked names in its opening and Collect sections."""
    text = path.read_text()
    found = {path.stem} & names
    scope = section(text, "When to open") + "\n" + section(text, "Collect")
    found |= {name for name in re.findall(r"`run collect ([a-z0-9_]+)", text) if name in names}
    found |= {name for name in re.findall(r"`([a-z0-9_]+)`", scope) if name in names}
    return found


def test_every_collector_is_covered_by_a_playbook():
    names = set(all_collectors())
    covered = set()
    for path in PLAYBOOKS:
        covered |= mentioned_collectors(path, names)
    assert not (names - covered), f"collectors that no playbook mentions: {sorted(names - covered)}"
