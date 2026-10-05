"""SKILL.md, reference/reading.md and the prompts must agree with the scripts, the guard and the collection plan."""
from __future__ import annotations

import re
from collections import defaultdict

import yaml

from conftest import SKILL_SRC
from skill_text_support import (
    FAKE_HOME, SCRIPTS_DIR, fenced_commands, fill_placeholders, guard_kind_and_reason, make_guard_context,
    run_references, script_accepts,
)
from triage.collection_plan import COLLECTOR_DOMAIN
from triage.collectors import all_collectors
from triage.verdict import ALLOW

SKILL_MD = SKILL_SRC / "SKILL.md"
READING_MD = SKILL_SRC / "reference" / "reading.md"
PROMPTS_DIR = SKILL_SRC / "prompts"
FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
FOLDER_FILE_RE = re.compile(r"\b(reference|prompts|playbooks|templates)/([^\s`'\"),;:]*\.[A-Za-z]+)")


def frontmatter() -> dict:
    text = SKILL_MD.read_text()
    assert text.startswith("---\n"), "SKILL.md must start with a YAML frontmatter block"
    return yaml.safe_load(text.split("---\n", 2)[1])


def test_frontmatter_name_and_description():
    meta = frontmatter()
    assert meta["name"] == "ai-triage"
    description = meta["description"]
    assert description.startswith("Use when"), description[:40]
    assert len(description) <= 1024, f"description is {len(description)} characters"


def matcher_covers(matcher: str, tool: str) -> bool:
    return re.fullmatch(matcher, tool) is not None


def test_pre_tool_use_hooks_cover_bash_and_file_tools_with_the_guard_script():
    entries = frontmatter()["hooks"]["PreToolUse"]
    for tool in ("Bash", *FILE_TOOLS):
        covering = [entry for entry in entries if matcher_covers(entry["matcher"], tool)]
        assert covering, f"no PreToolUse matcher covers {tool}"
        for entry in covering:
            for hook in entry["hooks"]:
                assert hook["type"] == "command"
                command = hook["command"].strip('"')
                prefix = '$HOME/.claude/skills/ai-triage/scripts/'
                assert command.startswith(prefix), f"{tool}: hook command {hook['command']} is not under {prefix}"
                script = command[len(prefix):]
                assert script.startswith("guard_hook") and (SCRIPTS_DIR / script).is_file(), (
                    f"{tool}: hook script scripts/{script} does not exist"
                )


def test_files_named_under_the_skill_folders_exist():
    missing = []
    for number, line in enumerate(SKILL_MD.read_text().splitlines(), start=1):
        for folder, name in FOLDER_FILE_RE.findall(line):
            if "<" in name or ">" in name:
                continue
            if not (SKILL_SRC / folder / name).is_file():
                missing.append(f"SKILL.md:{number}: {folder}/{name} does not exist")
    assert not missing, "\n" + "\n".join(missing)


def check_run_references(path) -> list[str]:
    problems, collectors = [], all_collectors()
    for number, script, subcommand in run_references(path.read_text()):
        where = f"{path.name}:{number}: `run {script}{' ' + subcommand if subcommand else ''}`"
        if not (SCRIPTS_DIR / f"{script}.py").is_file():
            problems.append(f"{where}: no script scripts/{script}.py")
        elif script == "collect":  # the collector name is a positional argument, not a subcommand
            if subcommand and subcommand not in collectors:
                problems.append(f"{where}: no collector named {subcommand}")
        elif subcommand:
            ok, message = script_accepts(script, subcommand)
            if not ok:
                problems.append(f"{where}: {script}.py does not accept it ({message})")
    return problems


def test_run_references_in_skill_md_name_real_scripts_and_subcommands():
    problems = check_run_references(SKILL_MD)
    assert not problems, "\n" + "\n".join(problems)


def test_run_references_in_reading_md_name_real_scripts_and_subcommands():
    problems = check_run_references(READING_MD)
    assert not problems, "\n" + "\n".join(problems)


def full_command_form() -> str:
    """The fenced line in SKILL.md that shows how to run a script, with a real script and plain arguments."""
    lines = fenced_commands(SKILL_MD.read_text(), prefixes=('"$HOME/',))
    assert len(lines) == 1, f"expected one full command form in SKILL.md, found {lines}"
    return lines[0][1].replace("<script>", "collect").replace("<arguments>", "--list")


def test_the_full_command_form_is_allowed(monkeypatch):
    kind, reason = guard_kind_and_reason(full_command_form(), monkeypatch)
    assert kind == ALLOW, f"{kind}: {reason}"


def test_the_same_command_with_a_tilde_or_a_variable_is_not_allowed(monkeypatch):
    command = full_command_form()
    variants = {
        "tilde": command.replace('"$HOME/', "~/").replace('.py"', ".py"),
        "quoted tilde": command.replace("$HOME", "~"),
        # The guard expands "$HOME" itself, so only other variables are refused.
        "braced own variable": command.replace("$HOME", "${SKILL_HOME}"),
        "own variable": command.replace("$HOME", "$SKILL_HOME"),
    }
    allowed = {name: guard_kind_and_reason(text, monkeypatch) for name, text in variants.items()}
    wrong = {name: result for name, result in allowed.items() if result[0] == ALLOW}
    assert not wrong, f"the guard approves forms the skill says it refuses: {wrong}"


def test_reading_md_commands_get_allow_from_the_guard(monkeypatch):
    _, values = make_guard_context()
    commands = [
        (number, command) for number, command in fenced_commands(READING_MD.read_text()) if "..." not in command
    ]
    assert commands, "reference/reading.md has no complete aws or kubectl command"
    problems = []
    for number, command in commands:
        command = command.replace(" [options]", "")
        kind, reason = guard_kind_and_reason(command, monkeypatch)
        if kind != ALLOW:
            problems.append(f"reading.md:{number}: guard says {kind}: {reason}\n    command: {fill_placeholders(command, values)}")
    assert not problems, "\n" + "\n".join(problems)


PREFIX_RE = re.compile(r"`([A-Za-z0-9_]+-)`")


def prompt_facts(path) -> tuple[str, set[str]]:
    """The analyst name and the evidence file prefixes the opening paragraph lists (parentheses excluded)."""
    text = path.read_text()
    name = re.search(r"Analyst name: `([a-z]+)`", text)
    assert name, f"{path.name}: no line `Analyst name: `<name>``"
    paragraph = re.search(r"Analyst name:.*?(?:\n\n|\Z)", text, re.S).group(0)
    paragraph = re.sub(r"\([^)]*\)", "", paragraph)
    return name.group(1), set(PREFIX_RE.findall(paragraph))


def test_analyst_prompts_agree_with_the_collector_domains():
    prompts = {
        path.stem.removeprefix("analyst-"): path
        for path in sorted(PROMPTS_DIR.glob("analyst-*.md")) if path.name != "analyst-common.md"
    }
    problems, owners = [], defaultdict(list)
    for domain, path in prompts.items():
        name, prefixes = prompt_facts(path)
        if name != domain:
            problems.append(f"{path.name}: names itself `{name}`, the file name says {domain}")
        for prefix in prefixes:
            owners[prefix].append(path.name)
        wanted = {f"{collector}-" for collector, owner in COLLECTOR_DOMAIN.items() if owner == domain}
        for missing in sorted(wanted - prefixes):
            problems.append(f"{path.name}: does not list the prefix `{missing}` of a {domain} collector")
        for extra in sorted(prefixes - wanted):
            problems.append(f"{path.name}: lists `{extra}`, which COLLECTOR_DOMAIN does not give to {domain}")
    for prefix, files in owners.items():
        if len(files) > 1:
            problems.append(f"prefix `{prefix}` is listed in {files}")
    for domain in set(COLLECTOR_DOMAIN.values()) - set(prompts):
        problems.append(f"no prompt analyst-{domain}.md for a domain in COLLECTOR_DOMAIN")
    assert not problems, "\n" + "\n".join(problems)
