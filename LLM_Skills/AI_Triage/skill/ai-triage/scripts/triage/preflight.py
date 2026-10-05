"""Check that everything a triage run needs is in place before it starts."""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from triage.awscli import Runner, subprocess_runner
from triage.config import ConfigError, TriageConfig, default_config_path, load_config
from triage.guard import FILTER_RULES, KUBECONFIG_NAME
from triage.service_map import MapError, default_map_path, load_map
from triage.verify import EXPIRED, PASSED, check_identity

OK = "ok"
WARN = "warn"
FAIL = "fail"
SIGN_IN = "sign-in"
SKIPPED = "skipped"


# zsh options that change how an argv the guard accepted is split or expanded (names without _ and in lower case).
UNSAFE_OPTIONS = ("magicequalsubst", "rcquotes", "cshjunkiequotes", "shwordsplit", "globsubst", "ksharrays",
                  "ignorebraces")
# Single-letter `set` flags for the options above.
OPTION_LETTERS = {"y": "shwordsplit", "I": "ignorebraces"}
UNSAFE_EMULATIONS = ("sh", "ksh", "csh")
# `name () {`, `name() { body; }`, possibly indented; `function a b {` defines several names at once.
FUNCTION_HEADER_RES = (re.compile(r"^\s*([^\s(){}=#'\"]+)\s*\(\s*\)\s*(\{.*)?$"),
                       re.compile(r"^\s*function\s+((?:[^\s(){}]+\s+)*?[^\s(){}]+)\s*(?:\(\s*\))?\s*(\{.*)?$"))
ALIAS_RE = re.compile(r"^\s*alias\s+((?:-[A-Za-z]+\s+)*)(?:--\s+)?(['\"]?)([^='\"\s]+)\2?=")
TABLE_RE = re.compile(r"^\s*(aliases|galiases|functions|options)\[['\"]?([^\]'\"]+)['\"]?\]=['\"]?(\S*?)['\"]?\s*$")
IFS_RE = re.compile(r"^\s*(?:export\s+|typeset\s+(?:-\w+\s+)*|local\s+)?IFS=")
SHELL_FIX = ("Remove it from your shell startup files, then start a new Claude Code session: the guard checks the "
             "command as written, and this would make zsh run something else.")


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


def guarded_command_words(skill_dir: Path) -> set[str]:
    """Every command word the guard can allow."""
    venv = skill_dir / ".venv" / "bin"
    return {"aws", "kubectl", str(venv / "python"), str(venv / "python3")} | set(FILTER_RULES)


def _option_turned_on(name: str, on: bool) -> str:
    """The unsafe option a setopt/unsetopt of this name turns on, or "". Each leading "no" inverts it."""
    name = name.lower().replace("_", "").replace("-", "")
    while name not in UNSAFE_OPTIONS and name.startswith("no"):
        name, on = name[2:], not on
    return name if on and name in UNSAFE_OPTIONS else ""


def _option_problems(words: list[str]) -> list[str]:
    command, args = words[0], [word for word in words[1:] if not word.startswith("#")]
    turned_on: list[str] = []
    if command in ("setopt", "unsetopt"):
        turned_on = [_option_turned_on(arg, command == "setopt") for arg in args if not arg.startswith(("-", "+"))]
    elif command == "set":
        index = 0
        while index < len(args):
            arg = args[index]
            if arg in ("-o", "+o") and index + 1 < len(args):
                turned_on.append(_option_turned_on(args[index + 1], arg == "-o"))
                index += 2
                continue
            if arg[:1] in "-+" and len(arg) > 1:
                turned_on += [_option_turned_on(OPTION_LETTERS[letter], arg[0] == "-")
                              for letter in arg[1:] if letter in OPTION_LETTERS]
            index += 1
    elif command == "emulate":
        modes = [arg for arg in args if not arg.startswith("-")]
        if modes and modes[0] in UNSAFE_EMULATIONS:
            return [f"emulate {modes[0]}"]
    return [f"option {name}" for name in turned_on if name]


def _function_names(line: str) -> tuple[list[str], bool] | None:
    """The names a function header defines, and whether its body continues on later lines."""
    for index, regex in enumerate(FUNCTION_HEADER_RES):
        match = regex.match(line)
        if match:
            names = match.group(1).split() if index == 1 else [match.group(1)]
            body = match.group(2) or ""
            return names, not (body and body.count("{") <= body.count("}"))
    return None


def shell_snapshot_problems(text: str, guarded_words: set[str]) -> list[str]:
    """What in a Claude Code shell snapshot would make zsh run something other than the guarded command.

    Reads top-level lines only; option and IFS changes inside a function body are local to that function.
    A body ends at a "}" line indented like its header.
    """
    problems: list[str] = []
    function_end: str | None = None
    for line in text.splitlines():
        if function_end is not None:
            if line.rstrip() == function_end:
                function_end = None
            continue
        header = _function_names(line)
        if header:
            names, continues = header
            problems += [f"function {name}" for name in names if name in guarded_words]
            if continues:
                function_end = line[: len(line) - len(line.lstrip())] + "}"
            continue
        alias = ALIAS_RE.match(line)
        if alias:
            flags, name = alias.group(1), alias.group(3)
            if "g" in flags.replace("-", ""):
                problems.append(f"global alias {name}")  # rewrites the word anywhere on a command line
            elif name in guarded_words:
                problems.append(f"alias {name}")
            continue
        table = TABLE_RE.match(line)
        if table:
            kind, name, value = table.groups()
            if kind == "galiases":
                problems.append(f"global alias {name}")
            elif kind in ("aliases", "functions") and name in guarded_words:
                problems.append(f"{'alias' if kind == 'aliases' else 'function'} {name}")
            elif kind == "options" and value.lower() == "on":
                problems += [f"option {option}" for option in [_option_turned_on(name, True)] if option]
            continue
        words = line.split()
        if words and words[0] in ("setopt", "unsetopt", "set", "emulate"):
            problems += _option_problems(words)
            continue
        if IFS_RE.match(line):
            problems.append("an IFS assignment")
    return problems


def _shell_environment(skill_dir: Path, snapshots_dir: Path) -> Check:
    name = "Shell environment"
    try:
        snapshots = [entry for entry in snapshots_dir.iterdir() if entry.is_file()] if snapshots_dir.is_dir() else []
        if not snapshots:
            return Check(name, SKIPPED, f"not checked: no shell snapshot in {snapshots_dir}")
        newest = max(snapshots, key=lambda entry: entry.stat().st_mtime)
        text = newest.read_text(errors="replace")
    except OSError as error:
        return Check(name, SKIPPED, f"not checked: {snapshots_dir} could not be read ({error.strerror or error})")
    problems = shell_snapshot_problems(text, guarded_command_words(skill_dir))
    if problems:
        return Check(name, FAIL, f"{newest.name}: {', '.join(problems)}", SHELL_FIX)
    return Check(name, OK, newest.name)


CREDENTIAL_VARIABLES = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


def _credentials_in_environment(env: Mapping[str, str]) -> Check | None:
    """kubectl's credential helper would use these in place of the triage profile. Names only, never values."""
    names = [name for name in CREDENTIAL_VARIABLES if env.get(name)]
    if not names:
        return None
    return Check(
        "AWS credentials in environment",
        FAIL,
        f"{', '.join(names)} is set, so kubectl would use it instead of the triage profile",
        f"Unset it in this shell: unset {' '.join(names)}",
    )


def _alias_names(text: str) -> list[str]:
    """Names defined in the [toplevel] section of an AWS CLI alias file."""
    names: list[str] = []
    in_toplevel = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_toplevel = stripped == "[toplevel]"
        elif in_toplevel and line == line.lstrip() and "=" in stripped and not stripped.startswith(("#", ";")):
            names.append(stripped.split("=", 1)[0].strip())
    return names


def _cli_aliases(home: str) -> Check | None:
    path = Path(home) / ".aws" / "cli" / "alias"
    if not path.is_file():
        return None
    try:
        names = _alias_names(path.read_text(errors="replace"))
    except OSError as error:
        return Check("AWS CLI aliases", WARN, f"{path} exists but could not be read ({error.strerror or error})")
    if not names:
        return None
    return Check(
        "AWS CLI aliases", WARN, f"{path} defines aliases: {', '.join(names)}",
        "An alias can change what an aws command does. Remove any that shadows a command triage runs.",
    )


def run_preflight(
    skill_dir: Path,
    accounts: Sequence[str] = (),
    *,
    runner: Runner = subprocess_runner,
    env: Mapping[str, str] = os.environ,
    which: Callable[[str], str | None] = shutil.which,
    replay: bool = False,
    snapshots_dir: Path | None = None,
    allow_replay: bool = False,
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
            name = f"Sign-in: {alias}"
            if replay:
                checks.append(Check(name, SKIPPED, "replay mode: no sign-in is checked"))
                continue
            identity, _ = check_identity(account, config.permission_set, runner)
            if identity.status == PASSED:
                checks.append(Check(name, OK, identity.detail))
            elif identity.status == EXPIRED:
                checks.append(Check(name, SIGN_IN, "the sign-in session has expired", f"aws sso login --profile {account.profile}"))
            else:
                checks.append(Check(name, FAIL, identity.detail, f"Check the profile {account.profile} in your AWS config."))

    home = env.get("HOME") or os.path.expanduser("~")
    for problem in (_credentials_in_environment(env), _cli_aliases(home)):
        if problem:
            checks.append(problem)

    if config.eks_clusters:
        kubeconfig = skill_dir / "config" / KUBECONFIG_NAME
        if replay:
            checks.append(Check("kubectl", SKIPPED, "replay mode: kubectl is not run"))
        elif which("kubectl") is None:
            checks.append(Check("kubectl", FAIL, "the kubectl command was not found", "Install kubectl."))
        elif not kubeconfig.is_file():
            checks.append(Check("kubectl", FAIL, "the triage kubeconfig does not exist", "Create it with the commands in the README."))
        else:
            checks.append(Check("kubectl", OK))

    if replay:
        checks.append(Check("Shell environment", SKIPPED, "replay mode: the shell is not checked"))
    else:
        checks.append(_shell_environment(skill_dir, snapshots_dir or Path(home) / ".claude" / "shell-snapshots"))

    if replay and not allow_replay:
        checks.append(Check(
            "REPLAY", FAIL, "AI_TRIAGE_FIXTURES is set, so answers come from recorded files and nothing is checked against AWS",
            "Unset AI_TRIAGE_FIXTURES, or pass --allow-replay for a replay run.",
        ))

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
