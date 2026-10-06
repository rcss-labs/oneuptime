"""Differential test: the scanner must agree with the real zsh on every string it accepts.

A stand-in program records the argv zsh passes to it. For every generated string
that split_command accepts as one simple command, the scanner's argv must equal
the recorded argv, and a redirect the scanner calls harmless must leave the
working directory untouched. Pipelines and && lists are compared too, as the
set of argvs every stand-in process received. The stand-in is first on PATH under the names aws
and kubectl, so no real aws or kubectl can run from this test.

Two modes run every string: `zsh -f -c CMD`, and Claude Code's own way, which
sources a shell snapshot and runs the command through `eval`. A last group of
tests shows what the guard cannot see: a function or alias in the snapshot,
named after a command word the guard allows, runs instead of that program.
Preflight's shell-environment check is the defence for that case.
"""
from __future__ import annotations

import itertools
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from triage.guard import FILTER_RULES, GuardContext, decide
from triage.shell_parse import Unparseable, split_command
from triage.verdict import ALLOW

ZSH = "/bin/zsh"
pytestmark = pytest.mark.skipif(
    not os.path.exists(ZSH), reason="/bin/zsh is not installed, so the scanner cannot be compared with the real shell"
)

STAND_IN_NAMES = ("aws", "kubectl")
# Files a zsh glob could match, so that a construct zsh would expand has something to expand to.
CWD_FILES = ("1", "22", "a", "ab", "-n", "delete")
WORKERS = max(2, min(10, os.cpu_count() or 2))
TIMEOUT_SECONDS = 10

WORDS = ["get", "pods", "-n", "--region", "eu-west-1", "x=1", "--query=a,b", "user@host", "50%", "+x", ".", "..",
         "a/b:c", "1", "22", "9", "-"]
QUOTED = ["'a b'", '"a b"', "''", '""', "'*'", "'<->'", '"$HOME/x"', '"${HOME}/x"', "'$HOME'", "a\\ b", "\\*",
          "\\<", '"a\\"b"', '"a\\b"', "$HOME/x", "$HOME", "'a b'", '"x\ny"']
REDIRECTS = [">/dev/null", "> /dev/null", "1>/dev/null", "1> /dev/null", "2>/dev/null", "2> /dev/null",
             ">>/dev/null", ">> /dev/null", "1>>/dev/null", "2>>/dev/null", "2>> /dev/null", "&>/dev/null",
             "&> /dev/null", "&>>/dev/null", "&>> /dev/null", "2>&1", "1>&2", ">&2", ">&1", ">& 2", ">out",
             "> out", "2>out", "&>out", ">>out"]
SEPARATORS = ["|", "&&", "| kubectl get", "&& kubectl get"]
ZSH_CONSTRUCTS = [
    "<->", "<1-30>", "<1->", "<-9>", "x<->", "delete<->", "<", "< a", "<a", "=ls", "=word", "<(echo)", "=(echo)",
    ">(echo)", "{a..b}", "{a,b}", "$'x'", "${x}", "$x", "$((1+1))", "$(echo)", "`echo`", "*", "**", "?", "[ab]",
    "^a", "~", "~/x", "x~y", "!", "!!", "&!", "&|", "|&", ">&-", "<<<x", "<<x", ">|out", ">!out", "2&>/dev/null",
    "1&>/dev/null", "9>/dev/null", "#", "a#b", "\t", "a\tb", "a b", "é", "a\\\nb", "\\\n", ";", "&", "||",
    "(a)", "a)", "x==ls", "0<a", "3>/dev/null", "2>&3", ">&'2'", '>"/dev/null"',
]
FRAGMENTS = WORDS + QUOTED + REDIRECTS + SEPARATORS + ZSH_CONSTRUCTS
# The fragments that most often interact; every three-fragment ordering of these is tried.
CORE = ["get", "1", "'a b'", '"$HOME/x"', ">/dev/null", "2>/dev/null", "&>/dev/null", ">& 2", "|", "<->", "&!",
        "\\\n"]
# A shell that starts fast keeps the stand-in cheap; any POSIX sh records the argv the same way.
STAND_IN_SHELL = "/bin/dash" if os.path.exists("/bin/dash") else "/bin/sh"
# zsh refuses to run a command whose output file cannot be opened; such a string cannot be compared.
UNWRITABLE_TARGET_ERRORS = ("permission denied", "read-only file system", "no such file or directory",
                            "operation not permitted", "is a directory")


def build_corpus() -> list[str]:
    corpus: set[str] = set()
    for name in STAND_IN_NAMES:
        for fragment in FRAGMENTS:
            corpus.add(f"{name} {fragment}")
    plain = set(WORDS + QUOTED)
    for first, second in itertools.product(FRAGMENTS, repeat=2):
        if not (first in plain and second in plain):  # two plain words side by side are covered when glued
            corpus.add(f"aws {first} {second}")
    for first, second in itertools.product(WORDS + QUOTED, FRAGMENTS):
        corpus.add(f"aws {first}{second}")
    for trio in itertools.product(CORE, repeat=3):
        corpus.add("kubectl " + " ".join(trio))
    return sorted(corpus)


def accepted_simple_commands(corpus: list[str]) -> list[tuple[str, tuple[str, ...], bool]]:
    accepted = []
    for command in corpus:
        try:
            segments = split_command(command)
        except Unparseable:
            continue
        if len(segments) == 1 and not segments[0].env:
            accepted.append((command, segments[0].argv, segments[0].writes_file))
    return accepted


def write_stand_ins(bin_dir: Path) -> None:
    bin_dir.mkdir()
    for name in STAND_IN_NAMES:
        script = bin_dir / name
        # One log file per process, so every command of a pipeline leaves its own record.
        script.write_text(f"#!{STAND_IN_SHELL}\nprintf '%s\\0' {name} \"$@\" > \"$ARGV_LOG.$$\"\n")
        script.chmod(0o755)


def reset_directory(folder: Path) -> None:
    folder.mkdir(exist_ok=True)
    for entry in folder.iterdir():
        entry.unlink()
    for name in CWD_FILES:
        (folder / name).write_text(name)


def snapshot(folder: Path) -> dict[str, tuple[int, int, int]]:
    """Name, inode, size and modification time of every entry: any create, truncate or write changes it."""
    return {entry.name: (entry.inode(), entry.stat().st_size, entry.stat().st_mtime_ns) for entry in os.scandir(folder)}


# What Claude Code runs (seen in the process list): source the snapshot, set two options, eval the command.
CLAUDE_CODE_SCRIPT = ('source "$TRIAGE_SNAPSHOT" && setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL '
                      '&& eval "$TRIAGE_COMMAND" < /dev/null')
# A snapshot like the one Claude Code writes: its options and its grep function, without PATH or exports.
SNAPSHOT_TEXT = """setopt nohashdirs
unalias grep 2>/dev/null || true
function grep { command grep "$@"; }
"""


def claude_code_invocation(command: str, env: dict[str, str], snapshot_file: Path) -> tuple[list[str], dict[str, str]]:
    return [ZSH, "-c", CLAUDE_CODE_SCRIPT], {**env, "TRIAGE_SNAPSHOT": str(snapshot_file), "TRIAGE_COMMAND": command}


class ZshRunner:
    """Runs strings through zsh in one worker's own working directory."""

    def __init__(self, root: Path, bin_dir: Path, home: Path, worker: int) -> None:
        self.cwd = root / f"cwd-{worker}"
        self.logs = root / f"argv-{worker}"
        self.logs.mkdir()
        reset_directory(self.cwd)
        self.snapshot_file = root / "snapshot.zsh"
        self.snapshot_file.write_text(SNAPSHOT_TEXT)
        self.env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(home), "ARGV_LOG": str(self.logs / "argv"),
                    "LANG": os.environ.get("LANG", "en_US.UTF-8"), "ZDOTDIR": str(home)}
        self.modes = ("zsh -f", "claude-code")

    def invocation(self, mode: str, command: str) -> tuple[list[str], dict[str, str]]:
        if mode == "zsh -f":
            return [ZSH, "-f", "-c", command], self.env
        return claude_code_invocation(command, self.env, self.snapshot_file)

    def run(self, mode: str, command: str) -> tuple[list[tuple[str, ...]], bool, str]:
        """Return the argvs the stand-ins saw (sorted, one per process), whether the folder changed, and stderr."""
        argv, env = self.invocation(mode, command)
        for log in self.logs.iterdir():
            log.unlink()
        before = snapshot(self.cwd)
        result = subprocess.run(argv, cwd=self.cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS,
                                check=False, close_fds=False)
        changed = snapshot(self.cwd) != before
        if changed:
            reset_directory(self.cwd)
        stderr = result.stderr.decode(errors="replace").lower()
        argvs = sorted(tuple(log.read_text().split("\0")[:-1]) for log in self.logs.iterdir())
        return argvs, changed, stderr

    def whence(self, mode: str, name: str) -> str:
        argv, env = self.invocation(mode, f"whence -w {name}; whence -p {name}")
        result = subprocess.run(argv, cwd=self.cwd, env=env,
                                capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        return result.stdout


@pytest.fixture
def runners(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    bin_dir = tmp_path / "bin"
    write_stand_ins(bin_dir)
    built = [ZshRunner(tmp_path, bin_dir, home, worker) for worker in range(WORKERS)]
    # Safety first: zsh must find the stand-in, never a real aws or kubectl, in both modes.
    for mode in built[0].modes:
        for name in STAND_IN_NAMES:
            assert built[0].whence(mode, name) == f"{name}: command\n{bin_dir / name}\n", (mode, name)
    return built


def _differences(runner: ZshRunner, cases: list[tuple[str, tuple[str, ...], bool]]) -> list[str]:
    found = []
    for command, argv, writes_file in cases:
        for mode in runner.modes:
            argvs, changed, stderr = runner.run(mode, command)
            seen = argvs[0] if len(argvs) == 1 else None
            if seen is None and writes_file and any(error in stderr for error in UNWRITABLE_TARGET_ERRORS):
                continue  # a write the guard never allows anyway, aimed at a path outside the test folder
            if seen != argv:
                found.append(f"{mode}: {command!r}\n    scanner {argv!r}\n    zsh     {seen!r}")
            elif changed and not writes_file:
                found.append(f"{mode}: {command!r} changed the working directory, but the scanner saw no write")
    return found


def test_the_corpus_is_large_and_reaches_the_shell():
    corpus = build_corpus()
    accepted = accepted_simple_commands(corpus)
    assert len(corpus) > 5000
    assert len(accepted) > 1000


def test_scanner_argv_matches_zsh_for_every_accepted_string(runners):
    accepted = accepted_simple_commands(build_corpus())
    slices = [accepted[worker::WORKERS] for worker in range(WORKERS)]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = pool.map(_differences, runners, slices)
    mismatches = [line for found in results for line in found]
    assert not mismatches, f"{len(mismatches)} mismatches:\n" + "\n".join(mismatches[:60])


# Pipelines and && lists, compared as the multiset of argvs every stand-in process received.
PIPELINE_SIDES = ["aws get", "kubectl 'a b'", "aws -n 2>/dev/null", "kubectl >/dev/null get", ">/dev/null",
                  "2>/dev/null", "&>/dev/null", "> out", "FOO=1", "FOO=1 >/dev/null", "aws <->", "kubectl \\\n x"]


def build_pipeline_corpus() -> list[str]:
    return sorted({f"{left} {separator} {right}" for left, right in itertools.product(PIPELINE_SIDES, repeat=2)
                   for separator in ("|", "&&")})


def _pipeline_differences(runner: ZshRunner, commands: list[str]) -> list[str]:
    found = []
    for command in commands:
        try:
            segments = split_command(command)
        except Unparseable:
            continue
        expected = sorted(segment.argv for segment in segments)
        for mode in runner.modes:
            argvs, _changed, _stderr = runner.run(mode, command)
            if argvs != expected:
                found.append(f"{mode}: {command!r}\n    scanner {expected!r}\n    zsh     {argvs!r}")
    return found


def test_every_pipeline_segment_matches_what_zsh_runs(runners):
    corpus = build_pipeline_corpus()
    slices = [corpus[worker::WORKERS] for worker in range(WORKERS)]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = pool.map(_pipeline_differences, runners, slices)
    mismatches = [line for found in results for line in found]
    assert not mismatches, f"{len(mismatches)} mismatches:\n" + "\n".join(mismatches[:60])



# ---- what the guard cannot see: a snapshot function or alias on an allowed word ----

AWS_READ = "aws ecs list-clusters --profile triage-prod-main --region eu-west-1"
# One allowed command for every command word the guard can allow. Adding a word to the guard's allow list
# without a case here fails test_every_allowed_command_word_has_a_shadow_case.
SHADOW_COMMANDS = {
    "aws": AWS_READ,
    "kubectl": "kubectl --kubeconfig {skill}/config/kubeconfig --context triage-platform-prod -n payments get pods",
    "jq": AWS_READ + " | jq .",
    "head": AWS_READ + " | head -5",
    "tail": AWS_READ + " | tail -5",
    "wc": AWS_READ + " | wc -l",
    "sort": AWS_READ + " | sort -r",
    "uniq": AWS_READ + " | uniq -c",
    "cut": AWS_READ + " | cut -d , -f 1",
    "tr": AWS_READ + " | tr a b",
    "column": AWS_READ + " | column -t",
    "venv python": "{skill}/.venv/bin/python {skill}/scripts/run.py preflight",
    "venv python3": "{skill}/.venv/bin/python3 {skill}/scripts/run.py preflight",
}
SHADOW_STAND_INS = ("aws", "kubectl", "jq", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "column")


def _shadow_word(word: str, skill: Path) -> str:
    return str(skill / ".venv" / "bin" / word.split()[1]) if word.startswith("venv ") else word


def test_every_allowed_command_word_has_a_shadow_case():
    assert set(SHADOW_COMMANDS) == {"aws", "kubectl", "venv python", "venv python3"} | set(FILTER_RULES)


@pytest.fixture
def shadow_setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    skill = home / ".claude" / "skills" / "ai-triage"
    (skill / "config").mkdir(parents=True)
    (skill / "scripts").mkdir()
    venv_bin = skill / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    logs = tmp_path / "logs"
    logs.mkdir()
    for folder, names in ((bin_dir, SHADOW_STAND_INS), (venv_bin, ("python", "python3"))):
        for name in names:
            script = folder / name
            script.write_text(f"#!{STAND_IN_SHELL}\nprintf '%s\\0' {name} \"$@\" > \"$ARGV_LOG.$$\"\n")
            script.chmod(0o755)
    monkeypatch.setenv("HOME", str(home))
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(home), "ARGV_LOG": str(logs / "argv"),
           "SHADOW_LOG": str(tmp_path / "shadow.log"), "LANG": os.environ.get("LANG", "en_US.UTF-8")}
    for name in ("aws", "kubectl"):  # safety first: never a real aws or kubectl
        found = subprocess.run([ZSH, "-f", "-c", f"whence -p {name}"], env=env, capture_output=True, text=True,
                               timeout=TIMEOUT_SECONDS, check=False).stdout
        assert found == f"{bin_dir / name}\n"
    context = GuardContext(profiles=frozenset({"triage-prod-main"}), kubeconfig=str(skill / "config" / "kubeconfig"),
                           kube_contexts=frozenset({"triage-platform-prod"}), opensearch_hosts=frozenset(),
                           skill_dir=str(skill))
    return {"tmp": tmp_path, "skill": skill, "env": env, "context": context}


@pytest.mark.parametrize("definition", ["function", "alias"])
@pytest.mark.parametrize("word", sorted(SHADOW_COMMANDS))
def test_a_snapshot_definition_runs_instead_of_what_the_guard_checked(word, definition, shadow_setup):
    skill, env = shadow_setup["skill"], shadow_setup["env"]
    command = SHADOW_COMMANDS[word].format(skill=skill)
    assert decide(command, shadow_setup["context"]).kind == ALLOW  # the guard approves the command ...
    name = _shadow_word(word, skill)
    if definition == "function":
        text = f'function {name} {{ print -rn -- shadow > "$SHADOW_LOG"; }}\n'
    else:
        text = f"alias {name}='print -rn -- shadow > \"$SHADOW_LOG\"; :'\n"
    snapshot_file = shadow_setup["tmp"] / "snapshot.zsh"
    snapshot_file.write_text(SNAPSHOT_TEXT + text)
    argv, run_env = claude_code_invocation(command, env, snapshot_file)
    subprocess.run(argv, cwd=shadow_setup["tmp"], env=run_env, stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=TIMEOUT_SECONDS, check=False)
    # ... but zsh runs the snapshot's definition. The guard cannot see this; preflight's shell check reports it.
    assert (shadow_setup["tmp"] / "shadow.log").read_text() == "shadow"
