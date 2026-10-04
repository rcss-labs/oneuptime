"""Differential test: the scanner must agree with the real zsh on every string it accepts.

A stand-in program records the argv zsh passes to it. For every generated string
that split_command accepts as one simple command, the scanner's argv must equal
the recorded argv, and a redirect the scanner calls harmless must leave the
working directory untouched. The stand-in is first on PATH under the names aws
and kubectl, so no real aws or kubectl can run from this test.
"""
from __future__ import annotations

import itertools
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from triage.shell_parse import Unparseable, split_command

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
        script.write_text(f"#!{STAND_IN_SHELL}\nprintf '%s\\0' {name} \"$@\" > \"$ARGV_LOG\"\n")
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


class ZshRunner:
    """Runs strings through zsh in one worker's own working directory."""

    def __init__(self, root: Path, bin_dir: Path, home: Path, worker: int) -> None:
        self.cwd = root / f"cwd-{worker}"
        self.log = root / f"argv-{worker}.log"
        reset_directory(self.cwd)
        base = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(home), "ARGV_LOG": str(self.log),
                "LANG": os.environ.get("LANG", "en_US.UTF-8")}
        # -f skips every startup file; the second mode reads them, from an empty ZDOTDIR.
        self.modes = {"zsh -f": ([ZSH, "-f", "-c"], base), "zsh": ([ZSH, "-c"], {**base, "ZDOTDIR": str(home)})}

    def run(self, mode: str, command: str) -> tuple[tuple[str, ...] | None, bool, str]:
        """Return the argv the stand-in saw (None if it did not run), whether the folder changed, and stderr."""
        prefix, env = self.modes[mode]
        if self.log.exists():
            self.log.unlink()
        before = snapshot(self.cwd)
        result = subprocess.run(prefix + [command], cwd=self.cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS,
                                check=False, close_fds=False)
        changed = snapshot(self.cwd) != before
        if changed:
            reset_directory(self.cwd)
        stderr = result.stderr.decode(errors="replace").lower()
        if not self.log.exists():
            return None, changed, stderr
        return tuple(self.log.read_text().split("\0")[:-1]), changed, stderr

    def whence(self, mode: str, name: str) -> str:
        prefix, env = self.modes[mode]
        result = subprocess.run(prefix + [f"whence -w {name}; whence -p {name}"], cwd=self.cwd, env=env,
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
            seen, changed, stderr = runner.run(mode, command)
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
