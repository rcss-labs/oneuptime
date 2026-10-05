"""Protected files: paths that only the skill's own scripts may write.

The guard denies the file tools (Write, Edit, MultiEdit, NotebookEdit) on the
installed skill folder and on the files of a run folder that the scripts own.
A hand edit there could turn a candidate cause into a confirmed one or mark an
unaudited report as audited. Paths are made absolute against the hook's cwd,
`~` is expanded, and symbolic links and `..` are resolved before the check.
Names are compared without regard to letter case or Unicode normalization,
because macOS file systems usually ignore both.

protected_write_tripwire is the Bash side, and it is a tripwire, not a
boundary: it reads the parsed command, and asks when a segment's command word
is a known file-changing tool and one of its arguments resolves to a protected
path, so that an obvious hand edit is put to the engineer. Quoted text and
other commands' option values cannot trigger it. The real limits on Bash are
the shell scanner (no redirect to a file is ever allowed, and an unparseable
command is never allowed) and the normal permission flow for every command the
guard does not know.
"""
from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass
from typing import Sequence

from triage.shell_parse import Segment
from triage.verdict import ASK, DENY, PASS, Verdict

FILE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
DEFAULT_CASES_DIR = "~/.ai-triage/cases"
INSTALLED_SKILL_DIR = "~/.claude/skills/ai-triage"
SKILL_FOLDER_REASON = ("files in the installed skill folder are changed only by install.sh; "
                       "use map_suggest.py apply instead to change the service map")
# Inside a run folder (<cases_dir>/<case>/<run>/): folder or file -> the script that writes it.
RUN_FOLDERS = {"evidence": "collect.py", "judgments": "judge.py"}
RUN_FILES = {
    ("findings", "checked.json"): "findings.py",
    ("audit.json",): "publish.py audit",
    ("case.json",): "case.py",
    ("case.md",): "case.py",
    ("report.md",): "report.py",
    ("work-order.json",): "report.py",
    ("slack-message.md",): "publish.py slack-message",
    ("timeline.md",): "timeline.py",
}
STALE_SUFFIX = ".stale"
STALE_WRITER = "judge.py"
RUN_DEPTH = 2  # <case>/<run>

# Command words that change files; with a protected path among their arguments the engineer decides.
WRITE_COMMANDS = frozenset({"rm", "mv", "cp", "tee", "sed", "truncate", "dd", "chmod", "chown", "ln", "link", "touch",
                            "install", "rsync", "perl"})
TRIPWIRE_REASON = ("the command may write a protected path (the skill folder or run files that only the skill's "
                   "scripts write); the engineer decides")


class UnresolvablePath(Exception):
    """The tool input does not name a path the guard can check."""


@dataclass(frozen=True)
class ProtectedRoots:
    skill_dirs: tuple[str, ...]  # resolved
    cases_dir: str  # resolved


def _comparable(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _resolved_root(path: str) -> str | None:
    expanded = os.path.expanduser(path)
    if expanded.startswith("~") or not os.path.isabs(expanded):
        return None
    return os.path.realpath(expanded)


def protected_roots(skill_dir: str, cases_dir: str) -> ProtectedRoots:
    """The guard's skill folder, the default installed one, and the case root, all resolved."""
    skill_dirs = tuple(dict.fromkeys(root for root in (_resolved_root(skill_dir), _resolved_root(INSTALLED_SKILL_DIR))
                                     if root))
    return ProtectedRoots(skill_dirs, _resolved_root(cases_dir or DEFAULT_CASES_DIR) or "")


def resolve_tool_path(raw: object, cwd: object) -> str:
    """Absolute path with ~ expanded and every existing symbolic link and .. resolved."""
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise UnresolvablePath("the tool input has no usable path")
    path = os.path.expanduser(raw)
    if path.startswith("~"):
        raise UnresolvablePath("~ cannot be expanded")
    if not os.path.isabs(path):
        if not isinstance(cwd, str) or not os.path.isabs(cwd) or "\x00" in cwd:
            raise UnresolvablePath("a relative path without a usable working directory")
        path = os.path.join(cwd, path)
    return os.path.realpath(path)


def _parts_below(path: str, root: str) -> list[str] | None:
    """The path's components below root (compared without case), or None when it is not under root."""
    path_key, root_key = _comparable(path), _comparable(root).rstrip(os.sep)
    if path_key == root_key:
        return []
    if not root_key or not path_key.startswith(root_key + os.sep):
        return None
    return path_key[len(root_key) + 1:].split(os.sep)


def _run_file_writer(rest: list[str]) -> str:
    if rest[0] in RUN_FOLDERS:
        return RUN_FOLDERS[rest[0]]
    if tuple(rest) in RUN_FILES:
        return RUN_FILES[tuple(rest)]
    if rest[-1].endswith(STALE_SUFFIX):
        return STALE_WRITER
    return ""


def protected_reason(resolved: str, roots: ProtectedRoots) -> str:
    """Why a resolved path may not be written by hand, or "" when it may."""
    if any(_parts_below(resolved, root) is not None for root in roots.skill_dirs):
        return SKILL_FOLDER_REASON
    parts = _parts_below(resolved, roots.cases_dir)
    if parts is None or len(parts) <= RUN_DEPTH:
        return ""
    rest = parts[RUN_DEPTH:]
    writer = _run_file_writer(rest)
    if not writer:
        return ""
    return f"{'/'.join(rest)} in a run folder is written only by the skill's scripts; use {writer} instead"


def decide_file_tool(tool: str, tool_input: object, cwd: object, roots: ProtectedRoots) -> Verdict:
    """Deny a protected path, ask when the path cannot be checked, otherwise pass."""
    if not isinstance(tool_input, dict):
        return Verdict(ASK, f"{tool} input has no path the guard can check")
    try:
        resolved = resolve_tool_path(tool_input.get(FILE_TOOLS[tool]), cwd)
    except UnresolvablePath as exc:
        return Verdict(ASK, f"{tool}: {exc}")
    reason = protected_reason(resolved, roots)
    return Verdict(DENY, reason) if reason else Verdict(PASS)


def protected_target(resolved: str, roots: ProtectedRoots) -> bool:
    """A protected file, or a folder that holds protected files (a run or case folder, a root, or above one)."""
    if not resolved.rstrip(os.sep) or protected_reason(resolved, roots):
        return True
    if any(root and _parts_below(root, resolved) is not None for root in (*roots.skill_dirs, roots.cases_dir)):
        return True
    parts = _parts_below(resolved, roots.cases_dir)
    return parts is not None and len(parts) <= RUN_DEPTH


def _argument_paths(argument: str) -> list[str]:
    # The word itself, and the value after = (dd of=PATH, --target-directory=PATH).
    return [argument] + ([argument.split("=", 1)[1]] if "=" in argument else [])


def protected_write_tripwire(segments: Sequence[Segment], skill_dir: str, cases_dir: str, cwd: object = "") -> str:
    """A reason to ask when a file-changing command names a protected path, else ""."""
    writers = [segment for segment in segments if segment.argv and os.path.basename(segment.argv[0]) in WRITE_COMMANDS]
    if not writers:
        return ""
    roots = protected_roots(skill_dir, cases_dir)
    for segment in writers:
        for argument in segment.argv[1:]:
            for candidate in _argument_paths(argument):
                try:
                    resolved = resolve_tool_path(candidate, cwd)
                except UnresolvablePath:
                    continue
                if protected_target(resolved, roots):
                    return TRIPWIRE_REASON
    return ""
