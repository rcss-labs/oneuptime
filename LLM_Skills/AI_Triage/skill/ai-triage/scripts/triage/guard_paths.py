"""Protected files: paths that only the skill's own scripts may write.

The guard denies the file tools (Write, Edit, MultiEdit, NotebookEdit) on the
installed skill folder and on the files of a run folder that the scripts own.
A hand edit there could turn a candidate cause into a confirmed one or mark an
unaudited report as audited. Paths are made absolute against the hook's cwd,
`~` is expanded, and symbolic links and `..` are resolved before the check.
Names are compared without regard to letter case or Unicode normalization,
because macOS file systems usually ignore both.
"""
from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass

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
