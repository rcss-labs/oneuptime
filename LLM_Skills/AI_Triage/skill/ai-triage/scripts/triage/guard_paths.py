"""Protected files: paths that only the skill's own scripts may write.

The guard denies the file tools (Write, Edit, MultiEdit, NotebookEdit) on the
installed skill folder and on the files of a run folder that the scripts own.
A hand edit there could turn a candidate cause into a confirmed one or mark an
unaudited report as audited. Paths are made absolute against the hook's cwd,
`~` is expanded, and symbolic links and `..` are resolved before the check.
Names are compared without regard to letter case or Unicode normalization,
because macOS file systems usually ignore both.

protected_write_tripwire is the Bash side, and it is a tripwire, not a
boundary: it only looks for a write-looking word next to a protected path in
the command text, so that an obvious hand edit is put to the engineer. The real
limits on Bash are the shell scanner (no redirect to a file is ever allowed)
and the normal permission flow for every command the guard does not know.
"""
from __future__ import annotations

import os
import re
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

WRITE_WORD_RE = re.compile(r"(?<![\w.-])(?:rm|mv|cp|tee|sed|truncate|dd|chmod|ln)(?![\w.-])")
# A > that is not part of >>, a redirect to /dev/null, or a copy of descriptor 1 or 2.
FILE_REDIRECT_RE = re.compile(r">(?!>|\s*/dev/null(?![\w./-])|&\s*[12](?![0-9]))")
PATH_MARKERS = (".claude/skills/ai-triage", ".ai-triage/cases")
# Names that point at run files when the command runs inside a protected folder.
BARE_NAME_RE = re.compile(
    r"(?<![\w.-])(?:evidence|judgments|checked\.json|audit\.json|case\.json|case\.md|report\.md|work-order\.json"
    r"|slack-message\.md|timeline\.md)(?![\w-])|\.stale(?!\w)"
)
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


def _home_relative(path: str) -> str:
    home = os.path.expanduser("~")
    if home.startswith("~"):
        return ""
    for base in (home, os.path.realpath(home)):
        if path.startswith(base.rstrip(os.sep) + os.sep):
            return path[len(base.rstrip(os.sep)) + 1:]
    return ""


def _path_markers(skill_dir: str, cases_dir: str, roots: ProtectedRoots) -> set[str]:
    candidates = {os.path.expanduser(skill_dir), os.path.expanduser(cases_dir or DEFAULT_CASES_DIR),
                  *roots.skill_dirs, roots.cases_dir}
    markers = set(PATH_MARKERS)
    for path in candidates:
        if path and os.path.isabs(path):
            markers.update({path, _home_relative(path)})
    return {_comparable(marker) for marker in markers if marker}


def _cwd_is_protected(cwd: object, roots: ProtectedRoots) -> bool:
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or "\x00" in cwd:
        return False
    resolved = os.path.realpath(cwd)
    return any(_parts_below(resolved, root) is not None for root in (*roots.skill_dirs, roots.cases_dir) if root)


def protected_write_tripwire(command: str, skill_dir: str, cases_dir: str, cwd: object = "") -> str:
    """A reason to ask when the text pairs a write-looking word with a protected path, else ""."""
    text = _comparable(command)
    if not (WRITE_WORD_RE.search(text) or FILE_REDIRECT_RE.search(text)):
        return ""
    roots = protected_roots(skill_dir, cases_dir)
    if any(marker in text for marker in _path_markers(skill_dir, cases_dir, roots)):
        return TRIPWIRE_REASON
    if BARE_NAME_RE.search(text) and _cwd_is_protected(cwd, roots):
        return TRIPWIRE_REASON
    return ""
