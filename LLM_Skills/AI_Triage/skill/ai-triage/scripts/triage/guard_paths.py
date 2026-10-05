"""Protected files: paths that only the skill's own scripts may write.

The guard denies the file tools (Write, Edit, MultiEdit, NotebookEdit) on the
installed skill folder and on the files of a run folder that the scripts own.
A hand edit there could turn a candidate cause into a confirmed one or mark an
unaudited report as audited. Paths are made absolute against the hook's cwd,
`~` is expanded, and symbolic links and `..` are resolved before the check.
Names are compared without regard to letter case and after NFKC normalization:
macOS file systems usually ignore case and decomposed accents, and compatibility
forms (a fullwidth letter) are treated as the plain name out of caution. A hard link made beforehand
to a protected file is not detected: it is a separate path to the same file.

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

# _Scanner is the scanner split_command uses; reading its tokens is the only way to see redirect targets.
from triage.shell_parse import Segment, _Scanner, _Word
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
    ("incident.json",): "case.py",
    ("render.json",): "report.py",
    ("timeline.json",): "timeline.py",
    ("report.md",): "report.py",
    ("work-order.json",): "report.py",
    ("slack-message.md",): "publish.py slack-message",
}
STALE_SUFFIX = ".stale"
STALE_WRITER = "judge.py"
RUN_DEPTH = 2  # <case>/<run>
# Directly under the cases root: what publish.py records for the connector check (guard_mcp).
PUBLISH_STATE = (".publish-state.json", "publish.py")
REDIRECT_OPERATORS = frozenset({">", ">>", "&>", "&>>"})

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
    # NFKC: a decomposed accent (APFS treats it as the same name) and a compatibility form such as a
    # fullwidth letter (a different file, refused anyway out of caution) both compare as the plain name.
    return unicodedata.normalize("NFKC", path).casefold()


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


def _script_owned_writer(parts: list[str]) -> str:
    """The script that owns a path below the cases root, or "". Names count at any depth, not only in a run
    folder, so that a copy of a run elsewhere under the root cannot be edited by hand either."""
    if parts == [PUBLISH_STATE[0]]:
        return PUBLISH_STATE[1]
    folder = next((part for part in parts if part in RUN_FOLDERS), None)
    if folder:
        return RUN_FOLDERS[folder]
    if parts[-2:] == ["findings", "checked.json"]:
        return RUN_FILES[("findings", "checked.json")]
    if (parts[-1],) in RUN_FILES:
        return RUN_FILES[(parts[-1],)]
    if parts[-1].endswith(STALE_SUFFIX):
        return STALE_WRITER
    return ""


def protected_reason(resolved: str, roots: ProtectedRoots) -> str:
    """Why a resolved path may not be written by hand, or "" when it may."""
    if any(_parts_below(resolved, root) is not None for root in roots.skill_dirs):
        return SKILL_FOLDER_REASON
    parts = _parts_below(resolved, roots.cases_dir)
    if not parts:
        return ""
    writer = _script_owned_writer(parts)
    if not writer:
        return ""
    return f"{'/'.join(parts[-2:])} under the cases root is written only by the skill's scripts; use {writer} instead"


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


def redirect_targets(command: str) -> list[str]:
    """The file names of output redirects in a command split_command accepts (>&1 and >&2 are not files)."""
    tokens = _Scanner(command.strip(" \t\n")).scan()
    return [tokens[index + 1].text for index, token in enumerate(tokens[:-1])
            if isinstance(token, str) and token in REDIRECT_OPERATORS and isinstance(tokens[index + 1], _Word)]


def _resolves_to_protected(candidate: str, cwd: object, roots: ProtectedRoots) -> bool:
    try:
        return protected_target(resolve_tool_path(candidate, cwd), roots)
    except UnresolvablePath:
        return False


def protected_write_tripwire(segments: Sequence[Segment], skill_dir: str, cases_dir: str, cwd: object = "",
                             targets: Sequence[str] = ()) -> str:
    """A reason to ask when a file-changing command or a redirect names a protected path, else ""."""
    writers = [segment for segment in segments if segment.argv and os.path.basename(segment.argv[0]) in WRITE_COMMANDS]
    if not writers and not targets:
        return ""
    roots = protected_roots(skill_dir, cases_dir)
    if any(_resolves_to_protected(target, cwd, roots) for target in targets):
        return TRIPWIRE_REASON
    for segment in writers:
        for argument in segment.argv[1:]:
            if any(_resolves_to_protected(candidate, cwd, roots) for candidate in _argument_paths(argument)):
                return TRIPWIRE_REASON
    return ""
