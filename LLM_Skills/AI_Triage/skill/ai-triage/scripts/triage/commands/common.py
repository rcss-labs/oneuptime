"""What the commands share: the skill folder, the config, and opening a case folder."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from triage.case import CaseError, check_replay, resolve_case_dir
from triage.cli import UsageError
from triage.config import ConfigError, TriageConfig, default_config_path, load_config

SKILL_DIR = Path(__file__).resolve().parents[3]  # scripts/triage/commands/ -> the skill folder


def fail(message: str, code: int) -> int:
    """Say why on stderr and return the exit code."""
    print(message, file=sys.stderr)
    return code


def load_skill_config(skill_dir: Path) -> TriageConfig:
    """The skill folder's config, or a UsageError with every problem on one line."""
    try:
        return load_config(default_config_path(skill_dir))
    except ConfigError as error:
        raise UsageError("; ".join(error.errors)) from error


def open_case(case_dir: Path, config: TriageConfig) -> tuple[Path, dict]:
    """The real path of a case folder under the cases root and its case.json, or a UsageError in one line.

    case.json is read as a dict (an empty one when it holds something else), so that its replay state can be
    compared with the session's before anything is read or written: a case of the other kind is refused."""
    try:
        real = resolve_case_dir(case_dir, config)
        case = json.loads((real / "case.json").read_text(encoding="utf-8"))
        case = case if isinstance(case, dict) else {}
        check_replay(case)
    except CaseError as error:
        raise UsageError("; ".join(error.errors)) from error
    except (OSError, ValueError) as error:
        raise UsageError(f"cannot read case.json in {case_dir}: {error}") from error
    return real, case
