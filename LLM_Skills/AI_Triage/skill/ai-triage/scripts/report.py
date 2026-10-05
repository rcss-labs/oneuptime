#!/usr/bin/env python3
"""Validate report.json and render the report and the remediation work order.

Exit codes: 0 done, 1 the report is invalid (every problem is printed), 2 usage, config, or missing file.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from triage.case import CaseError, load_case, resolve_case_dir
from triage.config import ConfigError, default_config_path, load_config
from triage.report import (
    OUTPUT_NAMES,
    build_work_order,
    check_case_inputs,
    coverage_from_evidence,
    input_hashes,
    load_checked,
    mark_stale,
    render_is_current,
    render_report,
    strip_local_paths,
    validate_report,
    validate_work_order,
    write_render_marker,
)
from triage.redact import Redactor
from triage.timeline import build_timeline
from triage.window import WindowError, parse_time

SKILL_DIR = Path(__file__).resolve().parent.parent


class InvalidReport(Exception):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="report", description=__doc__.split("\n\n")[0])
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for name, help_text in (("validate", "check report.json and print every problem"),
                            ("render", "validate, then write report.md and work-order.json")):
        child = commands.add_parser(name, help=help_text, description=help_text)
        child.add_argument("--case-dir", type=Path, required=True, help="the case folder")
        child.add_argument("--skill-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        child.add_argument("--now", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    return parser


def _load_report(case_dir: Path):
    path = case_dir / "report.json"
    if not path.is_file():
        raise CaseError([f"{path}: file not found"])
    try:
        return json.loads(path.read_text())
    except RecursionError as error:
        raise InvalidReport(["report.json: nested deeper than 50 levels"]) from error
    except ValueError as error:
        raise InvalidReport([f"report.json: not valid JSON ({error})"]) from error


def _validated(case_dir: Path, config) -> tuple[dict, dict, dict]:
    report = _load_report(case_dir)
    case = load_case(case_dir)
    findings, input_problems = check_case_inputs(case_dir)
    problems = input_problems + validate_report(report, case, findings, config)
    if problems:
        raise InvalidReport(problems)
    return report, case, findings


def _write_both(case_dir: Path, text: str, work_order: dict, inputs: dict) -> None:
    """Write both files to temporary names, move both into place, then write the marker."""
    contents = {"report.md": text, "work-order.json": json.dumps(work_order, indent=2) + "\n"}
    for name, content in contents.items():
        (case_dir / f"{name}.tmp").write_text(content)
    for name in OUTPUT_NAMES:
        os.replace(case_dir / f"{name}.tmp", case_dir / name)
    write_render_marker(case_dir, inputs)


def _render(case_dir: Path, config, now: datetime, inputs: dict) -> int:
    report, case, findings = _validated(case_dir, config)
    gaps = coverage_from_evidence(case_dir)
    text = render_report(report, case, findings, build_timeline(case_dir), gaps, now)
    work_order = build_work_order(report, case, now, checked=load_checked(case_dir)[0])
    work_order["coverage_gaps"] += [
        f"Evidence error {gap['code']}: {entry['command'] or entry['file']}" for gap in gaps for entry in gap["entries"]]
    work_order = Redactor().value(strip_local_paths(work_order, case))
    problems = validate_work_order(work_order)
    if problems:
        raise InvalidReport([f"work order: {problem}" for problem in problems])
    _write_both(case_dir, text, work_order, inputs)
    print(case_dir / "report.md")
    print(case_dir / "work-order.json")
    return 0


def _check_case_names_this_folder(case_dir: Path) -> None:
    """case.json says where the run lives, and the library reads the judgments from there; it must be this folder."""
    named = load_case(case_dir).get("case_dir")
    try:
        same = isinstance(named, str) and Path(named).resolve() == case_dir
    except (OSError, RuntimeError):
        same = False
    if not same:
        raise CaseError([f"{case_dir}/case.json: case_dir does not name this folder"])


def _stale_note(case_dir: Path) -> str:
    renamed, failed = mark_stale(case_dir)
    parts = []
    if renamed:
        parts.append(f"the earlier outputs no longer match report.json and were renamed: {', '.join(renamed)}")
    if failed:
        parts.append(f"these earlier outputs could not be renamed and must not be used: {', '.join(failed)}")
    return "; ".join(parts)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    outputs_at_risk = False
    try:
        config = load_config(default_config_path(args.skill_dir))
        args.case_dir = resolve_case_dir(args.case_dir, config)
        _check_case_names_this_folder(args.case_dir)
        had_outputs = any((args.case_dir / name).exists() for name in OUTPUT_NAMES)
        reasons = render_is_current(args.case_dir)
        if had_outputs and reasons:
            print("\n".join(reasons), file=sys.stderr)
        if args.command == "render":
            (args.case_dir / "render.json.tmp").unlink(missing_ok=True)
        inputs = input_hashes(args.case_dir)
        now = None
        if args.command == "render":
            now = parse_time(args.now) if getattr(args, "now", None) else datetime.now(timezone.utc)
        outputs_at_risk = True
        if args.command == "validate":
            _validated(args.case_dir, config)
            print("report is valid")
            return 0
        return _render(args.case_dir, config, now, inputs)
    except InvalidReport as error:
        message, code = "\n".join(f"- {problem}" for problem in error.problems), 1
    except (ConfigError, CaseError) as error:
        message, code = "\n".join(error.errors), 2
    except WindowError as error:
        message, code = str(error), 2
    except OSError as error:
        message, code = f"{error.filename or 'output'}: {error.strerror or error}", 2
    except Exception as error:  # a malformed input must end in one clear line, never a traceback
        message, code = f"{args.command} failed unexpectedly ({type(error).__name__}); nothing was written", 1
    if outputs_at_risk:
        message = "\n".join(part for part in (message, _stale_note(args.case_dir)) if part)
    print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
