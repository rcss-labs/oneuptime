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

from triage.case import CaseError, load_case
from triage.config import ConfigError, default_config_path, load_config
from triage.findings import valid_findings
from triage.report import (
    build_work_order,
    coverage_from_evidence,
    render_report,
    validate_report,
    validate_work_order,
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
    except ValueError as error:
        raise InvalidReport([f"report.json: not valid JSON ({error})"]) from error


def _validated(case_dir: Path, config) -> tuple[dict, dict, dict]:
    report = _load_report(case_dir)
    case = load_case(case_dir)
    findings = valid_findings(case_dir)
    problems = validate_report(report, case, findings, config)
    if problems:
        raise InvalidReport(problems)
    return report, case, findings


OUTPUT_NAMES = ("report.md", "work-order.json")


def _mark_stale(case_dir: Path) -> list[str]:
    """Rename outputs of an earlier render to <name>.stale, so nothing that no longer matches report.json is left."""
    renamed = []
    for name in OUTPUT_NAMES:
        (case_dir / f"{name}.tmp").unlink(missing_ok=True)
        path = case_dir / name
        if path.exists():
            os.replace(path, case_dir / f"{name}.stale")
            renamed.append(f"{name}.stale")
    return renamed


def _write_both(case_dir: Path, text: str, work_order: dict) -> None:
    """Write both files to temporary names, then move both into place."""
    contents = {"report.md": text, "work-order.json": json.dumps(work_order, indent=2) + "\n"}
    for name, content in contents.items():
        (case_dir / f"{name}.tmp").write_text(content)
    for name in OUTPUT_NAMES:
        os.replace(case_dir / f"{name}.tmp", case_dir / name)


def _render(case_dir: Path, config, now: datetime) -> int:
    report, case, findings = _validated(case_dir, config)
    gaps = coverage_from_evidence(case_dir)
    text = render_report(report, case, findings, build_timeline(case_dir), gaps, now)
    work_order = build_work_order(report, case, now)
    work_order["coverage_gaps"] += [
        f"Evidence error {gap['code']}: {entry['command'] or entry['file']}" for gap in gaps for entry in gap["entries"]]
    work_order = Redactor().value(work_order)
    problems = validate_work_order(work_order)
    if problems:
        raise InvalidReport([f"work order: {problem}" for problem in problems])
    _write_both(case_dir, text, work_order)
    print(case_dir / "report.md")
    print(case_dir / "work-order.json")
    return 0


def _fail_render(case_dir: Path) -> str:
    try:
        renamed = _mark_stale(case_dir)
    except OSError as error:
        return f"the earlier report.md and work-order.json could not be renamed ({error.strerror or error})"
    if not renamed:
        return ""
    return f"the earlier outputs no longer match report.json and were renamed: {', '.join(renamed)}"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    rendering = False
    try:
        if not args.case_dir.is_dir():
            raise CaseError([f"case folder not found: {args.case_dir}"])
        config = load_config(default_config_path(args.skill_dir))
        if args.command == "validate":
            _validated(args.case_dir, config)
            print("report is valid")
            return 0
        now = parse_time(args.now) if getattr(args, "now", None) else datetime.now(timezone.utc)
        rendering = True
        return _render(args.case_dir, config, now)
    except InvalidReport as error:
        message, code = "\n".join(f"- {problem}" for problem in error.problems), 1
    except (ConfigError, CaseError) as error:
        message, code = "\n".join(error.errors), 2
    except WindowError as error:
        message, code = str(error), 2
    except OSError as error:
        message, code = f"{error.filename or 'output'}: {error.strerror or error}", 2
    if rendering:
        message = "\n".join(part for part in (message, _fail_render(args.case_dir)) if part)
    print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
