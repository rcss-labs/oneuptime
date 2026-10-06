#!/usr/bin/env python3
"""Validate report.json and render the report and the remediation work order.

Exit codes: 0 done, 1 the report is invalid (every problem is printed), 2 usage, config, or missing file.
"""
from __future__ import annotations

import argparse
import json
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
    report_path, order_path = case_dir / "report.md", case_dir / "work-order.json"
    report_path.write_text(text)
    order_path.write_text(json.dumps(work_order, indent=2) + "\n")
    print(report_path)
    print(order_path)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if not args.case_dir.is_dir():
            raise CaseError([f"case folder not found: {args.case_dir}"])
        config = load_config(default_config_path(args.skill_dir))
        if args.command == "validate":
            _validated(args.case_dir, config)
            print("report is valid")
            return 0
        now = parse_time(args.now) if getattr(args, "now", None) else datetime.now(timezone.utc)
        return _render(args.case_dir, config, now)
    except InvalidReport as error:
        print("\n".join(f"- {problem}" for problem in error.problems), file=sys.stderr)
        return 1
    except (ConfigError, CaseError) as error:
        print("\n".join(error.errors), file=sys.stderr)
        return 2
    except WindowError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
