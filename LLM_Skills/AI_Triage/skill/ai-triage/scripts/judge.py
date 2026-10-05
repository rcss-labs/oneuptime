#!/usr/bin/env python3
"""Check Claude's conclusions with TypeSafe: judge the report draft, locate a service, or ask one ad hoc question.

Exit codes: 0 done (also when TypeSafe is unavailable; the summary records it),
1 judging failed part-way (a malformed answer or another failure; run it again) or the report draft,
the case input, or a question file is unusable, 2 usage, config, or case error, or a report draft that
breaks a rule (duplicate ids, a reserved id, supporting or contradicting that is not a list, too long a state).
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

from triage.case import CaseError, check_replay, load_case, resolve_case_dir
from triage.config import ConfigError, default_config_path, load_config
from triage.judge import (
    DraftRuleError,
    JudgeSession,
    JudgmentError,
    JudgmentStore,
    describe_candidates,
    incident_state,
    match_resource,
    retire_summary,
    run_adhoc,
    run_judgments,
    single_name_match,
)
from triage.judge_client import Judge, TypeSafeJudge
from triage.questions import QuestionError, default_questions_path, load_questions
from triage.redact import Redactor
from triage.service_map import MapError, ServiceMap, default_map_path, load_map
from triage.window import WindowError
from triage.cli import add_exit_codes, run

SKILL_DIR = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="judge", description=__doc__.split("\n\n")[0])
    parser.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text, description=help_text)
        child.add_argument("--skill-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        child.add_argument("--case-dir", type=Path, required=True)
        return child

    add("run", "judge the findings, causes, ranking, and actions of report.json and write judgments/summary.json")
    add("locate", "choose between the service map candidates of the case, or decide to ask the engineer")
    adhoc = add("adhoc", "ask one question that the fixed set does not cover")
    adhoc.add_argument("--question-file", type=Path, required=True, help="JSON with id, reason, state, and question")
    add_exit_codes(parser)
    return parser


def _fail(message: str, code: int) -> int:
    print(message, file=sys.stderr)
    return code


def _session(args: argparse.Namespace, config, judge: Judge | None) -> JudgeSession:
    judge = judge if judge is not None else TypeSafeJudge(config.typesafe_model)
    return JudgeSession(judge, JudgmentStore(args.case_dir), config, Redactor())


def _rng(case_dir: Path) -> random.Random:
    return random.Random(load_case(case_dir)["incident"]["number"])


def _run(args: argparse.Namespace, config, judge: Judge | None) -> int:
    questions = load_questions(default_questions_path(args.skill_dir))
    judge = judge if judge is not None else TypeSafeJudge(config.typesafe_model)
    summary = run_judgments(args.case_dir, config, judge, questions, _rng(args.case_dir))
    print(args.case_dir / "judgments" / "summary.json")
    if summary.get("status") == "failed":
        print(f"judging failed ({summary['typesafe']}); every label is candidate", file=sys.stderr)
        return 1
    return 0


def _locate(args: argparse.Namespace, config, judge: Judge | None) -> int:
    questions = load_questions(default_questions_path(args.skill_dir))
    case = load_case(args.case_dir)
    map_path = default_map_path(args.skill_dir)
    service_map = load_map(map_path, config) if map_path.is_file() else ServiceMap({})
    candidates = describe_candidates(case, service_map)
    if not candidates:
        raise JudgmentError(["case.json lists no candidates to choose between"])
    result = match_resource(_session(args, config, judge), questions, incident_state(args.case_dir), candidates,
                            _rng(args.case_dir), config.typesafe_thresholds,
                            fallback=single_name_match(case))
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


def _adhoc(args: argparse.Namespace, config, judge: Judge | None) -> int:
    try:
        document = json.loads(args.question_file.read_text(encoding="utf-8"))
    except OSError as error:
        raise JudgmentError([f"{args.question_file}: {error.strerror or error}"]) from error
    except ValueError as error:
        raise JudgmentError([f"{args.question_file}: not valid JSON ({error})"]) from error
    result = run_adhoc(args.case_dir, _session(args, config, judge), config, document)
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None, judge: Judge | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handler = {"run": _run, "locate": _locate, "adhoc": _adhoc}[args.subcommand]
    try:
        try:
            config = load_config(default_config_path(args.skill_dir))
        except ConfigError:
            if args.subcommand == "run":
                retire_summary(args.case_dir)  # a broken config must not leave an old summary looking current
            raise
        args.case_dir = resolve_case_dir(args.case_dir, config)  # refuses, writing nothing, outside the cases root
        if args.subcommand == "run":
            retire_summary(args.case_dir)  # first, so that no later failure leaves an old summary looking current
        check_replay(load_case(args.case_dir))
        return handler(args, config, judge)
    except (ConfigError, MapError, CaseError) as error:
        return _fail("\n".join(error.errors), 2)
    except WindowError as error:
        return _fail(str(error), 2)
    except DraftRuleError as error:
        return _fail("\n".join(error.errors), 2)
    except (JudgmentError, QuestionError) as error:
        return _fail("\n".join(error.errors), 1)


if __name__ == "__main__":
    sys.exit(run(main))
