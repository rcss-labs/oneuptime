"""Check analyst findings against the evidence they cite.

Exit codes: 0 checked, 2 usage error or missing case folder.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from triage.case import REPLAY_NOTICE, CaseError, check_replay, resolve_case_dir
from triage.config import ConfigError, default_config_path, load_config
from triage.findings import check_findings
from triage.cli import add_exit_codes, run
SKILL_DIR = Path(__file__).resolve().parent.parent

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='findings', description=__doc__.split('\n\n')[0])
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check', help='check every findings/*.json and write findings/checked.json')
    check.add_argument('--case-dir', type=Path, required=True, help='the case folder')
    parser.add_argument('--skill-dir', type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)
    add_exit_codes(parser)
    return parser

def main(argv: list[str] | None=None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        case_dir = resolve_case_dir(args.case_dir, load_config(default_config_path(args.skill_dir)))
        case = json.loads((case_dir / 'case.json').read_text(encoding='utf-8'))
        check_replay(case if isinstance(case, dict) else {})
    except (ConfigError, CaseError) as error:
        print('; '.join(error.errors), file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f'cannot read case.json in {args.case_dir}: {error}', file=sys.stderr)
        return 2
    if isinstance(case, dict) and case.get('replay'):
        print(REPLAY_NOTICE)
    result = check_findings(case_dir)
    print(f"valid={len(result['valid'])} rejected={len(result['rejected'])} unreadable={len(result['unreadable'])} requests={len(result['requests'])}")
    return 0
if __name__ == '__main__':
    sys.exit(run(main))