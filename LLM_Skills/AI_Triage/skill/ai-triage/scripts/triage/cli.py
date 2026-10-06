"""One wrapper around every command's main: one table of exit codes, and one line per error, never a traceback.

Exit codes (every command; each command's --help ends with this table):
  0  done
  1  a check failed or found a problem (the audit, the report, judging, nothing discovered, a planned
     collector, a map or config that validate_map or preflight checks), or an unexpected error (one line;
     set AI_TRIAGE_DEBUG=1 to see the traceback)
  2  usage, config, service map, case folder, or file error (including an evidence file that exists)
  3  a sign-in has expired: run aws sso login --profile <profile>
  4  unknown collector or bad target key (collect)
  5  refused by the OpenSearch read policy (opensearch_query)
  6  OpenSearch cluster error or unreachable (opensearch_query)
"""
from __future__ import annotations

import argparse
import os
import sys
import traceback
from pathlib import Path
from typing import Callable

from triage.case import CaseError
from triage.config import ConfigError
from triage.service_map import MapError

EXIT_CODES = __doc__.split("\n\n", 1)[1].replace(" (every command; each command's --help ends with this table)", "")
DEBUG_ENV = "AI_TRIAGE_DEBUG"
USAGE_OR_FILE = 2
UNEXPECTED = 1


class UsageError(Exception):
    """A usage, config or case folder problem that a command reports in one line; run prints it and exits 2."""


def add_exit_codes(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """End the parser's --help with the exit-code table."""
    parser.epilog = EXIT_CODES
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    return parser


def _say(message: str) -> None:
    print(message, file=sys.stderr)


def run(main: Callable[..., int], argv: list[str] | None = None, *, name: str | None = None) -> int:
    """Call main and turn an exception into an exit code with one line on stderr.

    Argparse's own exits (usage errors, --help) pass through unchanged.
    """
    script = name or Path(sys.argv[0]).stem or "script"
    try:
        return main(argv) if argv is not None else main()
    except UsageError as error:
        _say(str(error))
        return USAGE_OR_FILE
    except (ConfigError, CaseError, MapError) as error:
        for line in error.errors:
            _say(line)
        return USAGE_OR_FILE
    except OSError as error:
        reason = error.strerror or str(error)
        _say(f"{error.filename}: {reason}" if error.filename else f"{script}: {reason}")
        return USAGE_OR_FILE
    except KeyboardInterrupt:
        _say(f"{script}: interrupted")
        return UNEXPECTED
    except Exception as error:  # noqa: BLE001 - the one place that turns any failure into one line
        if os.environ.get(DEBUG_ENV) == "1":
            traceback.print_exc()
        _say(f"{script}: unexpected {type(error).__name__}; run again with {DEBUG_ENV}=1 to see where")
        return UNEXPECTED
