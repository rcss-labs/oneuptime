#!/usr/bin/env python3
"""Query an OpenSearch cluster read-only and write the answer as evidence.

The tool builds every request itself and sends it through the read policy. It never takes a raw path or body.
Exit codes: 0 done, 2 usage or config error, 5 refused by the read policy, 6 cluster error or unreachable.
"""
from __future__ import annotations

import argparse
import shlex
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from triage.config import ConfigError, default_config_path, load_config
from triage.case import CaseError, resolve_case_dir
from triage.evidence import Evidence, EvidenceExists
from triage.fixtures import FixtureError, fixture_dir, replay_banner, transport_from_env
from triage.opensearch import queries
from triage.opensearch.client import OpenSearchClient, OpenSearchError, Transport, urllib_transport
from triage.opensearch.policy import Refused
from triage.redact import Redactor
from triage.window import Window, WindowError, make_window
from triage.cli import add_exit_codes, run

SKILL_DIR = Path(__file__).resolve().parent.parent
INTERVALS = ("1m", "5m", "15m", "1h")
STATE_WINDOW = timedelta(minutes=1)
STATE_NOTE = "Reads the current state; takes no time range."


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _filter_pair(text: str) -> tuple[str, str]:
    key, separator, value = text.partition("=")
    if not separator or not key:
        raise argparse.ArgumentTypeError(f"{text!r} must look like KEY=VALUE")
    return key, value


def _add_index(parser: argparse.ArgumentParser, required: bool) -> None:
    parser.add_argument("--index", required=required, help="index name or pattern, within the cluster's allowed patterns")


def _add_window_options(parser: argparse.ArgumentParser) -> None:
    _add_index(parser, required=True)
    parser.add_argument("--start", required=True, help="window start, ISO 8601 with a timezone")
    parser.add_argument("--end", required=True, help="window end, ISO 8601 with a timezone")
    parser.add_argument("--query", help="Lucene query string")
    parser.add_argument("--filter", action="append", default=[], type=_filter_pair, metavar="KEY=VALUE",
                        help="exact match on a field; repeatable")


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cluster", required=True, metavar="NAME", help="cluster name from the config")
    common.add_argument("--case-dir", type=Path, help="write the evidence file into this case folder")
    common.add_argument("--suffix", default="", help="added to the evidence file name")
    common.add_argument("--skill-dir", type=Path, default=SKILL_DIR, help=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(prog="opensearch_query", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")

    def add(name: str, help_text: str, state_only: bool = False) -> argparse.ArgumentParser:
        description = f"{help_text}. {STATE_NOTE}" if state_only else help_text
        return sub.add_parser(name, parents=[common], help=help_text, description=description)

    add("health", "cluster status, node count, shards, pending tasks", True)
    add("nodes", "per node heap, disk, CPU and thread pool rejections", True)
    _add_index(add("indices", "indices that are not green, with counts by health", True), required=False)
    add("shards", "shards that are not STARTED", True)
    add("allocation-explain", "why a shard is unassigned", True)
    _add_index(add("mapping", "field names and types", True), required=True)
    _add_window_options(add("count", "number of matching documents"))
    histogram = add("histogram", "matching documents per time bucket")
    _add_window_options(histogram)
    histogram.add_argument("--interval", choices=INTERVALS, default="5m")
    top = add("top-messages", "most frequent messages")
    _add_window_options(top)
    top.add_argument("--field", help="message field; defaults to the cluster's message_field")
    found = add("search", "matching log lines")
    _add_window_options(found)
    found.add_argument("--size", type=_positive_int, help="number of hits; clamped to the configured limit")
    found.add_argument("--order", choices=("asc", "desc"), default="asc", help="oldest first (asc) or newest first (desc)")
    add_exit_codes(parser)
    return parser


def _fail(message: str, code: int) -> int:
    print(message, file=sys.stderr)
    return code


def _window_for(args: argparse.Namespace, max_hours: int) -> Window:
    if getattr(args, "start", None):
        return make_window(args.start, args.end, max_hours)
    now = datetime.now(timezone.utc)
    return Window(now - STATE_WINDOW, now)


def _invocation(args: argparse.Namespace) -> str:
    """The command line that reproduces this query, quoted so that it can be pasted into a shell."""
    words = ["opensearch_query.py", args.subcommand, "--cluster", args.cluster]
    for option, value in (("--index", args.index if hasattr(args, "index") else None),
                          ("--start", getattr(args, "start", None)), ("--end", getattr(args, "end", None)),
                          ("--query", getattr(args, "query", None))):
        if value:
            words += [option, value]
    for key, value in getattr(args, "filter", None) or []:
        words += ["--filter", f"{key}={value}"]
    for option, name in (("--interval", "interval"), ("--field", "field"), ("--size", "size")):
        if getattr(args, name, None):
            words += [option, str(getattr(args, name))]
    if getattr(args, "order", "asc") != "asc":
        words += ["--order", args.order]
    return shlex.join(words)


def _runner(args: argparse.Namespace) -> Callable[[queries.QueryContext], None]:
    filters = dict(getattr(args, "filter", []) or [])
    name = args.subcommand
    if name == "health":
        return queries.health
    if name == "nodes":
        return queries.nodes
    if name == "indices":
        return lambda ctx: queries.indices(ctx, args.index)
    if name == "shards":
        return queries.shards
    if name == "allocation-explain":
        return queries.allocation_explain
    if name == "mapping":
        return lambda ctx: queries.mapping(ctx, args.index)
    if name == "count":
        return lambda ctx: queries.count(ctx, args.index, args.query, filters)
    if name == "histogram":
        return lambda ctx: queries.histogram(ctx, args.index, args.interval, args.query, filters)
    if name == "top-messages":
        return lambda ctx: queries.top_messages(ctx, args.index, args.query, filters, args.field)
    return lambda ctx: queries.search(ctx, args.index, args.query, filters, args.size, args.order)


def main(argv: list[str] | None = None, transport: Transport | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        replay = fixture_dir()
        if replay and transport is None:
            print(replay_banner(replay), file=sys.stderr)
        transport = transport or transport_from_env()
    except FixtureError as error:
        print(error, file=sys.stderr)
        return 2
    try:
        config = load_config(default_config_path(args.skill_dir))
    except ConfigError as error:
        return _fail("; ".join(error.errors), 2)
    cluster = config.opensearch_clusters.get(args.cluster)
    if cluster is None:
        return _fail(f"unknown cluster {args.cluster}; configured: {', '.join(config.opensearch_clusters) or 'none'}", 2)
    try:
        window = _window_for(args, config.limits["max_window_hours"])
    except WindowError as error:
        return _fail(str(error), 2)
    evidence = Evidence("opensearch", cluster.account, cluster.name, window, replay=replay is not None)
    if args.case_dir:
        try:
            args.case_dir = resolve_case_dir(args.case_dir, config)
            evidence.ensure_new(args.case_dir, args.suffix)
        except CaseError as error:
            return _fail("; ".join(error.errors), 2)
        except EvidenceExists as error:
            return _fail(str(error), 2)
    client = OpenSearchClient(cluster, config.limits, transport=transport or urllib_transport)
    ctx = queries.QueryContext(client, cluster, config.limits, window, evidence, _invocation(args))
    try:
        _runner(args)(ctx)
    except Refused as refusal:
        return _fail(f"refused by the read policy: {refusal}", 5)
    except OpenSearchError as error:
        return _fail(f"OpenSearch error: {Redactor().text(str(error))}", 6)
    except (KeyError, TypeError, AttributeError, ValueError, IndexError, OverflowError, OSError) as error:
        return _fail(f"unexpected response from the cluster ({type(error).__name__})", 6)
    if args.case_dir:
        try:
            path = evidence.write_new(args.case_dir, args.suffix)
        except EvidenceExists as error:
            return _fail(str(error), 2)
        print(f"{path} facts={len(evidence.facts)} errors={len(evidence.errors)} truncated={evidence.truncated}")
    else:
        print(evidence.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(run(main))
