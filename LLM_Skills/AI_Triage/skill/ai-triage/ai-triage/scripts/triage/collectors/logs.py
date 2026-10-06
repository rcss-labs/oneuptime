"""CloudWatch Logs collector: when matching log lines started, which messages repeat, and the first lines."""
from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, Sequence

from triage.collectors import Collector
from triage.collectors.common import parse_iso
from triage.context import CollectContext
from triage.evidence import DERIVED, INCIDENT_TIME
from triage.window import format_time

DEFAULT_PATTERN = "(?i)(error|exception|fatal|panic|timed? ?out|refused|denied|oom|killed)"
POLL_SECONDS = 1
QUERY_FAILED = "QueryFailed"
QUERY_TIMEOUT = "QueryTimeout"
_FAILED_STATUSES = ("Failed", "Cancelled", "Timeout")
MAX_BUCKET_FACTS = 60

BUCKET_QUERY = "| stats count(*) as matches by bin(5m)"
PATTERN_QUERY = "| pattern @message | sort @sampleCount desc | limit 15"
LINES_QUERY = "| fields @timestamp, @logStream, @message | sort @timestamp asc | limit 20"


def run_query(
    ctx: CollectContext,
    log_groups: Sequence[str],
    query: str,
    *,
    sleep: Callable[[float], None] = time.sleep,
    max_wait_seconds: int = 60,
) -> list[dict[str, str]] | None:
    """Run a Logs Insights query over the window; None when it fails or does not finish in time."""
    start, end = ctx.window.epoch_seconds()
    started = ctx.aws(
        "logs", "start-query",
        ["--log-group-names", *log_groups, "--start-time", str(start), "--end-time", str(end), "--query-string", query],
    )
    query_id = (started or {}).get("queryId")
    if not query_id:
        return None
    waited = 0
    while True:
        reply = ctx.aws("logs", "get-query-results", ["--query-id", query_id])
        if reply is None:
            _stop(ctx, query_id)
            return None
        status = reply.get("status")
        if status == "Complete":
            return [_row_to_dict(row) for row in reply.get("results", [])]
        if status in _FAILED_STATUSES:
            ctx.evidence.add_error(ctx.last_command, QUERY_FAILED, f"the Logs Insights query ended with status {status}")
            return None
        if waited >= max_wait_seconds:
            _stop(ctx, query_id)
            ctx.evidence.add_error(
                ctx.last_command, QUERY_TIMEOUT, f"the Logs Insights query did not finish within {max_wait_seconds} seconds"
            )
            return None
        sleep(POLL_SECONDS)
        waited += POLL_SECONDS


def _stop(ctx: CollectContext, query_id: str) -> None:
    ctx.aws("logs", "stop-query", ["--query-id", query_id])


def _row_to_dict(row: list[dict]) -> dict[str, str]:
    return {cell.get("field", ""): cell.get("value", "") for cell in row if cell.get("field") != "@ptr"}


def _insights_time(text: str | None) -> datetime | None:
    """Logs Insights times look like "2026-10-04 10:42:10.123" and are UTC."""
    if not text:
        return None
    return parse_iso(text.replace(" ", "T", 1) + "Z")


def _number(text: str | None) -> int:
    try:
        return int(float(text or 0))
    except ValueError:
        return 0


def _escape_slashes(pattern: str) -> str | None:
    """Escape each unescaped forward slash; None when the pattern ends in a lone backslash."""
    out, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 == len(pattern):
                return None
            out.append(pattern[index: index + 2])
            index += 2
            continue
        out.append("\\/" if char == "/" else char)
        index += 1
    return "".join(out)


def _query_text(escaped_pattern: str, tail: str) -> str:
    return f"filter @message like /{escaped_pattern}/ {tail}"


def _split_groups(targets: dict[str, str]) -> list[str]:
    return [name.strip() for name in targets["log_groups"].split(",") if name.strip()]


def _add_buckets(ctx: CollectContext, resource: str, rows: list[dict[str, str]]) -> bool:
    buckets = sorted(
        ((moment, _number(row.get("matches"))) for row in rows if (moment := _insights_time(row.get("bin(5m)")))),
        key=lambda pair: pair[0],
    )
    shown = sorted(sorted(buckets, key=lambda pair: -pair[1])[:MAX_BUCKET_FACTS], key=lambda pair: pair[0])
    left_out = len(buckets) - len(shown)
    for moment, count in shown:
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=moment, command=ctx.last_command,
            summary=f"{count} matching log lines in the 5 minutes starting {format_time(moment)}",
            data={"matches": count},
        )
    non_empty = [pair for pair in buckets if pair[1] > 0]
    if not non_empty:
        return False
    peak = max(non_empty, key=lambda pair: pair[1])
    first = non_empty[0]
    ctx.evidence.add(
        kind=DERIVED, resource=resource, command=ctx.last_command,
        summary=(
            f"Peak bucket starts {format_time(peak[0])} with {peak[1]} matching log lines; "
            f"the first bucket with matches starts {format_time(first[0])} with {first[1]}"
            + (f"; {left_out} buckets with the lowest counts were left out" if left_out else "")
        ),
    )
    return True


def _add_patterns(ctx: CollectContext, resource: str, rows: list[dict[str, str]]) -> None:
    for row in rows:
        ctx.evidence.add(
            kind=DERIVED, resource=resource, command=ctx.last_command,
            summary=f"Message pattern seen {_number(row.get('@sampleCount'))} times",
            excerpt=row.get("@pattern", ""),
        )


def _add_lines(ctx: CollectContext, resource: str, rows: list[dict[str, str]]) -> None:
    for row in rows:
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=_insights_time(row.get("@timestamp")), command=ctx.last_command,
            summary=f"Matching log line in stream {row.get('@logStream', 'unknown')}",
            excerpt=row.get("@message", ""),
        )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    pattern = targets.get("pattern") or DEFAULT_PATTERN
    groups = _split_groups(targets)
    limit = ctx.config.limits["logs_insights_max_log_groups"]
    escaped = _escape_slashes(pattern)
    if escaped is None:
        ctx.evidence.add(
            kind=DERIVED, resource="log-groups/" + ",".join(groups[:limit]),
            summary="The pattern is not usable: it ends in a single backslash, so no query was sent",
        )
        return
    used, skipped = groups[:limit], groups[limit:]
    resource = "log-groups/" + ",".join(used)
    if skipped:
        ctx.evidence.add(
            kind=DERIVED, resource=resource,
            summary=(
                f"{len(groups)} log groups were given but the limit is {limit}; "
                f"queried the first {limit}, skipped: {', '.join(skipped)}"
            ),
        )
    buckets = run_query(ctx, used, _query_text(escaped, BUCKET_QUERY))
    if buckets is not None:
        if not _add_buckets(ctx, resource, buckets):
            ctx.evidence.add(
                kind=DERIVED, resource=resource, command=ctx.last_command,
                summary="No log lines matched the pattern in the window",
            )
            return
    patterns = run_query(ctx, used, _query_text(escaped, PATTERN_QUERY))
    if patterns is not None:
        _add_patterns(ctx, resource, patterns)
    lines = run_query(ctx, used, _query_text(escaped, LINES_QUERY))
    if lines is not None:
        _add_lines(ctx, resource, lines)


COLLECTOR = Collector(
    name="logs",
    description="CloudWatch Logs Insights: when matching log lines started and peaked, repeated messages, first lines",
    required=("log_groups",),
    optional=("pattern",),
    run=collect,
)
