"""RDS collector: instance or cluster state, events, error log lines, metrics, Performance Insights.

Log lines are masked before they enter a fact: quoted spans, row values, user names in a prefix and every run of
three or more digits are hidden. A quoted span is kept only when it is identifier-shaped and directly follows a word
such as relation, constraint, or column. Known limit: free text that an application raised inside the database
(a custom error message with a name in it, unquoted) is shown as written apart from numbers.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from triage.collectors import Collector
from triage.collectors.common import newest_in_window, parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_EVENTS = 30
MAX_LOG_LINES = 20
MAX_LOG_FILES = "10"
MAX_EVENT_ITEMS = "50"
MAX_MEMBERS = 6
INSTANCE_NOT_FOUND = ("DBInstanceNotFound", "DBInstanceNotFoundFault")
CLUSTER_NOT_FOUND = ("DBClusterNotFound", "DBClusterNotFoundFault")
LOG_LINES_TO_READ = "200"
TOP_WAIT_EVENTS = 5
PROBLEM_LINE = re.compile(r"ERROR|FATAL|PANIC|(?i:deadlock)|\bError:")
MASK = "<value>"
MAX_LOG_FILES_READ = 6
MAX_LISTING_PAGES = 5
LEADING_TIMESTAMP = re.compile(r"\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?")
FILE_HOUR = re.compile(r"(\d{4}-\d{2}-\d{2})[-.](\d{2})(?!\d)")
FILE_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")
EARLIEST = datetime.min.replace(tzinfo=timezone.utc)
DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
PHONE_SHAPE = re.compile(r"\+?\d+(?:[\s._()-]+\d{2,}){2,}")
LONG_DIGITS = re.compile(r"\d{3,}")
NUMBER_MASK = "<n>"
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.$]{0,62}")
IDENTIFIER_WORDS = (
    "relation", "table", "column", "constraint", "index", "schema", "database", "function", "type", "sequence",
    "view", "trigger", "key", "extension", "parameter",
)
PRECEDING_WORD = re.compile(r"([A-Za-z]+)\s*$")
ACCOUNT_VALUE = re.compile(r"\b(user|role|usename)=[^\s,)]+")
ENGINE_CODE = re.compile(
    r"MY-\d{6}|SQLSTATE[ :=\[]*\w{5}|ERROR \d{4} \(\w{5}\)|Error: \d+, Severity: \d+, State: \d+|ORA-\d{5}"
)
LOG_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
METRICS = (
    ("CPUUtilization", "Average"), ("DatabaseConnections", "Maximum"), ("FreeStorageSpace", "Minimum"),
    ("FreeableMemory", "Minimum"), ("ReplicaLag", "Maximum"), ("ReadLatency", "Average"), ("WriteLatency", "Average"),
)


def _describe_instance(ctx: CollectContext, name: str) -> dict | None:
    reply = ctx.aws("rds", "describe-db-instances", ["--db-instance-identifier", name], not_found=INSTANCE_NOT_FOUND)
    instances = (reply or {}).get("DBInstances", [])
    return instances[0] if instances else None


def _pending_text(instance: dict) -> str:
    pending = instance.get("PendingModifiedValues") or {}
    if not pending:
        return "no pending modified values"
    return "pending modified values " + ", ".join(f"{key}={value}" for key, value in sorted(pending.items()))


def _parameter_groups_text(instance: dict) -> str:
    groups = instance.get("DBParameterGroups", [])
    return ", ".join(f"{g.get('DBParameterGroupName')} {g.get('ParameterApplyStatus')}" for g in groups) or "none"


def _add_instance_state(ctx: CollectContext, instance: dict) -> None:
    name = instance.get("DBInstanceIdentifier")
    ctx.evidence.add(
        kind=CURRENT, resource=f"db/{name}", command=ctx.last_command,
        summary=(
            f"Instance {name} is {instance.get('DBInstanceStatus')}: class {instance.get('DBInstanceClass')}, "
            f"engine {instance.get('Engine')} {instance.get('EngineVersion')}, "
            f"multi-AZ {'yes' if instance.get('MultiAZ') else 'no'}, storage {instance.get('AllocatedStorage')} GiB, "
            f"{_pending_text(instance)}, parameter group {_parameter_groups_text(instance)}"
        ),
        data={key: instance.get(key) for key in ("DBInstanceStatus", "PendingModifiedValues")},
    )


def _add_events(ctx: CollectContext, name: str, source_type: str, noun: str) -> None:
    reply = ctx.aws("rds", "describe-events", [
        "--source-identifier", name, "--source-type", source_type,
        "--start-time", format_time(ctx.window.start), "--end-time", format_time(ctx.window.end),
        "--max-items", MAX_EVENT_ITEMS,
    ])
    for event in newest_in_window(ctx.window, (reply or {}).get("Events", []), lambda e: e.get("Date"), MAX_EVENTS):
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"db/{name}", time=event.get("Date"), command=ctx.last_command,
            summary=f"{noun} event on {name}: {event.get('Message')}",
        )


def _quoted_end(line: str, start: int) -> tuple[int | None, bool]:
    """Index just past the quoted span that opens at line[start] (None when never closed), and whether a backslash escape was used."""
    quote, index, escaped = line[start], start + 1, False
    while index < len(line):
        if line[index] == "\\" and quote != "`":
            escaped = True
            index += 2
        elif line[index] == quote:
            if line[index + 1:index + 2] == quote:
                index += 2
            else:
                return index + 1, escaped
        else:
            index += 1
    return None, escaped


def _keeps_identifier(before: str, span: str) -> bool:
    """True for an identifier-shaped quoted name that directly follows a word like relation or constraint."""
    word = PRECEDING_WORD.search(before)
    return bool(word) and word.group(1).lower() in IDENTIFIER_WORDS and bool(IDENTIFIER.fullmatch(span[1:-1]))


def _mask_quoted(line: str) -> str:
    out, index = [], 0
    while index < len(line):
        char = line[index]
        if char in "'\"`":
            end, escaped = _quoted_end(line, index)
            if end is not None and not escaped and _keeps_identifier("".join(out), line[index:end]):
                out.append(line[index:end])
                index = end
                continue
            if out and out[-1] in "Ee" and (len(out) == 1 or not out[-2].isalnum()) and char == "'":
                out.pop()
            out.append(MASK)
            if end is None or escaped:
                break
            index = end
            continue
        tag = DOLLAR_TAG.match(line, index) if char == "$" else None
        if tag:
            close = line.find(tag.group(0), tag.end())
            out.append(MASK)
            if close < 0:
                break
            index = close + len(tag.group(0))
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _balanced_end(text: str, start: int) -> int:
    """Index just past the parenthesis that closes the one at text[start]; len(text) when it never closes."""
    depth = 0
    for index in range(start, len(text)):
        depth += {"(": 1, ")": -1}.get(text[index], 0)
        if depth == 0:
            return index + 1
    return len(text)


def _mask_last_group(text: str, start: int) -> str:
    """Replace what lies between the first ( at or after start and the last ) of the text."""
    first, last = text.find("(", start), text.rfind(")")
    return text if first < 0 or last <= first else text[:first + 1] + MASK + text[last:]


def _mask_row_values(line: str) -> str:
    start = line.find("DETAIL:")
    if start >= 0:
        position = start + len("DETAIL:")
        key = re.compile(r"\s*Key \(").match(line, position)
        line = _mask_last_group(line, _balanced_end(line, key.end() - 1) if key else position)
    equals = line.find("=(")
    return _mask_last_group(line, equals + 1) if equals >= 0 else line


def _mask_numbers(text: str) -> str:
    """Mask phone-shaped and long digit runs, keeping engine error codes as written."""
    pieces, position = [], 0
    for code in ENGINE_CODE.finditer(text):
        pieces.append(LONG_DIGITS.sub(NUMBER_MASK, PHONE_SHAPE.sub(NUMBER_MASK, text[position:code.start()])))
        pieces.append(code.group(0))
        position = code.end()
    pieces.append(LONG_DIGITS.sub(NUMBER_MASK, PHONE_SHAPE.sub(NUMBER_MASK, text[position:])))
    return "".join(pieces)


def _mask_values(line: str) -> str:
    """Hide data values in a log line, keeping the error text, identifiers after known words, and the leading timestamp."""
    stamp = LEADING_TIMESTAMP.match(line)
    head, rest = (line[:stamp.end()], line[stamp.end():]) if stamp else ("", line)
    rest = ACCOUNT_VALUE.sub(lambda match: f"{match.group(1)}={MASK}", rest)
    rest = _mask_row_values(_mask_quoted(rest))
    return head + _mask_numbers(rest)


def _error_files(files: list[dict]) -> list[dict]:
    return [f for f in files if "error" in f.get("LogFileName", "").lower()]


def _file_span(file: dict) -> tuple[datetime, datetime]:
    """When a log file may hold lines: from the hour or date in its name (else unknown) to its last write."""
    name = file.get("LogFileName", "")
    written = datetime.fromtimestamp(file.get("LastWritten", 0) / 1000, tz=timezone.utc)
    hour, day = FILE_HOUR.search(name), FILE_DATE.search(name)
    if hour and parse_iso(f"{hour.group(1)}T{hour.group(2)}:00:00Z"):
        begin = parse_iso(f"{hour.group(1)}T{hour.group(2)}:00:00Z")
        return begin, max(begin + timedelta(hours=1), written)
    if day and parse_iso(f"{day.group(1)}T00:00:00Z"):
        begin = parse_iso(f"{day.group(1)}T00:00:00Z")
        return begin, max(begin + timedelta(days=1), written)
    return EARLIEST, written


def _overlapping_files(files: list[dict], window) -> list[dict]:
    """Files that may hold lines inside the window (its end is exclusive), oldest first."""
    spans = {f["LogFileName"]: _file_span(f) for f in files}
    inside = [f for f in files if spans[f["LogFileName"]][0] < window.end and spans[f["LogFileName"]][1] > window.start]
    return sorted(inside, key=lambda f: (spans[f["LogFileName"]][0], f.get("LastWritten", 0)))


def _choose_files(overlapping: list[dict], window) -> list[dict]:
    """At most MAX_LOG_FILES_READ files: the one covering the incident start, the one before it, then the newest."""
    if not overlapping:
        return []
    started = [f for f in overlapping if _file_span(f)[0] <= window.start]
    latest_begin = max((_file_span(f)[0] for f in started), default=None)
    cover = min((f for f in started if _file_span(f)[0] == latest_begin), key=lambda f: f.get("LastWritten", 0)) if started else overlapping[0]
    chosen = [cover]
    position = overlapping.index(cover)
    if position > 0:
        chosen.append(overlapping[position - 1])
    newest = sorted((f for f in overlapping if f not in chosen), key=lambda f: f.get("LastWritten", 0), reverse=True)
    chosen += newest[:MAX_LOG_FILES_READ - len(chosen)]
    return sorted(chosen, key=lambda f: overlapping.index(f))


def _line_time(line: str) -> datetime | None:
    match = LOG_TIMESTAMP.match(line.lstrip())
    return parse_iso(f"{match.group(1)}T{match.group(2)}Z") if match else None


def _list_error_files(ctx: CollectContext, name: str) -> tuple[list[dict], bool, int] | None:
    """Every error log file written since the window start, whether the listing was cut, and how many files were listed."""
    files: list[dict] = []
    token = None
    for page in range(MAX_LISTING_PAGES):
        args = [
            "--db-instance-identifier", name, "--filename-contains", "error",
            "--file-last-written", str(ctx.window.epoch_millis()[0]), "--max-items", MAX_LOG_FILES,
        ]
        if token:
            args += ["--starting-token", token]
        listing = ctx.aws("rds", "describe-db-log-files", args)
        if listing is None:
            return None if page == 0 else (_error_files(files), True, len(files))
        files += listing.get("DescribeDBLogFiles", [])
        token = listing.get("NextToken")
        if not token:
            return _error_files(files), False, len(files)
    return _error_files(files), True, len(files)


def _add_log_lines(ctx: CollectContext, name: str) -> None:
    listed = _list_error_files(ctx, name)
    if listed is None:
        return
    all_files, cut, count = listed
    overlapping = _overlapping_files(all_files, ctx.window)
    files = _choose_files(overlapping, ctx.window)
    cut_note = f", but the listing was cut after {MAX_LISTING_PAGES} pages, so later files could not be checked" if cut else ""
    if not files:
        ctx.evidence.add(
            kind=DERIVED, resource=f"db/{name}", command=ctx.last_command,
            summary=f"No error log file overlapping the window was found among the {count} files listed{cut_note}",
        )
        return
    if cut:
        ctx.evidence.add(
            kind=DERIVED, resource=f"db/{name}", command=ctx.last_command,
            summary=f"The listing was cut after {MAX_LISTING_PAGES} pages, so later error log files could not be checked",
        )
    skipped = [f["LogFileName"] for f in overlapping if f not in files]
    if skipped:
        ctx.evidence.add(
            kind=DERIVED, resource=f"db/{name}", command=ctx.last_command,
            summary=f"Error log files overlapping the window that were not read: {', '.join(skipped)}",
        )
    inside, read_names, command = [], [], ctx.last_command
    for file in files:
        file_name = file.get("LogFileName", "")
        portion = ctx.aws("rds", "download-db-log-file-portion", [
            "--db-instance-identifier", name, "--log-file-name", file_name, "--number-of-lines", LOG_LINES_TO_READ,
            "--no-paginate",
        ])
        if portion is None:
            continue
        command = ctx.last_command
        read_names.append(file_name)
        previous_kept: tuple[datetime, str, str] | None = None
        for line in (portion.get("LogFileData") or "").splitlines():
            moment = _line_time(line)
            if PROBLEM_LINE.search(line) and moment is not None and ctx.window.start <= moment < ctx.window.end:
                previous_kept = (moment, file_name, line)
                inside.append(previous_kept)
            elif previous_kept is not None and "DETAIL:" in line:
                inside.append((moment or previous_kept[0], file_name, line))
                previous_kept = None
            else:
                previous_kept = None
    for moment, file_name, line in inside[-MAX_LOG_LINES:]:
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"db/{name}", time=moment, command=command,
            summary=f"Database log line in {file_name} (last {LOG_LINES_TO_READ} lines of the file read)", excerpt=_mask_values(line.strip()),
        )
    if not inside and read_names:
        ctx.evidence.add(
            kind=DERIVED, resource=f"db/{name}", command=command,
            summary=(
                f"No error line inside the window was found in the last {LOG_LINES_TO_READ} lines read from "
                f"{', '.join(read_names)}; earlier lines of those files were not read"
            ),
        )


def _add_metrics(ctx: CollectContext, name: str) -> None:
    dimensions = {"DBInstanceIdentifier": name}
    add_metric_facts(ctx, f"db/{name}", [MetricSpec(metric, "AWS/RDS", metric, dimensions, stat) for metric, stat in METRICS])


def _add_wait_events(ctx: CollectContext, name: str, resource_id: str) -> None:
    queries = [{"Metric": "db.load.avg", "GroupBy": {"Group": "db.wait_event", "Limit": TOP_WAIT_EVENTS}}]
    reply = ctx.aws("pi", "get-resource-metrics", [
        "--service-type", "RDS", "--identifier", resource_id, "--metric-queries", json.dumps(queries),
        "--start-time", format_time(ctx.window.start), "--end-time", format_time(ctx.window.end),
        "--period-in-seconds", "300",
    ])
    if reply is None:
        return
    loads = []
    for series in reply.get("MetricList", []):
        dimensions = (series.get("Key") or {}).get("Dimensions") or {}
        values = [point["Value"] for point in series.get("DataPoints", []) if point.get("Value") is not None]
        if dimensions and values:
            label = dimensions.get("db.wait_event.name") or next(iter(dimensions.values()))
            loads.append((sum(values) / len(values), label))
    loads.sort(reverse=True)
    text = ", ".join(f"{label} {load:.2f}" for load, label in loads[:TOP_WAIT_EVENTS]) or "no wait event data was returned"
    ctx.evidence.add(
        kind=DERIVED, resource=f"db/{name}", command=ctx.last_command,
        summary=f"Top wait events by average database load in the window: {text}",
    )


def _collect_instance(ctx: CollectContext, instance: dict) -> None:
    name = instance.get("DBInstanceIdentifier", "")
    _add_instance_state(ctx, instance)
    _add_events(ctx, name, "db-instance", "Instance")
    _add_log_lines(ctx, name)
    _add_metrics(ctx, name)
    if instance.get("PerformanceInsightsEnabled") and instance.get("DbiResourceId"):
        _add_wait_events(ctx, name, instance["DbiResourceId"])


def _collect_cluster(ctx: CollectContext, name: str) -> None:
    reply = ctx.aws("rds", "describe-db-clusters", ["--db-cluster-identifier", name], not_found=CLUSTER_NOT_FOUND)
    clusters = (reply or {}).get("DBClusters", [])
    if not clusters:
        if reply is not None or was_not_found(ctx, CLUSTER_NOT_FOUND):
            ctx.evidence.add(
                kind=CURRENT, resource=f"db/{name}", command=ctx.last_command,
                summary=f"RDS instance or cluster {name} was not found",
            )
        return
    cluster = clusters[0]
    members = cluster.get("DBClusterMembers", [])
    roles = ", ".join(
        f"{m.get('DBInstanceIdentifier')} ({'writer' if m.get('IsClusterWriter') else 'reader'})" for m in members
    )
    ctx.evidence.add(
        kind=CURRENT, resource=f"db/{name}", command=ctx.last_command,
        summary=(
            f"Cluster {name} is {cluster.get('Status')}: engine {cluster.get('Engine')} {cluster.get('EngineVersion')}, "
            f"multi-AZ {'yes' if cluster.get('MultiAZ') else 'no'}, members {roles or 'none'}"
        ),
    )
    _add_events(ctx, name, "db-cluster", "Cluster")
    if len(members) > MAX_MEMBERS:
        ctx.evidence.add(
            kind=DERIVED, resource=f"db/{name}",
            summary=f"The cluster has {len(members)} members; only the first {MAX_MEMBERS} were described",
        )
    for member in members[:MAX_MEMBERS]:
        instance = _describe_instance(ctx, member.get("DBInstanceIdentifier", ""))
        if instance is not None:
            _collect_instance(ctx, instance)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["db"]
    instance = _describe_instance(ctx, name)
    if instance is not None:
        _collect_instance(ctx, instance)
    elif was_not_found(ctx, INSTANCE_NOT_FOUND):
        _collect_cluster(ctx, name)


COLLECTOR = Collector(
    name="rds",
    description="RDS instance or cluster state, events, error log lines, load and storage metrics, Performance Insights wait events",
    required=("db",),
    optional=(),
    run=collect,
)
