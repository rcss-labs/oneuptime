"""RDS collector: instance or cluster state, events, error log lines, metrics, Performance Insights.

Log lines are masked before they enter a fact, without trying to match quotes. The prefix keeps its timestamp, pid
and db/app/client values, and never shows a user (user=, role=, usename=, the role in user@database, MySQL
'user'@'host'). In the message, an apostrophe in an English contraction is part of the word, and an identifier-shaped
name quoted directly after a word such as relation, constraint or key is kept; from any other quote character
(ASCII, any Unicode initial or final quote, low quotes, CJK corner brackets, full-width quotes, acute and grave
accents) or dollar-quote tag, to the end of the line everything is replaced by <rest masked>, followed only by the
strict engine codes found in that tail. Row values on DETAIL lines are masked, and every run of two or more digits
becomes <n> apart from the timestamp, kept names, engine codes, and a few fixed contexts (error number, errno, at
character, line, a type length such as varchar(20)).
Known limit: unquoted free text that an application raised inside the database (a custom error message with a name
in it) is shown as written apart from numbers.
"""
from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone

from triage.collectors import Collector
from triage.collectors.common import newest_in_window, parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_EVENTS = 30
LINES_BEFORE_ONSET = 5
LINES_FROM_ONSET = 15
NEWEST_LINES = 20
MAX_LINE_PART = 240
DEFAULT_LEAD = timedelta(minutes=60)
MAX_LOG_FILES = "10"
MAX_EVENT_ITEMS = "50"
MAX_MEMBERS = 6
INSTANCE_NOT_FOUND = ("DBInstanceNotFound", "DBInstanceNotFoundFault")
CLUSTER_NOT_FOUND = ("DBClusterNotFound", "DBClusterNotFoundFault")
LOG_LINES_TO_READ = "1000"
TOP_WAIT_EVENTS = 5
PROBLEM_LINE = re.compile(r"ERROR|FATAL|PANIC|(?i:deadlock)|\bError:")
SQL_SERVER_ERROR = re.compile(r"\bError: \d+, Severity:")
MASK = "<value>"
MAX_LOG_FILES_READ = 6
MAX_LISTING_PAGES = 5
LEADING_TIMESTAMP = re.compile(r"\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
FILE_MINUTE = re.compile(r"(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(?!\d)")
FILE_HOUR = re.compile(r"(\d{4}-\d{2}-\d{2})[-.](\d{2})(?!\d)")
FILE_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")
EARLIEST = datetime.min.replace(tzinfo=timezone.utc)
REST_MASK = "<rest masked>"
ASCII_QUOTES = "'\"`"
# Quote characters beyond the Unicode initial and final quotes (Pi, Pf): low quotes, CJK corner brackets, full-width
# quotation mark and apostrophe, and the acute and grave accents people type as quotes.
OTHER_QUOTES = frozenset("\u201a\u201e\u2e42\u300c\u300d\u300e\u300f\uff02\uff07\u00b4\u02ca\u02cb\uff40")
DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
CONTRACTION_END = re.compile(r"(t|s|re|ve|ll|d|m)(?![A-Za-z0-9_'\"`$\\])")
NOT_STEMS = frozenset((
    "can", "don", "doesn", "didn", "isn", "wasn", "weren", "aren", "won", "couldn", "wouldn", "shouldn", "hasn",
    "haven", "hadn", "mustn", "needn",
))
PRONOUN_STEMS = frozenset(("i", "you", "we", "they", "he", "she", "it", "that", "there", "what", "who", "let", "here"))
DIGIT_RUN = re.compile(r"\d{2,}")
NUMBER_MASK = "<n>"
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.$]{0,62}")
IDENTIFIER_WORDS = frozenset((
    "relation", "table", "column", "constraint", "index", "schema", "database", "function", "type", "sequence",
    "view", "trigger", "key", "extension", "parameter",
))
WORD_BEFORE = re.compile(r"([A-Za-z0-9_.$]*)\s*$")
ACCOUNT_KEY = re.compile(r"\b(user|role|usename)=")
ACCOUNT_VALUE_END = re.compile(r"[,;)]|\s+[A-Za-z_]+=")
KEPT_PREFIX_VALUE = re.compile(r"\b(?:db|app|client)=[^,\s]*|\[\d+\]|\(\d+\)|\bspid\d+s?\b")
PREFIX_USER_AT = re.compile(r"(?<![^\s:\[\]()=,])[^\s:\[\]()@=,<>]+@")
MYSQL_ACCOUNT = re.compile(r"'[^'\s]*'@'[^'\s]*'")
# The fixed RDS PostgreSQL prefix %t:%r:%u@%d:[%p]: (after the timestamp): zone, client host(port), role, database, pid.
RDS_POSTGRES_PREFIX = re.compile(
    r"(?P<head>\s*[A-Z]{0,5}:(?:[^()\s]*\(\d+\)|[^:\s]*):)(?P<user>.*?)(?P<tail>@[^@\s]*?:\[\d+\]:)"
)
SQL_SERVER_PREFIX = re.compile(r"\s+(?:spid\d+s?|[A-Z][a-z]+)\s{2,}")
MESSAGE_MARKER = re.compile(
    r"\b(?:LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG\d?|DETAIL|HINT|CONTEXT|STATEMENT|QUERY|LOCATION):"
    r"|\[(?:ERROR|Warning|Note|System|Information)\]|\bError:|\bERROR \d"
)
TAIL_ENGINE_CODE = re.compile(
    r"(?<![A-Za-z0-9])(?:MY-\d{6}(?!\d)|SQLSTATE[ :=\[]*[0-9A-Z]{5}(?![0-9A-Za-z])|ORA-\d{5}(?!\d))"
    r"|Error: \d{1,6}, Severity: \d{1,6}, State: \d{1,6}(?!\d)"
)
TYPE_WORDS = r"character varying|bit varying|varchar|nvarchar|varbinary|nchar|char|character|numeric|decimal|binary|bit|float|timestamp|time"
KEPT_NUMBER = re.compile(
    r"(?i:\berror number \d{1,4}(?!\d)|\berrno:? \d{1,4}(?!\d)|\bat character \d{1,6}(?!\d)|\bline \d{1,6}(?!\d)"
    rf"|\b(?:{TYPE_WORDS})\(\d{{1,4}}(?:,\s*\d{{1,4}})?\))"
)
ENGINE_CODE = re.compile(
    r"MY-\d{6}(?!\d)|SQLSTATE[ :=\[]*[0-9A-Z]{5}(?![0-9A-Za-z])|ERROR \d{4} \([0-9A-Z]{5}\)"
    r"|Error: \d{1,6}, Severity: \d{1,6}, State: \d{1,6}(?!\d)|ORA-\d{5}(?!\d)"
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


def _is_quote(char: str) -> bool:
    return bool(char) and (
        char in ASCII_QUOTES or char in OTHER_QUOTES or unicodedata.category(char) in ("Pi", "Pf")
    )


def _is_contraction(text: str, index: int) -> bool:
    """An apostrophe inside an English contraction (Can't, doesn't, it's, we're). Only known stems count, so a literal
    glued to a word (N'...', E'...', _binary'...', select'...') is never taken for one."""
    if text[index] != "'" or text[index - 1:index].isspace():
        return False
    word = WORD_BEFORE.search(text[:index]).group(1).lower()
    ending = CONTRACTION_END.match(text, index + 1)
    if not ending:
        return False
    return (word in NOT_STEMS and ending.group(1) == "t") or (word in PRONOUN_STEMS and ending.group(1) != "t")


def _kept_identifier_end(text: str, index: int) -> int | None:
    """Index just past an identifier quoted at text[index] that may be shown, else None.

    Kept only when the whole word before the quote is one of IDENTIFIER_WORDS, the span closes with the same quote
    before any other quote character, its content is identifier-shaped, and whitespace, punctuation or the end follows.
    """
    quote = text[index]
    if not _is_quote(quote) or WORD_BEFORE.search(text[:index]).group(1).lower() not in IDENTIFIER_WORDS:
        return None
    close = next((i for i in range(index + 1, len(text)) if _is_quote(text[i])), None)
    if close is None or text[close] != quote or not IDENTIFIER.fullmatch(text[index + 1:close]):
        return None
    after = text[close + 1:close + 2]
    if after and (after.isalnum() or after in "_\\$" or _is_quote(after)):
        return None
    return close + 1


def _mask_quotes(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Scan left to right without matching quotes: keep contractions and kept identifiers, and replace everything from
    any other quote character (or dollar-quote tag) to the end of the line. When such a quote follows a kept identifier,
    the mask starts at the first kept identifier instead, because unescaped quotes inside a value can look like
    keyword 'name' pairs. Returns the text and the kept spans."""
    out: list[str] = []
    kept: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        char = text[index]
        is_quote = _is_quote(char) or (char == "$" and DOLLAR_TAG.match(text, index))
        if not is_quote or (char == "'" and _is_contraction(text, index)):
            out.append(char)
            index += 1
            continue
        end = _kept_identifier_end(text, index)
        if end is None:
            start = kept[0][0] if kept else index
            head = text[:start] + REST_MASK
            codes = list(dict.fromkeys(m.group(0).rstrip(".") for m in TAIL_ENGINE_CODE.finditer(text, start)))
            code_spans = []
            for code in codes:
                head += " ["
                code_spans.append((len(head), len(head) + len(code)))
                head += code + "]"
            return head, code_spans
        position = len("".join(out))
        out.append(text[index:end])
        kept.append((position, position + end - index))
        index = end
    return "".join(out), kept


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


def _mask_accounts(text: str) -> str:
    """Mask user=, role= and usename= values up to the next separator (a quoted value up to its closing quote), quotes
    and spaces included, and both parts of a MySQL 'user'@'host' pair."""
    text = MYSQL_ACCOUNT.sub(f"{MASK}@{MASK}", text)
    out, position = [], 0
    for key in ACCOUNT_KEY.finditer(text):
        if key.start() < position:
            continue
        start = key.end()
        if _is_quote(text[start:start + 1]):
            close = next((i for i in range(start + 1, len(text)) if _is_quote(text[i])), None)
            start = len(text) if close is None else close + 1
        stop = ACCOUNT_VALUE_END.search(text, start)
        end = stop.start() if stop else len(text)
        out.append(text[position:key.end()] + MASK)
        position = end
    return "".join(out) + text[position:]


def _mask_digits(text: str, kept: list[tuple[int, int]]) -> str:
    """Replace every run of two or more digits, keeping the given spans and engine error codes as written."""
    spans = sorted(kept + [(m.start(), m.end()) for pattern in (ENGINE_CODE, KEPT_NUMBER) for m in pattern.finditer(text)])
    out, position = [], 0
    for start, end in spans:
        if start < position:
            continue
        out.append(DIGIT_RUN.sub(NUMBER_MASK, text[position:start]) + text[start:end])
        position = end
    return "".join(out) + DIGIT_RUN.sub(NUMBER_MASK, text[position:])


def _split_prefix(rest: str) -> tuple[str, str]:
    """The line prefix (before the severity or message marker) with its account values masked, and the message."""
    rds = RDS_POSTGRES_PREFIX.match(rest)
    if rds:
        user = MASK if rds.group("user") else ""
        return rds.group("head") + user + rds.group("tail"), rest[rds.end():]
    server = SQL_SERVER_PREFIX.match(rest)
    if server:
        return server.group(0), rest[server.end():]
    marker = MESSAGE_MARKER.search(rest)
    if not marker or any(_is_quote(char) for char in rest[:marker.start()]):
        return "", rest
    prefix = PREFIX_USER_AT.sub(MASK + "@", _mask_accounts(rest[:marker.start()]))
    return _mask_digits(prefix, [(m.start(), m.end()) for m in KEPT_PREFIX_VALUE.finditer(prefix)]), rest[marker.start():]


def _mask_values(line: str) -> str:
    """Hide data values in a log line: the prefix keeps its timestamp, pid and db/app/client values but never a user;
    the message keeps contractions and identifiers after known words, and masks the rest of the line from any other
    quote; then every run of two or more digits is masked apart from engine error codes."""
    stamp = LEADING_TIMESTAMP.match(line)
    head, rest = (line[:stamp.end()], line[stamp.end():]) if stamp else ("", line)
    prefix, message = _split_prefix(rest)
    message, kept = _mask_quotes(_mask_row_values(_mask_accounts(message)))
    return head + prefix + _mask_digits(message, kept)


def _error_files(files: list[dict]) -> list[dict]:
    return [f for f in files if "error" in f.get("LogFileName", "").lower()]


def _file_span(file: dict) -> tuple[datetime, datetime]:
    """When a log file may hold lines: from the minute, hour or date in its name (else unknown) to its last write."""
    name = file.get("LogFileName", "")
    written = datetime.fromtimestamp(file.get("LastWritten", 0) / 1000, tz=timezone.utc)
    minute, hour, day = FILE_MINUTE.search(name), FILE_HOUR.search(name), FILE_DATE.search(name)
    for match, form, length in (
        (minute, "{0}T{1}:{2}:00Z", timedelta(minutes=1)),
        (hour, "{0}T{1}:00:00Z", timedelta(hours=1)),
        (day, "{0}T00:00:00Z", timedelta(days=1)),
    ):
        begin = parse_iso(form.format(*match.groups())) if match else None
        if begin is not None:
            return begin, max(begin + length, written)
    return EARLIEST, written


def _overlapping_files(files: list[dict], window) -> list[dict]:
    """Files that may hold lines inside the window (its end is exclusive), oldest first."""
    spans = {f["LogFileName"]: _file_span(f) for f in files}
    inside = [f for f in files if spans[f["LogFileName"]][0] < window.end and spans[f["LogFileName"]][1] > window.start]
    return sorted(inside, key=lambda f: (spans[f["LogFileName"]][0], f.get("LastWritten", 0)))


def _onset_file(overlapping: list[dict], onset: datetime) -> dict:
    """The file covering the incident start (the latest to begin, then the first to end); without one, the last file
    that ended before it, else the first that began after it."""
    covering = [f for f in overlapping if _file_span(f)[0] <= onset < _file_span(f)[1]]
    if covering:
        return max(covering, key=lambda f: (_file_span(f)[0], -f.get("LastWritten", 0)))
    ended = [f for f in overlapping if _file_span(f)[1] <= onset]
    return max(ended, key=lambda f: _file_span(f)[1]) if ended else overlapping[0]


def _choose_files(overlapping: list[dict], onset: datetime) -> list[dict]:
    """At most MAX_LOG_FILES_READ files: the one covering the incident start, the one before it, then the newest."""
    if not overlapping:
        return []
    cover = _onset_file(overlapping, onset)
    chosen = [cover]
    position = overlapping.index(cover)
    if position > 0:
        chosen.append(overlapping[position - 1])
    newest = sorted((f for f in overlapping if f not in chosen), key=lambda f: f.get("LastWritten", 0), reverse=True)
    chosen += newest[:MAX_LOG_FILES_READ - len(chosen)]
    return sorted(chosen, key=lambda f: overlapping.index(f))


def _incident_start(ctx: CollectContext, targets: dict[str, str]) -> datetime:
    """The incident start given as a target, as the changes collector takes it; without one, the window start plus the
    standard 60-minute lead (cut to the window end)."""
    given = targets.get("incident_start") or None
    moment = parse_iso(given) if given else None
    if given and moment is None:
        ctx.evidence.add_error(
            "", "InvalidTarget", "incident_start must be an ISO time with a timezone, for example 2026-10-04T10:50:00Z",
        )
    if moment is not None:
        return moment
    return min(ctx.window.start + DEFAULT_LEAD, ctx.window.end)


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


def _read_error_entries(ctx: CollectContext, name: str, files: list[dict]) -> tuple[list[tuple[datetime, str]], list[str], str]:
    """Error lines inside the window from the last lines of each file, each with the DETAIL line or SQL Server message
    line that follows it, masked, without duplicates, in time order; the files read; and the last command."""
    entries: dict[tuple[datetime, str], str] = {}
    read_names, command = [], ctx.last_command
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
        open_key: tuple[datetime, str] | None = None
        for line in (portion.get("LogFileData") or "").splitlines():
            moment = _line_time(line)
            if PROBLEM_LINE.search(line) and moment is not None and ctx.window.start <= moment < ctx.window.end:
                open_key = (moment, line) if (moment, line) not in entries else None
                entries.setdefault((moment, line), _shorten(_mask_values(line.strip())))
            elif open_key is not None and ("DETAIL:" in line or SQL_SERVER_ERROR.search(open_key[1])):
                entries[open_key] += " | " + _shorten(_mask_values(line.strip()))
                open_key = None
            else:
                open_key = None
    return [(moment, text) for (moment, _), text in sorted(entries.items(), key=lambda item: item[0][0])], read_names, command


def _shorten(text: str) -> str:
    return text if len(text) <= MAX_LINE_PART else text[: MAX_LINE_PART - 1] + "…"


def _lines_to_keep(entries: list[tuple[datetime, str]], onset: datetime) -> list[tuple[datetime, str]]:
    """The error lines nearest before the incident start, the first ones from it, and the newest, in time order."""
    before = [i for i, (moment, _) in enumerate(entries) if moment < onset]
    after = [i for i, (moment, _) in enumerate(entries) if moment >= onset]
    wanted = set(before[-LINES_BEFORE_ONSET:]) | set(after[:LINES_FROM_ONSET]) | set(range(len(entries))[-NEWEST_LINES:])
    return [entries[i] for i in sorted(wanted)]


def _add_log_lines(ctx: CollectContext, name: str, onset: datetime) -> None:
    listed = _list_error_files(ctx, name)
    if listed is None:
        return
    all_files, cut, count = listed
    overlapping = _overlapping_files(all_files, ctx.window)
    files = _choose_files(overlapping, onset)
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
    entries, read_names, command = _read_error_entries(ctx, name, files)
    lines_read = f"{int(LOG_LINES_TO_READ):,}"
    if not entries:
        if read_names:
            ctx.evidence.add(
                kind=DERIVED, resource=f"db/{name}", command=command,
                summary=(
                    f"No error line inside the window was found in the last {lines_read} lines read from "
                    f"{', '.join(read_names)}; earlier lines of those files were not read"
                ),
            )
        return
    kept = _lines_to_keep(entries, onset)
    from_onset = next((moment for moment, _ in kept if moment >= onset), kept[0][0])
    ctx.evidence.add(
        kind=INCIDENT_TIME, resource=f"db/{name}", time=from_onset, command=command,
        summary=(
            f"{len(entries)} error {'line' if len(entries) == 1 else 'lines'} found in the lines read, {len(kept)} kept, "
            f"{len(entries) - len(kept)} not kept "
            f"(up to {LINES_BEFORE_ONSET} just before the incident start at {format_time(onset)}, the first "
            f"{LINES_FROM_ONSET} from it, and the newest {NEWEST_LINES}); the last {lines_read} lines of each file "
            f"were read, so earlier lines were not seen; files read: {', '.join(read_names)}"
        ),
        data={"lines": [text for _, text in kept]},
        excerpt=next(text for moment, text in kept if moment == from_onset),
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


def _collect_instance(ctx: CollectContext, instance: dict, onset: datetime) -> None:
    name = instance.get("DBInstanceIdentifier", "")
    _add_instance_state(ctx, instance)
    _add_events(ctx, name, "db-instance", "Instance")
    _add_log_lines(ctx, name, onset)
    _add_metrics(ctx, name)
    if instance.get("PerformanceInsightsEnabled") and instance.get("DbiResourceId"):
        _add_wait_events(ctx, name, instance["DbiResourceId"])


def _collect_cluster(ctx: CollectContext, name: str, onset: datetime) -> None:
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
            _collect_instance(ctx, instance, onset)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    name = targets["db"]
    onset = _incident_start(ctx, targets)
    instance = _describe_instance(ctx, name)
    if instance is not None:
        _collect_instance(ctx, instance, onset)
    elif was_not_found(ctx, INSTANCE_NOT_FOUND):
        _collect_cluster(ctx, name, onset)


COLLECTOR = Collector(
    name="rds",
    description="RDS instance or cluster state, events, error log lines, load and storage metrics, Performance Insights wait events",
    required=("db",),
    optional=("incident_start",),
    run=collect,
)
