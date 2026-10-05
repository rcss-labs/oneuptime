"""CloudWatch alarms collector: current alarm state, state changes in the window, and the first alarm to fire."""
from __future__ import annotations

import json
from datetime import datetime

from triage.collectors import Collector
from triage.collectors.common import parse_iso, split_csv
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.window import format_time

INVALID_TARGET = "InvalidTarget"
MAX_ALARMS = 50
MAX_HISTORY_ALARMS = 20
MAX_HISTORY_ITEMS = "20"
MAX_HISTORY_PAGES = 5
# Without --alarm-types the CLI returns metric alarms only.
ALARM_TYPES = ["--alarm-types", "CompositeAlarm", "MetricAlarm"]


def _describe(ctx: CollectContext, names: list[str], prefix: str | None, in_alarm: bool = False) -> list[tuple[dict, str]]:
    """The alarms found, each with the command that returned it."""
    alarms: dict[str, tuple[dict, str]] = {}
    queries = []
    if names:
        queries.append(["--alarm-names", *names[:MAX_ALARMS]])
    if prefix:
        queries.append(["--alarm-name-prefix", prefix, "--max-items", str(MAX_ALARMS)])
    if in_alarm:
        queries.append(["--state-value", "ALARM", "--max-items", str(MAX_ALARMS)])
    for args in queries:
        reply = ctx.aws("cloudwatch", "describe-alarms", [*args, *ALARM_TYPES])
        if (reply or {}).get("NextToken") and "--alarm-name-prefix" in args:
            ctx.evidence.add(
                kind=DERIVED, resource="alarms", command=ctx.last_command,
                summary=f"More alarms match the prefix than the {MAX_ALARMS} shown",
            )
        if (reply or {}).get("NextToken") and "--state-value" in args:
            ctx.evidence.add(
                kind=DERIVED, resource="alarms", command=ctx.last_command,
                summary=f"More alarms are in the ALARM state than the {MAX_ALARMS} shown",
            )
        for alarm in (reply or {}).get("MetricAlarms", []) + (reply or {}).get("CompositeAlarms", []):
            alarms.setdefault(alarm.get("AlarmName", ""), (alarm, ctx.last_command))
    return list(alarms.values())


def _add_current(ctx: CollectContext, alarm: dict, command: str) -> None:
    name = alarm.get("AlarmName", "")
    if "AlarmRule" in alarm:
        what = f"composite rule {alarm['AlarmRule']}"
    else:
        what = f"metric {alarm.get('MetricName') or 'math expression'}"
        if "Threshold" in alarm:
            what += f", threshold {alarm.get('ComparisonOperator')} {alarm.get('Threshold')}"
    ctx.evidence.add(
        kind=CURRENT, resource=f"alarm/{name}", command=command,
        summary=f"Alarm {name} is {alarm.get('StateValue')}: {what}",
        excerpt=alarm.get("StateReason") or "",
    )


def _states(item: dict) -> tuple[str, str]:
    try:
        data = json.loads(item.get("HistoryData") or "{}")
        return data["oldState"]["stateValue"], data["newState"]["stateValue"]
    except (ValueError, KeyError, TypeError):
        return "unknown", "unknown"


def _read_history(ctx: CollectContext, name: str) -> tuple[list[tuple[datetime, dict]], int, bool]:
    """State changes in the window, newest first, following the page token up to MAX_HISTORY_PAGES.

    Returns the changes, the pages read, and whether the history was read to its end."""
    start, end = format_time(ctx.window.start), format_time(ctx.window.end)
    changes: list[tuple[datetime, dict]] = []
    token = None
    for page in range(1, MAX_HISTORY_PAGES + 1):
        args = ["--alarm-name", name, "--history-item-type", "StateUpdate", "--start-date", start, "--end-date", end,
                "--scan-by", "TimestampDescending", "--max-items", MAX_HISTORY_ITEMS, *ALARM_TYPES]
        if token:
            args += ["--starting-token", token]
        reply = ctx.aws("cloudwatch", "describe-alarm-history", args)
        if reply is None:
            return changes, page - 1, False
        for item in reply.get("AlarmHistoryItems", []):
            moment = parse_iso(item.get("Timestamp"))
            if moment is not None and ctx.window.contains(moment):
                changes.append((moment, item))
        token = reply.get("NextToken")
        if not token:
            return changes, page, True
    return changes, MAX_HISTORY_PAGES, False


def _add_history(ctx: CollectContext, alarm: dict) -> tuple[list[tuple[datetime, str, bool]], bool]:
    """Add facts for the newest state changes and the earliest change into ALARM.

    Returns the earliest time the alarm went into ALARM (empty when none was seen) and whether
    the history was read to its end, so that "no earlier change" is known to be true."""
    name, is_composite = alarm.get("AlarmName", ""), "AlarmRule" in alarm
    changes, pages, complete = _read_history(ctx, name)
    command = ctx.last_command
    changes.sort(key=lambda pair: pair[0])
    alarm_changes = [pair for pair in changes if _states(pair[1])[1] == "ALARM"]
    shown = changes[-int(MAX_HISTORY_ITEMS):]
    if alarm_changes and alarm_changes[0] not in shown:
        shown = [alarm_changes[0], *shown]
    for moment, item in shown:
        old, new = _states(item)
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"alarm/{name}", time=moment, command=command,
            summary=f"Alarm {name} changed from {old} to {new}",
            excerpt=item.get("HistorySummary") or "",
        )
    if not complete or len(shown) < len(changes):
        said = f"Alarm {name}: read {pages} {'page' if pages == 1 else 'pages'} of state changes, {len(changes)} in the window; "
        said += f"showing the newest {int(MAX_HISTORY_ITEMS)}" + (" and the earliest change into ALARM" if len(shown) > int(MAX_HISTORY_ITEMS) else "")
        said += "" if complete else f"; the history was cut after {pages} pages and older changes exist"
        ctx.evidence.add(kind=DERIVED, resource=f"alarm/{name}", summary=said, command=command)
    fired = [(alarm_changes[0][0], name, is_composite)] if alarm_changes else []
    return fired, complete


def _first_alarm_text(fired: list[tuple[datetime, str, bool]]) -> str | None:
    """First metric alarm into ALARM; a composite at the same time or earlier is named as a composite."""
    metrics = [entry for entry in fired if not entry[2]]
    composites = [entry for entry in fired if entry[2]]
    if not metrics:
        if not composites:
            return None
        moment, name, _ = min(composites)
        return f"The first alarm to go into ALARM in the window was the composite alarm {name} at {format_time(moment)}"
    moment, name, _ = min(metrics)
    text = f"The first alarm to go into ALARM in the window was {name} at {format_time(moment)}"
    earlier = [entry for entry in composites if entry[0] <= moment]
    if earlier:
        c_moment, c_name, _ = min(earlier)
        text += f". The composite alarm {c_name} changed to ALARM at {format_time(c_moment)}, at the same time or earlier"
    return text


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    names, prefix = split_csv(targets.get("alarm_names")), (targets.get("name_prefix") or "").strip() or None
    in_alarm = (targets.get("in_alarm") or "").strip().lower() == "true"
    usable = {"alarm_names": names, "name_prefix": prefix, "in_alarm": in_alarm}
    for key, value in usable.items():
        if key in targets and not value:
            ctx.evidence.add_error("", INVALID_TARGET, f"target {key} has no usable value, so it was not used")
    if not any(usable.values()):
        return
    alarms = _describe(ctx, names, prefix, in_alarm)
    if not alarms:
        ctx.evidence.add(kind=CURRENT, resource="alarms", summary="No alarms were found for the given names or prefix")
        return
    for alarm, command in alarms:
        _add_current(ctx, alarm, command)
    # Metric alarms first: they are the ones the "first alarm" fact is about.
    ordered = sorted((alarm for alarm, _ in alarms), key=lambda alarm: "AlarmRule" in alarm)
    fired: list[tuple[datetime, str, bool]] = []
    unsure = [alarm.get("AlarmName", "") for alarm in ordered[MAX_HISTORY_ALARMS:]]
    for alarm in ordered[:MAX_HISTORY_ALARMS]:
        found, complete = _add_history(ctx, alarm)
        fired += found
        if not complete:
            unsure.append(alarm.get("AlarmName", ""))
    if len(ordered) > MAX_HISTORY_ALARMS:
        ctx.evidence.add(
            kind=DERIVED, resource="alarms",
            summary=(
                f"State change history was read for {MAX_HISTORY_ALARMS} of {len(ordered)} alarms, metric alarms first; "
                f"{len(ordered) - MAX_HISTORY_ALARMS} were left out"
            ),
        )
    if unsure:
        text = (
            "Which alarm went into ALARM first cannot be named: the history was cut or not read for "
            f"{', '.join(unsure)}, so earlier changes may exist"
        )
    else:
        text = _first_alarm_text(fired)
    if text:
        ctx.evidence.add(kind=DERIVED, resource="alarms", summary=text)


COLLECTOR = Collector(
    name="alarms",
    description="CloudWatch alarm state, state changes in the window, and which alarm fired first; in_alarm=true lists alarms now in ALARM",
    required=(),
    optional=("alarm_names", "name_prefix", "in_alarm"),
    run=collect,
    one_of=("alarm_names", "name_prefix", "in_alarm"),
)
