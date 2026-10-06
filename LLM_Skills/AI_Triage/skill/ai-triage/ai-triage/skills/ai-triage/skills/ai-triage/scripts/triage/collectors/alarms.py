"""CloudWatch alarms collector: current alarm state, state changes in the window, and the first alarm to fire."""
from __future__ import annotations

import json
from datetime import datetime

from triage.collectors import Collector
from triage.collectors.common import parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.window import format_time

MAX_ALARMS = 50
MAX_HISTORY_ALARMS = 20
MAX_HISTORY_ITEMS = "20"
MISSING_TARGET = "MissingTarget"
# Without --alarm-types the CLI returns metric alarms only.
ALARM_TYPES = ["--alarm-types", "CompositeAlarm", "MetricAlarm"]


def _split(text: str | None) -> list[str]:
    return [item.strip() for item in (text or "").split(",") if item.strip()]


def _describe(ctx: CollectContext, names: list[str], prefix: str | None) -> list[tuple[dict, str]]:
    """The alarms found, each with the command that returned it."""
    alarms: dict[str, tuple[dict, str]] = {}
    queries = []
    if names:
        queries.append(["--alarm-names", *names[:MAX_ALARMS]])
    if prefix:
        queries.append(["--alarm-name-prefix", prefix, "--max-items", str(MAX_ALARMS)])
    for args in queries:
        reply = ctx.aws("cloudwatch", "describe-alarms", [*args, *ALARM_TYPES])
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


def _add_history(ctx: CollectContext, name: str) -> list[tuple[datetime, str]]:
    """Add one fact per state change in the window; return the times the alarm went into ALARM."""
    start, end = format_time(ctx.window.start), format_time(ctx.window.end)
    reply = ctx.aws(
        "cloudwatch", "describe-alarm-history",
        ["--alarm-name", name, "--history-item-type", "StateUpdate", "--start-date", start, "--end-date", end,
         "--scan-by", "TimestampAscending", "--max-items", MAX_HISTORY_ITEMS, *ALARM_TYPES],
    )
    changes = []
    for item in (reply or {}).get("AlarmHistoryItems", []):
        moment = parse_iso(item.get("Timestamp"))
        if moment is not None and ctx.window.contains(moment):
            changes.append((moment, item))
    fired = []
    for moment, item in sorted(changes, key=lambda pair: pair[0]):
        old, new = _states(item)
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=f"alarm/{name}", time=moment, command=ctx.last_command,
            summary=f"Alarm {name} changed from {old} to {new}",
            excerpt=item.get("HistorySummary") or "",
        )
        if new == "ALARM":
            fired.append((moment, name))
    return fired


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    names, prefix = _split(targets.get("alarm_names")), targets.get("name_prefix") or None
    if not names and not prefix:
        ctx.evidence.add_error("", MISSING_TARGET, "give alarm_names or name_prefix")
        return
    alarms = _describe(ctx, names, prefix)
    if not alarms:
        ctx.evidence.add(kind=CURRENT, resource="alarms", summary="No alarms were found for the given names or prefix")
        return
    for alarm, command in alarms:
        _add_current(ctx, alarm, command)
    fired: list[tuple[datetime, str]] = []
    for alarm, _ in alarms[:MAX_HISTORY_ALARMS]:
        fired += _add_history(ctx, alarm.get("AlarmName", ""))
    if fired:
        moment, name = min(fired)
        ctx.evidence.add(
            kind=DERIVED, resource=f"alarm/{name}",
            summary=f"The first alarm to go into ALARM in the window was {name} at {format_time(moment)}",
        )


COLLECTOR = Collector(
    name="alarms",
    description="CloudWatch alarm state, state changes in the window, and which alarm fired first",
    required=(),
    optional=("alarm_names", "name_prefix"),
    run=collect,
)
