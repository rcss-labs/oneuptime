"""CloudWatch alarms collector: current alarm state, state changes in the window, and the first alarm to fire."""
from __future__ import annotations

import json
from datetime import datetime

from triage.collectors import Collector
from triage.collectors.common import parse_iso, split_csv
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME
from triage.window import format_time

MAX_ALARMS = 50
MAX_HISTORY_ALARMS = 20
MAX_HISTORY_ITEMS = "20"
# Without --alarm-types the CLI returns metric alarms only.
ALARM_TYPES = ["--alarm-types", "CompositeAlarm", "MetricAlarm"]


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
        if (reply or {}).get("NextToken") and "--alarm-name-prefix" in args:
            ctx.evidence.add(
                kind=DERIVED, resource="alarms", command=ctx.last_command,
                summary=f"More alarms match the prefix than the {MAX_ALARMS} shown",
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


def _add_history(ctx: CollectContext, alarm: dict) -> list[tuple[datetime, str, bool]]:
    """Add one fact per state change in the window; return when the alarm went into ALARM."""
    name, is_composite = alarm.get("AlarmName", ""), "AlarmRule" in alarm
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
            fired.append((moment, name, is_composite))
    return fired


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
    names, prefix = split_csv(targets.get("alarm_names")), targets.get("name_prefix") or None
    alarms = _describe(ctx, names, prefix)
    if not alarms:
        ctx.evidence.add(kind=CURRENT, resource="alarms", summary="No alarms were found for the given names or prefix")
        return
    for alarm, command in alarms:
        _add_current(ctx, alarm, command)
    # Metric alarms first: they are the ones the "first alarm" fact is about.
    ordered = sorted((alarm for alarm, _ in alarms), key=lambda alarm: "AlarmRule" in alarm)
    fired: list[tuple[datetime, str, bool]] = []
    for alarm in ordered[:MAX_HISTORY_ALARMS]:
        fired += _add_history(ctx, alarm)
    if len(ordered) > MAX_HISTORY_ALARMS:
        ctx.evidence.add(
            kind=DERIVED, resource="alarms",
            summary=(
                f"State change history was read for {MAX_HISTORY_ALARMS} of {len(ordered)} alarms, metric alarms first; "
                f"{len(ordered) - MAX_HISTORY_ALARMS} were left out"
            ),
        )
    text = _first_alarm_text(fired)
    if text:
        ctx.evidence.add(kind=DERIVED, resource="alarms", summary=text)


COLLECTOR = Collector(
    name="alarms",
    description="CloudWatch alarm state, state changes in the window, and which alarm fired first",
    required=(),
    optional=(),
    run=collect,
    one_of=("alarm_names", "name_prefix"),
)
