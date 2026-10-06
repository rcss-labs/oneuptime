"""Compare CloudWatch metrics in the incident window with the same span one week earlier."""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Sequence

from triage.context import CollectContext
from triage.evidence import DERIVED, INCIDENT_TIME
from triage.window import Window, format_time, parse_time

BASELINE_SHIFT = timedelta(days=-7)
# The incident starts this long after the window start (window_around's default lead).
INCIDENT_LEAD = timedelta(minutes=60)
SAME_RANGE = (0.8, 1.25)


@dataclass(frozen=True)
class MetricSpec:
    label: str
    namespace: str
    metric: str
    dimensions: dict[str, str]
    stat: str = "Average"


@dataclass(frozen=True)
class MetricSummary:
    label: str
    stat: str
    window_avg: float | None
    window_max: float | None
    window_min: float | None
    peak_time: str | None
    baseline_avg: float | None
    baseline_max: float | None
    change_ratio: float | None
    datapoints: int
    # When the peak value held over consecutive points, the time of the last of them; else None.
    peak_end: str | None = None
    # Contract 6: what a metric fact states and carries in its data.
    minimum: float | None = None
    minimum_time: str | None = None
    minimum_end: str | None = None
    maximum: float | None = None
    maximum_time: str | None = None
    incident_average: float | None = None
    baseline_average: float | None = None
    first_departure_time: str | None = None
    direction: str | None = None  # rose, fell, unchanged; None without data
    notable: bool = False
    fact_time: str | None = None


def _queries(specs: Sequence[MetricSpec], period: int) -> str:
    return json.dumps(
        [
            {
                "Id": f"m{index}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": spec.namespace,
                        "MetricName": spec.metric,
                        "Dimensions": [{"Name": k, "Value": v} for k, v in spec.dimensions.items()],
                    },
                    "Period": period,
                    "Stat": spec.stat,
                },
                "ReturnData": True,
            }
            for index, spec in enumerate(specs)
        ]
    )


def _points(
    ctx: CollectContext, queries: str, window: Window, region: str | None
) -> dict[str, list[tuple[str, float]]] | None:
    """Return (time, value) pairs by query id, or None when the call failed."""
    data = ctx.aws(
        "cloudwatch", "get-metric-data",
        ["--metric-data-queries", queries, "--start-time", format_time(window.start), "--end-time", format_time(window.end)],
        region=region,
    )
    if data is None:
        return None
    points: dict[str, list[tuple[str, float]]] = {}
    for result in data.get("MetricDataResults", []):
        pairs = zip(result.get("Timestamps", []), result.get("Values", []))
        points[result["Id"]] = [(format_time(parse_time(stamp)), float(value)) for stamp, value in pairs]
    return points


def _baseline_range(values: list[float]) -> tuple[float, float]:
    """The range of last week's values, widened by the factors that already word "about the same"."""
    low, high = min(values), max(values)
    low = low * SAME_RANGE[0] if low >= 0 else low * SAME_RANGE[1]
    high = high * SAME_RANGE[1] if high >= 0 else high * SAME_RANGE[0]
    return low, high


def _from(points: list[tuple[str, float]], moment: datetime | None, shift: timedelta = timedelta(0)) -> list[tuple[str, float]]:
    """The points at or after moment (shifted); all points when there is no moment or none are that late."""
    if moment is None:
        return points
    later = [point for point in points if parse_time(point[0]) >= moment + shift]
    return later or points


def _average(points: list[tuple[str, float]]) -> float | None:
    return sum(value for _, value in points) / len(points) if points else None


def _summarise(
    spec: MetricSpec,
    window_points: list[tuple[str, float]],
    baseline_points: list[tuple[str, float]],
    incident_start: datetime | None = None,
) -> MetricSummary:
    baseline = sorted(baseline_points, key=lambda point: parse_time(point[0]))
    baseline_values = [value for _, value in baseline]
    baseline_avg = _average(baseline)
    baseline_max = max(baseline_values) if baseline_values else None
    if not window_points:
        return MetricSummary(spec.label, spec.stat, None, None, None, None, baseline_avg, baseline_max, None, 0)
    ordered = sorted(window_points, key=lambda point: parse_time(point[0]))
    values = [value for _, value in ordered]
    window_avg = sum(values) / len(values)
    window_max, window_min = max(values), min(values)
    peak_time, peak_end = _peak_span(ordered, window_max)
    minimum_time, minimum_end = _peak_span(ordered, window_min)
    incident_average = _average(_from(ordered, incident_start))
    same_hours = _average(_from(baseline, incident_start, BASELINE_SHIFT)) if baseline else None
    departure, direction = None, "unchanged"
    if baseline_values:
        low, high = _baseline_range(baseline_values)
        departure = next(((time, value) for time, value in ordered if value > high or value < low), None)
        if departure:
            direction = "rose" if departure[1] > high else "fell"
        notable = departure is not None
    else:
        notable = window_max != window_min
    extreme = {"rose": peak_time, "fell": minimum_time}.get(direction, peak_time)
    return MetricSummary(
        spec.label, spec.stat, window_avg, window_max, window_min, peak_time,
        baseline_avg, baseline_max, window_avg / baseline_avg if baseline_avg else None, len(values), peak_end,
        minimum=window_min, minimum_time=minimum_time, minimum_end=minimum_end,
        maximum=window_max, maximum_time=peak_time, incident_average=incident_average, baseline_average=same_hours,
        first_departure_time=departure[0] if departure else None, direction=direction, notable=notable,
        fact_time=departure[0] if departure else extreme,
    )


def _peak_span(ordered: list[tuple[str, float]], peak: float) -> tuple[str, str | None]:
    """The earliest point at the peak value, and the last of the consecutive points that held it (None for one)."""
    first = next(index for index, (_, value) in enumerate(ordered) if value == peak)
    last = first
    while last + 1 < len(ordered) and ordered[last + 1][1] == peak:
        last += 1
    return ordered[first][0], ordered[last][0] if last > first else None


def fetch_with_command(
    ctx: CollectContext, specs: Sequence[MetricSpec], period: int, region: str | None
) -> tuple[list[MetricSummary], str, bool]:
    """Summaries, the command of the window call, and whether the window call succeeded."""
    queries = _queries(specs, period)
    now_points = _points(ctx, queries, ctx.window, region)
    window_command = ctx.last_command
    before_points = _points(ctx, queries, ctx.window.shifted(BASELINE_SHIFT), region)
    incident_start = min(ctx.window.start + INCIDENT_LEAD, ctx.window.end)
    summaries = [
        _summarise(spec, (now_points or {}).get(f"m{index}", []), (before_points or {}).get(f"m{index}", []), incident_start)
        for index, spec in enumerate(specs)
    ]
    return summaries, window_command, now_points is not None


def fetch(
    ctx: CollectContext, specs: Sequence[MetricSpec], period: int = 300, region: str | None = None
) -> list[MetricSummary]:
    return fetch_with_command(ctx, specs, period, region)[0]


def _num(value: float) -> str:
    """Three significant figures; exponent form only for very large or very small values."""
    if not math.isfinite(value):
        return "not a number"
    if value == 0:
        return "0"
    if abs(value) >= 1e15 or abs(value) < 1e-6:
        return f"{value:.3g}"
    return format(Decimal(f"{value:.3g}"), "f")


def _at(time: str | None, end: str | None) -> str:
    return f"from {time} to {end}" if end else f"at {time}"


def _movement(summary: MetricSummary) -> str:
    if summary.direction == "rose":
        return f"rose above the range of one week earlier at {summary.first_departure_time}"
    if summary.direction == "fell":
        return f"fell below the range of one week earlier at {summary.first_departure_time}"
    if summary.baseline_max == 0 and summary.maximum == 0 and summary.minimum == 0:
        return "zero in both periods"
    return "about the same as one week earlier"


def summary_text(summary: MetricSummary) -> str:
    """Contract 6: statistic, lowest and highest with their times, the incident part against the same hours
    one week earlier, and when the series first left last week's range."""
    head = (
        f"{summary.label} ({summary.stat}): lowest {_num(summary.minimum)} {_at(summary.minimum_time, summary.minimum_end)}, "
        f"highest {_num(summary.maximum)} {_at(summary.maximum_time, summary.peak_end)}; "
        f"{_num(summary.incident_average)} during the incident"
    )
    if summary.baseline_average is None:
        return head + "; no comparable baseline"
    return head + f" against {_num(summary.baseline_average)} in the same hours one week earlier; {_movement(summary)}"


def add_metric_facts(
    ctx: CollectContext, resource: str, specs: Sequence[MetricSpec], period: int = 300, region: str | None = None
) -> list[MetricSummary]:
    summaries, command, read_ok = fetch_with_command(ctx, specs, period, region)
    for summary in summaries:
        if summary.datapoints == 0:
            outcome = "no data was returned for the window" if read_ok else "the metric could not be read (see errors)"
            ctx.evidence.add(
                kind=DERIVED, resource=resource, command=command, data=asdict(summary),
                summary=f"{summary.label} ({summary.stat}): {outcome}",
            )
            continue
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=summary.fact_time, command=command,
            summary=summary_text(summary), data=asdict(summary),
        )
    return summaries
