"""Compare CloudWatch metrics in the incident window with the same span one week earlier."""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from decimal import Decimal
from datetime import timedelta
from typing import Sequence

from triage.context import CollectContext
from triage.evidence import DERIVED, INCIDENT_TIME
from triage.window import Window, format_time, parse_time

BASELINE_SHIFT = timedelta(days=-7)
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


def _summarise(spec: MetricSpec, window_points: list[tuple[str, float]], baseline_points: list[tuple[str, float]]) -> MetricSummary:
    baseline_values = [value for _, value in baseline_points]
    baseline_avg = sum(baseline_values) / len(baseline_values) if baseline_values else None
    baseline_max = max(baseline_values) if baseline_values else None
    if not window_points:
        return MetricSummary(spec.label, spec.stat, None, None, None, None, baseline_avg, baseline_max, None, 0)
    ordered = sorted(window_points, key=lambda point: parse_time(point[0]))
    values = [value for _, value in ordered]
    window_avg = sum(values) / len(values)
    window_max = max(values)
    peak_time, peak_end = _peak_span(ordered, window_max)
    ratio = window_avg / baseline_avg if baseline_avg else None
    return MetricSummary(
        spec.label, spec.stat, window_avg, window_max, min(values), peak_time,
        baseline_avg, baseline_max, ratio, len(values), peak_end,
    )


def _peak_span(ordered: list[tuple[str, float]], peak: float) -> tuple[str, str | None]:
    """The earliest point at the peak value, and the last of the consecutive points that held it (None for one)."""
    first = next(index for index, (_, value) in enumerate(ordered) if value == peak)
    last = first
    while last + 1 < len(ordered) and ordered[last + 1][1] == peak:
        last += 1
    return ordered[first][0], ordered[last][0] if last > first else None


def _fetch(
    ctx: CollectContext, specs: Sequence[MetricSpec], period: int, region: str | None
) -> tuple[list[MetricSummary], str, bool]:
    """Summaries, the command of the window call, and whether the window call succeeded."""
    queries = _queries(specs, period)
    now_points = _points(ctx, queries, ctx.window, region)
    window_command = ctx.last_command
    before_points = _points(ctx, queries, ctx.window.shifted(BASELINE_SHIFT), region)
    summaries = [
        _summarise(spec, (now_points or {}).get(f"m{index}", []), (before_points or {}).get(f"m{index}", []))
        for index, spec in enumerate(specs)
    ]
    return summaries, window_command, now_points is not None


def fetch(
    ctx: CollectContext, specs: Sequence[MetricSpec], period: int = 300, region: str | None = None
) -> list[MetricSummary]:
    return _fetch(ctx, specs, period, region)[0]


def _num(value: float) -> str:
    """Three significant figures; exponent form only for very large or very small values."""
    if not math.isfinite(value):
        return "not a number"
    if value == 0:
        return "0"
    if abs(value) >= 1e15 or abs(value) < 1e-6:
        return f"{value:.3g}"
    return format(Decimal(f"{value:.3g}"), "f")


def _ratio_words(summary: MetricSummary) -> str:
    ratio = summary.change_ratio
    if ratio is None:
        return "zero in both periods" if summary.baseline_avg == 0 and summary.window_avg == 0 else "no comparable baseline"
    if SAME_RANGE[0] <= ratio <= SAME_RANGE[1]:
        return "about the same"
    if ratio > SAME_RANGE[1]:
        return f"{_num(ratio)} times higher"
    if summary.window_avg == 0:
        return "down to zero"
    return f"{_num(1 / ratio)} times lower"


def _summary_text(summary: MetricSummary) -> str:
    when = f"from {summary.peak_time} to {summary.peak_end}" if summary.peak_end else f"at {summary.peak_time}"
    head = f"{summary.label} ({summary.stat}): peak {_num(summary.window_max)} {when}; "
    if summary.baseline_avg is None:
        return head + f"window average {_num(summary.window_avg)}; no comparable baseline"
    earlier = "zero" if summary.baseline_avg == 0 else _num(summary.baseline_avg)
    return (
        head
        + f"window average {_num(summary.window_avg)} against {earlier} one week earlier "
        + f"({_ratio_words(summary)})"
    )


def add_metric_facts(
    ctx: CollectContext, resource: str, specs: Sequence[MetricSpec], period: int = 300, region: str | None = None
) -> list[MetricSummary]:
    summaries, command, read_ok = _fetch(ctx, specs, period, region)
    for summary in summaries:
        if summary.datapoints == 0:
            outcome = "no data was returned for the window" if read_ok else "the metric could not be read (see errors)"
            ctx.evidence.add(
                kind=DERIVED, resource=resource, command=command, data=asdict(summary),
                summary=f"{summary.label} ({summary.stat}): {outcome}",
            )
            continue
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=summary.peak_time, command=command,
            summary=_summary_text(summary), data=asdict(summary),
        )
    return summaries
