"""Compare CloudWatch metrics in the incident window with the same span one week earlier."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
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


def _points(ctx: CollectContext, queries: str, window: Window) -> dict[str, list[tuple[str, float]]]:
    """Return (time, value) pairs by query id; empty when the call failed."""
    data = ctx.aws(
        "cloudwatch", "get-metric-data",
        ["--metric-data-queries", queries, "--start-time", format_time(window.start), "--end-time", format_time(window.end)],
    )
    points: dict[str, list[tuple[str, float]]] = {}
    for result in (data or {}).get("MetricDataResults", []):
        pairs = zip(result.get("Timestamps", []), result.get("Values", []))
        points[result["Id"]] = [(format_time(parse_time(stamp)), float(value)) for stamp, value in pairs]
    return points


def _summarise(spec: MetricSpec, window_points: list[tuple[str, float]], baseline_points: list[tuple[str, float]]) -> MetricSummary:
    baseline_values = [value for _, value in baseline_points]
    baseline_avg = sum(baseline_values) / len(baseline_values) if baseline_values else None
    baseline_max = max(baseline_values) if baseline_values else None
    if not window_points:
        return MetricSummary(spec.label, spec.stat, None, None, None, None, baseline_avg, baseline_max, None, 0)
    values = [value for _, value in window_points]
    window_avg = sum(values) / len(values)
    peak_time, window_max = max(window_points, key=lambda point: point[1])
    ratio = window_avg / baseline_avg if baseline_avg else None
    return MetricSummary(
        spec.label, spec.stat, window_avg, window_max, min(values), peak_time,
        baseline_avg, baseline_max, ratio, len(values),
    )


def fetch(ctx: CollectContext, specs: Sequence[MetricSpec], period: int = 300) -> list[MetricSummary]:
    queries = _queries(specs, period)
    now_points = _points(ctx, queries, ctx.window)
    before_points = _points(ctx, queries, ctx.window.shifted(BASELINE_SHIFT))
    return [
        _summarise(spec, now_points.get(f"m{index}", []), before_points.get(f"m{index}", []))
        for index, spec in enumerate(specs)
    ]


def _ratio_words(ratio: float | None) -> str:
    if ratio is None:
        return "no baseline data"
    if SAME_RANGE[0] <= ratio <= SAME_RANGE[1]:
        return "about the same"
    if ratio > SAME_RANGE[1]:
        return f"{ratio:.1f} times higher"
    return f"{1 / ratio:.1f} times lower"


def _summary_text(summary: MetricSummary) -> str:
    head = f"{summary.label} ({summary.stat}): peak {summary.window_max:.1f} at {summary.peak_time}; "
    if summary.baseline_avg is None:
        return head + f"window average {summary.window_avg:.1f}; no baseline data"
    return (
        head
        + f"window average {summary.window_avg:.1f} against {summary.baseline_avg:.1f} one week earlier "
        + f"({_ratio_words(summary.change_ratio)})"
    )


def add_metric_facts(ctx: CollectContext, resource: str, specs: Sequence[MetricSpec], period: int = 300) -> list[MetricSummary]:
    summaries = fetch(ctx, specs, period)
    for summary in summaries:
        if summary.datapoints == 0:
            ctx.evidence.add(
                kind=DERIVED, resource=resource, command=ctx.last_command, data=asdict(summary),
                summary=f"{summary.label} ({summary.stat}): no data was returned for the window",
            )
            continue
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=summary.peak_time, command=ctx.last_command,
            summary=_summary_text(summary), data=asdict(summary),
        )
    return summaries
