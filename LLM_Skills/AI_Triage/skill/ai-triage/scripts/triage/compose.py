"""Turn stored TypeSafe answers into verdicts, gates, and labels with explicit rules."""
from __future__ import annotations

import math
from datetime import datetime, timedelta

from triage.window import parse_time

LABEL_ORDER = ("candidate", "probable", "confirmed")
CONTRADICT_CONFIDENCE = 0.6
SYMPTOM_FIT_MIN = 0.67
ACTION_TARGET_CONFIDENCE = 0.6
ACTION_SPECIFIC_MIN = 0.7
TIMING_TOLERANCE_SECONDS = 300
MAX_FINDINGS_JUDGED = 40


def probability(value: object) -> float | None:
    """The value when it is a finite number from 0 to 1, else None. Every comparison goes through this."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return value if 0 <= value <= 1 else None


def symptom_fit_value(answer: dict) -> float | None:
    """The score as a share of its highest level, or None when the score or levels are not usable."""
    score, levels = answer.get("score"), answer.get("levels")
    if isinstance(levels, bool) or not isinstance(levels, int) or levels < 2:
        return None
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        return None
    return score / (levels - 1) if 0 <= score <= levels - 1 else None


def finding_verdict(answer: dict, thresholds: dict) -> str:
    choice, confidence = answer.get("choice"), probability(answer.get("confidence"))
    if not isinstance(choice, str) or confidence is None:
        return "uncertain"
    supports_at = thresholds["evidence_supports"]
    if choice == "supports" and confidence >= supports_at:
        return "verified"
    if choice == "contradicts" and confidence >= CONTRADICT_CONFIDENCE:
        return "contradicted"
    if choice == "says_nothing" and confidence >= supports_at:
        return "unsupported"
    return "uncertain"


def timing_gate(cause: dict, findings: dict[str, dict], incident_start: datetime) -> bool | None:
    """True when supporting evidence from the incident itself is no later than the start plus a tolerance.

    None when no supporting finding has a time, which the caller counts as a missed gate.
    """
    supporting = [findings[finding_id] for finding_id in cause.get("supporting", []) if finding_id in findings]
    if not any(finding.get("time") for finding in supporting):
        return None
    latest = incident_start + timedelta(seconds=TIMING_TOLERANCE_SECONDS)
    return any(
        finding.get("provenance") == "incident_time" and finding.get("time") and parse_time(finding["time"]) <= latest
        for finding in supporting
    )


def cause_label(gates: dict[str, bool], top_choice: bool = True) -> str:
    """`top_choice` is whether the ranking chose this cause in both orderings."""
    if all(gates.values()) and top_choice:
        return "confirmed"
    if not gates["no_contradiction"] or not top_choice:
        return "candidate"
    return "probable" if sum(1 for passed in gates.values() if not passed) == 1 else "candidate"


def action_label(cause_label: str, target: dict, specific: object) -> tuple[str, list[str]]:
    reasons = []
    original_specific = specific
    confidence, specific = probability(target.get("confidence")), probability(specific)
    if cause_label != "confirmed":
        reasons.append(f"The cause is labelled {cause_label}, not confirmed")
    if target.get("choice") != "addresses_cause":
        reasons.append(f"The change was judged as {target.get('choice')}, not as addressing the cause")
    elif confidence is None or not confidence >= ACTION_TARGET_CONFIDENCE:
        reasons.append(
            f"The change addresses the cause with confidence {number(target.get('confidence'))}, below {number(ACTION_TARGET_CONFIDENCE)}"
        )
    if specific is None or not specific >= ACTION_SPECIFIC_MIN:
        reasons.append(f"The action is specific with probability {number(original_specific)}, below {number(ACTION_SPECIFIC_MIN)}")
    return ("candidate" if reasons else "recommended"), reasons


def cap_label(label: str, cap: str) -> str:
    return LABEL_ORDER[min(LABEL_ORDER.index(label), LABEL_ORDER.index(cap))]


def number(value: float) -> str:
    """A probability as short text, for example 0.48 or 0.6."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "invalid"
    return f"{round(value, 2):g}"
