"""Digests that tie a stored judgment to the draft it judged.

A cause, action, or hypothesis digest covers the whole object except the few fields that are
written after judging. A cause digest also covers the whole checked entry of every finding the
cause cites. The draft digest covers the report-level inputs, every cause and action, and
the case, so adding or changing anything that a label depended on changes it.
None of the functions raise on wrongly typed input.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

# What judge reads to build a state, an option, or a question.
JUDGED_CAUSE_FIELDS = ("id", "statement", "supporting", "contradicting")
JUDGED_ACTION_FIELDS = ("id", "cause", "title", "target", "current_state", "required_state", "change")
# Written after judging; the only fields a digest leaves out.
POST_JUDGING_CAUSE_FIELDS = ("label", "confidence", "reasons")
POST_JUDGING_ACTION_FIELDS = ("label", "confidence", "reasons")
POST_JUDGING_HYPOTHESIS_FIELDS = ("result",)


def _field(container: Any, name: str) -> Any:
    return container.get(name) if isinstance(container, dict) else None


def _canonical_hash(value: Any) -> str:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=repr)
    except (TypeError, ValueError):
        text = repr(value)
    return hashlib.sha256(text.encode("ascii", errors="backslashreplace")).hexdigest()


def _without(value: Any, skipped: tuple[str, ...]) -> Any:
    if not isinstance(value, dict):
        return value
    return {key: item for key, item in value.items() if key not in skipped}


def _cited_ids(cause: Any) -> list[str]:
    ids: list[str] = []
    for name in ("supporting", "contradicting"):
        listed = _field(cause, name)
        if isinstance(listed, list):
            ids += [item for item in listed if isinstance(item, str) and item not in ids]
    return ids


def cause_digest(cause: dict, findings_by_id: dict) -> str:
    """Covers the cause and the whole checked entry of every finding it cites."""
    registry = findings_by_id if isinstance(findings_by_id, dict) else {}
    return _canonical_hash({
        "cause": _without(cause, POST_JUDGING_CAUSE_FIELDS),
        "findings": {finding_id: registry.get(finding_id) for finding_id in _cited_ids(cause)},
    })


def action_digest(action: dict) -> str:
    return _canonical_hash(_without(action, POST_JUDGING_ACTION_FIELDS))


def case_identity(case: Any) -> str:
    """The incident number and the run folder name, as case.json holds them."""
    incident = _field(case, "incident")
    number = _field(incident, "number")
    folder = _field(case, "case_dir")
    return f"{number if isinstance(number, str) else ''}/{Path(folder).name if isinstance(folder, str) else ''}"


def _digests(entries: Any, digest) -> list[str]:
    return sorted(digest(entry) for entry in entries) if isinstance(entries, list) else []


def hypothesis_digest(hypothesis: dict) -> str:
    """Covers the hypothesis except its result, which is set to agree with the labels after judging."""
    return _canonical_hash(_without(hypothesis, POST_JUDGING_HYPOTHESIS_FIELDS))


def _entries_without(entries: Any, skipped: tuple[str, ...]) -> Any:
    return [_without(entry, skipped) for entry in entries] if isinstance(entries, list) else entries


def draft_text(report: Any) -> dict:
    """What the draft digest covers, shaped as in report.json: the summary text, symptoms, every cause, action, and
    hypothesis, the open questions, what was not checked, and the map changes. The fields decided after judging are
    left out: status, summary.top_cause, coverage.typesafe, the run details, the labels, confidences, and reasons of
    causes and actions, and the results of hypotheses.

    report checks every string in it for label words, so the check and the digest cover the same text.
    """
    summary = _field(report, "summary")
    coverage = _field(report, "coverage")
    return {
        "summary": {key: _field(summary, key) for key in ("what_broke", "impact", "scope")},
        "symptoms": _field(report, "symptoms"),
        "causes": _entries_without(_field(report, "causes"), POST_JUDGING_CAUSE_FIELDS),
        "hypotheses": _entries_without(_field(report, "hypotheses"), POST_JUDGING_HYPOTHESIS_FIELDS),
        "actions": _entries_without(_field(report, "actions"), POST_JUDGING_ACTION_FIELDS),
        "open_questions": _field(report, "open_questions"),
        "coverage": {"not_checked": _field(coverage, "not_checked")},
        "map_changes": _field(report, "map_changes"),
    }


def draft_digest(report: dict, findings_by_id: dict, case_identity: str) -> str:
    """Covers everything draft_text holds, each cause with the findings it cites, and the case."""
    text = draft_text(report)
    return _canonical_hash({
        "symptoms": text["symptoms"],
        "scope": text["summary"]["scope"],
        "what_broke": text["summary"]["what_broke"],
        "impact": text["summary"]["impact"],
        "open_questions": text["open_questions"],
        "not_checked": text["coverage"]["not_checked"],
        "map_changes": text["map_changes"],
        "hypotheses": _digests(text["hypotheses"], hypothesis_digest),
        "causes": _digests(text["causes"], lambda cause: cause_digest(cause, findings_by_id)),
        "actions": _digests(text["actions"], action_digest),
        "case": case_identity if isinstance(case_identity, str) else "",
    })
