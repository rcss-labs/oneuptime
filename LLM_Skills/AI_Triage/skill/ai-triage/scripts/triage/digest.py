"""Digests that tie a stored judgment to the draft it judged.

A cause or action digest covers the whole object except the few fields that are written
after judging. A cause digest also covers the whole checked entry of every finding the
cause cites. The draft digest covers the report-level inputs, every cause and action, and
the case, so adding or changing anything that a label depended on changes it.
None of the functions raise on wrongly typed input.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

# What judge.py reads to build a state, an option, or a question.
JUDGED_CAUSE_FIELDS = ("id", "statement", "supporting", "contradicting")
JUDGED_ACTION_FIELDS = ("id", "cause", "title", "target", "current_state", "required_state", "change")
# Written after judging; the only fields a digest leaves out.
POST_JUDGING_CAUSE_FIELDS = ("label", "confidence", "reasons")
POST_JUDGING_ACTION_FIELDS = ("label", "confidence", "reasons")


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


def draft_digest(report: dict, findings_by_id: dict, case_identity: str) -> str:
    """Covers the symptoms, the scope, every cause and action digest, and the case."""
    return _canonical_hash({
        "symptoms": _field(report, "symptoms"),
        "scope": _field(_field(report, "summary"), "scope"),
        "causes": _digests(_field(report, "causes"), lambda cause: cause_digest(cause, findings_by_id)),
        "actions": _digests(_field(report, "actions"), action_digest),
        "case": case_identity if isinstance(case_identity, str) else "",
    })
