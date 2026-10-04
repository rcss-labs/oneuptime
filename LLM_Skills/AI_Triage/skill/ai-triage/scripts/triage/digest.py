"""Digests of the text that judging reads, so a stored judgment can be tied to the draft it judged.

A digest covers only fields that exist before judging. Labels, confidences, and reasons
are written afterwards and are never part of it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

JUDGED_CAUSE_FIELDS = ("id", "statement", "supporting", "contradicting")
JUDGED_ACTION_FIELDS = ("id", "cause", "title", "target", "current_state", "required_state", "change")
JUDGED_FINDING_FIELDS = ("claim", "fact_ids", "excerpt")


def _field(container: Any, name: str) -> Any:
    return container.get(name) if isinstance(container, dict) else None


def _canonical_hash(value: Any) -> str:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=repr)
    except (TypeError, ValueError):
        text = repr(value)
    return hashlib.sha256(text.encode("ascii", errors="backslashreplace")).hexdigest()


def _cited_ids(cause: Any) -> list[str]:
    ids: list[str] = []
    for name in ("supporting", "contradicting"):
        listed = _field(cause, name)
        if isinstance(listed, list):
            ids += [item for item in listed if isinstance(item, str) and item not in ids]
    return ids


def cause_digest(cause: dict, findings_by_id: dict) -> str:
    """Covers the judged fields of the cause and the judged text of every finding it cites."""
    registry = findings_by_id if isinstance(findings_by_id, dict) else {}
    cited = {
        finding_id: {name: _field(registry.get(finding_id), name) for name in JUDGED_FINDING_FIELDS}
        if isinstance(registry.get(finding_id), dict) else None
        for finding_id in _cited_ids(cause)
    }
    return _canonical_hash({
        "cause": {name: _field(cause, name) for name in JUDGED_CAUSE_FIELDS},
        "findings": cited,
    })


def action_digest(action: dict) -> str:
    return _canonical_hash({name: _field(action, name) for name in JUDGED_ACTION_FIELDS})
