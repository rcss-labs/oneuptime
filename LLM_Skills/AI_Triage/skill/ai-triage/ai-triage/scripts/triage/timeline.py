"""Merge every timed fact of a case into one ordered timeline with offsets in words."""
from __future__ import annotations

import json
from pathlib import Path

from triage.evidence import INCIDENT_TIME
from triage.findings import evidence_documents
from triage.window import WindowError, describe_offset, parse_time

MAX_ROWS = 300
TIMELINE_NAME = "timeline.json"
_INCIDENT_TEXTS = (
    ("impact_started_at", "Impact started"),
    ("declared_at", "Incident declared"),
    ("resolved_at", "Incident resolved"),
)
_SOURCE_RANK = {"incident": 0, "oneuptime": 1}


def _read_json(path: Path) -> dict:
    data = json.loads(path.read_text())
    return data if isinstance(data, dict) else {}


def _row(time: str, source: str, text: str, fact_id: str | None = None, resource: str = "") -> dict:
    return {"time": time, "source": source, "fact_id": fact_id, "resource": resource, "text": text}


def _raw_rows(case_dir: Path, case: dict, incident: dict) -> list[dict]:
    rows = []
    incident_times = case.get("incident") if isinstance(case.get("incident"), dict) else {}
    for key, text in _INCIDENT_TEXTS:
        if incident_times.get(key):
            rows.append(_row(incident_times[key], "incident", text))
    for key in ("timeline", "notes"):
        entries = incident.get(key)
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and entry.get("time"):
                rows.append(_row(entry["time"], "oneuptime", str(entry.get("text", ""))))
    for _, document in evidence_documents(case_dir):
        for fact in document.get("facts", []):
            if isinstance(fact, dict) and fact.get("kind") == INCIDENT_TIME and fact.get("time"):
                rows.append(_row(fact["time"], str(document.get("collector", "")), str(fact.get("summary", "")),
                                 fact.get("id"), str(fact.get("resource", ""))))
    return rows


def _sort_key(row: dict) -> tuple:
    return (row["_moment"], _SOURCE_RANK.get(row["source"], 2), row["source"], row["fact_id"] or "")


def build_timeline(case_dir: Path) -> list[dict]:
    case = _read_json(case_dir / "case.json")
    incident = _read_json(case_dir / "incident.json")
    start = parse_time(case["incident_start"])
    rows = []
    for row in _raw_rows(case_dir, case, incident):
        try:
            row["_moment"] = parse_time(row["time"])
        except WindowError:
            continue
        row["offset"] = f"{describe_offset(row['_moment'], start)} the incident started"
        rows.append(row)
    dropped = max(0, len(rows) - MAX_ROWS)
    if dropped:
        rows = sorted(rows, key=lambda row: abs(row["_moment"] - start))[:MAX_ROWS]
    rows.sort(key=_sort_key)
    for row in rows:
        del row["_moment"]
    if dropped:
        note = _row("", "timeline", f"{dropped} more rows farther from the incident start were left out")
        note["offset"] = ""
        rows.append(note)
    (case_dir / TIMELINE_NAME).write_text(json.dumps(rows, indent=2) + "\n")
    return rows


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def render_rows(rows: list[dict]) -> str:
    lines = ["| Time | Relative to incident start | Event | Source |", "| --- | --- | --- | --- |"]
    for row in rows:
        source = row["fact_id"] or row["source"]
        lines.append(f"| {_cell(row['time'])} | {_cell(row['offset'])} | {_cell(row['text'])} | {_cell(source)} |")
    return "\n".join(lines)
