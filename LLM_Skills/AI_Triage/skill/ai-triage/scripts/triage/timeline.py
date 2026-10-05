"""Merge every timed fact of a case into one ordered timeline with offsets in words."""
from __future__ import annotations
import json
from pathlib import Path
from triage.evidence import INCIDENT_TIME
from triage.findings import evidence_documents, qualified_id
from triage.window import WindowError, describe_offset, format_time, parse_time
MAX_ROWS = 300
MAX_ROW_EXCERPT = 200
BEFORE_WINDOW = 'before the window'
TIMELINE_NAME = 'timeline.json'
_INCIDENT_TEXTS = (('impact_started_at', 'Impact started'), ('declared_at', 'Incident declared'), ('resolved_at', 'Incident resolved'))
_BAD_ID = '\x00bad-id'
_SOURCE_RANK = {'incident': 0, 'oneuptime': 1}

def _read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding='utf-8'))
    return data if isinstance(data, dict) else {}

def _row(time: str, source: str, text: str, fact_id: str | None=None, resource: str='') -> dict:
    return {'time': time, 'source': source, 'fact_id': fact_id, 'resource': resource, 'text': text}

def _shows_no_change(fact: dict) -> bool:
    """A metric fact flagged as not notable (about the same as before); a fact without the flag is kept."""
    data = fact.get('data')
    return isinstance(data, dict) and data.get('notable') is False

def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1] + '…'

def _metric_placement(fact: dict) -> tuple[str, str]:
    """The time and the opening words of a metric row (contract 6): placed where the series first left its
    baseline, else at the extreme in the direction of change, never at the window start for a later fall.
    A fact without the metric fields (old evidence, or not a metric) keeps its own time and adds no words."""
    data = fact.get('data') if isinstance(fact.get('data'), dict) else {}
    direction = data.get('direction')
    extreme = {'rose': 'maximum_time', 'fell': 'minimum_time'}.get(direction)
    time = fact['time']
    for candidate in (data.get('first_departure_time'), data.get(extreme) if extreme else None):
        if isinstance(candidate, str) and candidate:
            try:
                parse_time(candidate)
            except WindowError:
                continue
            time = candidate
            break
    opening = f'Metric {direction}: ' if direction in ('rose', 'fell') else ''
    return (str(time), opening)

def _fact_text(fact: dict, opening: str) -> str:
    text = opening + str(fact.get('summary', ''))
    excerpt = fact.get('excerpt')
    if isinstance(excerpt, str) and excerpt.strip():
        text += f': "{_cut(excerpt, MAX_ROW_EXCERPT)}"'
    return text

def _raw_rows(case_dir: Path, case: dict, incident: dict, warnings: list[str], unchanged: list[str]) -> list[dict]:
    rows = []
    incident_times = case.get('incident') if isinstance(case.get('incident'), dict) else {}
    for key, text in _INCIDENT_TEXTS:
        if incident_times.get(key):
            rows.append(_row(incident_times[key], 'incident', text))
    for key in ('timeline', 'notes'):
        entries = incident.get(key)
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and entry.get('time'):
                rows.append(_row(entry['time'], 'oneuptime', str(entry.get('text', ''))))
    for file_name, document in evidence_documents(case_dir, warnings):
        for fact in document.get('facts', []):
            if isinstance(fact, dict) and fact.get('kind') == INCIDENT_TIME and fact.get('time'):
                if _shows_no_change(fact):
                    unchanged.append(file_name)
                    continue
                fact_id = fact.get('id')
                time, opening = _metric_placement(fact)
                rows.append(_row(time, str(document.get('collector', '')), _fact_text(fact, opening), qualified_id(file_name, fact_id) if isinstance(fact_id, str) else _BAD_ID, str(fact.get('resource', ''))))
    return rows

def _sort_key(row: dict) -> tuple:
    return (row['_moment'], _SOURCE_RANK.get(row['source'], 2), row['source'], row['fact_id'] or '')

def _window_start(case: dict):
    window = case.get('window')
    try:
        return parse_time(window['start']) if isinstance(window, dict) and window.get('start') else None
    except WindowError:
        return None

def build_timeline(case_dir: Path) -> list[dict]:
    case = _read_json(case_dir / 'case.json')
    incident = _read_json(case_dir / 'incident.json')
    start = parse_time(case['incident_start'])
    window_start = _window_start(case)
    rows = []
    skipped = 0
    unreadable_files: list[str] = []
    unchanged: list[str] = []
    for row in _raw_rows(case_dir, case, incident, unreadable_files, unchanged):
        if row['fact_id'] == _BAD_ID:
            skipped += 1
            continue
        try:
            row['_moment'] = parse_time(row['time'])
        except WindowError:
            skipped += 1
            continue
        row['time'] = format_time(row['_moment'])
        row['offset'] = f"{describe_offset(row['_moment'], start)} the incident started"
        if row['fact_id'] and window_start and (row['_moment'] < window_start):
            row['group'] = BEFORE_WINDOW
        rows.append(row)
    dropped = max(0, len(rows) - MAX_ROWS)
    if dropped:
        rows = sorted(rows, key=lambda row: abs(row['_moment'] - start))[:MAX_ROWS]
    rows.sort(key=_sort_key)
    for row in rows:
        del row['_moment']
    notes = []
    if dropped:
        notes.append(f'{dropped} more rows farther from the incident start were left out')
    if skipped:
        notes.append(f'{skipped} events with an unreadable time or fact id were left out')
    if unchanged:
        notes.append(f'{len(unchanged)} metric facts that showed no change were left out; they are in the evidence files')
    if unreadable_files:
        notes.append(f'{len(unreadable_files)} evidence files were unreadable and left out')
    for text in notes:
        note = _row('', 'timeline', text)
        note['offset'] = ''
        rows.append(note)
    (case_dir / TIMELINE_NAME).write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8')
    return rows

def _cell(text: str) -> str:
    return ' '.join(text.split()).replace('\\', '\\\\').replace('|', '\\|')

def render_rows(rows: list[dict]) -> str:
    """A Markdown table of the rows; notes about rows that were left out follow it as plain lines."""
    header = ['| Time | Relative to incident start | Event | Source |', '| --- | --- | --- | --- |']
    lines = list(header)
    before: list[str] = []
    notes = []
    for row in rows:
        if row['source'] == 'timeline':
            notes.append(row['text'])
            continue
        source = row['fact_id'] or row['source']
        when = row['time'].replace('T', ' ')
        line = f"| {_cell(when)} | {_cell(row['offset'])} | {_cell(row['text'])} | {_cell(source)} |"
        (before if row.get('group') == BEFORE_WINDOW else lines).append(line)
    if before:
        lines += ['', 'Before the window (events dated before the collection window started):', '', *header, *before]
    if notes:
        lines.append('')
        lines.extend(notes)
    return '\n'.join(lines)