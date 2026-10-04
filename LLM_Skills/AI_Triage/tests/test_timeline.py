import json

import pytest

from triage.evidence import CURRENT, INCIDENT_TIME, Evidence
from triage.timeline import build_timeline, render_rows
from triage.window import make_window

START = "2026-10-04T10:42:00Z"
WINDOW = make_window("2026-10-04T09:00:00Z", "2026-10-04T12:00:00Z", 24)


def make_case(tmp_path, incident=None, **incident_times):
    incident_info = {"impact_started_at": None, "declared_at": "2026-10-04T10:45:00Z", "resolved_at": None}
    incident_info.update(incident_times)
    (tmp_path / "case.json").write_text(json.dumps({"incident_start": START, "incident": incident_info}))
    (tmp_path / "incident.json").write_text(json.dumps(incident or {"number": "INC-1", "title": "t", "declared_at": START}))
    return tmp_path


def add_facts(case_dir, collector, facts, region="eu-west-1"):
    evidence = Evidence(collector, "prod-main", region, WINDOW)
    for kind, time, summary in facts:
        evidence.add(kind=kind, resource="res", summary=summary, time=time)
    evidence.write(case_dir)


def test_rows_are_ordered_by_time_with_offsets(tmp_path):
    case = make_case(tmp_path, incident={"timeline": [{"time": "2026-10-04T10:50:00Z", "text": "Paged"}],
                                         "notes": [{"time": "2026-10-04T10:30:00Z", "text": "Deploy noted"}]})
    add_facts(case, "ecs", [(INCIDENT_TIME, "2026-10-04T10:38:00Z", "Tasks stopped")])
    rows = build_timeline(case)
    assert [row["text"] for row in rows] == ["Deploy noted", "Tasks stopped", "Incident declared", "Paged"]
    assert rows[1] == {"time": "2026-10-04T10:38:00Z", "source": "ecs", "fact_id": "ecs-0001", "resource": "res",
                       "text": "Tasks stopped", "offset": "4 minutes before the incident started"}
    assert rows[0]["source"] == "oneuptime" and rows[0]["fact_id"] is None and rows[0]["resource"] == ""
    assert rows[3]["offset"] == "8 minutes after the incident started"


def test_offset_at_the_start(tmp_path):
    case = make_case(tmp_path, impact_started_at=START)
    rows = [row for row in build_timeline(case) if row["text"] == "Impact started"]
    assert rows[0]["offset"] == "at the same time as the incident started"


def test_only_incident_time_facts_are_included(tmp_path):
    case = make_case(tmp_path)
    add_facts(case, "ecs", [(CURRENT, "2026-10-04T10:40:00Z", "now state"), (INCIDENT_TIME, None, "untimed")])
    assert [row["source"] for row in build_timeline(case)] == ["incident"]


def test_incident_rows_use_fixed_texts_and_skip_missing(tmp_path):
    case = make_case(tmp_path, impact_started_at="2026-10-04T10:42:00Z", resolved_at="2026-10-04T11:30:00Z")
    rows = build_timeline(case)
    assert [row["text"] for row in rows] == ["Impact started", "Incident declared", "Incident resolved"]
    assert {row["source"] for row in rows} == {"incident"}


def test_ties_order_incident_then_oneuptime_then_collectors_by_name(tmp_path):
    same = "2026-10-04T10:45:00Z"
    case = make_case(tmp_path, incident={"timeline": [{"time": same, "text": "created"}]})
    add_facts(case, "rds", [(INCIDENT_TIME, same, "rds fact")])
    add_facts(case, "ecs", [(INCIDENT_TIME, same, "ecs fact")])
    assert [row["source"] for row in build_timeline(case)] == ["incident", "oneuptime", "ecs", "rds"]


def test_timeline_json_is_written(tmp_path):
    case = make_case(tmp_path)
    rows = build_timeline(case)
    assert json.loads((case / "timeline.json").read_text()) == rows


def test_missing_incident_json_fields_default_to_empty(tmp_path):
    case = make_case(tmp_path, incident={"number": "INC-1"})
    assert len(build_timeline(case)) == 1


def test_cap_keeps_rows_nearest_to_the_start_and_notes_the_drop(tmp_path):
    entries = [{"time": f"2026-10-04T{h:02d}:{m:02d}:00Z", "text": f"e{h}{m}"} for h in range(0, 10) for m in range(0, 60, 1)]
    case = make_case(tmp_path, incident={"timeline": entries})
    rows = build_timeline(case)
    assert len(rows) == 301
    dropped = rows[-1]
    assert dropped["source"] == "timeline" and dropped["fact_id"] is None
    total = len(entries) + 1
    assert f"{total - 300} " in dropped["text"]
    assert rows[0]["time"] > "2026-10-04T00:00:00Z"
    assert any(row["text"] == "Incident declared" for row in rows)


def test_render_rows_makes_a_table_and_escapes_pipes(tmp_path):
    rows = [{"time": "2026-10-04T10:38:00Z", "source": "ecs", "fact_id": "ecs-0001", "resource": "r",
             "text": "a | b\nc", "offset": "4 minutes before the incident started"},
            {"time": "2026-10-04T10:45:00Z", "source": "incident", "fact_id": None, "resource": "",
             "text": "Incident declared", "offset": "3 minutes after the incident started"}]
    lines = render_rows(rows).splitlines()
    assert lines[0] == "| Time | Relative to incident start | Event | Source |"
    assert lines[1] == "| --- | --- | --- | --- |"
    assert lines[2] == "| 2026-10-04T10:38:00Z | 4 minutes before the incident started | a \\| b c | ecs-0001 |"
    assert lines[3].endswith("| Incident declared | incident |")


def test_render_empty_rows_still_has_header():
    assert len(render_rows([]).splitlines()) == 2
