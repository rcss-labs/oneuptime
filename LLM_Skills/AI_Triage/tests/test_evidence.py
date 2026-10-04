import json
from datetime import datetime, timezone

import pytest

from triage.evidence import (
    CURRENT,
    DERIVED,
    INCIDENT_TIME,
    MAX_EXCERPT,
    MAX_FACTS,
    Evidence,
    load_evidence,
)
from triage.window import make_window


def make_evidence(**kwargs):
    window = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", 6)
    return Evidence("ecs", "prod-main", "eu-west-1", window, **kwargs)


def add_simple(evidence, **overrides):
    fields = dict(kind=CURRENT, resource="service/a", summary="something")
    fields.update(overrides)
    return evidence.add(**fields)


def test_ids_are_numbered_from_one():
    evidence = make_evidence()
    assert add_simple(evidence).id == "ecs-0001"
    assert add_simple(evidence).id == "ecs-0002"


def test_unknown_kind_is_rejected():
    with pytest.raises(ValueError):
        add_simple(make_evidence(), kind="guess")


def test_all_three_kinds_are_accepted():
    evidence = make_evidence()
    for kind in (INCIDENT_TIME, CURRENT, DERIVED):
        assert add_simple(evidence, kind=kind).kind == kind


def test_datetime_time_is_formatted():
    moment = datetime(2026, 10, 4, 10, 42, 10, 500000, tzinfo=timezone.utc)
    assert add_simple(make_evidence(), time=moment).time == "2026-10-04T10:42:10Z"


def test_string_time_is_parsed_and_reformatted():
    fact = add_simple(make_evidence(), time="2026-10-04T12:42:10.123000+02:00")
    assert fact.time == "2026-10-04T10:42:10Z"


def test_missing_time_is_none():
    assert add_simple(make_evidence()).time is None


def test_excerpt_is_cut_with_an_ellipsis():
    fact = add_simple(make_evidence(), excerpt="x" * 900)
    assert len(fact.excerpt) == MAX_EXCERPT
    assert fact.excerpt.endswith("…")


def test_short_excerpt_is_kept():
    assert add_simple(make_evidence(), excerpt="short").excerpt == "short"


def test_every_text_field_is_redacted():
    password = "hunter" + "2" * 6
    evidence = make_evidence()
    fact = add_simple(
        evidence,
        resource="svc/mail-ops@example.com",
        summary="login with password=" + password,
        excerpt="token=" + password,
        data={"env": [{"name": "DB_PASSWORD", "value": password}]},
    )
    blob = json.dumps(fact.__dict__)
    assert password not in blob
    assert "mail-ops@example.com" not in fact.resource
    assert "<EMAIL-1>" in fact.resource


def test_fact_cap_sets_truncated_and_stores_nothing_more():
    evidence = make_evidence()
    for _ in range(MAX_FACTS):
        assert add_simple(evidence) is not None
    assert not evidence.truncated
    assert add_simple(evidence) is None
    assert evidence.truncated
    assert len(evidence.facts) == MAX_FACTS


def test_add_error_redacts_and_cuts():
    evidence = make_evidence()
    evidence.add_error("aws ecs list-tasks", "AccessDenied", "password=" + "p" * 8 + " " + "y" * 600)
    error = evidence.errors[0]
    assert error["command"] == "aws ecs list-tasks"
    assert error["code"] == "AccessDenied"
    assert "p" * 8 not in error["message"]
    assert len(error["message"]) <= 300


def test_to_dict_matches_the_document():
    evidence = make_evidence()
    add_simple(evidence, kind=INCIDENT_TIME, time="2026-10-04T10:42:10Z", data={"a": 1}, command="aws x")
    document = evidence.to_dict()
    assert set(document) == {"collector", "account", "region", "window", "facts", "errors", "truncated"}
    assert document["window"] == {"start": "2026-10-04T10:00:00Z", "end": "2026-10-04T12:00:00Z"}
    assert set(document["facts"][0]) == {"id", "kind", "time", "resource", "summary", "data", "command", "excerpt"}
    assert document["truncated"] is False
    assert json.loads(evidence.to_json()) == document


def test_write_path_without_suffix(tmp_path):
    path = make_evidence().write(tmp_path)
    assert path == tmp_path / "evidence" / "ecs-prod-main-eu-west-1.json"
    assert path.exists()


def test_write_path_with_cleaned_suffix(tmp_path):
    path = make_evidence().write(tmp_path, suffix="Cluster A/../x")
    assert path.name == "ecs-prod-main-eu-west-1-ClusterAx.json"
    assert path.parent == tmp_path / "evidence"


def test_load_evidence_round_trip(tmp_path):
    evidence = make_evidence()
    add_simple(evidence, time="2026-10-04T10:42:10Z")
    path = evidence.write(tmp_path)
    assert load_evidence(path) == evidence.to_dict()
