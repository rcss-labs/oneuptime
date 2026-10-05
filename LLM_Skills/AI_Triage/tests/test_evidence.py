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


def test_command_is_redacted_in_facts_and_errors():
    evidence = make_evidence()
    fact = add_simple(evidence, command="aws logs start-query --query-string 'like /bob@example.com/'")
    assert "bob@example.com" not in fact.command
    evidence.add_error("aws logs start-query --query-string 'like /bob@example.com/'", "X", "failed")
    assert "bob@example.com" not in evidence.errors[0]["command"]


def test_write_path_cannot_leave_the_evidence_folder(tmp_path):
    window = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", 6)
    path = Evidence("ecs", "prod-main", "/../../escaped", window).write(tmp_path)
    assert path.parent == tmp_path / "evidence"


def test_summary_is_cut_to_500_characters():
    fact = add_simple(make_evidence(), summary="s" * 900)
    assert len(fact.summary) == 500 and fact.summary.endswith("… [summary cut]")


def test_every_string_in_data_is_cut_at_any_depth():
    fact = add_simple(make_evidence(), data={"a": "x" * 900, "b": [{"c": "y" * 900}], "d": 5, "e": "short"})
    assert len(fact.data["a"]) == 500 and fact.data["a"].endswith("…")
    assert len(fact.data["b"][0]["c"]) == 500
    assert fact.data["d"] == 5 and fact.data["e"] == "short"


def test_summary_that_already_ends_with_the_marker_is_left_alone():
    summary = "x" * 400 + "… [summary cut]"
    assert add_simple(make_evidence(), summary=summary).summary == summary


def test_data_keeps_at_most_50_keys_of_100_characters():
    data = {f"k{n:03d}": n for n in range(60)}
    data["z" * 300] = 1
    fact = add_simple(make_evidence(), data=data)
    assert len(fact.data) == 50
    assert fact.data["keys_omitted"] == 61 - 49
    assert all(len(key) <= 100 for key in fact.data)
    assert "k000" in fact.data and "k048" in fact.data and "k049" not in fact.data


def test_data_with_few_keys_has_no_omission_note():
    fact = add_simple(make_evidence(), data={"a": 1})
    assert fact.data == {"a": 1}


def test_nested_keys_are_cut():
    fact = add_simple(make_evidence(), data={"a": {"k" * 300: 1}})
    assert all(len(key) <= 100 for key in fact.data["a"])


# Fix round 4

def test_keys_equal_after_the_cut_do_not_merge_silently():
    fact = add_simple(make_evidence(), data={"a" * 100 + "1": "first", "a" * 100 + "2": "second"})
    assert fact.data == {"a" * 100: "first", "keys_omitted": 1}


def test_nested_keys_equal_after_the_cut_are_counted():
    fact = add_simple(make_evidence(), data={"inner": {"b" * 100 + "1": 1, "b" * 100 + "2": 2}})
    assert fact.data["inner"] == {"b" * 100: 1, "keys_omitted": 1}


def test_nested_lists_and_dicts_are_capped_at_50_with_a_count_beside_them():
    fact = add_simple(make_evidence(), data={"items": list(range(5000)), "table": {f"k{n}": n for n in range(300)}, "few": [1, 2]})
    assert fact.data["items"] == list(range(50))
    assert fact.data["items_omitted"] == 4950
    assert len(fact.data["table"]) == 50 and fact.data["table_omitted"] == 250
    assert fact.data["few"] == [1, 2] and "few_omitted" not in fact.data


def test_lists_inside_lists_are_capped_with_a_marker_entry():
    fact = add_simple(make_evidence(), data={"rows": [list(range(60))]})
    assert fact.data["rows"][0] == list(range(50)) + ["10 more entries omitted"]


def test_non_finite_numbers_become_text_and_json_is_strict():
    evidence = make_evidence()
    add_simple(evidence, data={"a": float("nan"), "b": [float("inf")], "c": {"d": float("-inf")}, "e": 1.5})
    document = json.loads(evidence.to_json(), parse_constant=lambda name: pytest.fail(f"non-standard JSON {name}"))
    data = document["facts"][0]["data"]
    assert data == {"a": "not a number", "b": ["not a number"], "c": {"d": "not a number"}, "e": 1.5}


def test_write_refuses_to_overwrite_an_existing_file(tmp_path):
    first = make_evidence().write(tmp_path)
    before = first.read_text()
    with pytest.raises(FileExistsError) as raised:
        make_evidence().write(tmp_path)
    assert "--suffix" in str(raised.value)
    assert first.read_text() == before


def test_asked_is_recorded_redacted_and_is_not_a_fact():
    evidence = make_evidence()
    secret_query = "password=" + "sun" + "flower"
    evidence.set_asked({"cluster": "checkout", "log_groups": ["/a", "/b"], "pattern": secret_query},
                       {"start": "2026-10-04T10:00:00Z", "end": "2026-10-04T12:00:00Z"})
    document = evidence.to_dict()
    assert document["asked"]["targets"]["cluster"] == "checkout"
    assert document["asked"]["targets"]["log_groups"] == ["/a", "/b"]
    assert document["asked"]["window"] == {"start": "2026-10-04T10:00:00Z", "end": "2026-10-04T12:00:00Z"}
    assert "sunflower" not in json.dumps(document)
    assert document["facts"] == []


def test_asked_is_absent_until_set():
    assert "asked" not in make_evidence().to_dict()
