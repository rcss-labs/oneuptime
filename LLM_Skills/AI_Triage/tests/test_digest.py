import copy

import pytest

from triage.digest import JUDGED_ACTION_FIELDS, JUDGED_CAUSE_FIELDS, action_digest, cause_digest

FINDINGS = {
    "compute-1": {"id": "compute-1", "claim": "Containers exited", "fact_ids": ["ecs-0001"], "excerpt": "code 137",
                  "confidence": "high", "time": "2026-10-04T10:41:00Z"},
    "compute-2": {"id": "compute-2", "claim": "No tasks", "fact_ids": ["ecs-0002"], "excerpt": "running 0"},
}
CAUSE = {"id": "C1", "statement": "Memory limit", "supporting": ["compute-1"], "contradicting": ["compute-2"],
         "label": "confirmed"}
ACTION = {"id": "A1", "cause": "C1", "title": "Raise memory", "target": {"service": "checkout-api"},
          "current_state": "512", "required_state": "1024", "change": "Set 1024", "label": "recommended",
          "rationale": "not judged", "risk": "low"}
CHANGED = {"id": "C2", "statement": "Other", "supporting": ["compute-2"], "contradicting": [],
           "title": "T", "cause": "C9", "target": {"service": "other"}, "current_state": "1",
           "required_state": "2", "change": "c"}


def test_the_judged_fields_name_what_judging_reads():
    assert set(JUDGED_CAUSE_FIELDS) == {"id", "statement", "supporting", "contradicting"}
    assert set(JUDGED_ACTION_FIELDS) == {"id", "cause", "title", "target", "current_state", "required_state", "change"}


def test_digests_are_sha256_hex_and_stable():
    assert len(cause_digest(CAUSE, FINDINGS)) == 64 and cause_digest(CAUSE, FINDINGS) == cause_digest(copy.deepcopy(CAUSE), copy.deepcopy(FINDINGS))
    assert len(action_digest(ACTION)) == 64 and action_digest(ACTION) == action_digest(copy.deepcopy(ACTION))


@pytest.mark.parametrize("field", JUDGED_CAUSE_FIELDS)
def test_changing_a_judged_cause_field_changes_the_digest(field):
    changed = {**CAUSE, field: CHANGED[field]}
    assert cause_digest(changed, FINDINGS) != cause_digest(CAUSE, FINDINGS)


@pytest.mark.parametrize("field", JUDGED_ACTION_FIELDS)
def test_changing_a_judged_action_field_changes_the_digest(field):
    changed = {**ACTION, field: CHANGED[field]}
    assert action_digest(changed) != action_digest(ACTION)


@pytest.mark.parametrize("field, value", [("label", "candidate"), ("confidence", "low"), ("reasons", ["x"]), ("rationale", "y")])
def test_changing_a_label_or_other_written_field_does_not_change_the_digest(field, value):
    assert cause_digest({**CAUSE, field: value}, FINDINGS) == cause_digest(CAUSE, FINDINGS)
    assert action_digest({**ACTION, field: value}) == action_digest(ACTION)


@pytest.mark.parametrize("field, value", [("claim", "Different"), ("fact_ids", ["ecs-0009"]), ("excerpt", "other")])
def test_changing_a_cited_findings_judged_text_changes_the_cause_digest(field, value):
    for finding_id in ("compute-1", "compute-2"):
        changed = copy.deepcopy(FINDINGS)
        changed[finding_id][field] = value
        assert cause_digest(CAUSE, changed) != cause_digest(CAUSE, FINDINGS)


def test_a_finding_the_cause_does_not_cite_or_unjudged_finding_fields_do_not_matter():
    changed = copy.deepcopy(FINDINGS)
    changed["compute-3"] = {"claim": "x", "fact_ids": [], "excerpt": "y"}
    changed["compute-1"]["confidence"] = "low"
    assert cause_digest(CAUSE, changed) == cause_digest(CAUSE, FINDINGS)


def test_a_missing_field_is_null_and_differs_from_an_empty_one():
    without = {key: value for key, value in CAUSE.items() if key != "contradicting"}
    assert cause_digest(without, FINDINGS) != cause_digest({**CAUSE, "contradicting": []}, FINDINGS)
    assert cause_digest(without, FINDINGS) == cause_digest({**without, "contradicting": None}, FINDINGS)


def test_a_missing_finding_is_digested_as_null():
    assert cause_digest(CAUSE, {}) != cause_digest(CAUSE, FINDINGS)


@pytest.mark.parametrize("bad", [None, 5, "text", [], {"supporting": None}, {"supporting": 3, "contradicting": {"a": 1}},
                                 {"supporting": [["x"], {"y": 1}, 7], "statement": object()}])
def test_a_wrongly_typed_draft_never_raises(bad):
    assert len(cause_digest(bad, FINDINGS)) == 64
    assert len(action_digest(bad)) == 64
    assert len(cause_digest(CAUSE, {"compute-1": "not a dict"})) == 64
    assert len(cause_digest(CAUSE, None)) == 64


def test_non_ascii_text_digests_the_same_way_every_time():
    text = {**CAUSE, "statement": "Speicher überschritten"}
    assert cause_digest(text, FINDINGS) == cause_digest(copy.deepcopy(text), FINDINGS)
