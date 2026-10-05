import copy

import pytest

from triage.digest import (
    JUDGED_ACTION_FIELDS,
    JUDGED_CAUSE_FIELDS,
    POST_JUDGING_ACTION_FIELDS,
    POST_JUDGING_CAUSE_FIELDS,
    action_digest,
    case_identity,
    cause_digest,
    draft_digest,
)

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


def test_the_post_judging_fields_are_exactly_labels_confidences_and_reasons():
    assert set(POST_JUDGING_CAUSE_FIELDS) == {"label", "confidence", "reasons"}
    assert set(POST_JUDGING_ACTION_FIELDS) == {"label", "confidence", "reasons"}


@pytest.mark.parametrize("field, value", [("label", "candidate"), ("confidence", "low"), ("reasons", ["x"])])
def test_a_label_only_edit_changes_no_digest(field, value):
    assert cause_digest({**CAUSE, field: value}, FINDINGS) == cause_digest(CAUSE, FINDINGS)
    assert action_digest({**ACTION, field: value}) == action_digest(ACTION)
    edited = copy.deepcopy(REPORT)
    edited["causes"][0][field] = value
    edited["actions"][0][field] = value
    assert draft_digest(edited, FINDINGS, IDENTITY) == draft_digest(REPORT, FINDINGS, IDENTITY)


@pytest.mark.parametrize("field, value", [("rationale", "y"), ("risk", "high"), ("verification", ["other"]), ("extra", 1)])
def test_any_other_action_field_is_covered(field, value):
    assert action_digest({**ACTION, field: value}) != action_digest(ACTION)


def test_any_other_cause_field_is_covered():
    assert cause_digest({**CAUSE, "notes": "x"}, FINDINGS) != cause_digest(CAUSE, FINDINGS)


@pytest.mark.parametrize("field, value", [
    ("claim", "Different"), ("fact_ids", ["ecs-0009"]), ("excerpt", "other"), ("time", "2026-10-04T11:30:00Z"),
    ("provenance", "current"), ("matched_text", "new"), ("fact_summaries", {"ecs:ecs-0001": "changed"}),
    ("confidence", "low"), ("analyst", "other"),
])
def test_every_field_of_a_cited_finding_is_covered(field, value):
    for finding_id in ("compute-1", "compute-2"):
        changed = copy.deepcopy(FINDINGS)
        changed[finding_id][field] = value
        assert cause_digest(CAUSE, changed) != cause_digest(CAUSE, FINDINGS)


def test_a_finding_the_cause_does_not_cite_does_not_matter_to_the_cause():
    changed = copy.deepcopy(FINDINGS)
    changed["compute-3"] = {"claim": "x", "fact_ids": [], "excerpt": "y"}
    assert cause_digest(CAUSE, changed) == cause_digest(CAUSE, FINDINGS)


# draft_digest

IDENTITY = "INC-123/20261004-110000"
REPORT = {"symptoms": ["502 on checkout"], "summary": {"scope": "Only checkout", "top_cause": "C1"},
          "causes": [CAUSE, {"id": "C2", "statement": "Scaled to zero", "supporting": ["compute-2"], "contradicting": []}],
          "actions": [ACTION]}


def edited(change):
    report = copy.deepcopy(REPORT)
    findings = copy.deepcopy(FINDINGS)
    change(report, findings)
    return draft_digest(report, findings, IDENTITY)


@pytest.mark.parametrize("change", [
    lambda r, f: r["symptoms"].append("disk full"),
    lambda r, f: r["symptoms"].__setitem__(0, "other"),
    lambda r, f: r["summary"].__setitem__("scope", "Everything"),
    lambda r, f: r["causes"].append({"id": "C3", "statement": "New", "supporting": [], "contradicting": []}),
    lambda r, f: r["causes"][1].__setitem__("statement", "Rewritten competing cause"),
    lambda r, f: r["actions"][0].__setitem__("change", "other"),
    lambda r, f: r["actions"].append({"id": "A2", "cause": "C2"}),
    lambda r, f: f["compute-1"].__setitem__("time", "2026-10-04T11:30:00Z"),
    lambda r, f: f["compute-2"].__setitem__("claim", "changed"),
])
def test_an_edit_anywhere_in_the_draft_changes_the_draft_digest(change):
    assert edited(change) != draft_digest(REPORT, FINDINGS, IDENTITY)


def test_the_draft_digest_does_not_depend_on_cause_or_action_order():
    reordered = copy.deepcopy(REPORT)
    reordered["causes"].reverse()
    assert draft_digest(reordered, FINDINGS, IDENTITY) == draft_digest(REPORT, FINDINGS, IDENTITY)


def test_the_draft_digest_depends_on_the_case():
    assert draft_digest(REPORT, FINDINGS, "INC-123/other-run") != draft_digest(REPORT, FINDINGS, IDENTITY)


def test_case_identity_joins_the_incident_number_and_the_run_folder():
    assert case_identity({"incident": {"number": "INC-123"}, "case_dir": "/home/eng/cases/INC-123/20261004-110000"}) == IDENTITY
    assert case_identity(None) == "/" and case_identity({"incident": 5, "case_dir": None}) == "/"


@pytest.mark.parametrize("bad", [None, 5, "x", [], {"causes": None, "actions": 3, "symptoms": {"a": 1}, "summary": []},
                                 {"causes": [None, 5, {"supporting": [["x"]]}], "actions": ["a"], "summary": {"scope": object()}}])
def test_the_draft_digest_never_raises(bad):
    assert len(draft_digest(bad, FINDINGS, IDENTITY)) == 64
    assert len(draft_digest(REPORT, None, None)) == 64


def test_a_missing_field_differs_from_an_empty_one():
    without = {key: value for key, value in CAUSE.items() if key != "contradicting"}
    assert cause_digest(without, FINDINGS) != cause_digest({**CAUSE, "contradicting": []}, FINDINGS)


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


def test_changing_the_asked_text_of_a_cited_finding_changes_the_cause_digest():
    asked = copy.deepcopy(FINDINGS)
    asked["compute-1"]["asked"] = {"ecs:ecs-0001": ["query=level:INFO"]}
    changed = copy.deepcopy(asked)
    changed["compute-1"]["asked"]["ecs:ecs-0001"].append("filter=service=checkout")
    assert cause_digest(CAUSE, asked) != cause_digest(CAUSE, FINDINGS)
    assert cause_digest(CAUSE, changed) != cause_digest(CAUSE, asked)


# the draft digest covers the report text that is printed

FULL_REPORT = {
    "status": "cause_found", "summary": {"what_broke": "Containers died", "impact": "Checkout returned 502", "scope": "Only checkout",
                                         "top_cause": "C1"},
    "symptoms": ["502 on checkout"],
    "causes": [CAUSE], "actions": [ACTION],
    "hypotheses": [{"id": "H1", "statement": "Memory", "prediction": "137", "test": "events", "result": "confirmed",
                    "finding_ids": ["compute-1"], "cause": "C1"}],
    "open_questions": ["Who changed it?"],
    "coverage": {"typesafe": "available", "not_checked": [{"what": "RDS", "why": "no access"}]},
    "map_changes": [{"note": "add the queue"}], "run": {"engineer": "pat", "duration_minutes": 30},
}


@pytest.mark.parametrize("change", [
    lambda r: r["summary"].__setitem__("what_broke", "Something else"),
    lambda r: r["summary"].__setitem__("impact", "No impact"),
    lambda r: r["open_questions"].append("Another?"),
    lambda r: r["open_questions"].__setitem__(0, "Changed?"),
    lambda r: r["hypotheses"][0].__setitem__("statement", "Other"),
    lambda r: r["hypotheses"][0].__setitem__("prediction", "Other"),
    lambda r: r["hypotheses"][0].__setitem__("test", "Other"),
    lambda r: r["hypotheses"][0].__setitem__("result", "rejected"),
    lambda r: r["hypotheses"][0].__setitem__("cause", None),
    lambda r: r["hypotheses"][0].__setitem__("finding_ids", []),
    lambda r: r["hypotheses"].append({"id": "H2"}),
    lambda r: r["actions"][0].__setitem__("rationale", "Because"),
    lambda r: r["coverage"]["not_checked"][0].__setitem__("why", "all fine"),
    lambda r: r["coverage"]["not_checked"].clear(),
    lambda r: r["map_changes"].append({"note": "x"}),
])
def test_an_edit_to_printed_report_text_changes_the_draft_digest(change):
    edited = copy.deepcopy(FULL_REPORT)
    change(edited)
    assert draft_digest(edited, FINDINGS, IDENTITY) != draft_digest(FULL_REPORT, FINDINGS, IDENTITY)


@pytest.mark.parametrize("change", [
    lambda r: r.__setitem__("status", "unresolved"),
    lambda r: r["summary"].__setitem__("top_cause", None),
    lambda r: r["coverage"].__setitem__("typesafe", "unavailable: down"),
    lambda r: r["run"].__setitem__("engineer", "sam"),
    lambda r: r["run"].__setitem__("duration_minutes", 90),
    lambda r: r["causes"][0].__setitem__("label", "candidate"),
    lambda r: r["actions"][0].__setitem__("label", "candidate"),
])
def test_the_fields_the_judging_step_decides_stay_outside_the_draft_digest(change):
    edited = copy.deepcopy(FULL_REPORT)
    change(edited)
    assert draft_digest(edited, FINDINGS, IDENTITY) == draft_digest(FULL_REPORT, FINDINGS, IDENTITY)


def test_the_hypothesis_order_does_not_matter():
    reordered = copy.deepcopy(FULL_REPORT)
    reordered["hypotheses"].append({"id": "H2", "statement": "x"})
    first = draft_digest(reordered, FINDINGS, IDENTITY)
    reordered["hypotheses"].reverse()
    assert draft_digest(reordered, FINDINGS, IDENTITY) == first
