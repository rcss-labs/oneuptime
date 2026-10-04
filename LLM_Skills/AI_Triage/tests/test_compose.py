from datetime import datetime, timezone

import pytest

from triage import compose
from triage.compose import (
    ACTION_SPECIFIC_MIN,
    ACTION_TARGET_CONFIDENCE,
    CONTRADICT_CONFIDENCE,
    LABEL_ORDER,
    MAX_FINDINGS_JUDGED,
    SYMPTOM_FIT_MIN,
    TIMING_TOLERANCE_SECONDS,
    action_label,
    cap_label,
    cause_label,
    finding_verdict,
    timing_gate,
)

THRESHOLDS = {"evidence_supports": 0.8, "cause_top_probability": 0.6, "ask_engineer_below": 0.5}
START = datetime(2026, 10, 4, 10, 42, 0, tzinfo=timezone.utc)
ALL_TRUE = {"evidence": True, "no_contradiction": True, "rank": True, "timing": True, "symptom_fit": True, "scope": True}


def relation(name, confidence):
    return {"type": "choice", "choice": name, "confidence": confidence, "probabilities": {name: confidence}}


def test_constants_match_the_plan():
    assert (CONTRADICT_CONFIDENCE, SYMPTOM_FIT_MIN, ACTION_TARGET_CONFIDENCE, ACTION_SPECIFIC_MIN) == (0.6, 0.67, 0.6, 0.7)
    assert (TIMING_TOLERANCE_SECONDS, MAX_FINDINGS_JUDGED) == (300, 40)
    assert LABEL_ORDER == ("candidate", "probable", "confirmed")


# finding_verdict

@pytest.mark.parametrize("name, confidence, verdict", [
    ("supports", 0.8, "verified"),
    ("supports", 0.79, "uncertain"),
    ("contradicts", 0.6, "contradicted"),
    ("contradicts", 0.59, "uncertain"),
    ("says_nothing", 0.8, "unsupported"),
    ("says_nothing", 0.79, "uncertain"),
    ("supports", 0.99, "verified"),
    ("contradicts", 0.99, "contradicted"),
])
def test_finding_verdict_branches_and_boundaries(name, confidence, verdict):
    assert finding_verdict(relation(name, confidence), THRESHOLDS) == verdict


def test_finding_verdict_uses_the_configured_threshold():
    assert finding_verdict(relation("supports", 0.85), {**THRESHOLDS, "evidence_supports": 0.9}) == "uncertain"


# timing_gate

def cause(*ids):
    return {"id": "C1", "supporting": list(ids), "contradicting": []}


def finding(provenance="incident_time", time="2026-10-04T10:41:00Z"):
    return {"provenance": provenance, "time": time}


def test_timing_true_when_the_finding_is_before_the_start():
    assert timing_gate(cause("f1"), {"f1": finding()}, START) is True


def test_timing_true_within_the_tolerance_and_at_its_edge():
    assert timing_gate(cause("f1"), {"f1": finding(time="2026-10-04T10:44:00Z")}, START) is True
    assert timing_gate(cause("f1"), {"f1": finding(time="2026-10-04T10:47:00Z")}, START) is True


def test_timing_false_after_the_tolerance():
    assert timing_gate(cause("f1"), {"f1": finding(time="2026-10-04T10:47:01Z")}, START) is False


def test_timing_none_when_no_supporting_finding_has_a_time():
    assert timing_gate(cause("f1", "f2"), {"f1": finding(time=None), "f2": finding("current", None)}, START) is None
    assert timing_gate(cause(), {}, START) is None


def test_timing_ignores_current_findings_even_when_early():
    assert timing_gate(cause("f1"), {"f1": finding("current", "2026-10-04T10:00:00Z")}, START) is False


def test_timing_one_early_incident_time_finding_is_enough():
    findings = {"f1": finding(time="2026-10-04T11:30:00Z"), "f2": finding(time="2026-10-04T10:40:00Z")}
    assert timing_gate(cause("f1", "f2"), findings, START) is True


def test_timing_ignores_findings_that_are_not_supporting():
    cause_with_other = {"id": "C1", "supporting": ["f1"], "contradicting": ["f2"]}
    findings = {"f1": finding(time=None), "f2": finding()}
    assert timing_gate(cause_with_other, findings, START) is None


# cause_label

def test_all_gates_true_is_confirmed():
    assert cause_label(ALL_TRUE) == "confirmed"


@pytest.mark.parametrize("gate", ["evidence", "rank", "timing", "symptom_fit", "scope"])
def test_one_false_gate_is_probable(gate):
    assert cause_label({**ALL_TRUE, gate: False}) == "probable"


def test_two_false_gates_are_a_candidate():
    assert cause_label({**ALL_TRUE, "timing": False, "scope": False}) == "candidate"


def test_a_contradiction_alone_makes_a_candidate():
    assert cause_label({**ALL_TRUE, "no_contradiction": False}) == "candidate"


def test_a_cause_that_is_not_the_ranking_choice_is_a_candidate():
    assert cause_label({**ALL_TRUE, "rank": False}, top_choice=False) == "candidate"
    assert cause_label({**ALL_TRUE, "rank": False}, top_choice=True) == "probable"


# action_label

CONFIRMED_TARGET = {"type": "choice", "choice": "addresses_cause", "confidence": 0.6}


def test_action_recommended_when_everything_holds():
    assert action_label("confirmed", CONFIRMED_TARGET, 0.7) == ("recommended", [])


def test_action_misses_when_the_cause_is_not_confirmed():
    label, reasons = action_label("probable", CONFIRMED_TARGET, 0.9)
    assert label == "candidate" and len(reasons) == 1 and "probable" in reasons[0]


def test_action_misses_when_the_target_is_another_answer():
    label, reasons = action_label("confirmed", {**CONFIRMED_TARGET, "choice": "addresses_symptom_only"}, 0.9)
    assert label == "candidate" and len(reasons) == 1 and "addresses_symptom_only" in reasons[0]


def test_action_misses_when_the_target_confidence_is_low():
    label, reasons = action_label("confirmed", {**CONFIRMED_TARGET, "confidence": 0.59}, 0.9)
    assert label == "candidate" and len(reasons) == 1 and "0.59" in reasons[0] and "0.6" in reasons[0]


def test_action_misses_when_it_is_not_specific_enough():
    label, reasons = action_label("confirmed", CONFIRMED_TARGET, 0.69)
    assert label == "candidate" and len(reasons) == 1 and "0.69" in reasons[0] and "0.7" in reasons[0]


def test_action_reports_every_miss():
    label, reasons = action_label("candidate", {**CONFIRMED_TARGET, "choice": "unrelated"}, 0.1)
    assert label == "candidate" and len(reasons) == 3


# cap_label

@pytest.mark.parametrize("label, cap, expected", [
    ("confirmed", "probable", "probable"),
    ("probable", "probable", "probable"),
    ("candidate", "probable", "candidate"),
    ("confirmed", "candidate", "candidate"),
])
def test_cap_label_never_raises_a_label(label, cap, expected):
    assert cap_label(label, cap) == expected



# fail closed on answers that are not probabilities

NOT_PROBABILITIES = [float("nan"), float("inf"), float("-inf"), -0.1, 1.01, 7.0, True, "0.9", None]


@pytest.mark.parametrize("bad", NOT_PROBABILITIES)
def test_a_confidence_that_is_not_a_probability_is_uncertain(bad):
    for name in ("supports", "contradicts", "says_nothing"):
        assert finding_verdict(relation(name, bad), THRESHOLDS) == "uncertain"


def test_a_choice_that_is_not_text_is_uncertain():
    assert finding_verdict({"choice": None, "confidence": 0.99}, THRESHOLDS) == "uncertain"
    assert finding_verdict({"choice": ["supports"], "confidence": 0.99}, THRESHOLDS) == "uncertain"


@pytest.mark.parametrize("bad", NOT_PROBABILITIES)
def test_an_action_target_confidence_that_is_not_a_probability_is_a_miss(bad):
    label, reasons = action_label("confirmed", {**CONFIRMED_TARGET, "confidence": bad}, 0.9)
    assert label == "candidate" and len(reasons) == 1


@pytest.mark.parametrize("bad", NOT_PROBABILITIES)
def test_an_action_specificity_that_is_not_a_probability_is_a_miss(bad):
    label, reasons = action_label("confirmed", CONFIRMED_TARGET, bad)
    assert label == "candidate" and len(reasons) == 1


def test_probability_accepts_the_closed_unit_interval_only():
    assert [compose.probability(value) for value in (0, 0.0, 0.5, 1, 1.0)] == [0, 0.0, 0.5, 1, 1.0]
    assert all(compose.probability(value) is None for value in NOT_PROBABILITIES)


def test_symptom_fit_value_needs_a_score_inside_its_levels():
    good = {"score": 2.0, "levels": 4}
    assert compose.symptom_fit_value(good) == pytest.approx(2 / 3)
    for bad in ({"score": 9.0, "levels": 4}, {"score": -1.0, "levels": 4}, {"score": float("nan"), "levels": 4},
                {"score": 1.0, "levels": 1}, {"score": 1.0, "levels": 0}, {"score": 1.0, "levels": "4"},
                {"score": True, "levels": 4}, {"levels": 4}, {}):
        assert compose.symptom_fit_value(bad) is None


def test_number_text_never_raises_on_odd_values():
    assert compose.number(0.48) == "0.48" and compose.number(0.6) == "0.6"
    assert compose.number(None) == "invalid" and compose.number("x") == "invalid"
