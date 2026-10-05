"""Tests for the reviewed question file and its loader."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from triage.questions import (
    REQUIRED_IDS,
    QuestionError,
    build_choice,
    default_questions_path,
    load_questions,
)

SKILL_DIR = Path(__file__).resolve().parent.parent / "skill" / "ai-triage"


def valid_document() -> dict:
    return copy.deepcopy(json.loads(default_questions_path(SKILL_DIR).read_text()))


def write(tmp_path: Path, document) -> Path:
    path = tmp_path / "questions.json"
    path.write_text(json.dumps(document))
    return path


def errors_for(tmp_path: Path, document) -> list[str]:
    with pytest.raises(QuestionError) as caught:
        load_questions(write(tmp_path, document))
    return caught.value.errors


def test_shipped_file_loads_with_exactly_the_required_ids():
    questions = load_questions(default_questions_path(SKILL_DIR))
    assert set(questions) == set(REQUIRED_IDS)
    assert len(REQUIRED_IDS) == 7


def test_default_path_is_under_judgments():
    assert default_questions_path(SKILL_DIR) == SKILL_DIR / "judgments" / "questions.json"


def test_wrong_version_is_reported(tmp_path):
    document = valid_document()
    document["version"] = 2
    assert any("version" in e for e in errors_for(tmp_path, document))


def test_unreadable_or_non_object_file_is_reported(tmp_path):
    path = tmp_path / "questions.json"
    path.write_text("{not json")
    with pytest.raises(QuestionError):
        load_questions(path)
    with pytest.raises(QuestionError):
        load_questions(tmp_path / "missing.json")
    assert errors_for(tmp_path, [1, 2])


def test_missing_required_id_is_reported(tmp_path):
    document = valid_document()
    del document["questions"]["scope_fit"]
    assert any("scope_fit" in e for e in errors_for(tmp_path, document))


def test_unknown_type_is_reported(tmp_path):
    document = valid_document()
    document["questions"]["scope_fit"]["type"] = "essay"
    assert any("scope_fit" in e and "type" in e for e in errors_for(tmp_path, document))


def test_empty_instructions_are_reported(tmp_path):
    document = valid_document()
    document["questions"]["scope_fit"]["instructions"] = "  "
    assert any("scope_fit" in e and "instructions" in e for e in errors_for(tmp_path, document))


def test_choice_with_one_option_is_reported(tmp_path):
    document = valid_document()
    document["questions"]["scope_fit"]["criteria"] = {"only": "one option"}
    assert any("scope_fit" in e and "two" in e for e in errors_for(tmp_path, document))


def test_choice_needs_criteria_or_criteria_from(tmp_path):
    document = valid_document()
    del document["questions"]["scope_fit"]["criteria"]
    assert any("scope_fit" in e and "criteria" in e for e in errors_for(tmp_path, document))


def test_choice_with_both_criteria_and_criteria_from_is_reported(tmp_path):
    document = valid_document()
    document["questions"]["cause_rank"]["criteria"] = {"a": "x", "b": "y"}
    assert any("cause_rank" in e for e in errors_for(tmp_path, document))


def test_criteria_from_without_fallback_is_reported(tmp_path):
    document = valid_document()
    del document["questions"]["cause_rank"]["fallback"]
    assert any("cause_rank" in e and "fallback" in e for e in errors_for(tmp_path, document))


def test_fallback_with_two_options_is_reported(tmp_path):
    document = valid_document()
    document["questions"]["cause_rank"]["fallback"] = {"a": "x", "b": "y"}
    assert any("cause_rank" in e and "fallback" in e for e in errors_for(tmp_path, document))


def test_score_with_one_level_or_eleven_is_reported(tmp_path):
    document = valid_document()
    document["questions"]["symptom_fit"]["criteria"] = ["only one"]
    assert any("symptom_fit" in e for e in errors_for(tmp_path, document))
    document["questions"]["symptom_fit"]["criteria"] = [f"level {n}" for n in range(11)]
    assert any("symptom_fit" in e for e in errors_for(tmp_path, document))


def test_score_with_blank_level_is_reported(tmp_path):
    document = valid_document()
    document["questions"]["symptom_fit"]["criteria"] = ["fine", ""]
    assert any("symptom_fit" in e for e in errors_for(tmp_path, document))


def test_noul_with_criteria_is_reported(tmp_path):
    document = valid_document()
    document["questions"]["action_specific"]["criteria"] = ["x"]
    assert any("action_specific" in e and "criteria" in e for e in errors_for(tmp_path, document))


def test_unknown_keys_are_reported(tmp_path):
    document = valid_document()
    document["extra"] = 1
    document["questions"]["scope_fit"]["colour"] = "red"
    errors = errors_for(tmp_path, document)
    assert any("extra" in e for e in errors)
    assert any("scope_fit" in e and "colour" in e for e in errors)


def test_several_problems_are_reported_together(tmp_path):
    document = valid_document()
    document["version"] = 3
    del document["questions"]["scope_fit"]
    document["questions"]["symptom_fit"]["criteria"] = ["one"]
    document["questions"]["action_specific"]["criteria"] = ["x"]
    assert len(errors_for(tmp_path, document)) >= 4


@pytest.fixture
def cause_rank() -> dict:
    return load_questions(default_questions_path(SKILL_DIR))["cause_rank"]


def test_build_choice_keeps_order_and_puts_fallback_last(cause_rank):
    built = build_choice(cause_rank, {"C1": "first", "C2": "second", "C3": "third"}, ["C3", "C1", "C2"])
    assert list(built["criteria"]) == ["C3", "C1", "C2", "insufficient_evidence"]
    assert built["criteria"]["C3"] == "third"
    assert built["criteria"]["insufficient_evidence"] == "No candidate is clearly supported by its evidence"
    assert built["instructions"] == cause_rank["instructions"]
    assert built["type"] == "choice"


def test_build_choice_does_not_change_the_question(cause_rank):
    before = copy.deepcopy(cause_rank)
    build_choice(cause_rank, {"C1": "a"}, ["C1"])
    assert cause_rank == before


def test_build_choice_refuses_a_question_without_criteria_from():
    question = load_questions(default_questions_path(SKILL_DIR))["scope_fit"]
    with pytest.raises(QuestionError):
        build_choice(question, {"a": "x"}, ["a"])


def test_build_choice_refuses_no_options(cause_rank):
    with pytest.raises(QuestionError):
        build_choice(cause_rank, {}, [])


def test_build_choice_refuses_the_fallback_name_as_an_option(cause_rank):
    with pytest.raises(QuestionError):
        build_choice(cause_rank, {"insufficient_evidence": "x", "C1": "y"}, ["C1", "insufficient_evidence"])


def test_build_choice_refuses_an_order_that_does_not_match_the_options(cause_rank):
    with pytest.raises(QuestionError):
        build_choice(cause_rank, {"C1": "a", "C2": "b"}, ["C1"])


def test_evidence_relation_tells_the_judge_how_to_read_the_asked_text():
    instructions = valid_document()["questions"]["evidence_relation"]["instructions"]
    assert instructions == ("How does `evidence` relate to `claim`? Each evidence item states under asked what was "
                            "requested from the source; a count or a match means only what that request can show.")
