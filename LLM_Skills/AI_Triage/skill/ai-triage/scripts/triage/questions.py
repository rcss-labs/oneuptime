"""Load and validate the fixed question set, and build run-time choice questions."""
from __future__ import annotations
import copy
import json
from pathlib import Path
from typing import Any, Sequence
QUESTION_TYPES = ('noul', 'choice', 'score')
REQUIRED_IDS = ('evidence_relation', 'symptom_fit', 'scope_fit', 'cause_rank', 'remediation_target', 'action_specific', 'resource_match')
SUPPORTED_VERSION = 1
SCORE_LEVELS_MIN = 2
SCORE_LEVELS_MAX = 10
CHOICE_OPTIONS_MIN = 2
TOP_LEVEL_KEYS = {'version', 'questions'}
QUESTION_KEYS = {'type', 'instructions', 'criteria', 'criteria_from', 'fallback'}

class QuestionError(Exception):
    """Raised with every problem found, not just the first."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__('; '.join(self.errors))

def default_questions_path(skill_dir: Path) -> Path:
    return skill_dir / 'judgments' / 'questions.json'

def load_questions(path: Path) -> dict[str, dict]:
    try:
        document = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise QuestionError([f'cannot read the question file {path}: {error}']) from error
    if not isinstance(document, dict):
        raise QuestionError(['the question file must hold a JSON object'])
    errors: list[str] = []
    for key in sorted(set(document) - TOP_LEVEL_KEYS):
        errors.append(f"unknown key '{key}' in the question file")
    if document.get('version') != SUPPORTED_VERSION:
        errors.append(f'version must be {SUPPORTED_VERSION}')
    questions = document.get('questions')
    if not isinstance(questions, dict):
        errors.append('questions must be an object')
        raise QuestionError(errors)
    for missing in REQUIRED_IDS:
        if missing not in questions:
            errors.append(f"the required question '{missing}' is missing")
    for question_id, question in questions.items():
        errors.extend(_check_question(question_id, question))
    if errors:
        raise QuestionError(errors)
    return questions

def _check_question(question_id: str, question: Any) -> list[str]:
    if not isinstance(question, dict):
        return [f"question '{question_id}' must be an object"]
    errors = [f"question '{question_id}' has unknown key '{key}'" for key in sorted(set(question) - QUESTION_KEYS)]
    instructions = question.get('instructions')
    if not isinstance(instructions, str) or not instructions.strip():
        errors.append(f"question '{question_id}' needs non-empty instructions")
    kind = question.get('type')
    if kind == 'noul':
        errors.extend(_check_noul(question_id, question))
    elif kind == 'choice':
        errors.extend(_check_choice(question_id, question))
    elif kind == 'score':
        errors.extend(_check_score(question_id, question))
    else:
        errors.append(f"question '{question_id}' has type {kind!r}; it must be one of {', '.join(QUESTION_TYPES)}")
    return errors

def _check_noul(question_id: str, question: dict) -> list[str]:
    if 'criteria' in question:
        return [f"question '{question_id}' is a noul and must not have criteria"]
    return []

def _check_score(question_id: str, question: dict) -> list[str]:
    criteria = question.get('criteria')
    if not isinstance(criteria, list) or not SCORE_LEVELS_MIN <= len(criteria) <= SCORE_LEVELS_MAX:
        return [f"question '{question_id}' is a score and needs a criteria list of {SCORE_LEVELS_MIN} to {SCORE_LEVELS_MAX} strings"]
    if not all((isinstance(level, str) and level.strip() for level in criteria)):
        return [f"question '{question_id}' has a blank or non-string score criterion"]
    return []

def _check_choice(question_id: str, question: dict) -> list[str]:
    has_criteria = 'criteria' in question
    has_source = 'criteria_from' in question
    if has_criteria == has_source:
        return [f"question '{question_id}' is a choice and needs either criteria or criteria_from, not both and not neither"]
    if has_criteria:
        criteria = question['criteria']
        if not isinstance(criteria, dict) or len(criteria) < CHOICE_OPTIONS_MIN:
            return [f"question '{question_id}' needs a criteria object with at least two options"]
        if not all((isinstance(text, str) and text.strip() for text in criteria.values())):
            return [f"question '{question_id}' has a blank option description"]
        if 'fallback' in question:
            return [f"question '{question_id}' has a fallback but no criteria_from"]
        return []
    errors = []
    if not isinstance(question['criteria_from'], str) or not question['criteria_from'].strip():
        errors.append(f"question '{question_id}' needs criteria_from to name a state key")
    fallback = question.get('fallback')
    if not isinstance(fallback, dict) or len(fallback) != 1:
        errors.append(f"question '{question_id}' uses criteria_from and needs a fallback with exactly one option")
    return errors

def build_choice(question: dict, options: dict[str, str], order: Sequence[str]) -> dict:
    """Return the question with its criteria set to the options in the given order, then the fallback."""
    if 'criteria_from' not in question:
        raise QuestionError(['build_choice needs a question that has criteria_from'])
    if not options:
        raise QuestionError(['build_choice needs at least one option'])
    fallback = question['fallback']
    fallback_name, = fallback
    if fallback_name in options:
        raise QuestionError([f"the option name '{fallback_name}' is the fallback name"])
    if sorted(order) != sorted(options) or len(set(order)) != len(order):
        raise QuestionError(['the order must list each option exactly once'])
    built = {key: copy.deepcopy(value) for key, value in question.items() if key not in ('criteria_from', 'fallback')}
    built['criteria'] = {name: options[name] for name in order} | dict(fallback)
    return built