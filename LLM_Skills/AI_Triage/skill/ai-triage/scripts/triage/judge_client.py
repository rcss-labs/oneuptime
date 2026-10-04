"""A thin client around the official TypeSafe package that answers plain-data questions."""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

API_KEY_VARIABLE = "TYPESAFE_API_KEY"
PROBABILITY_SUM_TOLERANCE = 0.05


class JudgeUnavailable(Exception):
    """The judge cannot answer. The reason is short and never holds the key or request data."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class JudgeReply:
    answers: dict[str, dict]
    model: str
    request_id: str | None
    usage: dict = field(default_factory=dict)


class Judge(Protocol):
    def ask(self, state: Any, questions: dict[str, dict]) -> JudgeReply: ...


def to_plain(answer: Any, question: dict) -> dict:
    """Turn a client answer into the plain dict stored in judgment files."""
    kind = question["type"]
    if kind == "noul":
        return {"type": "noul", "noul": answer.noul}
    if kind == "choice":
        return {
            "type": "choice",
            "choice": answer.choice,
            "confidence": answer.confidence,
            "probabilities": dict(answer.probabilities),
        }
    probabilities = answer.probabilities
    ordered = [probabilities[level] for level in sorted(probabilities)]
    return {
        "type": "score",
        "score": answer.score,
        "confidence": answer.confidence,
        "probabilities": ordered,
        "levels": len(question["criteria"]),
    }


class TypeSafeJudge:
    """Asks TypeSafe through its official client. The key comes only from the environment."""

    def __init__(self, model: str, timeout: float = 30.0, transport: Any = None):
        self.model = model
        self.timeout = timeout
        self._transport = transport

    def ask(self, state: Any, questions: dict[str, dict]) -> JudgeReply:
        try:
            import typesafe_sdk
        except ImportError as error:
            raise JudgeUnavailable("the typesafe-sdk package is not installed") from error
        if not os.environ.get(API_KEY_VARIABLE, "").strip():
            raise JudgeUnavailable(f"{API_KEY_VARIABLE} is not set")

        reason = None
        try:
            sdk_questions = {question_id: _build_question(typesafe_sdk, question) for question_id, question in questions.items()}
            with typesafe_sdk.TypeSafeClient(transport=self._transport) as client:
                result = client.system_one(state, sdk_questions, model=self.model, timeout=self.timeout)
        except typesafe_sdk.TypeSafeError as error:
            reason = _reason(error)
        if reason is not None:
            # Raised outside the except block so the SDK error is not kept as __context__.
            raise JudgeUnavailable(reason)
        return self._reply(result, questions)

    def _reply(self, result: Any, questions: dict[str, dict]) -> JudgeReply:
        answers = {}
        for question_id, question in questions.items():
            source = {"noul": result.nouls, "choice": result.choices, "score": result.scores}[question["type"]]
            if question_id not in source:
                raise JudgeUnavailable(f"MissingAnswer for {question_id}")
            if not _is_well_formed(source[question_id], question):
                raise JudgeUnavailable(f"MalformedAnswer: {question_id}")
            answers[question_id] = to_plain(source[question_id], question)
        return JudgeReply(answers, result.model, _request_id(result), _usage(result.usage))


def _is_probability(value: Any) -> bool:
    return _is_number_between(value, 0.0, 1.0)


def _is_number_between(value: Any, low: float, high: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and low <= value <= high


def _is_well_formed(answer: Any, question: dict) -> bool:
    """Check an answer against the question that was sent, so odd numbers never reach the rules."""
    kind = question["type"]
    if kind == "noul":
        return _is_probability(answer.noul)
    if not _is_probability(answer.confidence):
        return False
    probabilities = answer.probabilities
    if not all(_is_probability(value) for value in probabilities.values()):
        return False
    if not math.isclose(sum(probabilities.values()), 1.0, abs_tol=PROBABILITY_SUM_TOLERANCE):
        return False
    if kind == "choice":
        options = set(question["criteria"])
        if answer.choice not in options or set(probabilities) != options:
            return False
        return probabilities[answer.choice] >= max(probabilities.values())
    levels = len(question["criteria"])
    return _is_number_between(answer.score, 0, levels - 1) and set(probabilities) == set(range(levels))


def _build_question(sdk: Any, question: dict) -> Any:
    kind = question["type"]
    if kind == "noul":
        return sdk.Noul(instructions=question["instructions"])
    if kind == "choice":
        return sdk.Choice(instructions=question["instructions"], criteria=question["criteria"])
    return sdk.Score(instructions=question["instructions"], criteria=question["criteria"])


def _reason(error: Exception) -> str:
    status = getattr(error, "status", None)
    name = type(error).__name__
    return f"{name} (status {status})" if status is not None else name


def _request_id(result: Any) -> str | None:
    try:
        return result.request_id
    except Exception:  # the SDK raises when the response header is absent
        return None


def _usage(usage: Any) -> dict:
    if usage is None:
        return {}
    return {"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens}
