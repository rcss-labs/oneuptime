"""Tests for the TypeSafe judge client, using the real SDK with the network replaced."""
from __future__ import annotations

import json
import os
import sys

import httpx2
import pytest

from triage.judge_client import JudgeReply, JudgeUnavailable, TypeSafeJudge, to_plain

FAKE_KEY = "test-" + "k" * 20

QUESTIONS = {
    "q1": {"type": "noul", "instructions": "Is it so?"},
    "q2": {
        "type": "choice",
        "instructions": "How does `evidence` relate to `claim`?",
        "criteria": {"supports": "yes", "contradicts": "no", "says_nothing": "n/a"},
    },
    "q3": {"type": "score", "instructions": "How much?", "criteria": ["none", "some", "most", "all"]},
}
SUCCESS_BODY = {
    "model": "jev-1.13.0",
    "answers": {
        "q1": {"type": "noul", "noul": 0.98},
        "q2": {
            "type": "choice",
            "choice": "supports",
            "confidence": 1.0,
            "probabilities": {"supports": 1.0, "contradicts": 0.0, "says_nothing": 0.0},
        },
        "q3": {
            "type": "score",
            "score": 2.4,
            "confidence": 0.8,
            "probabilities": {"1": 0.0, "2": 0.1, "3": 0.4, "4": 0.5},
            "legend": {"1": "none", "2": "some", "3": "most", "4": "all"},
        },
    },
    "usage": {"input_tokens": 440, "output_tokens": 60},
}


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", FAKE_KEY)


def transport_returning(status: int = 200, body: dict | None = None, seen: list | None = None):
    def handler(request: httpx2.Request) -> httpx2.Response:
        if seen is not None:
            seen.append(request)
        return httpx2.Response(status, json=SUCCESS_BODY if body is None else body, headers={"x-typesafe-request-id": "req-123"})

    return httpx2.MockTransport(handler)


def test_ask_sends_the_questions_state_and_model():
    seen: list = []
    judge = TypeSafeJudge("jev-1.13.0", timeout=12.0, transport=transport_returning(seen=seen))
    judge.ask({"claim": "c", "evidence": "e"}, QUESTIONS)
    payload = json.loads(seen[0].content)
    assert payload["state"] == {"claim": "c", "evidence": "e"}
    assert payload["model"] == "jev-1.13.0"
    assert payload["questions"]["q1"] == {"type": "noul", "instructions": "Is it so?"}
    assert payload["questions"]["q2"]["type"] == "choice"
    assert payload["questions"]["q2"]["criteria"] == QUESTIONS["q2"]["criteria"]
    assert payload["questions"]["q3"]["type"] == "score"
    assert payload["questions"]["q3"]["criteria"] == QUESTIONS["q3"]["criteria"]


def test_ask_converts_each_answer_type_to_the_plain_shape():
    reply = TypeSafeJudge("jev-1.13.0", transport=transport_returning()).ask({}, QUESTIONS)
    assert reply.answers["q1"] == {"type": "noul", "noul": 0.98}
    assert reply.answers["q2"] == {
        "type": "choice",
        "choice": "supports",
        "confidence": 1.0,
        "probabilities": {"supports": 1.0, "contradicts": 0.0, "says_nothing": 0.0},
    }
    assert reply.answers["q3"] == {
        "type": "score",
        "score": 2.4,
        "confidence": 0.8,
        "probabilities": [0.0, 0.1, 0.4, 0.5],
        "levels": 4,
    }


def test_reply_carries_model_request_id_and_usage():
    reply = TypeSafeJudge("jev-1.13.0", transport=transport_returning()).ask({}, QUESTIONS)
    assert isinstance(reply, JudgeReply)
    assert reply.model == "jev-1.13.0"
    assert reply.request_id == "req-123"
    assert reply.usage == {"input_tokens": 440, "output_tokens": 60}


def test_missing_request_id_header_gives_none():
    def handler(request):
        return httpx2.Response(200, json=SUCCESS_BODY)

    reply = TypeSafeJudge("m", transport=httpx2.MockTransport(handler)).ask({}, QUESTIONS)
    assert reply.request_id is None


def test_to_plain_score_levels_come_from_the_question():
    class Answer:
        score = 1.5
        confidence = 0.5
        probabilities = {2: 0.25, 1: 0.75}
        legend = {}

    plain = to_plain(Answer(), {"type": "score", "criteria": ["a", "b"]})
    assert plain == {"type": "score", "score": 1.5, "confidence": 0.5, "probabilities": [0.75, 0.25], "levels": 2}


def assert_unavailable(judge: TypeSafeJudge, expected_reason: str | None = None) -> JudgeUnavailable:
    with pytest.raises(JudgeUnavailable) as caught:
        judge.ask({}, QUESTIONS)
    assert FAKE_KEY not in caught.value.reason
    assert FAKE_KEY not in repr(caught.value)
    assert FAKE_KEY not in str(caught.value)
    if expected_reason is not None:
        assert caught.value.reason == expected_reason
    return caught.value


def test_package_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "typesafe_sdk", None)
    assert_unavailable(TypeSafeJudge("m"), "the typesafe-sdk package is not installed")


def test_key_missing(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY")
    assert_unavailable(TypeSafeJudge("m", transport=transport_returning()), "TYPESAFE_API_KEY is not set")


def test_key_blank(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "   ")
    assert_unavailable(TypeSafeJudge("m", transport=transport_returning()), "TYPESAFE_API_KEY is not set")


def test_key_check_happens_before_any_request(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY")
    seen: list = []
    assert_unavailable(TypeSafeJudge("m", transport=transport_returning(seen=seen)))
    assert seen == []


def test_api_error_reports_class_and_status_without_the_key():
    judge = TypeSafeJudge("m", transport=transport_returning(401, {"error": f"bad key {FAKE_KEY}"}))
    error = assert_unavailable(judge)
    assert "TypeSafeAuthenticationError" in error.reason
    assert "401" in error.reason


def test_connection_error_reports_the_class():
    def handler(request):
        raise httpx2.ConnectError("boom " + FAKE_KEY)

    error = assert_unavailable(TypeSafeJudge("m", transport=httpx2.MockTransport(handler)))
    assert "TypeSafeAPIConnectionError" in error.reason


def test_malformed_answer_body_is_unavailable_not_a_crash():
    error = assert_unavailable(TypeSafeJudge("m", transport=transport_returning(200, {"model": "m", "answers": "nope"})))
    assert error.reason


@pytest.mark.skipif(os.environ.get("AI_TRIAGE_LIVE_TYPESAFE") != "1", reason="live TypeSafe test; set AI_TRIAGE_LIVE_TYPESAFE=1")
def test_live_evidence_relation_has_the_expected_shape():
    from pathlib import Path

    from triage.questions import default_questions_path, load_questions

    skill_dir = Path(__file__).resolve().parent.parent / "skill" / "ai-triage"
    question = load_questions(default_questions_path(skill_dir))["evidence_relation"]
    state = {
        "claim": "The service orders-api-example restarted at 10:02.",
        "evidence": "Pod orders-api-example-7d9f restarted at 10:02 with exit code 137.",
    }
    reply = TypeSafeJudge("jev-1.13.0").ask(state, {"evidence_relation": question})
    answer = reply.answers["evidence_relation"]
    assert answer["type"] == "choice"
    assert answer["choice"] in question["criteria"]
    assert set(answer["probabilities"]) == set(question["criteria"])
    assert 0.0 <= answer["confidence"] <= 1.0
