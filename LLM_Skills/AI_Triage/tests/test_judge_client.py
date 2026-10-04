"""Tests for the TypeSafe judge client, using the real SDK with the network replaced."""
from __future__ import annotations

import json
import os
import sys

import httpx2
import pytest

from triage.judge_client import JudgeReply, JudgeUnavailable, TypeSafeJudge, _is_well_formed, to_plain

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
            "probabilities": {"0": 0.0, "1": 0.1, "2": 0.4, "3": 0.5},
            "legend": {"0": "none", "1": "some", "2": "most", "3": "all"},
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
        probabilities = {1: 0.25, 0: 0.75}
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


def body_with(question_id: str, **changes) -> bytes:
    """The success body with one answer changed, as raw JSON so NaN and Infinity survive."""
    body = json.loads(json.dumps(SUCCESS_BODY))
    body["answers"][question_id].update(changes)
    return json.dumps(body).encode()


def ask_with_raw_body(content: bytes) -> JudgeReply:
    def handler(request):
        return httpx2.Response(200, content=content, headers={"x-typesafe-request-id": "req-1"})

    return TypeSafeJudge("m", transport=httpx2.MockTransport(handler)).ask({}, QUESTIONS)


def assert_malformed(content: bytes, question_id: str) -> None:
    with pytest.raises(JudgeUnavailable) as caught:
        ask_with_raw_body(content)
    assert caught.value.reason == f"MalformedAnswer: {question_id}"


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity", "-0.1", "1.7"])
def test_noul_outside_zero_to_one_or_not_a_number_is_malformed(bad):
    content = json.dumps(SUCCESS_BODY).replace('"noul": 0.98', f'"noul": {bad}').encode()
    assert_malformed(content, "q1")


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-0.1", "1.7"])
def test_choice_confidence_outside_zero_to_one_is_malformed(bad):
    content = json.dumps(SUCCESS_BODY).replace('"confidence": 1.0', f'"confidence": {bad}').encode()
    assert_malformed(content, "q2")


@pytest.mark.parametrize("bad", ["true", '"0.9"'])
def test_boolean_or_string_numbers_are_refused_whoever_catches_them(bad):
    content = json.dumps(SUCCESS_BODY).replace('"noul": 0.98', f'"noul": {bad}').encode()
    with pytest.raises(JudgeUnavailable):
        ask_with_raw_body(content)


def test_a_boolean_is_not_a_number_in_the_answer_check():
    class Answer:
        noul = True

    assert not _is_well_formed(Answer(), {"type": "noul"})


def test_choice_probability_outside_zero_to_one_is_malformed():
    content = body_with("q2", probabilities={"supports": 1.7, "contradicts": 0.0, "says_nothing": 0.0})
    assert_malformed(content, "q2")


def test_choice_outside_the_options_sent_is_malformed():
    assert_malformed(body_with("q2", choice="partly"), "q2")


def test_choice_probabilities_keyed_by_other_options_are_malformed():
    content = body_with("q2", probabilities={"supports": 0.5, "contradicts": 0.5, "other": 0.0})
    assert_malformed(content, "q2")


def test_score_keyed_one_to_four_is_malformed():
    content = body_with("q3", probabilities={"1": 0.0, "2": 0.1, "3": 0.4, "4": 0.5}, legend={"1": "a", "2": "b", "3": "c", "4": "d"})
    assert_malformed(content, "q3")


def test_score_above_the_top_level_is_malformed():
    assert_malformed(body_with("q3", score=9.0), "q3")


def test_score_below_zero_is_malformed():
    assert_malformed(body_with("q3", score=-0.5), "q3")


def test_score_confidence_nan_is_malformed():
    content = json.dumps(SUCCESS_BODY).replace('"confidence": 0.8', '"confidence": NaN').encode()
    assert_malformed(content, "q3")


def test_choice_probabilities_summing_to_1_8_are_malformed():
    content = body_with("q2", probabilities={"supports": 0.9, "contradicts": 0.9, "says_nothing": 0.0})
    assert_malformed(content, "q2")


def test_choice_that_is_not_the_most_probable_option_is_malformed():
    content = body_with("q2", choice="contradicts", probabilities={"supports": 0.7, "contradicts": 0.2, "says_nothing": 0.1})
    assert_malformed(content, "q2")


def test_choice_tied_for_most_probable_is_accepted():
    content = body_with("q2", choice="contradicts", probabilities={"supports": 0.5, "contradicts": 0.5, "says_nothing": 0.0})
    assert ask_with_raw_body(content).answers["q2"]["choice"] == "contradicts"


def test_sum_within_the_tolerance_is_accepted():
    content = body_with("q2", probabilities={"supports": 0.97, "contradicts": 0.0, "says_nothing": 0.0})
    assert ask_with_raw_body(content).answers["q2"]["choice"] == "supports"


def test_score_probabilities_summing_to_0_4_are_malformed():
    content = body_with("q3", probabilities={"0": 0.1, "1": 0.1, "2": 0.1, "3": 0.1})
    assert_malformed(content, "q3")


def test_sdk_error_is_not_reachable_from_the_raised_exception():
    secret = "body-text-" + "x" * 8
    judge = TypeSafeJudge("m", transport=transport_returning(500, {"error": secret}))
    with pytest.raises(JudgeUnavailable) as caught:
        judge.ask({}, QUESTIONS)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    link, seen = caught.value, 0
    while link is not None and seen < 20:
        assert secret not in repr(link)
        link, seen = link.__cause__ or link.__context__, seen + 1


def test_malformed_reason_holds_no_answer_text():
    with pytest.raises(JudgeUnavailable) as caught:
        ask_with_raw_body(body_with("q2", choice="secret-looking-choice"))
    assert "secret-looking-choice" not in caught.value.reason
    assert "secret-looking-choice" not in repr(caught.value)


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
