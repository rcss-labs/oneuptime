import copy
import json
import random

import pytest

from fakes import FakeJudge
from triage import compose
from triage.config import parse_config
from triage.evidence import CURRENT, INCIDENT_TIME, Evidence
from triage.findings import check_findings
from triage.judge import (
    JudgeSession,
    JudgmentStore,
    judge_actions,
    judge_causes,
    judge_findings,
    match_resource,
    prepare_state,
    rank_causes,
    run_adhoc,
    run_judgments,
)
from triage.judge_client import JudgeReply, JudgeUnavailable
from triage.questions import load_questions
from triage.redact import Redactor
from triage.window import make_window
from conftest import SKILL_SRC

QUESTIONS = load_questions(SKILL_SRC / "judgments" / "questions.json")
WINDOW = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", 24)
CLAIM_1 = "Deployment failed because containers exited with code 137"
CLAIM_2 = "The service currently has no running tasks"
CLAIM_3 = "Autoscaling was unchanged"
STATEMENT_1 = "Containers of checkout-api:42 are killed for exceeding their memory limit"
STATEMENT_2 = "The service was scaled to zero"
SYMPTOMS = ["The health check of checkout.example.com returns 502"]
SCOPE = "Only checkout was affected; payments kept working"


@pytest.fixture
def config(config_data):
    return parse_config(config_data)


def build_case(tmp_path, config, extra_facts=0, labels=("confirmed", "candidate")):
    """A case folder with evidence, checked findings, case.json, and a report draft."""
    evidence = Evidence("ecs", "prod-main", "eu-west-1", WINDOW)
    evidence.add(kind=INCIDENT_TIME, resource="svc", summary="Essential container exited with code 137", time="2026-10-04T10:41:00Z")
    evidence.add(kind=CURRENT, resource="svc", summary="Service has 0 running tasks", time="2026-10-04T10:55:00Z", excerpt="desired 2, running 0")
    evidence.add(kind=INCIDENT_TIME, resource="svc", summary="Autoscaling policy unchanged", time="2026-10-04T10:50:00Z")
    for index in range(extra_facts):
        evidence.add(kind=CURRENT, resource=f"other-{index}", summary=f"Unrelated fact number {index} " + "x" * 150)
    evidence.write(tmp_path, "")

    def finding(number, claim, fact, excerpt, provenance, time):
        return {"id": f"compute-{number}", "claim": claim, "fact_ids": [fact], "excerpt": excerpt,
                "provenance": provenance, "confidence": "high", "time": time}

    findings = [
        finding(1, CLAIM_1, "ecs-0001", "exited with code 137", "incident_time", "2026-10-04T10:41:10Z"),
        finding(2, CLAIM_2, "ecs-0002", "0 running tasks", "current", None),
        finding(3, CLAIM_3, "ecs-0003", "policy unchanged", "incident_time", "2026-10-04T10:50:00Z"),
        finding(4, "Nobody lists this one", "ecs-0001", "with code 137", "incident_time", None),
    ]
    (tmp_path / "findings").mkdir()
    (tmp_path / "findings" / "compute.json").write_text(json.dumps({"analyst": "compute", "findings": findings}))
    assert check_findings(tmp_path)["rejected"] == []

    (tmp_path / "case.json").write_text(json.dumps({
        "case_dir": str(tmp_path),
        "incident": {"number": "INC-123", "title": "Checkout API is down", "url": "", "severity": "", "state": "",
                     "declared_at": "2026-10-04T10:45:00Z", "impact_started_at": "2026-10-04T10:42:00Z", "resolved_at": None},
        "incident_start": "2026-10-04T10:42:00Z",
        "window": {"start": "2026-10-04T09:42:00Z", "end": "2026-10-04T11:00:00Z"},
        "match": {"status": "many", "candidates": []},
        "target": None,
    }))
    account = config.accounts["prod-main"]
    action = {"type": "mitigation", "label": "recommended", "title": "Raise the memory limit",
              "target": {"account_alias": "prod-main", "account_id": account.account_id, "region": "eu-west-1",
                         "service": "checkout-api", "resource_id": "checkout/checkout-api", "arn": ""},
              "current_state": "memory 512", "required_state": "memory 1024", "change": "Set memory to 1024",
              "rationale": "not sent", "finding_ids": ["compute-1"]}
    report = {
        "status": "cause_found",
        "summary": {"what_broke": "", "impact": "", "scope": SCOPE, "top_cause": "C1"},
        "symptoms": list(SYMPTOMS),
        "causes": [
            {"id": "C1", "statement": STATEMENT_1, "label": labels[0], "supporting": ["compute-1"], "contradicting": ["compute-3"]},
            {"id": "C2", "statement": STATEMENT_2, "label": labels[1], "supporting": ["compute-2"], "contradicting": []},
        ],
        "actions": [
            {**action, "id": "A1", "cause": "C1"},
            {**action, "id": "A2", "cause": "C2", "label": "candidate", "title": "Scale the service back up"},
        ],
    }
    (tmp_path / "report.json").write_text(json.dumps(report))
    return tmp_path


def choice(name, confidence, question):
    options = list(question["criteria"])
    rest = (1 - confidence) / (len(options) - 1)
    return {"type": "choice", "choice": name, "confidence": confidence,
            "probabilities": {option: (confidence if option == name else rest) for option in options}}


def make_responder(relations=None, rank=(("C1", 0.72), ("C1", 0.72)), fit=2.5, scope="matches",
                   target=("addresses_cause", 0.9), specific=0.88):
    relations = relations or {CLAIM_3: ("says_nothing", 0.9)}
    counter = {"rank": 0}

    def respond(state, questions):
        answers = {}
        for question_id, question in questions.items():
            if question_id == "evidence_relation":
                name, confidence = relations.get(state["claim"], ("supports", 0.93))
                answers[question_id] = choice(name, confidence, question)
            elif question_id == "symptom_fit":
                answers[question_id] = {"type": "score", "score": fit, "confidence": 0.8,
                                        "probabilities": [0.0, 0.1, 0.4, 0.5], "levels": 4}
            elif question_id == "scope_fit":
                answers[question_id] = choice(scope, 0.9, question)
            elif question_id == "cause_rank":
                name, confidence = rank[counter["rank"]]
                counter["rank"] += 1
                answers[question_id] = choice(name, confidence, question)
            elif question_id == "remediation_target":
                answers[question_id] = choice(target[0], target[1], question)
            elif question_id == "action_specific":
                answers[question_id] = {"type": "noul", "noul": specific}
        return answers

    return respond


def run(case_dir, config, judge, seed=1):
    return run_judgments(case_dir, config, judge, QUESTIONS, random.Random(seed))


def session_for(tmp_path, config, judge):
    return JudgeSession(judge, JudgmentStore(tmp_path), config, Redactor())


# prepare_state

def test_prepare_state_redacts_at_every_depth(config):
    secret = "hunter" + "2"
    state = {"outer": [{"inner": {"password": secret}}], "text": f"password={secret}"}
    result = prepare_state(state, config, Redactor())
    assert secret not in json.dumps(result)


def test_prepare_state_replaces_a_configured_account_id_with_its_alias(config):
    account_id = config.accounts["prod-main"].account_id
    result = prepare_state({"arn": f"arn:aws:ecs:eu-west-1:{account_id}:service/x", "list": [f"id {account_id}."]}, config, Redactor())
    assert result == {"arn": "arn:aws:ecs:eu-west-1:prod-main:service/x", "list": ["id prod-main."]}


def test_prepare_state_replaces_the_second_account_with_its_own_alias(config):
    second = config.accounts["staging"].account_id
    assert prepare_state(f"in {second}", config, Redactor()) == "in staging"


def test_prepare_state_replaces_any_other_twelve_digit_number(config):
    other = str(int(config.accounts["prod-main"].account_id) + 1234567)
    assert len(other) == 12
    assert prepare_state({other: f"account {other}"}, config, Redactor()) == {"<ACCOUNT>": "account <ACCOUNT>"}


def test_prepare_state_leaves_longer_and_shorter_digit_runs(config):
    base = config.accounts["prod-main"].account_id
    state = f"{base}0 and {base[:-1]}"
    assert prepare_state(state, config, Redactor()) == state


def test_prepare_state_does_not_mutate_its_input(config):
    account_id = config.accounts["prod-main"].account_id
    state = {"a": [f"x {account_id}", {"b": "y"}]}
    snapshot = copy.deepcopy(state)
    prepare_state(state, config, Redactor())
    assert state == snapshot


# the store

def test_store_numbers_files_in_order_with_everything_asked_and_answered(tmp_path):
    store = JudgmentStore(tmp_path)
    reply = JudgeReply(answers={"q": {"type": "noul", "noul": 0.5}}, model="jev-test", request_id="req-9", usage={"input_tokens": 3})
    first = store.save("finding", "compute-1", {"claim": "c"}, {"q": {"type": "noul", "instructions": "i"}}, reply)
    second = store.save("cause", "C1", {"hypothesis": "h"}, {}, reply)
    assert first == tmp_path / "judgments" / "001-finding.json"
    assert second == tmp_path / "judgments" / "002-cause.json"
    assert json.loads(first.read_text()) == {
        "kind": "finding", "subject": "compute-1", "state": {"claim": "c"},
        "questions": {"q": {"type": "noul", "instructions": "i"}}, "answers": {"q": {"type": "noul", "noul": 0.5}},
        "model": "jev-test", "request_id": "req-9", "usage": {"input_tokens": 3},
    }


def test_store_continues_after_existing_files(tmp_path):
    (tmp_path / "judgments").mkdir()
    (tmp_path / "judgments" / "007-cause.json").write_text("{}")
    (tmp_path / "judgments" / "summary.json").write_text("{}")
    reply = JudgeReply(answers={}, model="m", request_id=None)
    assert JudgmentStore(tmp_path).save("action", "A1", {}, {}, reply).name == "008-action.json"


# what is asked

def test_a_bare_fact_id_shared_by_two_evidence_files_is_judged_from_the_cited_file(tmp_path, config):
    from triage.findings import load_facts, valid_findings
    first = Evidence("ecs", "prod-main", "eu-west-1", WINDOW)
    first.add(kind=INCIDENT_TIME, resource="svc", summary="Container exited with code 137 in Ireland", time="2026-10-04T10:41:00Z")
    first_path = first.write(tmp_path, "")
    second = Evidence("ecs", "prod-main", "eu-central-1", WINDOW)
    second.add(kind=INCIDENT_TIME, resource="svc", summary="Container exited with code 137 in Frankfurt", time="2026-10-04T10:41:00Z")
    second_path = second.write(tmp_path, "")
    cited = f"{second_path.stem}:ecs-0001"
    (tmp_path / "findings").mkdir()
    (tmp_path / "findings" / "compute.json").write_text(json.dumps({"analyst": "compute", "findings": [{
        "id": "compute-9", "claim": "Frankfurt tasks were killed", "fact_ids": [cited], "excerpt": "exited with code 137 in Frankfurt",
        "provenance": "incident_time", "confidence": "high", "time": None}]}))
    assert check_findings(tmp_path)["rejected"] == []
    assert first_path.stem != second_path.stem
    judge = FakeJudge(make_responder())
    judge_findings(session_for(tmp_path, config, judge), QUESTIONS, valid_findings(tmp_path), load_facts(tmp_path), ["compute-9"], limit=40)
    assert judge.calls[0][0]["evidence"] == [{"summary": "Container exited with code 137 in Frankfurt", "excerpt": ""}]


def test_a_finding_whose_facts_are_gone_falls_back_to_its_stored_summaries(tmp_path, config):
    finding = {"claim": "c", "fact_ids": ["gone:ecs-0001"], "fact_summaries": {"gone:ecs-0001": "Stored summary"}}
    judge = FakeJudge(make_responder())
    judge_findings(session_for(tmp_path, config, judge), QUESTIONS, {"f-1": finding}, {}, ["f-1"], limit=40)
    assert judge.calls[0][0]["evidence"] == [{"summary": "Stored summary", "excerpt": ""}]


def test_findings_are_asked_one_request_each_with_only_their_own_facts(tmp_path, config):
    case_dir = build_case(tmp_path, config, extra_facts=30)
    judge = FakeJudge(make_responder())
    session = session_for(case_dir, config, judge)
    from triage.findings import load_facts, valid_findings
    result = judge_findings(session, QUESTIONS, valid_findings(case_dir), load_facts(case_dir), ["compute-1", "compute-2"], limit=40)
    assert [call[0] for call in judge.calls] == [
        {"claim": CLAIM_1, "evidence": [{"summary": "Essential container exited with code 137", "excerpt": ""}]},
        {"claim": CLAIM_2, "evidence": [{"summary": "Service has 0 running tasks", "excerpt": "desired 2, running 0"}]},
    ]
    assert all(list(call[1]) == ["evidence_relation"] for call in judge.calls)
    assert all(call[1]["evidence_relation"] == QUESTIONS["evidence_relation"] for call in judge.calls)
    assert result["compute-1"] == {"relation": "supports", "confidence": 0.93, "verdict": "verified"}


def test_causes_ask_symptom_fit_and_scope_fit_in_one_request(tmp_path, config):
    judge = FakeJudge(make_responder())
    causes = [{"id": "C1", "statement": STATEMENT_1}, {"id": "C2", "statement": STATEMENT_2}]
    result = judge_causes(session_for(tmp_path, config, judge), QUESTIONS, causes, SYMPTOMS, SCOPE)
    assert [call[0] for call in judge.calls] == [
        {"hypothesis": STATEMENT_1, "symptoms": SYMPTOMS, "observed_scope": SCOPE},
        {"hypothesis": STATEMENT_2, "symptoms": SYMPTOMS, "observed_scope": SCOPE},
    ]
    assert all(list(call[1]) == ["symptom_fit", "scope_fit"] for call in judge.calls)
    assert result["C1"]["symptom_fit"]["score"] == 2.5 and result["C1"]["scope_fit"]["choice"] == "matches"


def test_ranking_is_asked_twice_in_reversed_order_with_the_fallback_last(tmp_path, config):
    judge = FakeJudge(make_responder())
    causes = [{"id": "C1", "statement": STATEMENT_1, "supporting": ["compute-1"]},
              {"id": "C2", "statement": STATEMENT_2, "supporting": ["compute-2"]}]
    findings = {"compute-1": {"claim": CLAIM_1}, "compute-2": {"claim": CLAIM_2}}
    verdicts = {"compute-1": {"verdict": "verified"}, "compute-2": {"verdict": "contradicted"}}
    result = rank_causes(session_for(tmp_path, config, judge), QUESTIONS, causes, SYMPTOMS, findings, verdicts, random.Random(1))

    expected = ["C1", "C2"]
    random.Random(1).shuffle(expected)
    assert len(judge.calls) == 2
    states = [call[0] for call in judge.calls]
    assert states[0] == states[1] == {"symptoms": SYMPTOMS, "candidates": {
        "C1": {"statement": STATEMENT_1, "supporting_evidence": [CLAIM_1]},
        "C2": {"statement": STATEMENT_2, "supporting_evidence": []},
    }}
    orders = [list(call[1]["cause_rank"]["criteria"]) for call in judge.calls]
    assert orders == [expected + ["insufficient_evidence"], expected[::-1] + ["insufficient_evidence"]]
    assert all(list(call[1]) == ["cause_rank"] for call in judge.calls)
    assert call_option_text(judge.calls[0]) == {"C1": STATEMENT_1, "C2": STATEMENT_2}
    assert result["choices"] == ["C1", "C1"]


def call_option_text(call):
    criteria = dict(call[1]["cause_rank"]["criteria"])
    criteria.pop("insufficient_evidence")
    return criteria


def test_a_single_cause_is_still_ranked_against_the_fallback(tmp_path, config):
    judge = FakeJudge(make_responder())
    causes = [{"id": "C1", "statement": STATEMENT_1, "supporting": []}]
    rank_causes(session_for(tmp_path, config, judge), QUESTIONS, causes, SYMPTOMS, {}, {}, random.Random(1))
    assert [list(call[1]["cause_rank"]["criteria"]) for call in judge.calls] == [["C1", "insufficient_evidence"]] * 2


def test_actions_ask_target_and_specificity_in_one_request(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    report = json.loads((case_dir / "report.json").read_text())
    judge = FakeJudge(make_responder())
    result = judge_actions(session_for(case_dir, config, judge), QUESTIONS, report["actions"], report["causes"])
    first_state = judge.calls[0][0]
    assert set(first_state) == {"cause", "action"}
    assert first_state["cause"] == STATEMENT_1
    assert set(first_state["action"]) == {"title", "target", "current_state", "required_state", "change"}
    assert first_state["action"]["target"]["account_id"] == "prod-main"
    assert judge.calls[1][0]["cause"] == STATEMENT_2
    assert all(list(call[1]) == ["remediation_target", "action_specific"] for call in judge.calls)
    assert result["A1"]["target"]["choice"] == "addresses_cause" and result["A1"]["specific"]["noul"] == 0.88


def test_a_full_run_asks_nine_requests_and_no_state_leaks_an_account_id(tmp_path, config):
    case_dir = build_case(tmp_path, config, extra_facts=30)
    judge = FakeJudge(make_responder())
    run(case_dir, config, judge)
    assert len(judge.calls) == 9
    for state, _ in judge.calls:
        text = json.dumps(state)
        assert len(text) < 6000
        assert config.accounts["prod-main"].account_id not in text
    finding_states = [state for state, _ in judge.calls[:3]]
    assert [state["claim"] for state in finding_states] == [CLAIM_3, CLAIM_1, CLAIM_2]
    assert all(len(state["evidence"]) == 1 for state in finding_states)
    assert "Unrelated fact" not in json.dumps(judge.calls)
    assert "Nobody lists this one" not in json.dumps(judge.calls)


def test_every_request_and_reply_is_stored_in_order(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    run(case_dir, config, FakeJudge(make_responder()))
    names = sorted(path.name for path in (case_dir / "judgments").glob("0*.json"))
    assert names == ["001-finding.json", "002-finding.json", "003-finding.json", "004-cause.json", "005-cause.json",
                     "006-ranking.json", "007-ranking.json", "008-action.json", "009-action.json"]
    stored = json.loads((case_dir / "judgments" / "004-cause.json").read_text())
    assert stored["subject"] == "C1" and set(stored["answers"]) == {"symptom_fit", "scope_fit"}
    assert stored["model"] == "jev-test" and stored["request_id"] == "req-004" and stored["usage"]["output_tokens"] == 2


# digests

def test_the_summary_stores_a_digest_beside_each_cause_and_action(tmp_path, config):
    from triage.digest import action_digest, cause_digest
    from triage.findings import valid_findings
    case_dir = build_case(tmp_path, config)
    summary = run(case_dir, config, FakeJudge(make_responder()))
    report = json.loads((case_dir / "report.json").read_text())
    findings = valid_findings(case_dir)
    for cause in report["causes"]:
        assert summary["causes"][cause["id"]]["digest"] == cause_digest(cause, findings)
    for action in report["actions"]:
        assert summary["actions"][action["id"]]["digest"] == action_digest(action)


def test_unavailable_summaries_carry_digests_too(tmp_path, config):
    summary = run(build_case(tmp_path, config), config, FakeJudge(fail_with="down"))
    assert len(summary["causes"]["C1"]["digest"]) == 64 and len(summary["actions"]["A1"]["digest"]) == 64


# composition through a run

def test_a_run_confirms_a_cause_whose_gates_all_pass(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    summary = run(case_dir, config, FakeJudge(make_responder()))
    assert summary["typesafe"] == "available" and summary["model"] == "jev-test"
    assert summary["thresholds"] == config.typesafe_thresholds and summary["uncalibrated"] is True
    assert summary["findings"]["compute-1"] == {"relation": "supports", "confidence": 0.93, "verdict": "verified"}
    assert summary["findings"]["compute-3"]["verdict"] == "unsupported"
    cause = summary["causes"]["C1"]
    assert cause["label"] == "confirmed" and cause["reasons"] == []
    assert cause["gates"] == {"evidence": True, "no_contradiction": True, "rank": True, "timing": True, "symptom_fit": True, "scope": True}
    assert cause["rank_probability"] == 0.72 and cause["scope"] == "matches"
    assert cause["symptom_fit"] == pytest.approx(2.5 / 3)
    action = summary["actions"]["A1"]
    assert len(action["digest"]) == 64
    assert {key: value for key, value in action.items() if key != "digest"} == {"label": "recommended", "target": "addresses_cause", "target_confidence": 0.9, "specific": 0.88, "reasons": []}
    assert summary["ask_engineer"] == [] and summary["adhoc"] == []
    assert json.loads((case_dir / "judgments" / "summary.json").read_text()) == summary


def test_a_cause_that_the_ranking_did_not_pick_is_a_candidate_with_reasons(tmp_path, config):
    summary = run(build_case(tmp_path, config), config, FakeJudge(make_responder()))
    cause = summary["causes"]["C2"]
    assert cause["label"] == "candidate"
    assert cause["gates"]["rank"] is False and cause["gates"]["timing"] is False
    assert any(reason.startswith("Ranking did not pick this cause") for reason in cause["reasons"])
    assert any("time" in reason for reason in cause["reasons"])
    assert summary["actions"]["A2"]["label"] == "candidate"
    assert any("candidate" in reason for reason in summary["actions"]["A2"]["reasons"])


def test_a_low_ranking_probability_reads_as_the_plan_example(tmp_path, config):
    responder = make_responder(rank=(("C1", 0.48), ("C1", 0.9)))
    summary = run(build_case(tmp_path, config), config, FakeJudge(responder))
    cause = summary["causes"]["C1"]
    assert cause["label"] == "probable" and cause["rank_probability"] == 0.48
    assert "Ranking picked this cause with probability 0.48, below 0.6" in cause["reasons"]
    assert summary["actions"]["A1"]["label"] == "candidate"


def test_an_unstable_ranking_asks_the_engineer_and_labels_candidates(tmp_path, config):
    responder = make_responder(rank=(("C1", 0.8), ("C2", 0.8)))
    summary = run(build_case(tmp_path, config), config, FakeJudge(responder))
    assert summary["ask_engineer"] == [
        "The ranking of causes changed with the order of the options; the evidence does not separate C1 from C2."]
    assert summary["causes"]["C1"]["label"] == "candidate" and summary["causes"]["C2"]["label"] == "candidate"


def test_a_verified_contradicting_finding_makes_the_cause_a_candidate(tmp_path, config):
    responder = make_responder(relations={CLAIM_3: ("supports", 0.95)})
    summary = run(build_case(tmp_path, config), config, FakeJudge(responder))
    cause = summary["causes"]["C1"]
    assert cause["gates"]["no_contradiction"] is False and cause["label"] == "candidate"
    assert any("compute-3" in reason for reason in cause["reasons"])


def test_a_contradicted_supporting_finding_fails_two_gates(tmp_path, config):
    responder = make_responder(relations={CLAIM_1: ("contradicts", 0.9), CLAIM_3: ("says_nothing", 0.9)})
    summary = run(build_case(tmp_path, config), config, FakeJudge(responder))
    gates = summary["causes"]["C1"]["gates"]
    assert summary["findings"]["compute-1"]["verdict"] == "contradicted"
    assert gates["evidence"] is False and gates["no_contradiction"] is False


def test_symptom_fit_and_scope_gates_use_the_answers(tmp_path, config):
    responder = make_responder(fit=1.0, scope="broader")
    summary = run(build_case(tmp_path, config), config, FakeJudge(responder))
    cause = summary["causes"]["C1"]
    assert cause["gates"]["symptom_fit"] is False and cause["gates"]["scope"] is False
    assert cause["label"] == "candidate" and cause["scope"] == "broader"
    assert len(cause["reasons"]) == 2


# answers that are not probabilities fail closed

def strict_json(path):
    def refuse(constant):
        raise AssertionError(f"{path} holds the non-JSON constant {constant}")
    return json.loads(path.read_text(), parse_constant=refuse)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 1.7, -0.2])
def test_a_specificity_that_is_not_a_probability_never_recommends(tmp_path, config, bad):
    case_dir = build_case(tmp_path, config)
    summary = run(case_dir, config, FakeJudge(make_responder(specific=bad)))
    assert summary["actions"]["A1"]["label"] == "candidate" and summary["actions"]["A1"]["specific"] is None
    strict_json(case_dir / "judgments" / "summary.json")
    for path in (case_dir / "judgments").glob("0*.json"):
        strict_json(path)


@pytest.mark.parametrize("bad", [float("nan"), 1.7])
def test_a_target_confidence_that_is_not_a_probability_never_recommends(tmp_path, config, bad):
    summary = run(build_case(tmp_path, config), config, FakeJudge(make_responder(target=("addresses_cause", bad))))
    assert summary["actions"]["A1"]["label"] == "candidate" and summary["actions"]["A1"]["target_confidence"] is None


@pytest.mark.parametrize("bad", [float("nan"), 1.7])
def test_a_ranking_probability_that_is_not_a_probability_fails_the_rank_gate(tmp_path, config, bad):
    case_dir = build_case(tmp_path, config)
    summary = run(case_dir, config, FakeJudge(make_responder(rank=(("C1", bad), ("C1", 0.9)))))
    cause = summary["causes"]["C1"]
    assert cause["gates"]["rank"] is False and cause["label"] != "confirmed" and cause["rank_probability"] is None
    strict_json(case_dir / "judgments" / "summary.json")


@pytest.mark.parametrize("bad", [9.0, -1.0, float("nan")])
def test_a_symptom_score_outside_its_levels_fails_the_fit_gate(tmp_path, config, bad):
    summary = run(build_case(tmp_path, config), config, FakeJudge(make_responder(fit=bad)))
    cause = summary["causes"]["C1"]
    assert cause["gates"]["symptom_fit"] is False and cause["symptom_fit"] is None and cause["label"] != "confirmed"


@pytest.mark.parametrize("bad", [float("nan"), 7.0])
def test_a_finding_confidence_that_is_not_a_probability_is_uncertain(tmp_path, config, bad):
    case_dir = build_case(tmp_path, config)
    summary = run(case_dir, config, FakeJudge(make_responder(relations={CLAIM_1: ("supports", bad), CLAIM_3: ("says_nothing", 0.9)})))
    assert summary["findings"]["compute-1"]["verdict"] == "uncertain" and summary["findings"]["compute-1"]["confidence"] is None
    assert summary["causes"]["C1"]["gates"]["evidence"] is False
    strict_json(case_dir / "judgments" / "summary.json")


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 1.7, -0.1])
def test_locate_asks_when_the_confidence_is_not_a_probability(tmp_path, config, bad):
    judge = FakeJudge(locate_answer("checkout-api/prod", bad))
    result = locate(tmp_path, config, judge)
    assert result["decision"] == "ask" and result["confidence"] is None
    json.dumps(result, allow_nan=False)


# the cap

def test_findings_beyond_the_cap_are_uncertain_and_never_asked(tmp_path, config, monkeypatch):
    monkeypatch.setattr(compose, "MAX_FINDINGS_JUDGED", 2)
    case_dir = build_case(tmp_path, config)
    judge = FakeJudge(make_responder())
    summary = run(case_dir, config, judge)
    asked = [state["claim"] for state, questions in judge.calls if "evidence_relation" in questions]
    assert asked == [CLAIM_3, CLAIM_1]
    capped = summary["findings"]["compute-2"]
    assert capped["verdict"] == "uncertain" and capped["relation"] is None and capped["confidence"] is None
    assert "2" in capped["reason"]
    assert summary["causes"]["C2"]["gates"]["evidence"] is False


def test_contradicting_findings_are_judged_before_supporting_ones(tmp_path, config, monkeypatch):
    monkeypatch.setattr(compose, "MAX_FINDINGS_JUDGED", 1)
    judge = FakeJudge(make_responder(relations={CLAIM_3: ("supports", 0.95)}))
    summary = run(build_case(tmp_path, config), config, judge)
    asked = [state["claim"] for state, questions in judge.calls if "evidence_relation" in questions]
    assert asked == [CLAIM_3]
    assert summary["causes"]["C1"]["gates"]["no_contradiction"] is False and summary["causes"]["C1"]["label"] == "candidate"


def test_an_unjudged_contradicting_finding_fails_the_no_contradiction_gate(tmp_path, config, monkeypatch):
    monkeypatch.setattr(compose, "MAX_FINDINGS_JUDGED", 0)
    summary = run(build_case(tmp_path, config), config, FakeJudge(make_responder()))
    cause = summary["causes"]["C1"]
    assert cause["gates"]["no_contradiction"] is False and cause["label"] == "candidate"
    assert any("compute-3" in reason and "not judged" in reason for reason in cause["reasons"])


def test_a_contradicting_finding_that_is_not_a_valid_finding_fails_the_gate(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    report = json.loads((case_dir / "report.json").read_text())
    report["causes"][0]["contradicting"] = ["compute-3", "compute-99"]
    (case_dir / "report.json").write_text(json.dumps(report))
    cause = run(case_dir, config, FakeJudge(make_responder()))["causes"]["C1"]
    assert cause["gates"]["no_contradiction"] is False
    assert any("compute-99" in reason and "not judged" in reason for reason in cause["reasons"])


# unavailable

def test_unavailable_at_the_first_call_caps_every_label(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    judge = FakeJudge(fail_with="TYPESAFE_API_KEY is not set")
    summary = run(case_dir, config, judge)
    assert len(judge.calls) == 1
    assert summary["typesafe"] == "unavailable: TYPESAFE_API_KEY is not set"
    assert summary["findings"] == {} and summary["uncalibrated"] is True
    assert summary["causes"]["C1"]["label"] == "probable" and summary["causes"]["C2"]["label"] == "candidate"
    note = "TypeSafe was unavailable; this label is Claude's own estimate, capped at probable"
    assert all(cause["reasons"] == [note] for cause in summary["causes"].values())
    assert {action["label"] for action in summary["actions"].values()} == {"candidate"}
    assert not any(path.name != "summary.json" for path in (case_dir / "judgments").glob("*.json"))
    assert json.loads((case_dir / "judgments" / "summary.json").read_text()) == summary


def test_unavailable_at_a_later_call_stops_judging_and_drops_earlier_numbers(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    responder = make_responder()
    judge = FakeJudge()

    def flaky(state, questions):
        if len(judge.calls) == 4:
            raise JudgeUnavailable("the connection failed")
        return responder(state, questions)

    judge.answers = flaky
    summary = run(case_dir, config, judge)
    assert len(judge.calls) == 4
    assert summary["typesafe"] == "unavailable: the connection failed"
    assert summary["findings"] == {}
    assert summary["causes"]["C1"]["label"] == "probable"
    assert "gates" in summary["causes"]["C1"] and summary["causes"]["C1"]["rank_probability"] is None
    assert summary["actions"]["A1"]["label"] == "candidate"
    assert len(list((case_dir / "judgments").glob("0*.json"))) == 3


def test_unavailable_never_raises_a_candidate_label(tmp_path, config):
    case_dir = build_case(tmp_path, config, labels=("probable", "confirmed"))
    summary = run(case_dir, config, FakeJudge(fail_with="down"))
    assert summary["causes"]["C1"]["label"] == "probable" and summary["causes"]["C2"]["label"] == "probable"


# locate

CANDIDATES = {"checkout-api/prod": "prod-main, eu-west-1, resources: ecs_service=checkout/checkout-api",
              "checkout-api/staging": "staging, eu-west-1, resources: ecs_service=checkout/checkout-api"}
INCIDENT = {"title": "Checkout API is down", "description": "", "monitors": [], "labels": ["checkout"], "hostnames": []}


def locate_answer(name, confidence):
    def respond(state, questions):
        return {"resource_match": choice(name, confidence, questions["resource_match"])}
    return respond


def locate(tmp_path, config, judge, seed=3):
    return match_resource(session_for(tmp_path, config, judge), QUESTIONS, INCIDENT, CANDIDATES, random.Random(seed), config.typesafe_thresholds)


def test_locate_picks_a_clear_match_and_stores_it(tmp_path, config):
    judge = FakeJudge(locate_answer("checkout-api/prod", 0.9))
    result = locate(tmp_path, config, judge)
    assert result["decision"] == "checkout-api/prod" and result["confidence"] == 0.9
    assert set(result["probabilities"]) == {"checkout-api/prod", "checkout-api/staging", "none_match"}
    state, questions = judge.calls[0]
    assert state == {"incident": INCIDENT, "candidates": CANDIDATES}
    options = list(questions["resource_match"]["criteria"])
    expected = list(CANDIDATES)
    random.Random(3).shuffle(expected)
    assert options == expected + ["none_match"]
    assert (tmp_path / "judgments" / "001-locate.json").is_file()


def test_locate_asks_on_none_match(tmp_path, config):
    assert locate(tmp_path, config, FakeJudge(locate_answer("none_match", 0.9)))["decision"] == "ask"


def test_locate_asks_when_confidence_is_below_the_threshold(tmp_path, config):
    result = locate(tmp_path, config, FakeJudge(locate_answer("checkout-api/prod", 0.49)))
    assert result["decision"] == "ask" and result["confidence"] == 0.49


def test_locate_accepts_confidence_at_the_threshold(tmp_path, config):
    assert locate(tmp_path, config, FakeJudge(locate_answer("checkout-api/prod", 0.5)))["decision"] == "checkout-api/prod"


def test_locate_asks_when_typesafe_is_unavailable(tmp_path, config):
    result = locate(tmp_path, config, FakeJudge(fail_with="down"))
    assert result["decision"] == "ask" and result["confidence"] is None and result["probabilities"] == {}


# the judged flag

ADHOC_DOCUMENT = {
    "id": "deploy_trigger", "reason": "No fixed question covers deploy timing", "state": {"deploy": "checkout-api:42"},
    "question": {"type": "choice", "instructions": "Is `deploy` the likely trigger?",
                 "criteria": {"yes": "The deploy is the likely trigger", "no": "The deploy is not the likely trigger"}},
}
ADHOC_ANSWER = {"deploy_trigger": {"type": "choice", "choice": "yes", "confidence": 0.8, "probabilities": {"yes": 0.8, "no": 0.2}}}


def test_a_judging_run_marks_its_summary_judged(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    assert run(case_dir, config, FakeJudge(make_responder()))["judged"] is True


def test_an_unavailable_judging_run_is_still_judged(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    assert run(case_dir, config, FakeJudge(fail_with="down"))["judged"] is True


def test_adhoc_alone_writes_a_summary_that_is_not_judged(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    run_adhoc(case_dir, session_for(case_dir, config, FakeJudge(ADHOC_ANSWER)), config, ADHOC_DOCUMENT)
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    assert summary["judged"] is False and summary["causes"] == {}


def test_a_later_judging_run_keeps_the_adhoc_list_and_becomes_judged(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    run_adhoc(case_dir, session_for(case_dir, config, FakeJudge(ADHOC_ANSWER)), config, ADHOC_DOCUMENT)
    summary = run(case_dir, config, FakeJudge(make_responder()))
    assert summary["judged"] is True
    assert summary["adhoc"] == [{"id": "deploy_trigger", "reason": "No fixed question covers deploy timing"}]
    assert summary["causes"]["C1"]["label"] == "confirmed"
    assert json.loads((case_dir / "judgments" / "summary.json").read_text())["adhoc"] == summary["adhoc"]


def test_a_rerun_over_a_judged_summary_starts_with_no_adhoc_entries(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    run(case_dir, config, FakeJudge(make_responder()))
    run_adhoc(case_dir, session_for(case_dir, config, FakeJudge(ADHOC_ANSWER)), config, ADHOC_DOCUMENT)
    assert run(case_dir, config, FakeJudge(make_responder()))["adhoc"] == []
