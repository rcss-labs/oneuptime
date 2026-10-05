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
    DraftRuleError,
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
              "rationale": "not sent", "finding_ids": ["compute-1"], "risk": "A restart of the tasks",
              "blast_radius": "The checkout service only", "preconditions": ["A free deployment slot"],
              "verification": ["Check that the health check returns 200"], "rollback": ["Set memory back to 512"]}
    report = {
        "status": "cause_found",
        "summary": {"what_broke": "Checkout containers were killed", "impact": "Checkout returned 502", "scope": SCOPE,
                    "top_cause": "C1"},
        "symptoms": list(SYMPTOMS),
        "hypotheses": [{"id": "H1", "statement": "Memory limit", "prediction": "Exit code 137", "test": "Read the task events",
                        "result": "confirmed", "finding_ids": ["compute-1"], "cause": "C1"}],
        "open_questions": [],
        "coverage": {"typesafe": "available", "not_checked": []},
        "map_changes": [],
        "run": {"engineer": "", "duration_minutes": 0},
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


def test_prepare_state_redacts_before_it_replaces_account_numbers(config):
    key = "AKIA" + "".join(str(digit) for digit in (*range(1, 10), 0, 1, 2)) + "ABCD"
    assert any(run.isdigit() and len(run) == 12 for run in (key[4:16],))
    result = prepare_state({"note": f"key {key} used"}, config, Redactor())
    assert key not in json.dumps(result) and "AKIA" not in json.dumps(result)
    assert "<ACCOUNT>" not in json.dumps(result)


def test_prepare_state_replaces_account_ids_stored_as_json_numbers(config):
    account_id = config.accounts["prod-main"].account_id
    other = int(account_id) + 1234567
    result = prepare_state({"OwnerId": int(account_id), "list": [other], "year": 2026}, config, Redactor())
    assert result == {"OwnerId": "prod-main", "list": ["<ACCOUNT>"], "year": 2026}


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
    assert judge.calls[0][0]["evidence"] == [{"summary": "Container exited with code 137 in Frankfurt", "excerpt": "", "asked": "", "quoted": "Container exited with code 137 in Frankfurt"}]


def test_a_finding_whose_facts_are_gone_falls_back_to_its_stored_summaries(tmp_path, config):
    finding = {"claim": "c", "fact_ids": ["gone:ecs-0001"], "fact_summaries": {"gone:ecs-0001": "Stored summary"}}
    judge = FakeJudge(make_responder())
    judge_findings(session_for(tmp_path, config, judge), QUESTIONS, {"f-1": finding}, {}, ["f-1"], limit=40)
    assert judge.calls[0][0]["evidence"] == [{"summary": "Stored summary", "excerpt": "", "asked": "", "quoted": ""}]


def test_findings_are_asked_one_request_each_with_only_their_own_facts(tmp_path, config):
    case_dir = build_case(tmp_path, config, extra_facts=30)
    judge = FakeJudge(make_responder())
    session = session_for(case_dir, config, judge)
    from triage.findings import load_facts, valid_findings
    result = judge_findings(session, QUESTIONS, valid_findings(case_dir), load_facts(case_dir), ["compute-1", "compute-2"], limit=40)
    assert [call[0] for call in judge.calls] == [
        {"claim": CLAIM_1, "evidence": [{"summary": "Essential container exited with code 137", "excerpt": "", "asked": "", "quoted": "Essential container exited with code 137"}]},
        {"claim": CLAIM_2, "evidence": [{"summary": "Service has 0 running tasks", "excerpt": "desired 2, running 0", "asked": "", "quoted": "Service has 0 running tasks"}]},
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
    assert orders == [expected + ["insufficient_evidence"], ["insufficient_evidence"] + expected[::-1]]
    assert [list(state["candidates"]) for state in states] == [expected, expected[::-1]]
    assert all(list(call[1]) == ["cause_rank"] for call in judge.calls)
    assert call_option_text(judge.calls[0]) == {"C1": STATEMENT_1, "C2": STATEMENT_2}
    assert result["choices"] == ["C1", "C1"]


def call_option_text(call):
    criteria = dict(call[1]["cause_rank"]["criteria"])
    criteria.pop("insufficient_evidence")
    return criteria


def sensitive(config):
    account_id = config.accounts["prod-main"].account_id
    secret = "hunter" + "2"
    return account_id, secret, f"Role arn:aws:iam::{account_id}:role/app lost access; password={secret}"


def test_ranking_options_are_redacted_and_aliased_in_the_request_and_the_stored_file(tmp_path, config):
    account_id, secret, statement = sensitive(config)
    judge = FakeJudge(make_responder())
    causes = [{"id": "C1", "statement": statement, "supporting": []}, {"id": "C2", "statement": STATEMENT_2, "supporting": []}]
    rank_causes(session_for(tmp_path, config, judge), QUESTIONS, causes, SYMPTOMS, {}, {}, random.Random(1))
    stored = "".join(path.read_text() for path in (tmp_path / "judgments").glob("*.json"))
    for text in (json.dumps(judge.calls), stored):
        assert account_id not in text and secret not in text
    assert "arn:aws:iam::prod-main:role/app" in json.dumps(judge.calls[0][1])


def test_locate_candidate_descriptions_are_redacted_in_the_question(tmp_path, config):
    account_id, secret, text = sensitive(config)
    candidates = {"a/prod": f"prod-main, eu-west-1, resources: {text}", "a/staging": "staging, eu-west-1, resources: x"}
    judge = FakeJudge(locate_answer("a/prod", 0.9))
    match_resource(session_for(tmp_path, config, judge), QUESTIONS, INCIDENT, candidates, random.Random(3), config.typesafe_thresholds)
    stored = (tmp_path / "judgments" / "001-locate.json").read_text()
    for text in (json.dumps(judge.calls), stored):
        assert account_id not in text and secret not in text


def test_a_single_cause_is_still_ranked_against_the_fallback(tmp_path, config):
    judge = FakeJudge(make_responder())
    causes = [{"id": "C1", "statement": STATEMENT_1, "supporting": []}]
    rank_causes(session_for(tmp_path, config, judge), QUESTIONS, causes, SYMPTOMS, {}, {}, random.Random(1))
    assert [list(call[1]["cause_rank"]["criteria"]) for call in judge.calls] == [["C1", "insufficient_evidence"], ["insufficient_evidence", "C1"]]


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


# the draft is checked before any paid call

def edit_report(case_dir, change):
    report = json.loads((case_dir / "report.json").read_text())
    change(report)
    (case_dir / "report.json").write_text(json.dumps(report))


@pytest.mark.parametrize("change, fragment", [
    (lambda r: r["causes"].append(dict(r["causes"][0])), "duplicate cause id C1"),
    (lambda r: r["actions"].append(dict(r["actions"][0])), "duplicate action id A1"),
    (lambda r: r["causes"][0].update(id="insufficient_evidence"), "insufficient_evidence"),
    (lambda r: r["causes"][0].update(supporting=None), "supporting"),
    (lambda r: r["causes"][0].update(contradicting="compute-3"), "contradicting"),
    (lambda r: r["causes"][0].update(supporting=[3]), "supporting"),
])
def test_a_draft_that_breaks_a_rule_is_refused_before_any_call(tmp_path, config, change, fragment):
    case_dir = build_case(tmp_path, config)
    edit_report(case_dir, change)
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError) as raised:
        run(case_dir, config, judge)
    assert fragment in str(raised.value) and judge.calls == []


def test_the_resource_match_fallback_name_is_also_reserved(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    edit_report(case_dir, lambda r: r["causes"][0].update(id="none_match"))
    with pytest.raises(DraftRuleError):
        run(case_dir, config, FakeJudge(make_responder()))


# a failed run leaves no summary that could vouch for the draft

def test_a_run_that_fails_replaces_the_previous_summary_with_a_failed_one(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    first = run(case_dir, config, FakeJudge(make_responder()))
    assert first["causes"]["C1"]["label"] == "confirmed"
    failed = run(case_dir, config, FakeJudge(lambda state, questions: {}))
    judgments = case_dir / "judgments"
    assert json.loads((judgments / "summary.json").read_text())["status"] == "failed" and failed["status"] == "failed"
    assert json.loads((judgments / "summary.json.stale").read_text()) == first


def test_a_draft_refused_before_any_call_also_retires_the_previous_summary(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    run(case_dir, config, FakeJudge(make_responder()))
    edit_report(case_dir, lambda r: r["causes"].append(dict(r["causes"][0])))
    with pytest.raises(DraftRuleError):
        run(case_dir, config, FakeJudge(make_responder()))
    assert not (case_dir / "judgments" / "summary.json").exists()
    assert (case_dir / "judgments" / "summary.json.stale").is_file()


def test_a_run_that_succeeds_leaves_no_stale_file(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    run(case_dir, config, FakeJudge(make_responder()))
    run(case_dir, config, FakeJudge(lambda state, questions: {}))
    assert (case_dir / "judgments" / "summary.json.stale").is_file()
    run(case_dir, config, FakeJudge(make_responder()))
    assert (case_dir / "judgments" / "summary.json").is_file()
    assert not (case_dir / "judgments" / "summary.json.stale").exists()


# size limits

def test_a_state_over_the_limit_is_refused_before_it_is_sent(tmp_path, config):
    from triage.judge import MAX_STATE_CHARS, JudgmentError
    assert MAX_STATE_CHARS == 8000
    judge = FakeJudge(make_responder())
    session = session_for(tmp_path, config, judge)
    session.ask("finding", "ok", {"claim": "x" * 100}, {"evidence_relation": QUESTIONS["evidence_relation"]})
    with pytest.raises(JudgmentError, match="8000"):
        session.ask("finding", "big", {"claim": "x" * 8001}, {"evidence_relation": QUESTIONS["evidence_relation"]})
    assert len(judge.calls) == 1 and len(list((tmp_path / "judgments").glob("0*.json"))) == 1


def test_a_finding_that_cites_more_than_ten_facts_is_a_draft_problem(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    checked = json.loads((case_dir / "findings" / "checked.json").read_text())
    checked["valid"][0]["fact_ids"] = [f"ecs:ecs-{number:04d}" for number in range(11)]
    (case_dir / "findings" / "checked.json").write_text(json.dumps(checked))
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError, match="compute-1"):
        run(case_dir, config, judge)
    assert judge.calls == []


def test_a_finding_that_cites_ten_facts_is_allowed(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    checked = json.loads((case_dir / "findings" / "checked.json").read_text())
    checked["valid"][0]["fact_ids"] = checked["valid"][0]["fact_ids"] * 10
    (case_dir / "findings" / "checked.json").write_text(json.dumps(checked))
    assert run(case_dir, config, FakeJudge(make_responder()))["typesafe"] == "available"


# a failure part-way never raises a label

def failing_at(call_number, reason, responder=None):
    responder = responder or make_responder()
    judge = FakeJudge()

    def answer(state, questions):
        if len(judge.calls) == call_number:
            raise JudgeUnavailable(reason)
        return responder(state, questions)

    judge.answers = answer
    return judge


@pytest.mark.parametrize("reason", ["MalformedAnswer: action_specific", "MissingAnswer for action_specific"])
def test_a_malformed_answer_is_a_failed_run_with_every_label_candidate(tmp_path, config, reason):
    case_dir = build_case(tmp_path, config)
    summary = run(case_dir, config, failing_at(9, reason))
    assert summary["status"] == "failed" and summary["typesafe"].startswith(f"failed: {reason}")
    assert {cause["label"] for cause in summary["causes"].values()} == {"candidate"}
    assert {action["label"] for action in summary["actions"].values()} == {"candidate"}
    assert all("run again" in cause["reasons"][0] for cause in summary["causes"].values())
    assert "run again" in summary["actions"]["A1"]["reasons"][0]
    assert summary["findings"] == {} and len(summary["draft_digest"]) == 64


def test_any_other_failure_after_calls_began_is_a_failed_run_too(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    first = run(case_dir, config, FakeJudge(make_responder()))
    summary = run(case_dir, config, FakeJudge(lambda state, questions: {}))
    assert summary["status"] == "failed" and summary["typesafe"].startswith("failed: KeyError")
    assert {cause["label"] for cause in summary["causes"].values()} == {"candidate"}
    assert "KeyError" in summary["typesafe"] and "evidence_relation" not in summary["typesafe"]


def test_a_failure_before_any_call_still_raises(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    edit_report(case_dir, lambda r: r["causes"].append(dict(r["causes"][0])))
    with pytest.raises(DraftRuleError):
        run(case_dir, config, FakeJudge(make_responder()))
    assert not (case_dir / "judgments" / "summary.json").exists()


def test_an_unavailable_service_part_way_keeps_the_probable_cap_when_nothing_is_ruled_out(tmp_path, config):
    summary = run(build_case(tmp_path, config), config, failing_at(9, "the connection failed"))
    assert summary["typesafe"] == "unavailable: the connection failed"
    assert summary["status"] == "unavailable" and summary["causes"]["C1"]["label"] == "probable"


def test_an_unavailable_service_part_way_keeps_a_cause_the_answers_rule_out_at_candidate(tmp_path, config):
    verified_against = make_responder(relations={CLAIM_3: ("supports", 0.95)})
    summary = run(build_case(tmp_path, config), config, failing_at(9, "down", verified_against))
    cause = summary["causes"]["C1"]
    assert cause["label"] == "candidate"
    assert any("compute-3" in reason for reason in cause["reasons"]) and any("unavailable" in reason for reason in cause["reasons"])


def test_a_contradicted_supporting_finding_in_hand_keeps_the_cause_at_candidate(tmp_path, config):
    responder = make_responder(relations={CLAIM_1: ("contradicts", 0.9), CLAIM_3: ("says_nothing", 0.9)})
    summary = run(build_case(tmp_path, config), config, failing_at(4, "down", responder))
    assert summary["causes"]["C1"]["label"] == "candidate"


def test_a_scope_answer_in_hand_that_misses_keeps_the_cause_at_candidate(tmp_path, config):
    summary = run(build_case(tmp_path, config), config, failing_at(6, "down", make_responder(scope="broader")))
    assert summary["causes"]["C1"]["label"] == "candidate"


def test_findings_not_yet_judged_do_not_count_against_a_cause(tmp_path, config):
    summary = run(build_case(tmp_path, config), config, failing_at(2, "down"))
    assert summary["causes"]["C2"]["label"] == "candidate"  # the draft label already was
    assert summary["causes"]["C1"]["label"] == "probable"


def test_a_judged_contradicting_finding_that_came_back_uncertain_caps_the_cause_at_probable(tmp_path, config):
    responder = make_responder(relations={CLAIM_3: ("says_nothing", 0.5)})
    cause = run(build_case(tmp_path, config), config, FakeJudge(responder))["causes"]["C1"]
    assert cause["gates"]["no_contradiction"] is True and cause["label"] == "probable"
    assert any("compute-3" in reason and "uncertain" in reason for reason in cause["reasons"])


def test_a_contradiction_judged_as_not_holding_lets_the_cause_stay_confirmed(tmp_path, config):
    for relation in (("says_nothing", 0.9), ("contradicts", 0.9)):
        case_dir = tmp_path / relation[0]
        case_dir.mkdir()
        cause = run(build_case(case_dir, config), config, FakeJudge(make_responder(relations={CLAIM_3: relation})))["causes"]["C1"]
        assert cause["label"] == "confirmed"


# the ranking answers in hand count when the service goes down later

@pytest.mark.parametrize("call", [7, 8, 9])
def test_a_ranking_answer_in_hand_keeps_a_ruled_out_cause_at_candidate(tmp_path, config, call):
    case_dir = build_case(tmp_path, config, labels=("confirmed", "probable"))
    outage = run(case_dir, config, failing_at(call, "timeout"))
    assert outage["causes"]["C2"]["label"] == "candidate"
    assert any("Ranking" in reason for reason in outage["causes"]["C2"]["reasons"])
    other = tmp_path / "no-outage"
    other.mkdir()
    complete = run(build_case(other, config, labels=("confirmed", "probable")), config, FakeJudge(make_responder()))
    assert complete["causes"]["C2"]["label"] == "candidate"


def test_with_no_ranking_answer_in_hand_nothing_rules_the_cause_out(tmp_path, config):
    summary = run(build_case(tmp_path, config, labels=("confirmed", "probable")), config, failing_at(6, "timeout"))
    assert summary["causes"]["C2"]["label"] == "probable"


def test_a_picked_cause_whose_ranking_probability_in_hand_misses_the_threshold_is_candidate(tmp_path, config):
    responder = make_responder(rank=(("C1", 0.4), ("C1", 0.9)))
    summary = run(build_case(tmp_path, config), config, failing_at(7, "timeout", responder))
    assert summary["causes"]["C1"]["label"] == "candidate"


def test_ranking_answers_are_kept_as_they_arrive(tmp_path, config):
    causes = [{"id": "C1", "statement": STATEMENT_1, "supporting": []}, {"id": "C2", "statement": STATEMENT_2, "supporting": []}]
    judge = FakeJudge()
    base = make_responder()

    def answer(state, questions):
        if len(judge.calls) == 2:
            raise JudgeUnavailable("timeout")
        return base(state, questions)

    judge.answers = answer
    kept = {"orders": [], "answers": [], "choices": []}
    with pytest.raises(JudgeUnavailable):
        rank_causes(session_for(tmp_path, config, judge), QUESTIONS, causes, SYMPTOMS, {}, {}, random.Random(1), kept)
    assert kept["choices"] == ["C1"] and len(kept["answers"]) == 1 and len(kept["orders"]) == 2


# the draft and checked.json are validated before the first call

def edit_checked(case_dir, change):
    path = case_dir / "findings" / "checked.json"
    checked = json.loads(path.read_text())
    change(checked)
    path.write_text(json.dumps(checked))


@pytest.mark.parametrize("bad_time", ["garbage", 5, ["2026-10-04T10:41:00Z"]])
def test_an_unparseable_finding_time_is_refused_before_any_call(tmp_path, config, bad_time):
    case_dir = build_case(tmp_path, config)
    edit_checked(case_dir, lambda c: c["valid"][0].update(time=bad_time))
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError, match="compute-1"):
        run(case_dir, config, judge)
    assert judge.calls == [] and list((case_dir / "judgments").glob("0*.json")) == []


@pytest.mark.parametrize("change", [
    lambda c: c["valid"][0].pop("claim"),
    lambda c: c["valid"][0].pop("id"),
    lambda c: c["valid"].__setitem__(0, 5),
    lambda c: c.__setitem__("valid", {"a": 1}),
    lambda c: c.__setitem__("valid", None),
    lambda c: c["valid"][0].update(fact_ids="ecs:ecs-0001"),
    lambda c: c["valid"][0].update(id=7),
])
def test_a_checked_json_of_the_wrong_shape_is_one_line_never_a_traceback(tmp_path, config, change):
    case_dir = build_case(tmp_path, config)
    edit_checked(case_dir, change)
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError) as raised:
        run(case_dir, config, judge)
    assert len(raised.value.errors) == 1 and "findings check" in raised.value.errors[0] and judge.calls == []


def test_a_checked_json_that_is_not_json_is_refused(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    (case_dir / "findings" / "checked.json").write_text("{nope")
    with pytest.raises(DraftRuleError, match="findings check"):
        run(case_dir, config, FakeJudge(make_responder()))


@pytest.mark.parametrize("bad_id", ["C2 bad\n## x", "-C", "C" * 129, "a b"])
def test_a_cause_or_action_id_outside_the_report_pattern_is_refused_before_any_call(tmp_path, config, bad_id):
    for kind in ("causes", "actions"):
        case_dir = tmp_path / kind
        case_dir.mkdir(exist_ok=True)
        build_case(case_dir, config)
        edit_report(case_dir, lambda r: r[kind][1].update(id=bad_id))
        judge = FakeJudge(make_responder())
        with pytest.raises(DraftRuleError):
            run(case_dir, config, judge)
        assert judge.calls == []


def test_a_finding_id_outside_the_report_pattern_is_refused(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    edit_checked(case_dir, lambda c: c["valid"][0].update(id="compute 1\n## x"))
    edit_report(case_dir, lambda r: r["causes"][0].update(supporting=["compute 1\n## x"]))
    with pytest.raises(DraftRuleError):
        run(case_dir, config, FakeJudge(make_responder()))


# asked text in the evidence items

def finding_with(asked, fact_ids=("ev:x-0001",), summary="4000 documents matched in the window"):
    finding = {"claim": "checkout logged 4000 OutOfMemoryError errors", "fact_ids": list(fact_ids)}
    if asked is not None:
        finding["asked"] = asked
    facts = {fact_id: {"summary": summary, "excerpt": ""} for fact_id in fact_ids}
    return finding, facts


def evidence_sent(tmp_path, config, finding, facts):
    judge = FakeJudge(make_responder())
    judge_findings(session_for(tmp_path, config, judge), QUESTIONS, {"f-1": finding}, facts, ["f-1"], limit=40)
    return judge.calls[0][0]["evidence"]


def test_the_state_carries_what_was_asked_of_the_source(tmp_path, config):
    finding, facts = finding_with({"ev:x-0001": ["query=level:INFO", "filter=service=checkout"]})
    assert evidence_sent(tmp_path, config, finding, facts) == [{
        "summary": "4000 documents matched in the window", "excerpt": "",
        "asked": "query=level:INFO; filter=service=checkout", "quoted": ""}]


def test_a_finding_without_an_asked_field_still_works(tmp_path, config):
    finding, facts = finding_with(None)
    assert evidence_sent(tmp_path, config, finding, facts)[0]["asked"] == ""
    for odd in ("text", 5, {"ev:x-0001": "text"}, {"ev:x-0001": [1, None]}):
        finding, facts = finding_with(odd)
        assert evidence_sent(tmp_path, config, finding, facts)[0]["asked"] == ""


def test_the_asked_text_is_redacted_and_then_cut_to_300_characters(tmp_path, config):
    account_id = config.accounts["prod-main"].account_id
    finding, facts = finding_with({"ev:x-0001": [f"target={account_id}", "x" * 200, "y" * 200]})
    asked = evidence_sent(tmp_path, config, finding, facts)[0]["asked"]
    assert len(asked) == 300 and account_id not in asked and asked.startswith("target=prod-main; ")


def test_the_fallback_summaries_carry_asked_too(tmp_path, config):
    finding = {"claim": "c", "fact_ids": ["gone:a-1"], "fact_summaries": {"gone:a-1": "Stored"}, "asked": {"gone:a-1": ["index=app-logs"]}}
    assert evidence_sent(tmp_path, config, finding, {}) == [{"summary": "Stored", "excerpt": "", "asked": "index=app-logs", "quoted": ""}]


def test_twenty_asked_strings_on_ten_facts_stay_inside_the_state_limit(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    ids = [f"gone:ecs-{number:04d}" for number in range(10)]
    edit_checked(case_dir, lambda c: c["valid"][0].update(
        fact_ids=ids, fact_summaries={fact_id: "short summary" for fact_id in ids},
        asked={fact_id: [f"name{n}=" + "v" * 190 for n in range(20)] for fact_id in ids}))
    judge = FakeJudge(make_responder())
    assert run(case_dir, config, judge)["status"] == "complete"
    assert all(len(json.dumps(state)) <= 8000 for state, _ in judge.calls)
    sent = [state for state, questions in judge.calls if state.get("claim") == CLAIM_1][0]
    assert len(sent["evidence"]) == 10 and all(len(item["asked"]) == 300 for item in sent["evidence"])


def test_asked_text_counts_in_the_measurement_before_the_first_call(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    ids = [f"gone:ecs-{number:04d}" for number in range(10)]
    edit_checked(case_dir, lambda c: c["valid"][0].update(
        fact_ids=ids, fact_summaries={fact_id: huge(600) for fact_id in ids},
        asked={fact_id: ["q=" + "v" * 190, "r=" + "w" * 190] for fact_id in ids}))
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError, match="compute-1"):
        run(case_dir, config, judge)
    assert judge.calls == []


# the quoted passage of the evidence

DB_CHANGE = "DB_HOST changed from old-db.example.com to new-db.example.com"
CHANGE_SUMMARY = "The task definition changed between revision 41 and 42: 1 change (1 environment value)"


def quoting_finding(excerpt, matched, fact_ids):
    return {"claim": "DB_HOST of the task definition changed", "fact_ids": list(fact_ids), "excerpt": excerpt, "matched_text": matched}


def test_a_quote_that_lies_in_a_facts_data_is_sent_under_quoted(tmp_path, config):
    facts = {"ev:x-0001": {"summary": CHANGE_SUMMARY, "excerpt": "", "data": {"changes": [DB_CHANGE, "MEMORY changed from 512 to 1024"]}}}
    finding = quoting_finding(DB_CHANGE, DB_CHANGE, ["ev:x-0001"])
    assert evidence_sent(tmp_path, config, finding, facts) == [
        {"summary": CHANGE_SUMMARY, "excerpt": "", "asked": "", "quoted": DB_CHANGE}]


def test_a_quote_that_lies_in_the_summary_is_sent_under_quoted_too(tmp_path, config):
    facts = {"ev:x-0001": {"summary": CHANGE_SUMMARY, "excerpt": "", "data": {}}}
    finding = quoting_finding("changed between revision 41 and 42", CHANGE_SUMMARY, ["ev:x-0001"])
    assert evidence_sent(tmp_path, config, finding, facts)[0]["quoted"] == CHANGE_SUMMARY


def test_a_finding_citing_two_facts_carries_the_quote_on_the_one_that_holds_it(tmp_path, config):
    facts = {"ev:x-0001": {"summary": "Service has 2 running tasks", "excerpt": "", "data": {}},
             "ev:x-0002": {"summary": CHANGE_SUMMARY, "excerpt": "", "data": {"changes": [DB_CHANGE]}}}
    finding = quoting_finding(DB_CHANGE, DB_CHANGE, ["ev:x-0001", "ev:x-0002"])
    first, second = evidence_sent(tmp_path, config, finding, facts)
    assert first["quoted"] == "" and second["quoted"] == DB_CHANGE


def test_a_finding_without_matched_text_has_empty_quoted(tmp_path, config):
    facts = {"ev:x-0001": {"summary": CHANGE_SUMMARY, "excerpt": "", "data": {"changes": [DB_CHANGE]}}}
    finding = quoting_finding(DB_CHANGE, "", ["ev:x-0001"])
    del finding["matched_text"]
    assert evidence_sent(tmp_path, config, finding, facts)[0]["quoted"] == ""
    finding["matched_text"] = 5
    assert evidence_sent(tmp_path, config, finding, facts)[0]["quoted"] == ""


def test_the_quoted_text_is_redacted_and_cut_to_500_characters(tmp_path, config):
    account_id = config.accounts["prod-main"].account_id
    text = f"role in {account_id} " + "q" * 600
    facts = {"ev:x-0001": {"summary": "s", "excerpt": "", "data": {"note": text}}}
    quoted = evidence_sent(tmp_path, config, quoting_finding(text[:200], text[:500], ["ev:x-0001"]), facts)[0]["quoted"]
    assert account_id not in quoted and quoted.startswith("role in prod-main ") and len(quoted) <= 500


def test_a_finding_checked_for_real_sends_its_matched_text_from_the_data(tmp_path, config):
    from triage.findings import load_facts, valid_findings
    evidence = Evidence("ecs", "prod-main", "eu-west-1", WINDOW)
    evidence.add(kind=INCIDENT_TIME, resource="td", summary=CHANGE_SUMMARY, time="2026-10-04T10:41:00Z",
                 data={"changes": [DB_CHANGE]})
    path = evidence.write(tmp_path, "")
    (tmp_path / "findings").mkdir()
    (tmp_path / "findings" / "compute.json").write_text(json.dumps({"analyst": "compute", "findings": [{
        "id": "compute-1", "claim": "DB_HOST changed", "fact_ids": [f"{path.stem}:ecs-0001"], "excerpt": DB_CHANGE,
        "provenance": "incident_time", "confidence": "high", "time": None}]}))
    assert check_findings(tmp_path)["rejected"] == []
    judge = FakeJudge(make_responder())
    judge_findings(session_for(tmp_path, config, judge), QUESTIONS, valid_findings(tmp_path), load_facts(tmp_path), ["compute-1"], limit=40)
    assert judge.calls[0][0]["evidence"][0]["quoted"] == DB_CHANGE


def test_the_quoted_text_counts_against_the_state_limit_before_the_first_call(tmp_path, config):
    def build(matched):
        case_dir = tmp_path / ("with" if matched else "without")
        case_dir.mkdir()
        build_case(case_dir, config)
        ids = [f"gone:ecs-{number:04d}" for number in range(10)]
        edit_checked(case_dir, lambda c: c["valid"][0].update(
            fact_ids=ids, fact_summaries={fact_id: "w" * 700 for fact_id in ids}, matched_text="q" * 500 if matched else ""))
        return case_dir

    judge = FakeJudge(make_responder())
    assert run(build(False), config, judge)["status"] == "complete"
    refused = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError, match="compute-1"):
        run(build(True), config, refused)
    assert refused.calls == []


# the draft passes the report's own checks before any call

REPORT_RULE_DRAFTS = [
    ("preconditions as a string", lambda r: r["actions"][0].update(preconditions="A free slot")),
    ("a missing required action field", lambda r: r["actions"][0].pop("rollback")),
    ("an empty required action text", lambda r: r["actions"][0].update(title="  ")),
    ("an unknown hypothesis result", lambda r: r["hypotheses"][0].update(result="maybe")),
    ("a missing hypothesis field", lambda r: r["hypotheses"][0].pop("prediction")),
    ("an unknown action type", lambda r: r["actions"][0].update(type="hotfix")),
    ("no symptoms", lambda r: r.update(symptoms=[""])),
    ("a missing open_questions", lambda r: r.pop("open_questions")),
    ("a hypothesis naming no cause", lambda r: r["hypotheses"][0].update(cause="C9")),
    ("an unknown account alias", lambda r: r["actions"][0]["target"].update(account_alias="nowhere")),
    ("a missing coverage", lambda r: r.pop("coverage")),
    ("a wrong run duration", lambda r: r["run"].update(duration_minutes="long")),
    ("a bad status", lambda r: r.update(status="maybe")),
]


@pytest.mark.parametrize("name, change", REPORT_RULE_DRAFTS, ids=[name for name, _ in REPORT_RULE_DRAFTS])
def test_a_draft_that_the_report_would_refuse_is_refused_before_any_call(tmp_path, config, name, change):
    from triage.findings import valid_findings
    from triage.report import validate_report
    case_dir = build_case(tmp_path, config)
    edit_report(case_dir, change)
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError) as raised:
        run(case_dir, config, judge)
    assert judge.calls == [] and list((case_dir / "judgments").glob("*.json")) == []
    report = json.loads((case_dir / "report.json").read_text())
    case = json.loads((case_dir / "case.json").read_text())
    own_words = validate_report(report, case, valid_findings(case_dir), config)
    assert raised.value.errors and all(error in own_words for error in raised.value.errors)


def test_labels_and_judgments_do_not_stop_a_draft_from_being_judged(tmp_path, config):
    case_dir = build_case(tmp_path, config, labels=("confirmed", "confirmed"))
    edit_report(case_dir, lambda r: r["coverage"].update(typesafe="unavailable: typed before judging"))
    assert run(case_dir, config, FakeJudge(make_responder()))["status"] == "complete"


@pytest.mark.parametrize("change", [
    lambda r: None,
    lambda r: r["hypotheses"].append({"id": "H2", "statement": "s", "prediction": "p", "test": "t", "result": "rejected",
                                       "finding_ids": [], "cause": None}),
    lambda r: r.update(open_questions=["Who changed the memory limit?"]),
    lambda r: r["actions"][1].update(preconditions=[]),
])
def test_a_draft_that_judging_accepts_is_not_refused_by_validate_for_a_reason_outside_labels(tmp_path, config, change):
    from triage.findings import valid_findings
    from triage.report import validate_report
    case_dir = build_case(tmp_path, config, labels=("probable", "candidate"))

    def lower_actions(report):
        for action in report["actions"]:
            action["label"] = "candidate"
        change(report)

    edit_report(case_dir, lower_actions)
    run(case_dir, config, FakeJudge(make_responder()))
    report = json.loads((case_dir / "report.json").read_text())
    case = json.loads((case_dir / "case.json").read_text())
    assert validate_report(report, case, valid_findings(case_dir), config) == []


# findings named by the draft must exist

def test_a_finding_the_draft_names_that_does_not_exist_is_refused_before_any_call(tmp_path, config):
    changes = [
        lambda r: r["causes"][0].update(contradicting=["compute-3", "compute-99"]),
        lambda r: r["causes"][1].update(supporting=["compute-98"]),
        lambda r: r["actions"][0].update(finding_ids=["compute-1", "compute-97"]),
        lambda r: r["causes"][0].update(supporting=["compute 1\n## x"]),
        lambda r: r["actions"][0].update(finding_ids="compute-1"),
    ]
    for number, change in enumerate(changes):
        case_dir = tmp_path / str(number)
        case_dir.mkdir()
        build_case(case_dir, config)
        edit_report(case_dir, change)
        judge = FakeJudge(make_responder())
        with pytest.raises(DraftRuleError):
            run(case_dir, config, judge)
        assert judge.calls == [] and list((case_dir / "judgments").glob("0*.json")) == []


def test_the_error_names_the_missing_finding(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    edit_report(case_dir, lambda r: r["causes"][0].update(contradicting=["compute-99"]))
    with pytest.raises(DraftRuleError, match="compute-99"):
        run(case_dir, config, FakeJudge(make_responder()))


# everything is measured before the first call

def huge(value):
    return "word " * (value // 5 + 1)


@pytest.mark.parametrize("change", [
    lambda r: r["causes"][0].update(statement=huge(9000)),
    lambda r: r.update(symptoms=[huge(9000)]),
    lambda r: r["actions"][0].update(change=huge(9000)),
    lambda r: r["summary"].update(scope=huge(9000)),
])
def test_an_oversized_state_is_refused_before_the_first_call(tmp_path, config, change):
    case_dir = build_case(tmp_path, config)
    edit_report(case_dir, change)
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError, match="8000"):
        run(case_dir, config, judge)
    assert judge.calls == [] and list((case_dir / "judgments").glob("0*.json")) == []


def test_a_finding_with_oversized_evidence_is_refused_before_the_first_call(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    checked = json.loads((case_dir / "findings" / "checked.json").read_text())
    ids = [f"gone:ecs-{number:04d}" for number in range(10)]
    checked["valid"][0]["fact_ids"] = ids
    checked["valid"][0]["fact_summaries"] = {fact_id: huge(900) for fact_id in ids}
    (case_dir / "findings" / "checked.json").write_text(json.dumps(checked))
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError, match="compute-1"):
        run(case_dir, config, judge)
    assert judge.calls == []


# other draft problems

def test_an_action_whose_cause_does_not_exist_is_refused_before_any_call(tmp_path, config):
    for bad in ("C9", 7, None):
        case_dir = tmp_path / str(bad)
        case_dir.mkdir()
        build_case(case_dir, config)
        edit_report(case_dir, lambda r: r["actions"][1].update(cause=bad))
        judge = FakeJudge(make_responder())
        with pytest.raises(DraftRuleError, match="A2"):
            run(case_dir, config, judge)
        assert judge.calls == []


def test_a_checked_json_in_the_old_shape_is_refused(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    checked = json.loads((case_dir / "findings" / "checked.json").read_text())
    checked["valid"][0]["fact_ids"] = ["ecs-0001"]
    checked["valid"][0]["fact_summaries"] = ["Essential container exited"]
    (case_dir / "findings" / "checked.json").write_text(json.dumps(checked))
    judge = FakeJudge(make_responder())
    with pytest.raises(DraftRuleError, match="findings check"):
        run(case_dir, config, judge)
    assert judge.calls == []


def test_prepare_state_replaces_float_and_dashed_account_ids(config):
    account_id = config.accounts["prod-main"].account_id
    dashed = "-".join(account_id[start:start + 4] for start in (0, 4, 8))
    result = prepare_state({"OwnerId": float(account_id), "text": f"account {dashed} here", "other": f"{dashed}0"}, config, Redactor())
    assert result == {"OwnerId": "prod-main", "text": "account prod-main here", "other": f"{dashed}0"}


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


def test_the_summary_stores_the_draft_digest_at_the_top_level(tmp_path, config):
    from triage.digest import case_identity, draft_digest
    from triage.findings import valid_findings
    case_dir = build_case(tmp_path, config)
    for judge in (FakeJudge(make_responder()), FakeJudge(fail_with="down")):
        summary = run(case_dir, config, judge)
        report = json.loads((case_dir / "report.json").read_text())
        case = json.loads((case_dir / "case.json").read_text())
        assert summary["draft_digest"] == draft_digest(report, valid_findings(case_dir), case_identity(case))
        assert case_identity(case) == "INC-123/" + case_dir.name


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


# the sentinel test: no printed string of the report can change after judging

POST_JUDGING = {("status",), ("summary", "top_cause"), ("coverage", "typesafe"), ("run", "engineer")}
POST_JUDGING_KEYS = {"label", "confidence", "reasons"}


def string_leaves(value, path=()):
    if isinstance(value, str):
        yield path
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from string_leaves(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from string_leaves(item, (*path, index))


def set_leaf(report, path, text):
    node = report
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = text


def test_no_printed_string_of_a_judged_report_can_change_without_validation_refusing_it(tmp_path, config):
    import copy as copy_module
    from triage.findings import valid_findings
    from triage.report import validate_report
    case_dir = build_case(tmp_path, config, labels=("probable", "candidate"))

    def fill(report):
        for action in report["actions"]:
            action["label"] = "candidate"
        report["open_questions"] = ["Who changed the memory limit?"]
        report["coverage"]["not_checked"] = [{"what": "The database", "why": "No access"}]
        report["map_changes"] = []

    edit_report(case_dir, fill)
    run(case_dir, config, FakeJudge(make_responder()))
    original = json.loads((case_dir / "report.json").read_text())
    case = json.loads((case_dir / "case.json").read_text())
    findings = valid_findings(case_dir)
    assert validate_report(original, case, findings, config) == []
    leaves = list(string_leaves(original))
    assert len(leaves) > 40
    accepted = []
    for path in leaves:
        outside = path in POST_JUDGING or (len(path) > 1 and path[-1] in POST_JUDGING_KEYS)
        edited = copy_module.deepcopy(original)
        old = edited
        for key in path:
            old = old[key]
        set_leaf(edited, path, old + " changed")
        problems = validate_report(edited, case, findings, config)
        if not problems and not outside:
            accepted.append(path)
    assert accepted == [], f"these strings changed without any refusal: {accepted}"


# replay and locate

def test_a_replay_case_is_judged_as_before_and_its_summary_says_so(tmp_path, config):
    case_dir = build_case(tmp_path, config)
    case = json.loads((case_dir / "case.json").read_text())
    case["replay"] = True
    (case_dir / "case.json").write_text(json.dumps(case))
    summary = run(case_dir, config, FakeJudge(make_responder()))
    assert summary["replay"] is True and summary["causes"]["C1"]["label"] == "confirmed"
    assert json.loads((case_dir / "judgments" / "summary.json").read_text())["replay"] is True


def test_a_live_case_summary_has_no_replay_key(tmp_path, config):
    assert "replay" not in run(build_case(tmp_path, config), config, FakeJudge(make_responder()))


def test_candidates_are_described_with_their_match_reasons(config, map_data):
    from triage.judge import describe_candidates
    from triage.service_map import parse_map
    case = {"match": {"candidates": [
        {"service": "checkout-api", "environment": "prod", "reasons": ["monitor:checkout api", "hostname:checkout.example.com"]},
        {"service": "checkout-api", "environment": "staging", "reasons": ["label:checkout"]}]}}
    described = describe_candidates(case, parse_map(map_data, config))
    assert described["checkout-api/prod"].endswith("matched by: monitor:checkout api, hostname:checkout.example.com")
    assert described["checkout-api/staging"].endswith("matched by: label:checkout")


def test_without_the_service_the_one_candidate_matched_by_name_is_picked(tmp_path, config):
    from triage.judge import single_name_match
    case = {"match": {"candidates": [
        {"service": "a", "environment": "prod", "reasons": ["monitor:x", "label:y"]},
        {"service": "a", "environment": "staging", "reasons": ["label:y"]}]}}
    assert single_name_match(case) == "a/prod"
    both = {"match": {"candidates": [{"service": "a", "environment": "prod", "reasons": ["hostname:h"]},
                                     {"service": "a", "environment": "staging", "reasons": ["monitor:m"]}]}}
    assert single_name_match(both) is None
    assert single_name_match({"match": {"candidates": [{"service": "a", "environment": "prod", "reasons": ["label:l"]}]}}) is None
    result = match_resource(session_for(tmp_path, config, FakeJudge(fail_with="down")), QUESTIONS, INCIDENT, CANDIDATES,
                            random.Random(3), config.typesafe_thresholds, fallback="checkout-api/prod")
    assert result["decision"] == "checkout-api/prod" and result["confidence"] is None and "name" in result["reason"]


def test_the_fallback_is_not_used_when_the_service_answered_none_match(tmp_path, config):
    result = match_resource(session_for(tmp_path, config, FakeJudge(locate_answer("none_match", 0.9))), QUESTIONS, INCIDENT,
                            CANDIDATES, random.Random(3), config.typesafe_thresholds, fallback="checkout-api/prod")
    assert result["decision"] == "ask"
