"""Ask TypeSafe the fixed questions about findings, causes, rankings, and actions, and store every exchange.

Code owns the workflow: it builds one small state per question set, sends only redacted
text, stores each request and answer, and composes labels from the stored answers.
"""
from __future__ import annotations

import json
import math
import os
import random
import re
from pathlib import Path
from typing import Any

from triage import compose
from triage.case import load_case
from triage.config import TriageConfig
from triage.digest import JUDGED_ACTION_FIELDS, JUDGED_CAUSE_FIELDS, action_digest, case_identity, cause_digest, draft_digest
from triage.findings import load_facts, valid_findings
from triage.judge_client import Judge, JudgeReply, JudgeUnavailable
from triage.questions import REQUIRED_IDS, _check_question, build_choice
from triage.redact import Redactor
from triage.service_map import ServiceMap
from triage.window import parse_time

SUMMARY_NAME = "summary.json"
UNAVAILABLE_NOTE = "TypeSafe was unavailable; this label is Claude's own estimate, capped at probable"
UNAVAILABLE_ACTION_NOTE = "TypeSafe was unavailable; no action can be recommended without its checks"
_ACCOUNT_NUMBER_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
MAX_STATE_CHARS = 8000
MAX_FACTS_PER_FINDING = 10
_STORED_NAME_RE = re.compile(r"^(\d{3})-")
_ACTION_STATE_FIELDS = tuple(name for name in JUDGED_ACTION_FIELDS if name not in ("id", "cause"))


class JudgmentError(Exception):
    """The input of a judging command is unusable. Carries every problem found."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


class DraftRuleError(JudgmentError):
    """The report draft breaks a rule that must hold before anything is sent. The command exits 2."""


# --- what is sent -----------------------------------------------------------------------

def _replace_accounts(value: Any, aliases: dict[str, str]) -> Any:
    if isinstance(value, int) and not isinstance(value, bool) and _ACCOUNT_NUMBER_RE.fullmatch(str(value)):
        return aliases.get(str(value), "<ACCOUNT>")
    if isinstance(value, str):
        return _ACCOUNT_NUMBER_RE.sub(lambda match: aliases.get(match.group(), "<ACCOUNT>"), value)
    if isinstance(value, dict):
        return {_replace_accounts(key, aliases): _replace_accounts(item, aliases) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_replace_accounts(item, aliases) for item in value]
    return value


def prepare_state(value: Any, config: TriageConfig, redactor: Redactor) -> Any:
    """A redacted copy of the state: account ids become aliases, other 12-digit numbers <ACCOUNT>.

    Redaction runs first; replacing numbers first would split secrets that contain 12 digits.
    """
    aliases = {account.account_id: account.alias for account in config.accounts.values()}
    return _replace_accounts(redactor.value(value), aliases)


def _json_safe(value: Any) -> Any:
    """Copy of the value where a non-finite float becomes its name as text, so every stored file is valid JSON."""
    if isinstance(value, float) and not math.isfinite(value):
        return "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


class JudgmentStore:
    """Writes judgments/<nnn>-<kind>.json, numbered from 001 in the order asked."""

    def __init__(self, case_dir: Path):
        self.directory = Path(case_dir) / "judgments"

    def _next_number(self) -> int:
        numbers = [int(match.group(1)) for path in self.directory.glob("*.json") if (match := _STORED_NAME_RE.match(path.name))]
        return max(numbers, default=0) + 1

    def save(self, kind: str, subject: str, state: Any, questions: dict[str, dict], reply: JudgeReply) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{self._next_number():03d}-{kind}.json"
        record = {
            "kind": kind, "subject": subject, "state": state, "questions": questions,
            "answers": reply.answers, "model": reply.model, "request_id": reply.request_id, "usage": reply.usage,
        }
        path.write_text(json.dumps(_json_safe(record), indent=2, allow_nan=False) + "\n")
        return path


class JudgeSession:
    """Sends one prepared state, stores the exchange, and returns the reply. JudgeUnavailable passes through."""

    def __init__(self, judge: Judge, store: JudgmentStore, config: TriageConfig, redactor: Redactor):
        self.judge = judge
        self.store = store
        self.config = config
        self.redactor = redactor
        self.model: str | None = None

    def prepare(self, value: Any) -> Any:
        """The value as it may leave this machine: redacted and with account ids replaced."""
        return prepare_state(value, self.config, self.redactor)

    def prepare_options(self, question: dict) -> dict:
        """A run-time choice question with its option texts prepared. Its instructions stay as written."""
        return {**question, "criteria": self.prepare(question["criteria"])}

    def ask(self, kind: str, subject: str, state: Any, questions: dict[str, dict]) -> JudgeReply:
        prepared = prepare_state(state, self.config, self.redactor)
        size = len(json.dumps(_json_safe(prepared)))
        if size > MAX_STATE_CHARS:
            raise JudgmentError([f"the state for {kind} {subject} is {size} characters, over the limit of {MAX_STATE_CHARS}; send less"])
        reply = self.judge.ask(prepared, questions)
        self.store.save(kind, subject, prepared, questions, reply)
        self.model = reply.model
        return reply


# --- the four kinds of request ----------------------------------------------------------

def _evidence_of(finding: dict, facts: dict[str, dict]) -> list[dict]:
    cited = [facts[fact_id] for fact_id in finding.get("fact_ids", []) if fact_id in facts]
    if not cited:
        summaries = finding.get("fact_summaries")
        return [{"summary": summary, "excerpt": ""} for summary in (summaries.values() if isinstance(summaries, dict) else [])]
    return [{"summary": fact.get("summary", ""), "excerpt": fact.get("excerpt", "")} for fact in cited]


def judge_findings(
    session: JudgeSession, questions: dict[str, dict], findings: dict[str, dict], facts: dict[str, dict],
    ordered_ids: list[str], limit: int,
) -> dict[str, dict]:
    """Finding id to relation, confidence, and verdict. Findings beyond the limit are uncertain and not asked."""
    results: dict[str, dict] = {}
    thresholds = session.config.typesafe_thresholds
    for position, finding_id in enumerate(finding_id for finding_id in ordered_ids if finding_id in findings):
        if position >= limit:
            results[finding_id] = {"relation": None, "confidence": None, "verdict": "uncertain",
                                   "reason": f"Not judged: only the first {limit} findings are judged"}
            continue
        finding = findings[finding_id]
        state = {"claim": finding["claim"], "evidence": _evidence_of(finding, facts)}
        answer = session.ask("finding", finding_id, state, {"evidence_relation": questions["evidence_relation"]}).answers["evidence_relation"]
        results[finding_id] = {"relation": answer["choice"], "confidence": compose.probability(answer["confidence"]),
                               "verdict": compose.finding_verdict(answer, thresholds)}
    return results


def _judged_cause(cause: dict) -> dict:
    """The fields of a cause that judging reads; the same ones the digest covers."""
    return {name: cause.get(name) for name in JUDGED_CAUSE_FIELDS}


def judge_causes(
    session: JudgeSession, questions: dict[str, dict], causes: list[dict], symptoms: list[str], scope: str,
) -> dict[str, dict]:
    asked = {name: questions[name] for name in ("symptom_fit", "scope_fit")}
    results = {}
    for cause in causes:
        judged = _judged_cause(cause)
        state = {"hypothesis": judged["statement"], "symptoms": symptoms, "observed_scope": scope}
        answers = session.ask("cause", cause["id"], state, asked).answers
        results[cause["id"]] = {"symptom_fit": answers["symptom_fit"], "scope_fit": answers["scope_fit"]}
    return results


def rank_causes(
    session: JudgeSession, questions: dict[str, dict], causes: list[dict], symptoms: list[str],
    findings: dict[str, dict], verdicts: dict[str, dict], rng: random.Random,
) -> dict:
    """Ask for the best supported cause twice, in a shuffled order and in its reverse."""
    candidates = {}
    for cause in causes:
        verified = [findings[finding_id]["claim"] for finding_id in cause.get("supporting", [])
                    if finding_id in findings and verdicts.get(finding_id, {}).get("verdict") == "verified"]
        candidates[cause["id"]] = {"statement": cause["statement"], "supporting_evidence": verified}
    options = {cause["id"]: cause["statement"] for cause in causes}
    first = list(options)
    rng.shuffle(first)
    orders = [first, first[::-1]]
    answers = []
    for position, order in enumerate(orders, start=1):
        state = {"symptoms": symptoms, "candidates": {cause_id: candidates[cause_id] for cause_id in order}}
        question = build_choice(questions["cause_rank"], options, first)
        if position == 2:  # the whole option list is reversed, so the fallback comes first
            question["criteria"] = dict(reversed(list(question["criteria"].items())))
        asked = {"cause_rank": session.prepare_options(question)}
        answers.append(session.ask("ranking", f"order {position}", state, asked).answers["cause_rank"])
    return {"orders": orders, "answers": answers, "choices": [answer["choice"] for answer in answers]}


def judge_actions(
    session: JudgeSession, questions: dict[str, dict], actions: list[dict], causes: list[dict],
) -> dict[str, dict]:
    asked = {name: questions[name] for name in ("remediation_target", "action_specific")}
    statements = {cause["id"]: cause["statement"] for cause in causes}
    results = {}
    for action in actions:
        state = {"cause": statements.get(action.get("cause"), ""), "action": {name: action.get(name) for name in _ACTION_STATE_FIELDS}}
        answers = session.ask("action", action["id"], state, asked).answers
        results[action["id"]] = {"target": answers["remediation_target"], "specific": answers["action_specific"]}
    return results


def match_resource(
    session: JudgeSession, questions: dict[str, dict], incident: dict, candidates: dict[str, str],
    rng: random.Random, thresholds: dict[str, float],
) -> dict:
    """Pick the service an incident is about among map candidates, or decide to ask the engineer."""
    order = list(candidates)
    rng.shuffle(order)
    asked = {"resource_match": session.prepare_options(build_choice(questions["resource_match"], candidates, order))}
    try:
        answer = session.ask("locate", "locate", {"incident": incident, "candidates": candidates}, asked).answers["resource_match"]
    except JudgeUnavailable as unavailable:
        return {"decision": "ask", "confidence": None, "probabilities": {},
                "reason": f"TypeSafe is unavailable: {unavailable.reason}"}
    decision, confidence = answer["choice"], compose.probability(answer["confidence"])
    probabilities = {name: compose.probability(value) for name, value in answer["probabilities"].items()}
    result = {"decision": decision, "confidence": confidence, "probabilities": probabilities}
    if decision not in candidates:
        result.update(decision="ask", reason="No candidate clearly matches the incident")
    elif confidence is None or not confidence >= thresholds["ask_engineer_below"]:
        result.update(decision="ask", reason=f"The best match has confidence {compose.number(answer['confidence'])}, below {compose.number(thresholds['ask_engineer_below'])}")
    return result


def describe_candidates(case: dict, service_map: ServiceMap) -> dict[str, str]:
    """"<service>/<environment>" to "<account>, <region>, resources: <keys and string values>"."""
    candidates = {}
    for entry in case.get("match", {}).get("candidates", []):
        name = f"{entry['service']}/{entry['environment']}"
        service = service_map.services.get(entry["service"])
        environment = service.environments.get(entry["environment"]) if service else None
        if environment is None:
            candidates[name] = "not in the service map"
            continue
        resources = ", ".join(f"{key}={value}" if isinstance(value, str) else key for key, value in environment.resources.items())
        candidates[name] = f"{environment.account}, {environment.region}, resources: {resources}"
    return candidates


def incident_state(case_dir: Path) -> dict:
    path = Path(case_dir) / "incident.json"
    try:
        incident = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise JudgmentError([f"{path}: cannot be read ({error})"]) from error
    return {name: incident.get(name, "" if name in ("title", "description") else []) for name in
            ("title", "description", "monitors", "labels", "hostnames")}


# --- the report draft and the summary ---------------------------------------------------

def load_report_draft(case_dir: Path, reserved_ids: frozenset[str] = frozenset()) -> dict:
    path = Path(case_dir) / "report.json"
    try:
        report = json.loads(path.read_text())
    except OSError as error:
        raise JudgmentError([f"{path}: cannot be read ({error.strerror or error})"]) from error
    except ValueError as error:
        raise JudgmentError([f"{path}: not valid JSON ({error})"]) from error
    errors = []
    if not isinstance(report, dict):
        raise JudgmentError([f"{path}: the top level must be an object"])
    if not isinstance(report.get("symptoms"), list) or not all(isinstance(item, str) for item in report["symptoms"]):
        errors.append("report.json: symptoms must be a list of strings")
    if not isinstance(report.get("summary"), dict):
        errors.append("report.json: summary must be an object")
    causes = report.get("causes")
    if not isinstance(causes, list) or not causes:
        errors.append("report.json: causes must be a non-empty list")
    else:
        for cause in causes:
            if not (isinstance(cause, dict) and isinstance(cause.get("id"), str) and cause["id"]
                    and isinstance(cause.get("statement"), str)):
                errors.append("report.json: every cause needs an id and a statement")
                break
    actions = report.get("actions", [])
    if not isinstance(actions, list) or not all(isinstance(a, dict) and isinstance(a.get("id"), str) for a in actions):
        errors.append("report.json: every action needs an id")
    if errors:
        raise JudgmentError(errors)
    rule_errors = _draft_rule_errors(report, reserved_ids)
    if rule_errors:
        raise DraftRuleError(rule_errors)
    return report


def _draft_rule_errors(report: dict, reserved_ids: frozenset[str]) -> list[str]:
    errors = []
    for kind, entries in (("cause", report["causes"]), ("action", report.get("actions", []))):
        seen: set[str] = set()
        for entry in entries:
            if entry["id"] in seen:
                errors.append(f"report.json: duplicate {kind} id {entry['id']}")
            seen.add(entry["id"])
    for cause in report["causes"]:
        if cause["id"] in reserved_ids:
            errors.append(f"report.json: the cause id {cause['id']} is reserved for a question option; rename the cause")
        for name in ("supporting", "contradicting"):
            listed = cause.get(name, [])
            if not isinstance(listed, list) or not all(isinstance(item, str) for item in listed):
                errors.append(f"report.json: {name} of cause {cause['id']} must be a list of finding ids")
    return errors


def _finding_order(causes: list[dict]) -> list[str]:
    """Contradicting findings first, so a cap can never hide evidence against a cause."""
    ordered: list[str] = []
    for name in ("contradicting", "supporting"):
        for cause in causes:
            for finding_id in cause.get(name, []):
                if finding_id not in ordered:
                    ordered.append(finding_id)
    return ordered


def _base_summary(config: TriageConfig, typesafe: str, model: str | None, judged: bool = True) -> dict:
    """`judged` is false only for the minimal summary that ad hoc questions create before any judging run."""
    return {"typesafe": typesafe, "model": model, "thresholds": dict(config.typesafe_thresholds), "uncalibrated": True,
            "judged": judged, "findings": {}, "causes": {}, "actions": {}, "ask_engineer": [], "adhoc": []}


def _minimal_adhoc_entries(case_dir: Path) -> list:
    """The ad hoc list of a summary that only ad hoc questions wrote; empty when there is none."""
    try:
        summary = json.loads((Path(case_dir) / "judgments" / SUMMARY_NAME).read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(summary, dict) or summary.get("judged") is not False:
        return []
    return list(summary.get("adhoc") or [])


def _draft_label(cause: dict) -> str:
    return cause.get("label") if cause.get("label") in compose.LABEL_ORDER else "candidate"


def _unavailable_summary(config: TriageConfig, report: dict, findings: dict[str, dict], reason: str, model: str | None) -> dict:
    summary = _base_summary(config, f"unavailable: {reason}", model)
    for cause in report["causes"]:
        summary["causes"][cause["id"]] = {
            "label": compose.cap_label(_draft_label(cause), "probable"), "gates": {}, "rank_probability": None,
            "symptom_fit": None, "scope": None, "reasons": [UNAVAILABLE_NOTE],
            "digest": cause_digest(cause, findings),
        }
    for action in report.get("actions", []):
        summary["actions"][action["id"]] = {
            "label": "candidate", "target": None, "target_confidence": None, "specific": None,
            "reasons": [UNAVAILABLE_ACTION_NOTE],
            "digest": action_digest(action),
        }
    return summary


def _verdict(verdicts: dict[str, dict], finding_id: str) -> str:
    return verdicts.get(finding_id, {}).get("verdict", "uncertain")


def _cause_gates(
    cause: dict, verdicts: dict[str, dict], findings: dict[str, dict], incident_start, thresholds: dict,
    rank: dict, fit: float | None, scope: str,
) -> tuple[dict[str, bool], bool, float | None, list[str]]:
    """The six gates of a cause, whether the ranking picked it twice, its lower ranking probability, and reasons."""
    cause_id, supporting = cause["id"], cause.get("supporting", [])
    picked = [compose.probability(answer["probabilities"].get(cause_id)) for answer in rank["answers"]]
    low = None if None in picked else min(picked)
    top = rank["choices"] == [cause_id, cause_id]
    timing = compose.timing_gate(cause, findings, incident_start)
    unverified = [finding_id for finding_id in supporting if _verdict(verdicts, finding_id) != "verified"]
    contradicted = [finding_id for finding_id in supporting if _verdict(verdicts, finding_id) == "contradicted"]
    listed_against = cause.get("contradicting", [])
    opposed = [finding_id for finding_id in listed_against if _verdict(verdicts, finding_id) == "verified"]
    unjudged = [finding_id for finding_id in listed_against if verdicts.get(finding_id, {}).get("relation") is None]
    gates = {
        "evidence": bool(supporting) and not unverified,
        "no_contradiction": not contradicted and not opposed and not unjudged,
        "rank": top and low is not None and low >= thresholds["cause_top_probability"],
        "timing": timing is True,
        "symptom_fit": fit is not None and fit >= compose.SYMPTOM_FIT_MIN,
        "scope": scope == "matches",
    }
    reasons = []
    if not supporting:
        reasons.append("The cause lists no supporting findings")
    reasons += [f"Supporting finding {finding_id} was judged {_verdict(verdicts, finding_id)}, not verified" for finding_id in unverified]
    reasons += [f"Supporting finding {finding_id} is contradicted by its own evidence" for finding_id in contradicted]
    reasons += [f"Finding {finding_id}, listed as contradicting this cause, is verified" for finding_id in opposed]
    reasons += [f"Finding {finding_id}, listed as contradicting this cause, was not judged" for finding_id in unjudged]
    if not gates["rank"]:
        if top:
            reasons.append(f"Ranking picked this cause with probability {compose.number(low)}, below {compose.number(thresholds['cause_top_probability'])}")
        else:
            reasons.append(f"Ranking did not pick this cause in both orderings (it picked {rank['choices'][0]}, then {rank['choices'][1]})")
    if timing is None:
        reasons.append("No supporting finding has a time, so the timing could not be checked")
    elif not timing:
        reasons.append(f"No supporting finding from the incident period is at or before the incident start plus {compose.TIMING_TOLERANCE_SECONDS // 60} minutes")
    if not gates["symptom_fit"]:
        reasons.append(f"Symptom fit is {compose.number(fit)}, below {compose.number(compose.SYMPTOM_FIT_MIN)}")
    if not gates["scope"]:
        reasons.append(f"The scope answer is {scope}, not matches")
    return gates, top, low, reasons


def _compose_summary(
    config: TriageConfig, report: dict, findings: dict[str, dict], incident_start, model: str | None,
    verdicts: dict[str, dict], cause_answers: dict[str, dict], rank: dict, action_answers: dict[str, dict],
) -> dict:
    thresholds = config.typesafe_thresholds
    summary = _base_summary(config, "available", model)
    summary["findings"] = verdicts
    for cause in report["causes"]:
        answers = cause_answers[cause["id"]]
        score = answers["symptom_fit"]
        fit = compose.symptom_fit_value(score)
        scope = answers["scope_fit"]["choice"]
        gates, top, low, reasons = _cause_gates(cause, verdicts, findings, incident_start, thresholds, rank, fit, scope)
        summary["causes"][cause["id"]] = {
            "label": compose.cause_label(gates, top), "gates": gates, "rank_probability": low,
            "symptom_fit": fit, "scope": scope, "reasons": reasons,
            "digest": cause_digest(cause, findings),
        }
    if rank["choices"][0] != rank["choices"][1]:
        summary["ask_engineer"].append(
            "The ranking of causes changed with the order of the options; "
            f"the evidence does not separate {rank['choices'][0]} from {rank['choices'][1]}.")
    for action in report.get("actions", []):
        answers = action_answers[action["id"]]
        cause_label = summary["causes"].get(action.get("cause"), {}).get("label", "candidate")
        label, reasons = compose.action_label(cause_label, answers["target"], answers["specific"]["noul"])
        summary["actions"][action["id"]] = {
            "label": label, "target": answers["target"]["choice"], "target_confidence": compose.probability(answers["target"]["confidence"]),
            "specific": compose.probability(answers["specific"]["noul"]), "reasons": reasons,
            "digest": action_digest(action),
        }
    return summary


def write_summary(case_dir: Path, summary: dict) -> Path:
    path = Path(case_dir) / "judgments" / SUMMARY_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_json_safe(summary), indent=2, allow_nan=False) + "\n")
    return path


def _check_citation_counts(causes: list[dict], findings: dict[str, dict]) -> None:
    """A finding that cites too many facts cannot be judged in one small state."""
    errors = []
    for finding_id in _finding_order(causes):
        cited = len(findings.get(finding_id, {}).get("fact_ids", []))
        if cited > MAX_FACTS_PER_FINDING:
            errors.append(f"finding {finding_id} cites {cited} facts; the limit is {MAX_FACTS_PER_FINDING}. Split the finding or cite fewer facts")
    if errors:
        raise DraftRuleError(errors)


def _reserved_ids(questions: dict[str, dict]) -> frozenset[str]:
    """Option names the code adds itself, which no cause id may use."""
    return frozenset(name for question_id in ("cause_rank", "resource_match") for name in questions[question_id].get("fallback", {}))


def run_judgments(case_dir: Path, config: TriageConfig, judge: Judge, questions: dict[str, dict], rng: random.Random) -> dict:
    """Ask every fixed question about the report draft, store the exchanges, and write judgments/summary.json."""
    case_dir = Path(case_dir)
    adhoc = _minimal_adhoc_entries(case_dir)
    summary_path = case_dir / "judgments" / SUMMARY_NAME
    stale_path = summary_path.with_name(SUMMARY_NAME + ".stale")
    if summary_path.is_file():  # a run that fails must not leave an older summary that still vouches for labels
        os.replace(summary_path, stale_path)
    case = load_case(case_dir)
    report = load_report_draft(case_dir, _reserved_ids(questions))
    findings = valid_findings(case_dir)
    _check_citation_counts(report["causes"], findings)
    session = JudgeSession(judge, JudgmentStore(case_dir), config, Redactor())
    causes, actions = report["causes"], report.get("actions", [])
    try:
        verdicts = judge_findings(session, questions, findings, load_facts(case_dir), _finding_order(causes), compose.MAX_FINDINGS_JUDGED)
        cause_answers = judge_causes(session, questions, causes, report["symptoms"], report["summary"].get("scope", ""))
        rank = rank_causes(session, questions, causes, report["symptoms"], findings, verdicts, rng)
        action_answers = judge_actions(session, questions, actions, causes)
    except JudgeUnavailable as unavailable:
        summary = _unavailable_summary(config, report, findings, unavailable.reason, session.model)
    else:
        summary = _compose_summary(config, report, findings, parse_time(case["incident_start"]), session.model,
                                   verdicts, cause_answers, rank, action_answers)
    summary["draft_digest"] = draft_digest(report, findings, case_identity(case))
    summary["adhoc"] = adhoc
    write_summary(case_dir, summary)
    stale_path.unlink(missing_ok=True)
    return summary


# --- ad hoc questions -------------------------------------------------------------------

def parse_adhoc(document: Any) -> tuple[str, str, Any, dict]:
    """Validate an ad hoc question file and return its id, reason, state, and question."""
    if not isinstance(document, dict):
        raise JudgmentError(["the question file must hold a JSON object"])
    errors = []
    for name in ("id", "reason"):
        if not isinstance(document.get(name), str) or not document[name].strip():
            errors.append(f"{name} must be a non-empty string")
    if document.get("state") is None:
        errors.append("state is required")
    question = document.get("question")
    if not isinstance(question, dict):
        errors.append("question must be an object")
    elif isinstance(document.get("id"), str):
        if document["id"] in REQUIRED_IDS:
            errors.append(f"id {document['id']} belongs to a fixed question; choose another id")
        errors += _check_question(document["id"] or "question", question)
        if "criteria_from" in question:
            errors.append("an ad hoc question must list its options in criteria, not criteria_from")
    if errors:
        raise JudgmentError(errors)
    return document["id"], document["reason"], document["state"], question


def run_adhoc(case_dir: Path, session: JudgeSession, config: TriageConfig, document: Any) -> dict:
    """Ask one question Claude wrote, store it, and list it in the summary."""
    question_id, reason, state, question = parse_adhoc(document)
    try:
        reply = session.ask("adhoc", question_id, state, {question_id: session.prepare(question)})
    except JudgeUnavailable as unavailable:
        _record_adhoc(case_dir, config, {"id": question_id, "reason": reason, "unavailable": unavailable.reason},
                      f"unavailable: {unavailable.reason}", None)
        return {"id": question_id, "unavailable": unavailable.reason}
    _record_adhoc(case_dir, config, {"id": question_id, "reason": reason}, "available", reply.model)
    return {"id": question_id, "answer": _json_safe(reply.answers[question_id])}


def _record_adhoc(case_dir: Path, config: TriageConfig, entry: dict, typesafe: str, model: str | None) -> None:
    """Append the entry to the summary, creating a minimal one (judged false) when there is none."""
    path = Path(case_dir) / "judgments" / SUMMARY_NAME
    if path.is_file():
        try:
            summary = json.loads(path.read_text())
        except ValueError as error:
            raise JudgmentError([f"{path}: not valid JSON ({error})"]) from error
    else:
        summary = _base_summary(config, typesafe, model, judged=False)
    summary.setdefault("adhoc", []).append(entry)
    write_summary(case_dir, summary)
