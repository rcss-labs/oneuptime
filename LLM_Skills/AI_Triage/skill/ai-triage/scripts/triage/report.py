"""Validate report.json, render the report, and build the remediation work order.

Validation is the quality gate: a report is rendered only when it is complete and consistent.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path, PurePath
from typing import Any

from triage.compose import LABEL_ORDER, cap_label, number
from triage.config import TriageConfig
from triage.digest import action_digest, case_identity, cause_digest, draft_digest, draft_text
from triage.findings import evidence_documents, load_facts
from triage.redact import Redactor, audit_text
from triage.window import WindowError, format_time, parse_time

STATUSES = ("cause_found", "unresolved")
HYPOTHESIS_RESULTS = ("confirmed", "rejected", "inconclusive")
ACTION_TYPES = ("mitigation", "permanent_fix")
ACTION_LABELS = ("recommended", "candidate")
WORK_ORDER_CAUSE_LABELS = LABEL_ORDER + ("unresolved",)
WORK_ORDER_ACTION_KEYS = ("id", "type", "label", "cause", "title", "target", "current_state", "required_state", "change",
                          "rationale", "finding_ids", "risk", "blast_radius", "preconditions", "verification", "rollback")
WORK_ORDER_KEYS = ("incident", "generated_at", "skill_version", "cause", "causes", "findings", "actions", "open_questions",
                   "coverage_gaps")
WORK_ORDER_OPTIONAL_KEYS = ("replay",)
LABEL_WORD_RE = re.compile(r"\b(?:confirmed|probable|candidate|recommended|root\s+cause|typesafe)\b", re.IGNORECASE)
REPLAY_LINE = "REPLAY: the evidence in this report comes from recordings, not from live systems."
DISCOVERED_TARGET_TEXT = "The target was discovered, not mapped; a map entry is proposed after publishing."
TARGET_KEYS = ("account_alias", "account_id", "region", "service", "resource_id", "arn")
ACTION_TEXT_KEYS = ("title", "current_state", "required_state", "change", "rationale", "risk", "blast_radius")
ACTION_LIST_KEYS = ("preconditions", "verification", "rollback")
REQUIRED_HEADINGS = (
    "# Triage report:",
    "## 1. Summary",
    "## 2. Incident and window",
    "## 3. Timeline",
    "## 4. Findings",
    "## 5. Ranked causes",
    "## 6. Remediation work order",
    "## 7. Coverage notes",
    "## 8. Proposed service map changes",
    "## 9. Run details",
)
SUMMARY_NAME = "summary.json"
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
FINDING_VERDICTS = ("verified", "contradicted", "unsupported", "uncertain")
# Every fixed field name of report.json. A key outside this set is report text and is never echoed.
REPORT_KEYS = frozenset({
    "status", "summary", "what_broke", "impact", "scope", "top_cause", "symptoms", "causes", "id", "statement",
    "label", "supporting", "contradicting", "hypotheses", "prediction", "test", "result", "finding_ids", "cause",
    "actions", "type", "title", "target", "account_alias", "account_id", "region", "service", "resource_id", "arn",
    "current_state", "required_state", "change", "rationale", "risk", "blast_radius", "preconditions",
    "verification", "rollback", "open_questions", "coverage", "not_checked", "what", "why", "typesafe",
    "map_changes", "run", "engineer", "duration_minutes",
})
TYPESAFE_UNAVAILABLE_PREFIX = "unavailable: "
TYPESAFE_FAILED_PREFIX = "failed: "
NO_CAUSE_TEXT = "No cause was established."


# --- shape helpers --------------------------------------------------------------------------

def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _text_field(data: dict, key: str, where: str, problems: list[str], required_text: bool = True) -> None:
    if key not in data:
        problems.append(f"{where}.{key}: missing")
    elif not isinstance(data[key], str):
        problems.append(f"{where}.{key}: must be text")
    elif required_text and not data[key].strip():
        problems.append(f"{where}.{key}: is empty")


def _only_keys(data: dict, allowed: tuple[str, ...], where: str, problems: list[str]) -> None:
    if any(key not in allowed for key in data):
        problems.append(f"{where}: has a key that is not in the work order contract")


def _id_field(data: dict, key: str, where: str, problems: list[str]) -> None:
    if key not in data:
        problems.append(f"{where}.{key}: missing")
    elif not isinstance(data[key], str):
        problems.append(f"{where}.{key}: must be text")
    elif not ID_RE.fullmatch(data[key]):
        problems.append(f"{where}.{key}: not a valid id (letters, digits, . _ : -, up to 128, starting with a letter or digit)")


def _finding_ids_field(data: dict, key: str, where: str, problems: list[str], at_least_one: bool = False) -> None:
    if key not in data:
        problems.append(f"{where}.{key}: missing")
    elif not isinstance(data[key], list) or not all(isinstance(item, str) for item in data[key]):
        problems.append(f"{where}.{key}: must be a list of text")
    else:
        for position, item in enumerate(data[key]):
            if not ID_RE.fullmatch(item):
                problems.append(f"{where}.{key}[{position}]: not a valid id")


def _choice_field(data: dict, key: str, allowed: tuple[str, ...], where: str, problems: list[str]) -> None:
    if key not in data:
        problems.append(f"{where}.{key}: missing")
    elif data[key] not in allowed:
        problems.append(f"{where}.{key}: must be one of {', '.join(allowed)}")


def _string_list_field(data: dict, key: str, where: str, problems: list[str], at_least_one: bool = False) -> None:
    if key not in data:
        problems.append(f"{where}.{key}: missing")
    elif not isinstance(data[key], list) or not all(isinstance(item, str) for item in data[key]):
        problems.append(f"{where}.{key}: must be a list of text")
    elif at_least_one and not any(item.strip() for item in data[key]):
        problems.append(f"{where}.{key}: needs at least one non-empty step")


def _dict_field(data: dict, key: str, where: str, problems: list[str]) -> dict | None:
    if key not in data:
        problems.append(f"{where}.{key}: missing")
    elif not isinstance(data[key], dict):
        problems.append(f"{where}.{key}: must be an object")
    else:
        return data[key]
    return None


def _object_items(report: dict, key: str, problems: list[str]) -> list[tuple[int, dict]]:
    if key not in report:
        problems.append(f"{key}: missing")
        return []
    if not isinstance(report[key], list):
        problems.append(f"{key}: must be a list")
        return []
    items = []
    for index, item in enumerate(report[key]):
        if isinstance(item, dict):
            items.append((index, item))
        else:
            problems.append(f"{key}[{index}]: must be an object")
    return items


def _duplicate_ids(items: list[tuple[int, dict]], key: str, problems: list[str]) -> None:
    seen: set[str] = set()
    for index, item in items:
        item_id = item.get("id")
        if isinstance(item_id, str) and item_id in seen:
            problems.append(f"{key}[{index}].id: duplicate id")
        if isinstance(item_id, str):
            seen.add(item_id)


# --- shape ---------------------------------------------------------------------------------

def _check_shape(report: dict, problems: list[str]) -> dict[str, list[tuple[int, dict]]]:
    _choice_field(report, "status", STATUSES, "report", problems)
    summary = _dict_field(report, "summary", "report", problems)
    if summary is not None:
        for key in ("what_broke", "impact", "scope"):
            _text_field(summary, key, "summary", problems)
        if "top_cause" not in summary:
            problems.append("summary.top_cause: missing")
        elif summary["top_cause"] is not None and not isinstance(summary["top_cause"], str):
            problems.append("summary.top_cause: must be text or null")
    if "symptoms" not in report:
        problems.append("symptoms: missing")
    elif not isinstance(report["symptoms"], list) or not all(isinstance(item, str) for item in report["symptoms"]):
        problems.append("symptoms: must be a list of text")
    elif not any(item.strip() for item in report["symptoms"]):
        problems.append("symptoms: needs at least one non-empty symptom")

    causes = _object_items(report, "causes", problems)
    for index, cause in causes:
        where = f"causes[{index}]"
        _id_field(cause, "id", where, problems)
        _text_field(cause, "statement", where, problems)
        _choice_field(cause, "label", LABEL_ORDER, where, problems)
        _finding_ids_field(cause, "supporting", where, problems)
        _finding_ids_field(cause, "contradicting", where, problems)
    hypotheses = _object_items(report, "hypotheses", problems)
    for index, hypothesis in hypotheses:
        where = f"hypotheses[{index}]"
        _id_field(hypothesis, "id", where, problems)
        for key in ("statement", "prediction", "test"):
            _text_field(hypothesis, key, where, problems)
        _choice_field(hypothesis, "result", HYPOTHESIS_RESULTS, where, problems)
        _finding_ids_field(hypothesis, "finding_ids", where, problems)
        if hypothesis.get("cause") is not None and not isinstance(hypothesis["cause"], str):
            problems.append(f"{where}.cause: must be text or null")
    actions = _object_items(report, "actions", problems)
    for index, action in actions:
        _check_action_shape(action, f"actions[{index}]", problems)

    if "open_questions" not in report:
        problems.append("open_questions: missing")
    else:
        _string_list_field(report, "open_questions", "report", problems)
    coverage = _dict_field(report, "coverage", "report", problems)
    if coverage is not None:
        _check_coverage_shape(coverage, problems)
    if "map_changes" not in report:
        problems.append("map_changes: missing")
    elif not isinstance(report["map_changes"], list):
        problems.append("map_changes: must be a list")
    run = _dict_field(report, "run", "report", problems)
    if run is not None:
        _text_field(run, "engineer", "run", problems, required_text=False)
        if "duration_minutes" not in run:
            problems.append("run.duration_minutes: missing")
        elif not _is_number(run["duration_minutes"]):
            problems.append("run.duration_minutes: must be a number")
    for key, items in (("causes", causes), ("hypotheses", hypotheses), ("actions", actions)):
        _duplicate_ids(items, key, problems)
    return {"causes": causes, "hypotheses": hypotheses, "actions": actions}


def _check_action_shape(action: dict, where: str, problems: list[str]) -> None:
    _id_field(action, "id", where, problems)
    _choice_field(action, "type", ACTION_TYPES, where, problems)
    _choice_field(action, "label", ACTION_LABELS, where, problems)
    _text_field(action, "cause", where, problems)
    for key in ACTION_TEXT_KEYS:
        _text_field(action, key, where, problems)
    target = _dict_field(action, "target", where, problems)
    if target is not None:
        for key in TARGET_KEYS:
            _text_field(target, key, f"{where}.target", problems,
                        required_text=key in ("account_alias", "region", "service", "resource_id"))
    _finding_ids_field(action, "finding_ids", where, problems)
    for key in ACTION_LIST_KEYS:
        _string_list_field(action, key, where, problems, at_least_one=key in ("verification", "rollback"))


def _check_coverage_shape(coverage: dict, problems: list[str]) -> None:
    _text_field(coverage, "typesafe", "coverage", problems)
    typesafe = coverage.get("typesafe")
    if (isinstance(typesafe, str) and typesafe != "available"
            and not typesafe.startswith((TYPESAFE_UNAVAILABLE_PREFIX, TYPESAFE_FAILED_PREFIX))):
        problems.append(f"coverage.typesafe: must be 'available' or start with '{TYPESAFE_UNAVAILABLE_PREFIX}' or '{TYPESAFE_FAILED_PREFIX}'")
    if "not_checked" not in coverage:
        problems.append("coverage.not_checked: missing")
    elif not isinstance(coverage["not_checked"], list):
        problems.append("coverage.not_checked: must be a list")
    else:
        for index, entry in enumerate(coverage["not_checked"]):
            if not isinstance(entry, dict):
                problems.append(f"coverage.not_checked[{index}]: must be an object")
                continue
            for key in ("what", "why"):
                _text_field(entry, key, f"coverage.not_checked[{index}]", problems)


# --- consistency --------------------------------------------------------------------------
# Only values that passed the shape check (text) are used as ids or dictionary keys, so a value of the
# wrong type is reported by the shape check and never raises here. Messages carry paths, never values.

def _text_ids(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _by_id(items: list[tuple[int, dict]]) -> dict[str, dict]:
    """Id to the first item with that id. Later duplicates are reported by the shape check."""
    found: dict[str, dict] = {}
    for _, item in items:
        if isinstance(item.get("id"), str):
            found.setdefault(item["id"], item)
    return found


def _check_finding_ids(items: list[tuple[int, dict]], section: str, keys: tuple[str, ...],
                       findings: dict[str, dict], problems: list[str]) -> None:
    for index, item in items:
        for key in keys:
            ids = item.get(key)
            for position, finding_id in enumerate(ids if isinstance(ids, list) else []):
                if isinstance(finding_id, str) and ID_RE.fullmatch(finding_id) and finding_id not in findings:
                    problems.append(
                        f"{section}[{index}].{key}[{position}]: not a valid finding "
                        "(it does not exist or failed its evidence check)")


def _check_causes(parts: dict, findings: dict[str, dict], problems: list[str]) -> None:
    for index, cause in parts["causes"]:
        label, where = cause.get("label"), f"causes[{index}]"
        supporting = [i for i in _text_ids(cause.get("supporting")) if i in findings]
        contradicting = _text_ids(cause.get("contradicting"))
        if label in ("confirmed", "probable") and not supporting:
            problems.append(f"{where}: labelled {label} but has no supporting finding")
        if label == "confirmed":
            if contradicting:
                problems.append(f"{where}: labelled confirmed but has a contradicting finding")
            if not any(findings[i].get("provenance") == "incident_time" for i in supporting):
                problems.append(f"{where}: labelled confirmed but no supporting finding has provenance incident_time")


def _check_status(report: dict, parts: dict, problems: list[str]) -> None:
    status = report.get("status")
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    top = summary.get("top_cause")
    causes = _by_id(parts["causes"])
    results = [h.get("result") for _, h in parts["hypotheses"]]
    if status == "cause_found":
        if not isinstance(top, str) or top not in causes:
            problems.append("summary.top_cause: not a known cause id")
        else:
            only_cause = len(parts["causes"]) == 1
            if not any(h.get("result") == "confirmed" and (h.get("cause") == top or (h.get("cause") is None and only_cause))
                       for _, h in parts["hypotheses"]):
                problems.append("status is cause_found but no confirmed hypothesis belongs to the top cause "
                                "(a hypothesis with no cause counts only when the report has exactly one cause)")
    if results.count("rejected") >= 3 and "confirmed" not in results and status != "unresolved":
        problems.append("status: three or more hypotheses were rejected and none confirmed, so status must be unresolved")
    if status == "unresolved":
        if top not in (None, ""):
            problems.append("summary.top_cause: must be null or empty when status is unresolved")


def _check_status_labels(report: dict, parts: dict, problems: list[str]) -> None:
    """The status rules that involve labels."""
    status = report.get("status")
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    top = summary.get("top_cause")
    causes = _by_id(parts["causes"])
    if status == "cause_found" and isinstance(top, str) and top in causes:
        if causes[top].get("label") not in ("confirmed", "probable"):
            problems.append("summary.top_cause: the top cause must be labelled confirmed or probable")
    if status == "unresolved":
        for index, cause in parts["causes"]:
            if cause.get("label") == "confirmed":
                problems.append(f"causes[{index}]: status is unresolved, so no cause may be labelled confirmed")
        for index, action in parts["actions"]:
            if action.get("label") == "recommended":
                problems.append(f"actions[{index}]: status is unresolved, so no action may be labelled recommended")


def _check_actions(config: TriageConfig, parts: dict, findings: dict[str, dict], problems: list[str]) -> None:
    causes = _by_id(parts["causes"])
    for index, action in parts["actions"]:
        where, cause_id = f"actions[{index}]", action.get("cause")
        cause = causes.get(cause_id) if isinstance(cause_id, str) else None
        if cause is None:
            problems.append(f"{where}.cause: not a known cause id")
        target = action.get("target") if isinstance(action.get("target"), dict) else {}
        alias = target.get("account_alias")
        if isinstance(alias, str) and alias.strip() and alias not in config.accounts:
            problems.append(f"{where}.target.account_alias: not an account in the config")
        if not any(i in findings for i in _text_ids(action.get("finding_ids"))):
            problems.append(f"{where}.finding_ids: needs at least one valid finding")


def _check_action_labels(parts: dict, problems: list[str]) -> None:
    causes = _by_id(parts["causes"])
    for index, action in parts["actions"]:
        cause = causes.get(action.get("cause")) if isinstance(action.get("cause"), str) else None
        if cause is not None and action.get("label") == "recommended" and cause.get("label") != "confirmed":
            problems.append(f"actions[{index}]: recommended, but its cause is not labelled confirmed")


def _check_hypothesis_causes(parts: dict, problems: list[str]) -> None:
    cause_ids = set(_by_id(parts["causes"]))
    for index, hypothesis in parts["hypotheses"]:
        cause = hypothesis.get("cause")
        if isinstance(cause, str) and cause not in cause_ids:
            problems.append(f"hypotheses[{index}].cause: not a known cause id")


def _check_typesafe(report: dict, parts: dict, problems: list[str]) -> None:
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    typesafe = coverage.get("typesafe")
    if isinstance(typesafe, str) and typesafe.startswith(TYPESAFE_UNAVAILABLE_PREFIX):
        for index, cause in parts["causes"]:
            if cause.get("label") == "confirmed":
                problems.append(f"causes[{index}]: TypeSafe was unavailable, so no cause may be labelled confirmed")
    elif isinstance(typesafe, str) and typesafe.startswith(TYPESAFE_FAILED_PREFIX):
        for index, cause in parts["causes"]:
            if cause.get("label") in ("confirmed", "probable"):
                problems.append(f"causes[{index}]: TypeSafe judging failed, so no cause may be labelled above candidate")


def load_summary(case: dict) -> tuple[dict | None, str | None]:
    """The stored judgments summary, or None, plus a problem when the file exists but cannot be read."""
    path = Path(case.get("case_dir", "")) / "judgments" / SUMMARY_NAME
    if not path.is_file():
        return None, None
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        summary = None
    if not isinstance(summary, dict) or not isinstance(summary.get("causes"), dict):
        return None, f"judgments/{SUMMARY_NAME}: cannot be read as a judgments summary, so labels cannot be checked"
    return summary, None


def _is_number_or_none(value: Any) -> bool:
    return value is None or _is_number(value)


def _text_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _summary_shape_problems(summary: dict) -> list[str]:
    """Wrong types anywhere in the stored judgments summary, as paths. Keys are never echoed."""
    where, problems = f"judgments/{SUMMARY_NAME}", []

    def table(name: str) -> list[dict]:
        value = summary.get(name)
        if value is None:
            return []
        if not isinstance(value, dict):
            problems.append(f"{where} {name}: must be an object")
            return []
        entries = []
        for position, entry in enumerate(value.values()):
            if isinstance(entry, dict):
                entries.append((position, entry))
            else:
                problems.append(f"{where} {name} entry {position}: must be an object")
        return entries

    if not isinstance(summary.get("typesafe"), str):
        problems.append(f"{where} typesafe: must be text")
    if summary.get("model") is not None and not isinstance(summary["model"], str):
        problems.append(f"{where} model: must be text or null")
    for position, entry in table("findings"):
        for key in ("relation", "verdict"):
            if entry.get(key) is not None and not isinstance(entry[key], str):
                problems.append(f"{where} findings entry {position}.{key}: must be text")
        if not _is_number_or_none(entry.get("confidence")):
            problems.append(f"{where} findings entry {position}.confidence: must be a number")
    for position, entry in table("causes"):
        name = f"{where} causes entry {position}"
        if "gates" in entry and not (isinstance(entry["gates"], dict) and all(isinstance(v, bool) for v in entry["gates"].values())):
            problems.append(f"{name}.gates: must be an object of true or false")
        if "reasons" in entry and not _text_list(entry["reasons"]):
            problems.append(f"{name}.reasons: must be a list of text")
        for key in ("rank_probability", "symptom_fit"):
            if not _is_number_or_none(entry.get(key)):
                problems.append(f"{name}.{key}: must be a number")
        if entry.get("scope") is not None and not isinstance(entry["scope"], str):
            problems.append(f"{name}.scope: must be text")
    for position, entry in table("actions"):
        name = f"{where} actions entry {position}"
        if "reasons" in entry and not _text_list(entry["reasons"]):
            problems.append(f"{name}.reasons: must be a list of text")
        for key in ("target_confidence", "specific"):
            if not _is_number_or_none(entry.get(key)):
                problems.append(f"{name}.{key}: must be a number")
        if entry.get("target") is not None and not isinstance(entry["target"], str):
            problems.append(f"{name}.target: must be text")
    if "ask_engineer" in summary and not _text_list(summary["ask_engineer"]):
        problems.append(f"{where} ask_engineer: must be a list of text")
    adhoc = summary.get("adhoc")
    if adhoc is not None and not (isinstance(adhoc, list) and all(
            isinstance(item, dict) and isinstance(item.get("id"), str) and isinstance(item.get("reason"), str) for item in adhoc)):
        problems.append(f"{where} adhoc: must be a list of objects with text id and reason")
    return problems


def _judged(summary: dict | None) -> dict | None:
    """The summary when a judging run wrote it. One written only by ad hoc questions counts as none."""
    return summary if summary is not None and summary.get("judged") is True else None


def _summary_entry(table: Any, key: Any) -> dict | None:
    entry = table.get(key) if isinstance(table, dict) and isinstance(key, str) else None
    return entry if isinstance(entry, dict) else None


def _stored_digest_matches(entry: dict, current: str) -> bool:
    stored = entry.get("digest")
    return isinstance(stored, str) and stored == current


def _edited_entries(summary: dict, parts: dict, findings: dict[str, dict], problems: list[str]) -> tuple[set[int], set[int]]:
    """Indexes of causes and actions whose content no longer matches what was judged. Each is a problem."""
    causes, actions = set(), set()
    for index, cause in parts["causes"]:
        entry = _summary_entry(summary["causes"], cause.get("id"))
        if entry is not None and not _stored_digest_matches(entry, cause_digest(cause, findings)):
            causes.add(index)
            problems.append(f"causes[{index}]: edited after judging (or its stored digest is missing); "
                            "it counts as candidate, so run the judgments again")
    for index, action in parts["actions"]:
        entry = _summary_entry(summary.get("actions"), action.get("id"))
        if entry is not None and not _stored_digest_matches(entry, action_digest(action)):
            actions.add(index)
            problems.append(f"actions[{index}]: edited after judging (or its stored digest is missing); "
                            "it counts as candidate, so run the judgments again")
    return causes, actions


COMPLETE_STATUS, UNAVAILABLE_STATUS = "complete", "unavailable"


def _blanket_cap_reason(summary: dict, report: dict, case: dict, findings: dict[str, dict], problems: list[str]) -> str | None:
    """Why every cause and action counts as candidate: a changed draft or case, or a run that did not complete.

    A changed draft is a problem. A status other than complete or unavailable only caps labels.
    """
    stored = summary.get("draft_digest")
    if not isinstance(stored, str) or stored != draft_digest(report, findings, case_identity(case)):
        problems.append("draft: the draft or the case changed after judging (or the stored draft digest is missing); "
                        "every cause and action counts as candidate, so run the judgments again")
        return "the draft changed after judging"
    if summary.get("status") not in (COMPLETE_STATUS, UNAVAILABLE_STATUS):
        return "judging did not complete"
    return None


def _check_causes_against_summary(summary: dict, parts: dict, edited: set[int], blanket: str | None,
                                  problems: list[str]) -> None:
    for index, cause in parts["causes"]:
        label, where = cause.get("label"), f"causes[{index}]"
        if label not in LABEL_ORDER:
            continue
        if index in edited:
            if cap_label(label, "candidate") != label:
                problems.append(f"{where}: labelled {label}, stronger than candidate, which this cause counts as because "
                                f"{blanket or 'it was edited after judging'}")
            continue
        entry = _summary_entry(summary["causes"], cause.get("id"))
        if entry is None:
            if cap_label(label, "candidate") != label:
                problems.append(f"{where}: not in judgments/{SUMMARY_NAME}, so at most candidate; labelled {label}")
            continue
        judged = entry.get("label")
        if not isinstance(judged, str) or judged not in LABEL_ORDER:
            problems.append(f"{where}: its entry in judgments/{SUMMARY_NAME} has a missing or invalid label, counted as candidate")
            judged = LABEL_ORDER[0]
        if label != cap_label(label, judged):
            problems.append(f"{where}: labelled {label}, stronger than the judged label {judged}")


def _check_actions_against_summary(summary: dict, parts: dict, edited_causes: set[int], edited_actions: set[int],
                                   blanket: str | None, problems: list[str]) -> None:
    edited_cause_ids = {cause["id"] for index, cause in parts["causes"] if index in edited_causes and isinstance(cause.get("id"), str)}
    for index, action in parts["actions"]:
        where = f"actions[{index}]"
        if action.get("label") == "recommended":
            own_edit = index in edited_actions
            cause_edit = isinstance(action.get("cause"), str) and action["cause"] in edited_cause_ids
            if own_edit:
                problems.append(f"{where}: recommended, but the action was edited after judging")
            if cause_edit:
                problems.append(f"{where}: recommended, but its cause was edited after judging")
            if blanket and not own_edit and not cause_edit:
                problems.append(f"{where}: recommended, but {blanket}")
        entry = _summary_entry(summary.get("actions"), action.get("id"))
        if entry is not None and entry.get("label") not in ACTION_LABELS and action.get("label") == "recommended":
            problems.append(f"{where}: its entry in judgments/{SUMMARY_NAME} has a missing or invalid label")
        elif action.get("label") == "recommended":
            if entry is None:
                problems.append(f"{where}: recommended, but it is not in judgments/{SUMMARY_NAME}")
            elif entry.get("label") != "recommended":
                problems.append(f"{where}: recommended, but the summary labels it candidate")


def _check_findings_against_summary(summary: dict, parts: dict, problems: list[str]) -> None:
    verdicts = summary.get("findings")
    for index, cause in parts["causes"]:
        for position, finding_id in enumerate(cause.get("supporting") if isinstance(cause.get("supporting"), list) else []):
            entry = _summary_entry(verdicts, finding_id)
            if entry is None:
                continue
            verdict = entry.get("verdict")
            if verdict not in FINDING_VERDICTS:
                problems.append(f"causes[{index}].supporting[{position}]: its verdict in judgments/{SUMMARY_NAME} is missing or invalid")
            elif verdict in ("contradicted", "unsupported"):
                problems.append(f"causes[{index}].supporting[{position}]: judged {verdict}, so it cannot support a cause")
    for index, action in parts["actions"]:
        for position, finding_id in enumerate(action.get("finding_ids") if isinstance(action.get("finding_ids"), list) else []):
            entry = _summary_entry(verdicts, finding_id)
            if entry is not None and entry.get("verdict") == "contradicted":
                problems.append(f"actions[{index}].finding_ids[{position}]: judged contradicted, so an action cannot cite it")


def _check_typesafe_against_summary(report: dict, summary: dict | None, problems: list[str]) -> None:
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    typesafe = coverage.get("typesafe")
    if not isinstance(typesafe, str):
        return
    if summary is None:
        if not typesafe.startswith(TYPESAFE_UNAVAILABLE_PREFIX):
            problems.append(f"coverage.typesafe: no judging run is stored, so it must start with '{TYPESAFE_UNAVAILABLE_PREFIX}'")
    elif typesafe != summary.get("typesafe"):
        problems.append(f"coverage.typesafe: must equal the value stored in judgments/{SUMMARY_NAME}")


def _check_hypothesis_results(parts: dict, summary: dict | None, problems: list[str]) -> None:
    """A hypothesis may be confirmed only when its cause is judged probable or confirmed in the summary."""
    only_cause = parts["causes"][0][1].get("id") if len(parts["causes"]) == 1 else None
    for index, hypothesis in parts["hypotheses"]:
        if hypothesis.get("result") != "confirmed":
            continue
        cause = hypothesis.get("cause")
        cause_id = cause if isinstance(cause, str) else only_cause if cause is None else None
        entry = _summary_entry((summary or {}).get("causes"), cause_id)
        judged = entry.get("label") if entry else None
        if not (isinstance(judged, str) and judged in ("probable", "confirmed")):
            problems.append(f"hypotheses[{index}].result: confirmed, but no cause judged probable or confirmed backs it")


def _check_judgments(report: dict, case: dict, parts: dict, findings: dict[str, dict], problems: list[str]) -> None:
    raw, unreadable = load_summary(case)
    if unreadable:
        problems.append(unreadable)
        return
    shape = _summary_shape_problems(raw) if raw is not None else []
    if shape:
        problems.extend(shape)
        return
    summary = _judged(raw)
    _check_typesafe_against_summary(report, summary, problems)
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    already_barred = str(coverage.get("typesafe")).startswith(TYPESAFE_UNAVAILABLE_PREFIX)
    if summary is None:
        for index, cause in parts["causes"]:
            label = cause.get("label")
            if label == "probable" or (label == "confirmed" and not already_barred):
                problems.append(f"causes[{index}]: no judging run is stored, so no cause may be labelled above candidate")
    if summary is not None:
        edited_causes, edited_actions = _edited_entries(summary, parts, findings, problems)
        blanket = _blanket_cap_reason(summary, report, case, findings, problems)
        capped = {index for index, _ in parts["causes"]} if blanket else edited_causes
        _check_causes_against_summary(summary, parts, capped, blanket, problems)
        _check_actions_against_summary(summary, parts, edited_causes, edited_actions, blanket, problems)
        _check_findings_against_summary(summary, parts, problems)


def _walk_text(value: Any, path: str, free: bool = False):
    """Yield (path, text) for every string, key included. A path never contains a key the report chose."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            if free or key not in REPORT_KEYS:
                label = f"a key under {path or 'report'}"
                yield label, str(key)
                yield from _walk_text(item, label, True)
            else:
                yield from _walk_text(item, f"{path}.{key}" if path else key, False)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_text(item, f"{path}[{index}]", free or path == "map_changes")


def _check_secrets(report: dict, problems: list[str]) -> None:
    for path, text in _walk_text(report, ""):
        categories = sorted({hit.category for hit in audit_text(text)})
        if categories:
            problems.append(f"{path}: contains what looks like a secret ({', '.join(categories)}); remove it")


MAX_DEPTH = 50


def _too_deep(value: Any) -> bool:
    """True when containers are nested deeper than MAX_DEPTH. Iterative, so depth cannot cause recursion."""
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (dict, list)):
            if depth > MAX_DEPTH:
                return True
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return False


# Keys whose values are ids or allowed values, not prose; a resource may be named "candidate-api".
IDENTIFIER_KEYS = frozenset({"id", "cause", "supporting", "contradicting", "finding_ids", "target", "type"})
# A map change holds resource names, map keys, and ARNs; in an object item only a value with whitespace is prose.
# In a map change a label word joined to a name (candidate-api, probable.orders, arn:...:confirmed) is a name.
NAME_SAFE_LABEL_WORD_RE = re.compile(
    r"(?<![\w./:-])(?:confirmed|probable|candidate|recommended|root\s+cause|typesafe)(?![\w./-])(?!:\S)", re.IGNORECASE)


def _free_text(value: Any, path: str):
    """Yield (path, text) for every string under value, skipping identifier keys."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in IDENTIFIER_KEYS:
                continue
            yield from _free_text(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _free_text(item, f"{path}[{index}]")


def _map_change_text(changes: Any):
    """Yield (path, text) for the prose of each map change: a text item, or any string value of an object item
    that contains whitespace, whatever its key. A value without whitespace is a name, a key, or an ARN."""
    for index, item in enumerate(changes if isinstance(changes, list) else []):
        if isinstance(item, str):
            yield f"map_changes[{index}]", item
        elif isinstance(item, (dict, list)):
            for path, text in _all_strings(item, f"map_changes[{index}]"):
                if any(char.isspace() for char in text.strip()):
                    yield path, text


def _all_strings(value: Any, path: str):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _all_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _all_strings(item, f"{path}[{index}]")


def _check_label_words(report: dict, problems: list[str]) -> None:
    """Free text that the draft digest covers may not state a label; labels are printed from the judgments.

    The walk is over draft_text, the same fields the draft digest covers, so every printed field the draft writes
    is checked. In map_changes only the prose is checked, and a label word joined to a name counts as the name."""
    message = "labels are printed from the judgments; describe what happened without them"
    text = draft_text(report)
    changes = text.pop("map_changes")
    found = [(path, words) for path, words in _free_text(text, "") if LABEL_WORD_RE.search(words)]
    found += [(path, words) for path, words in _map_change_text(changes) if NAME_SAFE_LABEL_WORD_RE.search(words)]
    for path, _ in found:
        problems.append(f"{path}: {message}")


def _draft_problems(report: Any, findings: dict[str, dict], config: TriageConfig) -> tuple[list[str], dict | None]:
    """The checks that do not depend on labels or judgments, and the parts of the draft they found."""
    if not isinstance(report, dict):
        return ["report: must be a JSON object"], None
    if _too_deep(report):
        return [f"report: nested deeper than {MAX_DEPTH} levels"], None
    problems: list[str] = []
    parts = _check_shape(report, problems)
    _check_finding_ids(parts["causes"], "causes", ("supporting", "contradicting"), findings, problems)
    _check_finding_ids(parts["hypotheses"], "hypotheses", ("finding_ids",), findings, problems)
    _check_finding_ids(parts["actions"], "actions", ("finding_ids",), findings, problems)
    _check_status(report, parts, problems)
    _check_actions(config, parts, findings, problems)
    _check_hypothesis_causes(parts, problems)
    _check_label_words(report, problems)
    _check_secrets(report, problems)
    return problems, parts


def check_draft(report: Any, findings: dict[str, dict], config: TriageConfig) -> list[str]:
    """Every problem with a draft that does not depend on labels or on stored judgments.

    Shapes, types, required fields, id rules, allowed values, finding ids against the valid findings,
    the cross-references inside the draft, the status rules without labels, depth, and secrets.
    A draft with only label, summary, digest, coverage, or render problems gives an empty list.
    """
    return _draft_problems(report, findings, config)[0]


def validate_report(report: Any, case: dict, findings: dict[str, dict], config: TriageConfig) -> list[str]:
    """Every problem that stops the report from being rendered. An empty list means it may be rendered.

    The draft checks come first, then the label, summary, digest, and coverage rules.
    Never raises on a malformed report, and no message repeats a value from the report.
    """
    problems, parts = _draft_problems(report, findings, config)
    if parts is None:
        return problems
    _check_causes(parts, findings, problems)
    _check_status_labels(report, parts, problems)
    _check_action_labels(parts, problems)
    _check_typesafe(report, parts, problems)
    _check_judgments(report, case, parts, findings, problems)
    raw, unreadable = load_summary(case)
    _check_hypothesis_results(parts, None if unreadable else _judged(raw), problems)
    return problems


# --- the stored inputs: checked.json and the evidence facts --------------------------------

FINDING_TEXT_KEYS = ("id", "claim", "excerpt", "provenance", "confidence", "analyst")


def load_checked(case_dir: Path) -> tuple[dict, list[str]]:
    """findings/checked.json as a dict, plus a problem for each wrong type at any level.

    Nothing is returned that a reader would have to type-check again. A missing file is no problem.
    """
    path = Path(case_dir) / "findings" / "checked.json"
    where = "findings/checked.json"
    if not path.is_file():
        return {}, []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}, [f"{where}: cannot be read as JSON"]
    if not isinstance(data, dict):
        return {}, [f"{where}: must be a JSON object"]
    problems: list[str] = []
    checked: dict = {}
    valid = []
    if data.get("valid") is not None and not isinstance(data["valid"], list):
        problems.append(f"{where} valid: must be a list")
    for index, entry in enumerate(data["valid"] if isinstance(data.get("valid"), list) else []):
        entry_problems = _finding_entry_problems(entry, f"{where} valid[{index}]")
        problems += entry_problems
        if not entry_problems:
            valid.append(entry)
    checked["valid"] = valid
    for key in ("rejected", "unreadable"):
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            problems.append(f"{where} {key}: must be a list of objects")
        else:
            checked[key] = value
    if data.get("warnings") is not None:
        if _text_list(data["warnings"]):
            checked["warnings"] = data["warnings"]
        else:
            problems.append(f"{where} warnings: must be a list of text")
    if data.get("checked") is not None:
        value = data["checked"]
        if isinstance(value, dict) and all(_text_list(item) for item in value.values()):
            checked["checked"] = value
        else:
            problems.append(f"{where} checked: must be an object of lists of text")
    return checked, problems


def _finding_entry_problems(entry: Any, where: str) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{where}: must be an object"]
    problems = []
    for key in FINDING_TEXT_KEYS:
        if not isinstance(entry.get(key), str):
            problems.append(f"{where}.{key}: must be text")
    if isinstance(entry.get("id"), str) and not ID_RE.fullmatch(entry["id"]):
        problems.append(f"{where}.id: not a valid id")
    fact_ids = entry.get("fact_ids")
    if not _text_list(fact_ids):
        problems.append(f"{where}.fact_ids: must be a list of text")
    else:
        problems += [f"{where}.fact_ids[{i}]: not a valid id" for i, item in enumerate(fact_ids) if not ID_RE.fullmatch(item)]
    return problems


def _optional_text(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _case_shape_problems(case_dir: Path) -> list[str]:
    """Wrong types in the parts of case.json that render reads."""
    where = "case.json"
    try:
        case = json.loads((Path(case_dir) / "case.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return [f"{where}: cannot be read as JSON"]
    if not isinstance(case, dict):
        return [f"{where}: must be a JSON object"]
    problems = []
    for key in ("skill_version", "case_dir", "incident_start"):
        if not isinstance(case.get(key), str):
            problems.append(f"{where} {key}: must be text")
    incident = case.get("incident")
    if not isinstance(incident, dict):
        problems.append(f"{where} incident: must be an object")
    else:
        for key in ("number", "title"):
            if not isinstance(incident.get(key), str) or not incident[key].strip():
                problems.append(f"{where} incident.{key}: must be non-empty text")
        for key in ("url", "severity", "state", "declared_at", "impact_started_at", "resolved_at"):
            if not _optional_text(incident.get(key)):
                problems.append(f"{where} incident.{key}: must be text or null")
    if case.get("replay") is not None and not isinstance(case["replay"], bool):
        problems.append(f"{where} replay: must be true or false")
    window = case.get("window")
    if not isinstance(window, dict) or not all(isinstance(window.get(key), str) for key in ("start", "end")):
        problems.append(f"{where} window: must be an object with text start and end")
    target = case.get("target")
    if target is not None:
        if not isinstance(target, dict) or not all(isinstance(target.get(key), str) for key in ("source", "account", "region")):
            problems.append(f"{where} target: must be null or an object with text source, account, and region")
        elif not _optional_text(target.get("service")):
            problems.append(f"{where} target.service: must be text or null")
    return problems


def _evidence_shape_problems(case_dir: Path) -> list[str]:
    """Wrong types in the evidence files that render reads. A file that cannot be read is reported elsewhere."""
    problems = []
    for position, (_, document) in enumerate(evidence_documents(Path(case_dir))):
        where = f"evidence file {position}"
        if not isinstance(document.get("facts", []), list):
            problems.append(f"{where}.facts: must be a list")
        elif not all(isinstance(fact, dict) for fact in document.get("facts", [])):
            problems.append(f"{where}.facts: every entry must be an object")
        errors = document.get("errors", [])
        if errors is not None and not (isinstance(errors, list) and all(isinstance(item, dict) for item in errors)):
            problems.append(f"{where}.errors: must be a list of objects")
        if not isinstance(document.get("truncated", False), bool):
            problems.append(f"{where}.truncated: must be true or false")
    return problems


def check_case_inputs(case_dir: Path) -> tuple[dict[str, dict], list[str]]:
    """The usable findings of the case (id to finding) and every problem with checked.json and the evidence facts.

    A finding with a wrong type, or an id or fact id that fails the id pattern, is a problem and is left out.
    """
    checked, problems = load_checked(case_dir)
    findings = {item["id"]: item for item in checked.get("valid", [])}
    problems += _case_shape_problems(case_dir)
    shape = _evidence_shape_problems(case_dir)
    if shape:
        return findings, problems + shape
    for position, (key, fact) in enumerate(load_facts(Path(case_dir)).items()):
        if not ID_RE.fullmatch(key) or not isinstance(fact.get("id"), str) or not ID_RE.fullmatch(fact["id"]):
            problems.append(f"evidence fact {position}: its id is not a valid id")
    return findings, problems


# --- work order ---------------------------------------------------------------------------

def _top_cause(report: dict) -> dict | None:
    top = report["summary"].get("top_cause")
    return next((cause for cause in report["causes"] if cause["id"] == top), None) if top else None


def build_work_order(report: dict, case: dict, now: datetime, checked: dict | None = None) -> dict:
    """The machine-readable work order for an agent that never saw the investigation."""
    incident = case["incident"]
    top = _top_cause(report)
    cause = (
        {"statement": top["statement"], "label": top["label"], "finding_ids": list(top["supporting"])}
        if top else {"statement": NO_CAUSE_TEXT, "label": "unresolved", "finding_ids": []}
    )
    gaps = [f"{entry['what']}: {entry['why']}" for entry in report["coverage"]["not_checked"]]
    typesafe = report["coverage"]["typesafe"]
    if typesafe.startswith(TYPESAFE_UNAVAILABLE_PREFIX):
        gaps.append(f"TypeSafe {typesafe}")
    elif typesafe.startswith(TYPESAFE_FAILED_PREFIX):
        gaps.append(f"TypeSafe {typesafe}")
    for item in (checked or {}).get("unreadable") or []:
        if isinstance(item, dict):
            gaps.append(f"Finding file not read: {item.get('file')} ({item.get('reason')})")
    acted_on = {action["cause"] for action in report["actions"]}
    causes = [{"id": c["id"], "statement": c["statement"], "label": c["label"], "finding_ids": list(c["supporting"])}
              for c in report["causes"] if c["id"] in acted_on]
    order = {
        "incident": {"number": incident["number"], "title": incident["title"], "url": incident.get("url") or ""},
        "generated_at": format_time(now),
        "skill_version": case["skill_version"],
        "cause": cause,
        "causes": causes,
        "findings": _cited_findings(causes, report["actions"], cause, checked),
        "actions": [{key: copy.deepcopy(action[key]) for key in WORK_ORDER_ACTION_KEYS} for action in report["actions"]],
        "open_questions": list(report["open_questions"]),
        "coverage_gaps": gaps,
    }
    if case.get("replay") is True:
        order["replay"] = True
    return order


def _cited_findings(causes: list[dict], actions: list[dict], top: dict, checked: dict | None) -> list[dict]:
    """Claim, quote, and provenance of every finding the work order cites, in order of first mention."""
    ids: list[str] = []
    for source in (top, *causes, *actions):
        for finding_id in source.get("finding_ids", []):
            if finding_id not in ids:
                ids.append(finding_id)
    stored = {item.get("id"): item for item in (checked or {}).get("valid") or [] if isinstance(item, dict)}
    return [{"id": finding_id, "claim": str(stored[finding_id].get("claim", "")),
             "quote": str(stored[finding_id].get("excerpt", "")), "provenance": str(stored[finding_id].get("provenance", ""))}
            for finding_id in ids if finding_id in stored]


def _check_work_order_causes(work_order: dict, problems: list[str]) -> None:
    for key, text_keys in (("causes", ("id", "statement")), ("findings", ("id", "claim", "quote", "provenance"))):
        if key not in work_order:
            problems.append(f"work order.{key}: missing")
        elif not isinstance(work_order[key], list):
            problems.append(f"work order.{key}: must be a list")
        else:
            for index, entry in enumerate(work_order[key]):
                where = f"{key}[{index}]"
                if not isinstance(entry, dict):
                    problems.append(f"{where}: must be an object")
                    continue
                _only_keys(entry, text_keys + (("label", "finding_ids") if key == "causes" else ()), where, problems)
                for text_key in text_keys:
                    _text_field(entry, text_key, where, problems)  # every one must be non-empty text
                if key == "causes":
                    _choice_field(entry, "label", LABEL_ORDER, where, problems)
                    _string_list_field(entry, "finding_ids", where, problems)


def validate_work_order(work_order: Any) -> list[str]:
    """Check a work order against the structure in the design spec."""
    if not isinstance(work_order, dict):
        return ["work order: must be a JSON object"]
    problems: list[str] = []
    _only_keys(work_order, WORK_ORDER_KEYS + WORK_ORDER_OPTIONAL_KEYS, "work order", problems)
    if "replay" in work_order and work_order["replay"] is not True:
        problems.append("work order.replay: must be true when present")
    incident = _dict_field(work_order, "incident", "work order", problems)
    if incident is not None:
        _only_keys(incident, ("number", "title", "url"), "incident", problems)
        _text_field(incident, "number", "incident", problems)
        _text_field(incident, "title", "incident", problems)
        _text_field(incident, "url", "incident", problems, required_text=False)
    _text_field(work_order, "skill_version", "work order", problems)
    if "generated_at" not in work_order:
        problems.append("work order.generated_at: missing")
    else:
        try:
            parse_time(work_order["generated_at"])
        except WindowError:
            problems.append("work order.generated_at: not a valid UTC time")
    cause = _dict_field(work_order, "cause", "work order", problems)
    if cause is not None:
        _only_keys(cause, ("statement", "label", "finding_ids"), "cause", problems)
        _text_field(cause, "statement", "cause", problems)
        _choice_field(cause, "label", WORK_ORDER_CAUSE_LABELS, "cause", problems)
        _string_list_field(cause, "finding_ids", "cause", problems)
    _check_work_order_causes(work_order, problems)
    if "actions" not in work_order:
        problems.append("work order.actions: missing")
    elif not isinstance(work_order["actions"], list):
        problems.append("work order.actions: must be a list")
    else:
        for index, action in enumerate(work_order["actions"]):
            if not isinstance(action, dict):
                problems.append(f"actions[{index}]: must be an object")
                continue
            _only_keys(action, WORK_ORDER_ACTION_KEYS, f"actions[{index}]", problems)
            if isinstance(action.get("target"), dict):
                _only_keys(action["target"], TARGET_KEYS, f"actions[{index}].target", problems)
            _check_action_shape(action, f"actions[{index}]", problems)
    for key in ("open_questions", "coverage_gaps"):
        _string_list_field(work_order, key, "work order", problems)
    return problems


# --- evidence coverage --------------------------------------------------------------------

TRUNCATED_CODE = "truncated"
UNREADABLE_CODE = "unreadable"


def coverage_from_evidence(case_dir: Path) -> list[dict]:
    """Evidence errors grouped by code, then files marked truncated, as [{"code", "entries"}] sorted by code."""
    groups: dict[str, list[dict]] = {}
    readable = {name for name, _ in evidence_documents(case_dir)}
    for path in sorted((case_dir / "evidence").glob("*.json")):
        if path.name not in readable:
            groups.setdefault(UNREADABLE_CODE, []).append(
                {"file": path.name, "command": "", "message": "the file could not be read as an evidence document; its facts are missing"})
    for file_name, document in evidence_documents(case_dir):
        for error in document.get("errors") or []:
            if isinstance(error, dict):
                groups.setdefault(str(error.get("code", "unknown")), []).append(
                    {"file": file_name, "command": str(error.get("command", "")), "message": str(error.get("message", ""))})
        if document.get("truncated"):
            groups.setdefault(TRUNCATED_CODE, []).append(
                {"file": file_name, "command": "", "message": "evidence was cut off at the fact limit; later facts are missing"})
    return [{"code": code, "entries": groups[code]} for code in sorted(groups)]


# --- rendering ----------------------------------------------------------------------------

def _inline(value: Any) -> str:
    """One line of safe text: whitespace collapsed so a field cannot start a heading or break a list, angle
    brackets written as entities so it cannot make HTML, and "](" broken so it cannot make a link."""
    text = " ".join(str(value).split()).replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("](", "] (").replace("`", "'").replace("*", "\\*")


def _time_text(value: Any) -> str:
    """A timestamp re-formatted in UTC, or "unreadable time". An empty value reads "-"."""
    if value in (None, ""):
        return "-"
    try:
        return format_time(parse_time(value))
    except (WindowError, TypeError, ValueError, OverflowError):
        return "unreadable time"


def _cell(value: Any) -> str:
    return _inline(value).replace("|", "\\|")


def display_case_folder(case: dict) -> str:
    """The case folder without any local path: "cases/<incident folder>/<run folder>" under a cases root,
    otherwise its last two path components."""
    folder = case.get("case_dir") if isinstance(case, dict) else None
    if not isinstance(folder, str) or not folder:
        return "-"
    parts = [part for part in PurePath(folder).parts if part not in ("/", "\\") and not part.endswith(":\\")]
    incident = case.get("incident") if isinstance(case.get("incident"), dict) else {}
    number = incident.get("number")
    expected = re.sub(r"[^A-Za-z0-9_-]", "-", number) if isinstance(number, str) else None
    tail = "/".join(parts[-2:])
    return f"cases/{tail}" if len(parts) >= 2 and parts[-2] == expected else tail or "-"


def strip_local_paths(value: Any, case: dict) -> Any:
    """Text with this run's absolute case folder, its cases root, and the home folder replaced by short forms.

    Works on text, lists, and dictionaries (values only). Nothing else about the value changes.
    """
    if isinstance(value, str):
        folder = case.get("case_dir") if isinstance(case, dict) else None
        if isinstance(folder, str) and folder:
            value = value.replace(folder, display_case_folder(case))
            root = str(PurePath(folder).parent.parent)
            if root not in ("", ".", "/"):
                value = value.replace(root, "cases")
        home = str(Path.home())
        return value.replace(home, "~") if home not in ("", "/") else value
    if isinstance(value, list):
        return [strip_local_paths(item, case) for item in value]
    if isinstance(value, dict):
        return {key: strip_local_paths(item, case) for key, item in value.items()}
    return value


def _read_checked(case: dict) -> dict:
    try:
        checked = json.loads((Path(case["case_dir"]) / "findings" / "checked.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError):
        return {}
    return checked if isinstance(checked, dict) else {}


def _checks_recorded(checked: dict) -> list[str]:
    """One line per analyst that recorded what it checked."""
    recorded = checked.get("checked") if isinstance(checked.get("checked"), dict) else {}
    return [f"{_inline(analyst)}: {'; '.join(_inline(item) for item in items)}"
            for analyst, items in sorted(recorded.items()) if isinstance(items, list) and items]


def _none(checked: dict) -> list[str]:
    """The text of an empty section: what the analysts recorded as checked, or that nothing was recorded."""
    lines = _checks_recorded(checked)
    if not lines:
        return ["None. No checks were recorded."]
    return ["None. Checks recorded by the analysts:", ""] + [f"- {line}" for line in lines]


def _bullets(items: list[str]) -> list[str]:
    return [f"- {_inline(item)}" for item in items] or ["None."]


def _field(label: str, value: Any) -> str:
    return f"- {label}: {_inline(value) if value not in (None, '') else '-'}"


def _judged_top_cause(report: dict, summary: dict | None) -> tuple[dict, str] | None:
    """The top cause and its label from the judgments summary, or None when no cause was judged as the top."""
    top = _top_cause(report)
    entry = _summary_entry((summary or {}).get("causes"), top.get("id")) if top else None
    label = entry.get("label") if entry else None
    return (top, label) if top and isinstance(label, str) and label in LABEL_ORDER else None


def _render_summary(report: dict, summary: dict | None) -> list[str]:
    author = report["summary"]
    judged = _judged_top_cause(report, summary)
    what = f"{_inline(judged[0]['statement'])} ({_inline(judged[1])})" if judged else NO_CAUSE_TEXT
    lines = ["## 1. Summary", "", f"**What broke:** {what}", "", f"**Scope:** {_inline(author['scope'])}", "",
             "**Symptoms:**", ""]
    lines += _bullets(report["symptoms"])
    lines += ["", "**Author's summary (not scored)**", "",
              f"- What broke: {_inline(author['what_broke'])}", f"- Impact: {_inline(author['impact'])}"]
    return lines


def _render_incident(case: dict) -> list[str]:
    incident, window, target = case["incident"], case["window"], case.get("target")
    lines = ["## 2. Incident and window", "",
             _field("Number", incident["number"]), _field("Title", incident["title"]), _field("Link", incident.get("url")),
             _field("Severity", incident.get("severity")), _field("State", incident.get("state")),
             _field("Impact started", incident.get("impact_started_at")), _field("Declared", incident.get("declared_at")),
             _field("Resolved", incident.get("resolved_at")),
             _field("Window examined", f"{window['start']} to {window['end']}")]
    if target:
        found = "from the service map" if target.get("source") == "map" else "found by discovery"
        name = target.get("service") or "unnamed service"
        lines.append(_field("Target", f"{name} in account {target['account']}, region {target['region']} ({found})"))
    else:
        lines.append(_field("Target", "none was chosen"))
    return lines


def _finding_verdict_lines(finding_id: str, summary: dict | None) -> list[str]:
    entry = ((summary or {}).get("findings") or {}).get(finding_id)
    if not isinstance(entry, dict):
        return []
    confidence = entry.get("confidence")
    detail = ", ".join(part for part in (
        entry.get("relation"), f"confidence {number(confidence)}" if isinstance(confidence, (int, float)) else None) if part)
    return [_field("TypeSafe verdict", f"{entry.get('verdict', '-')} ({detail})" if detail else entry.get("verdict"))]


def _renderable(finding: Any) -> bool:
    """A finding is rendered only when its id and cited fact ids are plain, pattern-matching text."""
    return (isinstance(finding, dict) and isinstance(finding.get("id"), str) and ID_RE.fullmatch(finding["id"]) is not None
            and _text_list(finding.get("fact_ids")) and all(ID_RE.fullmatch(f) for f in finding["fact_ids"]))


def _short_command(command: Any) -> str:
    """A metric query command is shortened to the operation, metric names, statistic, and period."""
    text = str(command or "")
    if "get-metric-data" not in text or "MetricName" not in text:
        return text or "-"
    names = list(dict.fromkeys(re.findall(r"MetricName\W+([A-Za-z0-9_./-]+)", text)))
    stat = re.search(r"(?<![A-Za-z])Stat\W+([A-Za-z0-9.]+)", text)
    period = re.search(r"Period\W+(\d+)", text)
    return (f"aws cloudwatch get-metric-data (metric {', '.join(names)}; statistic {stat.group(1) if stat else '-'}; "
            f"period {period.group(1) + ' s' if period else '-'})")


def _fact_line(fact_id: str, fact: dict | None) -> str:
    if fact is None or not isinstance(fact.get("id"), str) or not ID_RE.fullmatch(fact["id"]):
        return f"  - {_inline(fact_id)}: fact not available"
    line = (f"  - {_inline(fact_id)}: command `{_inline(_short_command(fact.get('command')))}`, "
            f"resource {_inline(fact.get('resource') or '-')}, time {_time_text(fact.get('time'))}, "
            f"summary: {_inline(fact.get('summary') or '-')}")
    return line + (f", excerpt: {_inline(fact['excerpt'])}" if fact.get("excerpt") else "")


def _safe_rows(rows: list[dict]) -> list[dict]:
    """Timeline rows with every text passed through the same escaping, and times re-formatted or marked unreadable."""
    safe = []
    for row in rows:
        row = row if isinstance(row, dict) else {}
        fact_id = row.get("fact_id")
        safe.append({
            "time": _time_text(row.get("time")) if row.get("time") else "",
            "offset": _inline(row.get("offset", "")),
            "text": _inline(row.get("text", "")),
            "source": _inline(row.get("source", "")),
            "fact_id": _inline(fact_id) if isinstance(fact_id, str) and ID_RE.fullmatch(fact_id) else None,
            "resource": _inline(row.get("resource", "")),
            "group": row.get("group") if isinstance(row.get("group"), str) else None,
        })
    return safe


BEFORE_WINDOW_GROUP = "before the window"


def _render_timeline(rows: list[dict], checked: dict) -> str:
    """The timeline table; rows dated before the collection window follow under their own sub-heading."""
    from triage.timeline import render_rows

    if not rows:
        return "\n".join(_none(checked))
    safe = _safe_rows(rows)
    inside = [row for row in safe if row["group"] != BEFORE_WINDOW_GROUP]
    before = [{**row, "group": None} for row in safe if row["group"] == BEFORE_WINDOW_GROUP]
    text = render_rows(inside)
    if before:
        text += "\n\n### Before the window\n\nThese events are dated before the collection window started.\n\n" + render_rows(before)
    return text


def _render_findings(findings: dict[str, dict], facts: dict[str, dict], summary: dict | None, checked: dict) -> list[str]:
    lines = ["## 4. Findings", ""]
    shown = [finding for finding in findings.values() if _renderable(finding)]
    if not shown:
        return lines + _none(checked)
    by_analyst: dict[str, list[dict]] = {}
    for finding in shown:
        by_analyst.setdefault(str(finding.get("analyst", "unknown")), []).append(finding)
    for analyst in sorted(by_analyst):
        lines += [f"### {_inline(analyst)}", ""]
        for finding in by_analyst[analyst]:
            lines += [f"**{_inline(finding['id'])}**: {_inline(finding.get('claim', '-'))}", "",
                      _field("Provenance", finding.get("provenance")), _field("Confidence", finding.get("confidence")),
                      _field("Quote", finding.get("excerpt")),
                      _field("Cited facts", ", ".join(finding["fact_ids"]))]
            lines += [_fact_line(fact_id, facts.get(fact_id)) for fact_id in finding["fact_ids"]]
            lines += _finding_verdict_lines(finding["id"], summary)
            lines.append("")
        lines.pop()
    checks = _checks_recorded(checked)
    if checks:
        lines += ["", "**Checks recorded by the analysts**", ""] + [f"- {line}" for line in checks]
    return lines


def _hypothesis_table(hypotheses: list[dict]) -> list[str]:
    lines = ["| Hypothesis | Prediction | Test | Result |", "| --- | --- | --- | --- |"]
    for item in hypotheses:
        lines.append(f"| {_cell(item['id'])}: {_cell(item['statement'])} | {_cell(item['prediction'])} | "
                     f"{_cell(item['test'])} | {_cell(item['result'])} |")
    return lines


def _numeric(value: Any) -> str:
    return number(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else "-"


def _judgment_lines(cause_id: str, summary: dict | None) -> list[str]:
    entry = ((summary or {}).get("causes") or {}).get(cause_id)
    if not isinstance(entry, dict):
        return []
    gates = entry.get("gates") if isinstance(entry.get("gates"), dict) else {}
    passed = [name for name, ok in gates.items() if ok]
    missed = [name for name, ok in gates.items() if not ok]
    lines = [_field("Gates met", ", ".join(passed) or "none") if gates else _field("Gates", "none were evaluated"),
             _field("Gates not met", ", ".join(missed) or "none") if gates else None,
             _field("Ranking probability", _numeric(entry.get("rank_probability"))),
             _field("Symptom fit", _numeric(entry.get("symptom_fit"))),
             _field("Scope", entry.get("scope"))]
    lines = [line for line in lines if line]
    reasons = [str(reason) for reason in entry.get("reasons") or []]
    if reasons:
        lines += ["- Reasons:"] + [f"  - {_inline(reason)}" for reason in reasons]
    return lines


def _render_causes(report: dict, summary: dict | None, checked: dict) -> list[str]:
    lines = ["## 5. Ranked causes", ""]
    if not report["causes"]:
        return lines + _none(checked)
    for rank, cause in enumerate(report["causes"], 1):
        tested = [h for h in report["hypotheses"] if h.get("cause") == cause["id"]]
        lines += [f"### {rank}. {_inline(cause['id'])} ({_inline(cause['label'])}): {_inline(cause['statement'])}", "",
                  _field("Supporting findings", ", ".join(cause["supporting"]) or "none"),
                  _field("Contradicting findings", ", ".join(cause["contradicting"]) or "none")]
        lines += _judgment_lines(cause["id"], summary) + [""]
        lines += _hypothesis_table(tested) if tested else ["No hypothesis tested this cause."]
        lines.append("")
    cause_ids = {cause["id"] for cause in report["causes"]}
    others = [h for h in report["hypotheses"] if h.get("cause") not in cause_ids]
    if others:
        lines += ["### Other hypotheses", ""] + _hypothesis_table(others) + [""]
    return lines[:-1]


def _render_action(action: dict, summary: dict | None) -> list[str]:
    target = action["target"]
    lines = [f"### {_inline(action['id'])}: {_inline(action['title'])}", ""]
    if action["label"] == "candidate":
        lines += ["**Candidate: needs more evidence before anyone acts on it.**", ""]
    lines += [_field("Type", action["type"]), _field("Label", action["label"]), _field("Cause", action["cause"]),
              _field("Account", f"{target['account_alias']} ({target['account_id'] or '-'})"),
              _field("Region", target["region"]), _field("Service", target["service"]),
              _field("Resource", target["resource_id"]), _field("ARN", target["arn"]),
              _field("Current state", action["current_state"]), _field("Required state", action["required_state"]),
              _field("Change", action["change"]), _field("Rationale", action["rationale"]),
              _field("Findings", ", ".join(action["finding_ids"])), _field("Risk", action["risk"]),
              _field("Blast radius", action["blast_radius"])]
    entry = ((summary or {}).get("actions") or {}).get(action["id"])
    if isinstance(entry, dict):
        confidence = entry.get("target_confidence")
        answer = entry.get("target")
        if answer is not None:
            lines.append(_field("Target answer", f"{answer} (confidence {_numeric(confidence)})"))
        if action["label"] == "candidate" and entry.get("reasons"):
            lines.append("- Reasons it is a candidate:")
            lines += [f"  - {_inline(reason)}" for reason in entry["reasons"]]
    for key, label in (("preconditions", "Preconditions"), ("verification", "Verification"), ("rollback", "Rollback")):
        lines.append(f"- {label}:")
        lines += [f"  - {_inline(step)}" for step in action[key]] or ["  - None."]
    return lines


def _render_actions(report: dict, summary: dict | None, checked: dict) -> list[str]:
    lines = ["## 6. Remediation work order", ""]
    ordered = [a for kind in ACTION_TYPES for a in report["actions"] if a["type"] == kind]
    if not ordered:
        return lines + _none(checked)
    for action in ordered:
        lines += _render_action(action, summary) + [""]
    return lines[:-1]


def _rejected_findings(case: dict) -> list[dict]:
    try:
        checked = json.loads((Path(case["case_dir"]) / "findings" / "checked.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError):
        return []
    rejected = checked.get("rejected") if isinstance(checked, dict) else None
    return [item for item in rejected or [] if isinstance(item, dict)]


def _typesafe_line(report: dict, summary: dict | None) -> str:
    typesafe = summary.get("typesafe") if summary else report["coverage"]["typesafe"]
    if typesafe != "available":
        return f"TypeSafe: {_inline(typesafe)}"
    if summary is None:
        return "TypeSafe: available; no judgments are stored for this case"
    return f"TypeSafe: available (model {_inline(summary.get('model') or 'unknown')}); thresholds are uncalibrated"


def _render_coverage(report: dict, case: dict, evidence_gaps: list[dict], summary: dict | None,
                     adhoc: list[dict], checked: dict) -> list[str]:
    lines = ["## 7. Coverage notes", "", "**Not checked**", ""]
    lines += _bullets([f"{e['what']}: {e['why']}" for e in report["coverage"]["not_checked"]])
    lines += ["", "**Evidence errors**", ""]
    entries = [f"{gap['code']}: `{_inline(e['command'] or e['file'])}` ({_inline(e['message'])})"
               for gap in evidence_gaps for e in gap["entries"]]
    lines += _bullets(entries)
    asks = [str(item) for item in (summary or {}).get("ask_engineer") or []]
    lines += ["", "**TypeSafe**", "", _typesafe_line(report, summary), "", "**Questions for the engineer**", ""]
    lines += _bullets(asks)
    lines += ["", "**Ad hoc questions**", ""]
    lines += _bullets([f"{entry.get('id')}: {entry.get('reason')}" for entry in adhoc if isinstance(entry, dict)])
    lines += ["", "**Rejected findings**", ""]
    lines += _bullets([f"{r.get('analyst', '?')} {r.get('id')}: {'; '.join(map(str, r.get('reasons', [])))}"
                       for r in _rejected_findings(case)])
    lines += ["", "**Finding files that could not be read**", ""]
    lines += _bullets([f"{u.get('file')}: {u.get('reason')}" for u in checked.get("unreadable") or [] if isinstance(u, dict)])
    lines += ["", "**Notes from the finding check**", ""]
    lines += _bullets([str(note) for note in checked.get("warnings") or []])
    lines += ["", "**Open questions**", ""] + _bullets(report["open_questions"])
    return lines


def _render_map_changes(report: dict, case: dict) -> list[str]:
    changes = [item if isinstance(item, str) else json.dumps(item, sort_keys=True) for item in report["map_changes"]]
    target = case.get("target") if isinstance(case.get("target"), dict) else {}
    lines = ["## 8. Proposed service map changes", ""] + (_bullets(changes) if changes else ["None."])
    if target.get("source") == "discovered":
        lines += ["", DISCOVERED_TARGET_TEXT]
    return lines


def _render_run(report: dict, case: dict, now: datetime) -> list[str]:
    run = report["run"]
    return ["## 9. Run details", "", _field("Engineer", run["engineer"]),
            _field("Duration", f"{run['duration_minutes']} minutes"), _field("Skill version", case["skill_version"]),
            _field("Case folder", display_case_folder(case)), _field("Report rendered", format_time(now))]


def render_report(report: dict, case: dict, findings: dict[str, dict], timeline_rows: list[dict],
                  evidence_gaps: list[dict], now: datetime) -> str:
    """The fixed-format Markdown report. Facts and rejected findings are read from the case folder."""
    incident = case["incident"]
    facts = load_facts(Path(case["case_dir"]))
    raw_summary, _ = load_summary(case)
    summary = _judged(raw_summary)
    adhoc = (raw_summary or {}).get("adhoc") or []
    checked = _read_checked(case)
    blocks = [
        [f"{REQUIRED_HEADINGS[0]} {_inline(incident['number'])} {_inline(incident['title'])}"]
        + (["", REPLAY_LINE] if case.get("replay") is True else []),
        _render_summary(report, summary),
        _render_incident(case),
        ["## 3. Timeline", "", _render_timeline(timeline_rows, checked)],
        _render_findings(findings, facts, summary, checked),
        _render_causes(report, summary, checked),
        _render_actions(report, summary, checked),
        _render_coverage(report, case, evidence_gaps, summary, adhoc, checked),
        _render_map_changes(report, case),
        _render_run(report, case, now),
    ]
    text = "\n\n".join("\n".join(block) for block in blocks) + "\n"
    return Redactor().text(strip_local_paths(text, case))


# --- the render marker: which inputs the outputs were rendered from ---------------------------

OUTPUT_NAMES = ("report.md", "work-order.json")
INPUT_NAMES = ("report.json", "judgments/summary.json", "findings/checked.json")
MARKER_NAME = "render.json"


def _sha256(path: Path) -> str | None:
    """The hash of a file, or None when it does not exist."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def input_hashes(case_dir: Path) -> dict[str, str | None]:
    """The hash of report.json, the judgment summary, and checked.json. A missing file is None."""
    return {name: _sha256(Path(case_dir) / name) for name in INPUT_NAMES}


def write_render_marker(case_dir: Path, inputs: dict[str, str | None]) -> None:
    """Record the hash of both outputs on disk and of the inputs they were rendered from."""
    case_dir = Path(case_dir)
    marker = {**{name: _sha256(case_dir / name) for name in OUTPUT_NAMES}, **inputs}
    (case_dir / f"{MARKER_NAME}.tmp").write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")
    os.replace(case_dir / f"{MARKER_NAME}.tmp", case_dir / MARKER_NAME)


def mark_stale(case_dir: Path) -> tuple[list[str], list[str]]:
    """Rename every output of an earlier render, and its marker, to <name>.stale.

    Returns (renamed outputs, outputs that could not be renamed). One failure does not stop the others,
    and leftover temporary names are cleared if they can be.
    """
    case_dir = Path(case_dir)
    renamed, failed = [], []
    marker = case_dir / MARKER_NAME
    if marker.exists():
        try:
            os.replace(marker, case_dir / f"{MARKER_NAME}.stale")
        except OSError:
            pass
    for name in OUTPUT_NAMES:
        path = case_dir / name
        if path.exists():
            try:
                os.replace(path, case_dir / f"{name}.stale")
                renamed.append(f"{name}.stale")
            except OSError:
                failed.append(name)
        for leftover in (f"{name}.tmp", f"{MARKER_NAME}.tmp"):
            try:
                (case_dir / leftover).unlink(missing_ok=True)
            except OSError:
                pass
    return renamed, failed


def _marker_reasons(case_dir: Path) -> list[str]:
    try:
        marker = json.loads((case_dir / MARKER_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [f"{MARKER_NAME} is missing or cannot be read"]
    if not isinstance(marker, dict):
        return [f"{MARKER_NAME} is damaged"]
    reasons = []
    current = {**{name: _sha256(case_dir / name) for name in OUTPUT_NAMES}, **input_hashes(case_dir)}
    for name, digest in current.items():
        if name not in marker:
            reasons.append(f"{MARKER_NAME} does not record {name}")
        elif marker[name] != digest:
            kind = "the rendered file" if name in OUTPUT_NAMES else "an input"
            reasons.append(f"{name} ({kind}) is not what {MARKER_NAME} records")
    return reasons


def render_is_current(case_dir: Path) -> list[str]:
    """Why the rendered outputs are not current, as reasons; an empty list means they are.

    The outputs are current only when render.json matches report.md, work-order.json, report.json, the
    judgment summary, and findings/checked.json. When they are not, both outputs that exist are renamed
    to .stale and the last reason says so. This is the only side effect, and the function never raises.
    """
    try:
        case_dir = Path(case_dir)
        if not any((case_dir / name).exists() for name in OUTPUT_NAMES):
            return ["report.md and work-order.json have not been rendered"]
        reasons = _marker_reasons(case_dir)
        if reasons:
            renamed, failed = mark_stale(case_dir)
            reasons.append("the outputs no longer match their inputs and were renamed"
                           + (f" ({', '.join(renamed)})" if renamed else "")
                           + "; the report must be rendered again"
                           + (f" (could not rename: {', '.join(failed)})" if failed else ""))
        return reasons
    except Exception as error:  # a damaged folder is a reason, never a traceback
        return [f"the render state could not be checked ({type(error).__name__}); the report must be rendered again"]
