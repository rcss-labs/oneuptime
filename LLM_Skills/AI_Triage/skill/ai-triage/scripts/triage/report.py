"""Validate report.json, render the report, and build the remediation work order.

Validation is the quality gate: a report is rendered only when it is complete and consistent.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from triage.compose import LABEL_ORDER, cap_label, number
from triage.config import TriageConfig
from triage.digest import action_digest, cause_digest
from triage.findings import evidence_documents, load_facts
from triage.redact import Redactor, audit_text
from triage.window import WindowError, format_time, parse_time

STATUSES = ("cause_found", "unresolved")
HYPOTHESIS_RESULTS = ("confirmed", "rejected", "inconclusive")
ACTION_TYPES = ("mitigation", "permanent_fix")
ACTION_LABELS = ("recommended", "candidate")
WORK_ORDER_CAUSE_LABELS = LABEL_ORDER + ("unresolved",)
WORK_ORDER_ACTION_KEYS = ("id", "type", "label", "title", "target", "current_state", "required_state", "change",
                          "rationale", "finding_ids", "risk", "blast_radius", "preconditions", "verification", "rollback")
WORK_ORDER_KEYS = ("incident", "generated_at", "skill_version", "cause", "actions", "open_questions", "coverage_gaps")
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
    if isinstance(typesafe, str) and typesafe != "available" and not typesafe.startswith(TYPESAFE_UNAVAILABLE_PREFIX):
        problems.append(f"coverage.typesafe: must be 'available' or start with '{TYPESAFE_UNAVAILABLE_PREFIX}'")
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
            if causes[top].get("label") not in ("confirmed", "probable"):
                problems.append("summary.top_cause: the top cause must be labelled confirmed or probable")
            if not any(h.get("result") == "confirmed" and h.get("cause") in (None, top) for _, h in parts["hypotheses"]):
                problems.append("status is cause_found but no confirmed hypothesis belongs to the top cause "
                                "(a hypothesis with no cause counts as belonging to it)")
    if results.count("rejected") >= 3 and "confirmed" not in results and status != "unresolved":
        problems.append("status: three or more hypotheses were rejected and none confirmed, so status must be unresolved")
    if status == "unresolved":
        if top not in (None, ""):
            problems.append("summary.top_cause: must be null or empty when status is unresolved")
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
        elif action.get("label") == "recommended" and cause.get("label") != "confirmed":
            problems.append(f"{where}: recommended, but its cause is not labelled confirmed")
        target = action.get("target") if isinstance(action.get("target"), dict) else {}
        alias = target.get("account_alias")
        if isinstance(alias, str) and alias.strip() and alias not in config.accounts:
            problems.append(f"{where}.target.account_alias: not an account in the config")
        if not any(i in findings for i in _text_ids(action.get("finding_ids"))):
            problems.append(f"{where}.finding_ids: needs at least one valid finding")


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


def load_summary(case: dict) -> tuple[dict | None, str | None]:
    """The stored judgments summary, or None, plus a problem when the file exists but cannot be read."""
    path = Path(case.get("case_dir", "")) / "judgments" / SUMMARY_NAME
    if not path.is_file():
        return None, None
    try:
        summary = json.loads(path.read_text())
    except (OSError, ValueError):
        summary = None
    if not isinstance(summary, dict) or not isinstance(summary.get("causes"), dict):
        return None, f"judgments/{SUMMARY_NAME}: cannot be read as a judgments summary, so labels cannot be checked"
    return summary, None


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


def _check_causes_against_summary(summary: dict, parts: dict, edited: set[int], problems: list[str]) -> None:
    for index, cause in parts["causes"]:
        label, where = cause.get("label"), f"causes[{index}]"
        if label not in LABEL_ORDER:
            continue
        if index in edited:
            if cap_label(label, "candidate") != label:
                problems.append(f"{where}: labelled {label}, stronger than candidate, which an edited cause counts as")
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
                                   problems: list[str]) -> None:
    edited_cause_ids = {cause.get("id") for index, cause in parts["causes"] if index in edited_causes}
    for index, action in parts["actions"]:
        where = f"actions[{index}]"
        if action.get("label") == "recommended":
            if index in edited_actions:
                problems.append(f"{where}: recommended, but the action was edited after judging")
            if isinstance(action.get("cause"), str) and action["cause"] in edited_cause_ids:
                problems.append(f"{where}: recommended, but its cause was edited after judging")
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


def _check_judgments(report: dict, case: dict, parts: dict, findings: dict[str, dict], problems: list[str]) -> None:
    raw, unreadable = load_summary(case)
    if unreadable:
        problems.append(unreadable)
        return
    summary = _judged(raw)
    _check_typesafe_against_summary(report, summary, problems)
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    already_barred = str(coverage.get("typesafe")).startswith(TYPESAFE_UNAVAILABLE_PREFIX)
    if summary is None and not already_barred:
        for index, cause in parts["causes"]:
            if cause.get("label") == "confirmed":
                problems.append(f"causes[{index}]: no judging run is stored, so no cause may be labelled confirmed")
    if summary is not None:
        edited_causes, edited_actions = _edited_entries(summary, parts, findings, problems)
        _check_causes_against_summary(summary, parts, edited_causes, problems)
        _check_actions_against_summary(summary, parts, edited_causes, edited_actions, problems)
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


def validate_report(report: Any, case: dict, findings: dict[str, dict], config: TriageConfig) -> list[str]:
    """Every problem that stops the report from being rendered. An empty list means it may be rendered.

    Never raises on a malformed report, and no message repeats a value from the report.
    """
    if not isinstance(report, dict):
        return ["report: must be a JSON object"]
    problems: list[str] = []
    parts = _check_shape(report, problems)
    _check_finding_ids(parts["causes"], "causes", ("supporting", "contradicting"), findings, problems)
    _check_finding_ids(parts["hypotheses"], "hypotheses", ("finding_ids",), findings, problems)
    _check_finding_ids(parts["actions"], "actions", ("finding_ids",), findings, problems)
    _check_causes(parts, findings, problems)
    _check_status(report, parts, problems)
    _check_actions(config, parts, findings, problems)
    _check_hypothesis_causes(parts, problems)
    _check_typesafe(report, parts, problems)
    _check_judgments(report, case, parts, findings, problems)
    _check_secrets(report, problems)
    return problems


# --- work order ---------------------------------------------------------------------------

def _top_cause(report: dict) -> dict | None:
    top = report["summary"].get("top_cause")
    return next((cause for cause in report["causes"] if cause["id"] == top), None) if top else None


def build_work_order(report: dict, case: dict, now: datetime) -> dict:
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
    return {
        "incident": {"number": incident["number"], "title": incident["title"], "url": incident.get("url") or ""},
        "generated_at": format_time(now),
        "skill_version": case["skill_version"],
        "cause": cause,
        "actions": [{key: copy.deepcopy(action[key]) for key in WORK_ORDER_ACTION_KEYS} for action in report["actions"]],
        "open_questions": list(report["open_questions"]),
        "coverage_gaps": gaps,
    }


def validate_work_order(work_order: Any) -> list[str]:
    """Check a work order against the structure in the design spec."""
    if not isinstance(work_order, dict):
        return ["work order: must be a JSON object"]
    problems: list[str] = []
    _only_keys(work_order, WORK_ORDER_KEYS, "work order", problems)
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
            _check_action_shape({**action, "cause": "-"}, f"actions[{index}]", problems)
    for key in ("open_questions", "coverage_gaps"):
        _string_list_field(work_order, key, "work order", problems)
    return problems


# --- evidence coverage --------------------------------------------------------------------

TRUNCATED_CODE = "truncated"


def coverage_from_evidence(case_dir: Path) -> list[dict]:
    """Evidence errors grouped by code, then files marked truncated, as [{"code", "entries"}] sorted by code."""
    groups: dict[str, list[dict]] = {}
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
    """One line of text: whitespace collapsed so a field cannot start a heading or break a list."""
    return " ".join(str(value).split())


def _cell(value: Any) -> str:
    return _inline(value).replace("|", "\\|")


def _bullets(items: list[str]) -> list[str]:
    return [f"- {_inline(item)}" for item in items] or ["None."]


def _field(label: str, value: Any) -> str:
    return f"- {label}: {_inline(value) if value not in (None, '') else '-'}"


def _render_summary(report: dict) -> list[str]:
    summary = report["summary"]
    top = _top_cause(report)
    lines = ["## 1. Summary", "", f"**What broke:** {_inline(summary['what_broke'])}", "",
             f"**Impact:** {_inline(summary['impact'])}", "", f"**Scope:** {_inline(summary['scope'])}", "",
             "**Symptoms:**", ""]
    lines += _bullets(report["symptoms"])
    lines.append("")
    if top:
        lines.append(f"**Top cause ({top['label']}):** {_inline(top['id'])}: {_inline(top['statement'])}")
    else:
        lines.append(f"**Top cause:** {NO_CAUSE_TEXT}")
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


def _render_findings(findings: dict[str, dict], facts: dict[str, dict], summary: dict | None) -> list[str]:
    lines = ["## 4. Findings", ""]
    if not findings:
        return lines + ["None."]
    by_analyst: dict[str, list[dict]] = {}
    for finding in findings.values():
        by_analyst.setdefault(finding.get("analyst", "unknown"), []).append(finding)
    for analyst in sorted(by_analyst):
        lines += [f"### {_inline(analyst)}", ""]
        for finding in by_analyst[analyst]:
            lines += [f"**{_inline(finding['id'])}**: {_inline(finding['claim'])}", "",
                      _field("Provenance", finding["provenance"]), _field("Confidence", finding["confidence"]),
                      _field("Cited facts", ", ".join(finding["fact_ids"]))]
            lines += _finding_verdict_lines(finding["id"], summary)
            for fact_id in finding["fact_ids"]:
                fact = facts.get(fact_id)
                if fact is None:
                    lines.append(f"  - {fact_id}: fact not found")
                    continue
                lines.append(f"  - {fact_id}: command `{_inline(fact.get('command') or '-')}`, resource {_inline(fact.get('resource') or '-')}, "
                             f"time {fact.get('time') or '-'}, excerpt: {_inline(fact.get('excerpt') or fact.get('summary') or '-')}")
            lines.append("")
        lines.pop()
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
    lines = [_field("Gates passed", ", ".join(passed) or "none") if gates else _field("Gates", "none were evaluated"),
             _field("Gates missed", ", ".join(missed) or "none") if gates else None,
             _field("Ranking probability", _numeric(entry.get("rank_probability"))),
             _field("Symptom fit", _numeric(entry.get("symptom_fit"))),
             _field("Scope", entry.get("scope"))]
    lines = [line for line in lines if line]
    reasons = [str(reason) for reason in entry.get("reasons") or []]
    if reasons:
        lines += ["- Reasons:"] + [f"  - {_inline(reason)}" for reason in reasons]
    return lines


def _render_causes(report: dict, summary: dict | None) -> list[str]:
    lines = ["## 5. Ranked causes", ""]
    if not report["causes"]:
        return lines + ["None."]
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


def _render_actions(report: dict, summary: dict | None) -> list[str]:
    lines = ["## 6. Remediation work order", ""]
    ordered = [a for kind in ACTION_TYPES for a in report["actions"] if a["type"] == kind]
    if not ordered:
        return lines + ["None."]
    for action in ordered:
        lines += _render_action(action, summary) + [""]
    return lines[:-1]


def _rejected_findings(case: dict) -> list[dict]:
    try:
        checked = json.loads((Path(case["case_dir"]) / "findings" / "checked.json").read_text())
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
                     adhoc: list[dict]) -> list[str]:
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
    lines += ["", "**Open questions**", ""] + _bullets(report["open_questions"])
    return lines


def _render_map_changes(report: dict) -> list[str]:
    changes = [item if isinstance(item, str) else json.dumps(item, sort_keys=True) for item in report["map_changes"]]
    return ["## 8. Proposed service map changes", ""] + _bullets(changes)


def _render_run(report: dict, case: dict, now: datetime) -> list[str]:
    run = report["run"]
    return ["## 9. Run details", "", _field("Engineer", run["engineer"]),
            _field("Duration", f"{run['duration_minutes']} minutes"), _field("Skill version", case["skill_version"]),
            _field("Case folder", case["case_dir"]), _field("Report rendered", format_time(now))]


def render_report(report: dict, case: dict, findings: dict[str, dict], timeline_rows: list[dict],
                  evidence_gaps: list[dict], now: datetime) -> str:
    """The fixed-format Markdown report. Facts and rejected findings are read from the case folder."""
    from triage.timeline import render_rows

    incident = case["incident"]
    facts = load_facts(Path(case["case_dir"]))
    raw_summary, _ = load_summary(case)
    summary = _judged(raw_summary)
    adhoc = (raw_summary or {}).get("adhoc") or []
    blocks = [
        [f"{REQUIRED_HEADINGS[0]} {_inline(incident['number'])} {_inline(incident['title'])}"],
        _render_summary(report),
        _render_incident(case),
        ["## 3. Timeline", "", render_rows(timeline_rows) if timeline_rows else "None."],
        _render_findings(findings, facts, summary),
        _render_causes(report, summary),
        _render_actions(report, summary),
        _render_coverage(report, case, evidence_gaps, summary, adhoc),
        _render_map_changes(report),
        _render_run(report, case, now),
    ]
    text = "\n\n".join("\n".join(block) for block in blocks) + "\n"
    return Redactor().text(text)
