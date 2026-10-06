"""Check analyst findings against the evidence they cite, before any model judges them."""
from __future__ import annotations

import json
import re
from pathlib import Path

from triage.evidence import CURRENT, INCIDENT_TIME, load_evidence
from triage.redact import Redactor
from triage.window import WindowError, parse_time

CHECKED_NAME = "checked.json"
PROVENANCES = ("incident_time", "current", "inferred")
CONFIDENCES = ("high", "medium", "low")
_WHITESPACE_RE = re.compile(r"\s+")


def _collapse(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def evidence_documents(case_dir: Path, warnings: list[str] | None = None) -> list[tuple[str, dict]]:
    """Every readable evidence document of the case as (file name, document), in file name order."""
    documents = []
    for path in sorted((case_dir / "evidence").glob("*.json")):
        try:
            document = load_evidence(path)
        except (OSError, ValueError):
            document = None
        if not isinstance(document, dict):
            if warnings is not None:
                warnings.append(f"evidence file {path.name} is unreadable and was skipped")
            continue
        documents.append((path.name, document))
    return documents


def load_facts(case_dir: Path, warnings: list[str] | None = None) -> dict[str, dict]:
    """Fact id to fact across all evidence files. A repeated id is kept as "<file>:<id>"."""
    facts: dict[str, dict] = {}
    for file_name, document in evidence_documents(case_dir, warnings):
        for fact in document.get("facts", []):
            if not isinstance(fact, dict) or "id" not in fact:
                continue
            key = fact["id"]
            if key in facts:
                key = f"{file_name}:{fact['id']}"
                if warnings is not None:
                    warnings.append(f"fact id {fact['id']} appears in more than one evidence file; kept as {key}")
            facts[key] = {**fact, "file": file_name}
    return facts


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _field_problems(finding: dict) -> list[str]:
    problems = []
    for name in ("id", "claim", "excerpt"):
        if name not in finding:
            problems.append(f"{name} is missing")
        elif not isinstance(finding[name], str):
            problems.append(f"{name} must be text")
    if "fact_ids" not in finding:
        problems.append("fact_ids is missing")
    elif not isinstance(finding["fact_ids"], list) or not all(isinstance(item, str) for item in finding["fact_ids"]):
        problems.append("fact_ids must be a list of text")
    elif not finding["fact_ids"]:
        problems.append("fact_ids is empty")
    for name, allowed in (("provenance", PROVENANCES), ("confidence", CONFIDENCES)):
        if name not in finding:
            problems.append(f"{name} is missing")
        elif finding[name] not in allowed:
            problems.append(f"{name} must be one of {', '.join(allowed)}")
    if isinstance(finding.get("id"), str) and not _is_text(finding["id"]):
        problems.append("id is empty")
    if isinstance(finding.get("claim"), str) and not _is_text(finding["claim"]):
        problems.append("claim is empty")
    return problems


def _citation_problems(finding: dict, facts: dict[str, dict]) -> tuple[list[str], list[dict]]:
    """Problems with the cited facts and the excerpt, plus the cited facts that exist."""
    problems, cited = [], []
    if not isinstance(finding.get("fact_ids"), list) or not all(isinstance(item, str) for item in finding["fact_ids"]):
        return problems, cited
    for fact_id in finding["fact_ids"]:
        if fact_id in facts:
            cited.append(facts[fact_id])
        else:
            problems.append(f"fact id {fact_id} does not exist")
    excerpt = finding.get("excerpt")
    if isinstance(excerpt, str):
        needle = _collapse(excerpt)
        if not needle:
            problems.append("excerpt is empty")
        elif not any(needle in _collapse(str(fact.get(field) or "")) for fact in cited for field in ("summary", "excerpt")):
            problems.append("excerpt was not found in the summary or excerpt of any cited fact")
    provenance = finding.get("provenance")
    required_kind = {"incident_time": INCIDENT_TIME, "current": CURRENT}.get(provenance)
    if required_kind and finding["fact_ids"] and not any(fact.get("kind") == required_kind for fact in cited):
        problems.append(f"provenance is {provenance} but no cited fact has kind {required_kind}")
    return problems, cited


def _finding_problems(finding: object, analyst: str, facts: dict[str, dict], seen_ids: set[str]) -> tuple[list[str], list[dict]]:
    if not isinstance(finding, dict):
        return ["finding is not an object"], []
    problems = _field_problems(finding)
    citation_problems, cited = _citation_problems(finding, facts)
    problems += citation_problems
    finding_id = finding.get("id")
    if isinstance(finding_id, str) and finding_id:
        if not finding_id.startswith(f"{analyst}-"):
            problems.append(f"id must start with {analyst}-")
        if finding_id in seen_ids:
            problems.append(f"id {finding_id} repeats an earlier finding")
    if finding.get("time") is not None:
        try:
            parse_time(finding["time"])
        except WindowError:
            problems.append(f"time {finding['time']!r} cannot be parsed")
    return problems, cited


def _read_finding_file(path: Path, case_dir: Path) -> tuple[dict | None, str]:
    try:
        data = json.loads(path.read_text())
    except OSError as error:
        return None, f"cannot be read: {error.strerror or error}"
    except ValueError:
        return None, "not valid JSON"
    if not isinstance(data, dict):
        return None, "top level is not an object"
    if not isinstance(data.get("findings"), list):
        return None, "findings is missing or not a list"
    return data, ""


def check_findings(case_dir: Path) -> dict:
    warnings: list[str] = []
    facts = load_facts(case_dir, warnings)
    redactor = Redactor()
    result: dict = {"valid": [], "rejected": [], "unreadable": [], "requests": [], "checked": {}, "warnings": warnings}
    seen_ids: set[str] = set()
    for path in sorted((case_dir / "findings").glob("*.json")):
        if path.name == CHECKED_NAME:
            continue
        data, reason = _read_finding_file(path, case_dir)
        if data is None:
            result["unreadable"].append({"file": f"findings/{path.name}", "reason": reason})
            continue
        analyst = data["analyst"] if _is_text(data.get("analyst")) else path.stem
        for finding in data["findings"]:
            problems, cited = _finding_problems(finding, analyst, facts, seen_ids)
            finding_id = finding.get("id") if isinstance(finding, dict) else None
            if problems:
                result["rejected"].append({"analyst": analyst, "id": finding_id, "reasons": problems})
                continue
            seen_ids.add(finding_id)
            stored = {**finding, "analyst": analyst, "fact_summaries": [fact.get("summary", "") for fact in cited]}
            result["valid"].append(redactor.value(stored))
        if isinstance(data.get("checked"), list):
            result["checked"][analyst] = [redactor.text(item) for item in data["checked"] if isinstance(item, str)]
        for request in data.get("requests") if isinstance(data.get("requests"), list) else []:
            if isinstance(request, dict):
                result["requests"].append(redactor.value({"analyst": analyst, **request}))
    findings_dir = case_dir / "findings"
    findings_dir.mkdir(exist_ok=True)
    (findings_dir / CHECKED_NAME).write_text(json.dumps(result, indent=2) + "\n")
    return result


def valid_findings(case_dir: Path) -> dict[str, dict]:
    """Finding id to finding, from the last check. Empty when no check has run."""
    try:
        checked = json.loads((case_dir / "findings" / CHECKED_NAME).read_text())
    except (OSError, ValueError):
        return {}
    return {item["id"]: item for item in checked.get("valid", [])}
