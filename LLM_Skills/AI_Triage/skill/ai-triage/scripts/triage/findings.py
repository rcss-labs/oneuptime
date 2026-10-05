"""Check analyst findings against the evidence they cite, before any model judges them."""
from __future__ import annotations

import json
import re
from pathlib import Path

from triage.evidence import CURRENT, INCIDENT_TIME, load_evidence
from triage.redact import PLACEHOLDER_RE, Redactor
from triage.window import WindowError, parse_time

CHECKED_NAME = "checked.json"
MIN_EXCERPT = 12
MAX_MATCHED_TEXT = 500
# Data under these keys says what was asked of a source, not what it returned, so a finding
# must not quote it: a search query would otherwise "prove" the claim it was typed to look for.
NOT_QUOTABLE_KEYS = frozenset({
    "asked", "query", "index", "filters", "window", "method", "command", "request", "target", "parameters",
})
MIN_WHOLE_VALUE = 3
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
        facts = document.get("facts", []) if isinstance(document, dict) else None
        if not isinstance(facts, list) or not all(isinstance(fact, dict) for fact in facts):
            if warnings is not None:
                warnings.append(f"evidence file {path.name} is unreadable and was skipped")
            continue
        documents.append((path.name, document))
    return documents


def qualified_id(file_name: str, fact_id: str) -> str:
    return f"{Path(file_name).stem}:{fact_id}"


def load_facts(case_dir: Path, warnings: list[str] | None = None) -> dict[str, dict]:
    """Qualified fact id ("<evidence file stem>:<fact id>") to fact, across all evidence files.

    Fact ids are numbered per file, so only the qualified id is unique in a case.
    """
    facts: dict[str, dict] = {}
    for file_name, document in evidence_documents(case_dir, warnings):
        for fact in document.get("facts", []):
            if not isinstance(fact, dict) or not isinstance(fact.get("id"), str):
                if warnings is not None:
                    warnings.append(f"a fact in {file_name} has no text id and was skipped")
                continue
            facts[qualified_id(file_name, fact["id"])] = {**fact, "file": file_name}
    return facts


def _resolve_citation(cited: str, facts: dict[str, dict]) -> tuple[str | None, str | None]:
    """The qualified id a citation names, or a problem when it names none or several."""
    if cited in facts:
        return cited, None
    matches = sorted(key for key, fact in facts.items() if fact["id"] == cited)
    if len(matches) == 1:
        return matches[0], None
    if matches:
        return None, f"fact id {cited} exists in more than one evidence file; cite it as one of: {', '.join(matches)}"
    return None, f"fact id {cited} does not exist"


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


def quotable_strings(fact: dict) -> list[str]:
    """The text a finding may quote: summary, excerpt, and every string in data (never keys or numbers).

    Strings under NOT_QUOTABLE_KEYS are skipped at any depth.
    """
    strings = [_collapse(fact[name]) for name in ("summary", "excerpt") if isinstance(fact.get(name), str)]
    pending = [fact.get("data")]
    while pending:
        item = pending.pop(0)
        if isinstance(item, str):
            strings.append(_collapse(item))
        elif isinstance(item, dict):
            pending.extend(value for key, value in item.items() if str(key).lower() not in NOT_QUOTABLE_KEYS)
        elif isinstance(item, list):
            pending.extend(item)
    return strings


def _around(text: str, needle: str) -> str:
    """At most MAX_MATCHED_TEXT characters of text, centred on the first place the needle occurs."""
    if len(text) <= MAX_MATCHED_TEXT:
        return text
    middle = max(text.find(needle), 0) + len(needle) // 2
    start = min(max(middle - MAX_MATCHED_TEXT // 2, 0), len(text) - MAX_MATCHED_TEXT)
    return text[start:start + MAX_MATCHED_TEXT]


def _matched_string(fact: dict, needle: str) -> str | None:
    """The quotable string holding the excerpt. A short excerpt must equal a whole string."""
    if PLACEHOLDER_RE.fullmatch(needle):
        return None
    for text in quotable_strings(fact):
        if len(needle) >= MIN_EXCERPT:
            if needle in text:
                return text
        elif len(needle) >= MIN_WHOLE_VALUE and needle == text:
            return text
    return None


def _citation_problems(finding: dict, facts: dict[str, dict]) -> tuple[list[str], dict[str, dict], str]:
    """Problems with the cited facts and the excerpt, plus the cited facts that exist by qualified id."""
    problems: list[str] = []
    cited: dict[str, dict] = {}
    if not isinstance(finding.get("fact_ids"), list) or not all(isinstance(item, str) for item in finding["fact_ids"]):
        return problems, cited, ""
    for fact_id in finding["fact_ids"]:
        key, problem = _resolve_citation(fact_id, facts)
        if problem:
            problems.append(problem)
        else:
            cited[key] = facts[key]
    excerpt = finding.get("excerpt")
    matching: list[dict] = []
    matched_text = ""
    if isinstance(excerpt, str):
        needle = _collapse(excerpt)
        for fact in cited.values():
            text = _matched_string(fact, needle) if needle else None
            if text is not None:
                matching.append(fact)
                matched_text = matched_text or _around(text, needle)
        if not needle:
            problems.append("excerpt is empty")
        elif not matching and len(needle) < MIN_EXCERPT:
            problems.append(
                f"excerpt is shorter than {MIN_EXCERPT} characters and is not a whole value "
                f"(at least {MIN_WHOLE_VALUE} characters) of a cited fact"
            )
        elif not matching:
            problems.append("excerpt was not found in the summary, excerpt, or data of any cited fact")
    provenance = finding.get("provenance")
    required_kind = {"incident_time": INCIDENT_TIME, "current": CURRENT}.get(provenance)
    if required_kind and finding["fact_ids"] and matching and not any(fact.get("kind") == required_kind for fact in matching):
        problems.append(f"provenance is {provenance} but no cited fact containing the excerpt has kind {required_kind}")
    elif required_kind and finding["fact_ids"] and not matching and not any(fact.get("kind") == required_kind for fact in cited.values()):
        problems.append(f"provenance is {provenance} but no cited fact has kind {required_kind}")
    return problems, cited, matched_text


def _finding_problems(finding: object, analyst: str, facts: dict[str, dict], seen_ids: set[str]) -> tuple[list[str], dict[str, dict], str]:
    if not isinstance(finding, dict):
        return ["finding is not an object"], {}, ""
    problems = _field_problems(finding)
    citation_problems, cited, matched_text = _citation_problems(finding, facts)
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
    return problems, cited, matched_text


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
        analyst = path.stem
        if "analyst" in data and data["analyst"] != analyst:
            reason = f"analyst field {data['analyst']!r} does not match the file name {analyst}"
            result["unreadable"].append({"file": f"findings/{path.name}", "reason": reason})
            continue
        for finding in data["findings"]:
            problems, cited, matched_text = _finding_problems(finding, analyst, facts, seen_ids)
            finding_id = finding.get("id") if isinstance(finding, dict) else None
            if problems:
                result["rejected"].append({"analyst": analyst, "id": finding_id, "reasons": problems})
                continue
            seen_ids.add(finding_id)
            # Ids and summaries come from evidence that is already redacted, and an id is not text.
            stored = redactor.value({**finding, "analyst": analyst})
            stored["fact_ids"] = list(cited)
            stored["fact_summaries"] = {key: fact.get("summary", "") for key, fact in cited.items()}
            stored["matched_text"] = matched_text
            result["valid"].append(stored)
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
