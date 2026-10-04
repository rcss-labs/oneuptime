"""Check what is published for secrets, prepare the Confluence request and the Slack message, and record what was published."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from triage.case import CaseError, load_case, save_case
from triage.config import TriageConfig
from triage.redact import Redactor, audit_text
from triage.window import format_time

PUBLISHED_FILES = ("report.md", "work-order.json", "slack-message.md")
TITLE_LIMIT = 200
SLACK_LIMIT = 1500
SLACK_ACTION_LIMIT = 3
NO_LINK_LINE = "Full report: not published to Confluence"
AUDIT_AGAIN = "run the audit again"


class PublishError(Exception):
    """A precondition of publishing is not met."""


def _read_json(case_dir: Path, name: str) -> dict:
    path = case_dir / name
    if not path.is_file():
        raise PublishError(f"{name}: file not found in {case_dir}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise PublishError(f"{name}: not valid JSON ({error})") from error


def _case(case_dir: Path) -> dict:
    try:
        return load_case(case_dir)
    except CaseError as error:
        raise PublishError("; ".join(error.errors)) from error


def audit_case(case_dir: Path) -> dict:
    """Audit every published file that exists and write audit.json. Reports positions, never values."""
    if not (case_dir / "report.md").is_file():
        raise PublishError(f"report.md: file not found in {case_dir}")
    checked, hits = [], []
    for name in PUBLISHED_FILES:
        path = case_dir / name
        if not path.is_file():
            continue
        checked.append(name)
        for hit in audit_text(path.read_text()):
            hits.append({"file": name, "line": hit.line, "column": hit.column, "category": hit.category})
    result = {"clean": not hits, "checked": checked, "hits": hits}
    (case_dir / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def page_title(case: dict) -> str:
    incident = case["incident"]
    return f"{incident['number']} Triage: {incident['title']}"[:TITLE_LIMIT]


def _require_fresh_clean_audit(case_dir: Path) -> None:
    audit_path, report_path = case_dir / "audit.json", case_dir / "report.md"
    if not audit_path.is_file() or not report_path.is_file():
        raise PublishError(AUDIT_AGAIN)
    try:
        clean = json.loads(audit_path.read_text()).get("clean") is True
    except (json.JSONDecodeError, AttributeError):
        clean = False
    if not clean or audit_path.stat().st_mtime <= report_path.stat().st_mtime:
        raise PublishError(AUDIT_AGAIN)


def _recorded_page(case: dict) -> dict | None:
    confluence = (case.get("publish") or {}).get("confluence")
    if confluence and confluence.get("page_id"):
        return {"page_id": confluence["page_id"], "url": confluence.get("url")}
    return None


def previous_page(case_dir: Path) -> dict | None:
    """The Confluence page recorded for this run, else for the newest older run of the same incident."""
    found = _recorded_page(_case(case_dir))
    if found:
        return found
    siblings = sorted((p for p in case_dir.parent.iterdir() if p.is_dir() and p.name != case_dir.name),
                      key=lambda p: p.name, reverse=True)
    for sibling in siblings:
        if not (sibling / "case.json").is_file():
            continue
        found = _recorded_page(_case(sibling))
        if found:
            return found
    return None


def confluence_request(case_dir: Path, config: TriageConfig) -> dict:
    _require_fresh_clean_audit(case_dir)
    return {
        "space_key": config.confluence_space_key,
        "parent_page_id": config.confluence_parent_page_id,
        "title": page_title(_case(case_dir)),
        "body_file": str((case_dir / "report.md").resolve()),
        "existing_page": previous_page(case_dir),
    }


def _top_cause(report: dict) -> dict | None:
    top_id = (report.get("summary") or {}).get("top_cause")
    return next((cause for cause in report.get("causes", []) if cause.get("id") == top_id), None)


def _cap(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def slack_message(case_dir: Path, confluence_url: str | None) -> str:
    """Build the Slack text, redact it, keep it within the limit, and write slack-message.md."""
    report = _read_json(case_dir, "report.json")
    incident = _case(case_dir)["incident"]
    cause = _top_cause(report) if report.get("status") == "cause_found" else None
    status = "cause found" if report.get("status") == "cause_found" else "unresolved"
    lines = [f"{incident['number']}: {incident['title']}", f"Status: {status}"]
    if cause:
        lines.append(f"Top cause ({cause['label']}): {cause['statement']}")
    else:
        lines.append("No cause was established.")
    actions = report.get("actions", [])[:SLACK_ACTION_LIMIT]
    if actions:
        lines.append("Actions:")
        lines += [f"- {action['title']} ({action['label']})" for action in actions]
    redactor = Redactor()
    body = redactor.text("\n".join(lines))
    footer = redactor.text(f"Full report: {confluence_url}" if confluence_url else NO_LINK_LINE)
    text = _cap(body, SLACK_LIMIT - len(footer) - 1) + "\n" + footer
    (case_dir / "slack-message.md").write_text(text)
    return text


def _publish_section(case: dict) -> dict:
    return case.setdefault("publish", {})


def record_confluence(case_dir: Path, page_id: str, url: str, now: datetime) -> None:
    case = _case(case_dir)
    _publish_section(case)["confluence"] = {"page_id": page_id, "url": url, "at": format_time(now)}
    save_case(case_dir, case)


def record_slack(case_dir: Path, destination: str, now: datetime) -> None:
    case = _case(case_dir)
    _publish_section(case).setdefault("slack", []).append({"destination": destination, "at": format_time(now)})
    save_case(case_dir, case)
