"""Check what is published for secrets, prepare the Confluence request and the Slack message, and record what was published."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from triage.case import save_case
from triage.config import TriageConfig
from triage.redact import Redactor, audit_text
from triage.window import format_time

PUBLISHED_FILES = ("report.md", "work-order.json", "slack-message.md")
TITLE_LIMIT = 200
SLACK_LIMIT = 1500
SLACK_ACTION_LIMIT = 3
# A link longer than this cannot leave room for the message, so it is replaced by a plain line.
SLACK_LINK_LIMIT = 1400
NO_LINK_LINE = "Full report: not published to Confluence"
LINK_TOO_LONG_LINE = "Full report: link too long to include"
ZERO_WIDTH_SPACE = "​"
_WHITESPACE_RE = re.compile(r"\s+")
_PARTIAL_ENTITY_RE = re.compile(r"&[a-z]*$")


class PublishError(Exception):
    """A precondition of publishing is not met."""


def _one_line(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def _read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublishError(f"{path.name}: not valid UTF-8 ({error.reason})") from error
    except OSError as error:
        raise PublishError(f"{path.name}: {error.strerror or error}") from error


def _read_json(case_dir: Path, name: str) -> dict:
    path = case_dir / name
    if not path.is_file():
        raise PublishError(f"{name}: file not found in {case_dir}")
    try:
        data = json.loads(_read_text(path))
    except json.JSONDecodeError as error:
        raise PublishError(f"{name}: not valid JSON ({error})") from error
    if not isinstance(data, dict):
        raise PublishError(f"{name}: must hold a JSON object")
    return data


def _load_case_file(run_dir: Path) -> dict:
    """case.json of one run; PublishError names the file when it is missing or damaged."""
    path = run_dir / "case.json"
    if not path.is_file():
        raise PublishError(f"{path}: file not found")
    try:
        data = json.loads(_read_text(path))
    except json.JSONDecodeError as error:
        raise PublishError(f"{path}: damaged, not valid JSON ({error})") from error
    except PublishError as error:
        raise PublishError(f"{path}: damaged, {error}") from error
    if not isinstance(data, dict):
        raise PublishError(f"{path}: damaged, must hold a JSON object")
    return data


def _regular_file_bytes(case_dir: Path, name: str) -> bytes | None:
    """The bytes of a published file, None when absent; a link or a non-regular file is refused."""
    path = case_dir / name
    if path.is_symlink():
        raise PublishError(f"{name}: is a symbolic link; publish a regular file inside the run folder")
    if not path.exists():
        return None
    if not path.is_file():
        raise PublishError(f"{name}: is not a regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise PublishError(f"{name}: {error.strerror or error}") from error


def _decode(name: str, data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublishError(f"{name}: not valid UTF-8 ({error.reason})") from error


def _audit(case_dir: Path, title: str | None = None) -> dict:
    """Read each published file once, audit those exact bytes, and write audit.json."""
    contents = {name: _regular_file_bytes(case_dir, name) for name in PUBLISHED_FILES}
    if contents["report.md"] is None:
        raise PublishError(f"report.md: file not found in {case_dir}")
    checked, hits, digests = [], [], {}
    for name, data in contents.items():
        digests[name] = None if data is None else hashlib.sha256(data).hexdigest()
        if data is None:
            continue
        checked.append(name)
        for hit in audit_text(_decode(name, data)):
            hits.append({"file": name, "line": hit.line, "column": hit.column, "category": hit.category})
    if title is not None:
        for hit in audit_text(title):
            hits.append({"file": "title", "line": hit.line, "column": hit.column, "category": hit.category})
    result = {"clean": not hits, "checked": checked, "hits": hits, "sha256": digests}
    (case_dir / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def audit_case(case_dir: Path) -> dict:
    """Audit every published file that exists and write audit.json. Reports positions, never values."""
    return _audit(case_dir)


def page_title(case: dict) -> str:
    incident = case.get("incident")
    if not isinstance(incident, dict) or not incident.get("number") or not incident.get("title"):
        raise PublishError("case.json: the incident has no number or title")
    return _one_line(f"{incident['number']} Triage: {incident['title']}")[:TITLE_LIMIT]


def _hit_lines(result: dict) -> str:
    return "; ".join(f"{hit['file']}:{hit['line']}:{hit['column']} {hit['category']}" for hit in result["hits"])


def _recorded_page(case: dict) -> dict | None:
    publish = case.get("publish")
    confluence = publish.get("confluence") if isinstance(publish, dict) else None
    if isinstance(confluence, dict) and isinstance(confluence.get("page_id"), str) and confluence["page_id"]:
        return {"page_id": confluence["page_id"], "url": confluence.get("url")}
    return None


def previous_page(case_dir: Path) -> dict | None:
    """The page recorded for this run, else for the newest older run of the incident, else for a newer one."""
    case_dir = case_dir.resolve()
    found = _recorded_page(_load_case_file(case_dir))
    if found:
        return found
    siblings = [p for p in case_dir.parent.iterdir() if p.is_dir() and p.name != case_dir.name]
    older = sorted((p for p in siblings if p.name < case_dir.name), key=lambda p: p.name, reverse=True)
    newer = sorted((p for p in siblings if p.name > case_dir.name), key=lambda p: p.name)
    for sibling in older + newer:
        if not (sibling / "case.json").is_file():
            continue
        try:
            found = _recorded_page(_load_case_file(sibling))
        except PublishError as error:
            print(f"skipped {sibling.name}: {error}", file=sys.stderr)
            continue
        if found:
            return found
    return None


def confluence_request(case_dir: Path, config: TriageConfig) -> dict:
    """Audit the files and the title now, and return the request only when the audit is clean.

    Nothing is trusted from an earlier audit: the request carries the sha256 of the report bytes audited here.
    """
    title = page_title(_load_case_file(case_dir))
    result = _audit(case_dir, title)
    if not result["clean"]:
        raise PublishError("the audit found secrets, nothing is prepared: " + _hit_lines(result))
    return {
        "space_key": config.confluence_space_key,
        "parent_page_id": config.confluence_parent_page_id,
        "title": title,
        "body_file": str(case_dir.resolve() / "report.md"),
        "body_sha256": result["sha256"]["report.md"],
        "existing_page": previous_page(case_dir),
    }


def _field(item: dict, key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PublishError(f"report.json: {where} has no {key}")
    return value


def _top_cause(report: dict) -> dict | None:
    if report.get("status") != "cause_found":
        return None
    top_id = (report.get("summary") or {}).get("top_cause")
    cause = next((c for c in report.get("causes", []) if isinstance(c, dict) and c.get("id") == top_id), None)
    if cause is None:
        raise PublishError(f"report.json: status is cause_found but top_cause {top_id!r} is not in causes")
    return cause


def _neutralise(text: str) -> str:
    """Stop Slack from reading the text as a mention, a link, or markup."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("@", "@" + ZERO_WIDTH_SPACE)


def _cap(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return _PARTIAL_ENTITY_RE.sub("", text[:limit - 1]).rstrip() + "…"


def slack_message(case_dir: Path, confluence_url: str | None) -> str:
    """Build the Slack text, redact and neutralise it, keep it within the limit, and write slack-message.md."""
    report = _read_json(case_dir, "report.json")
    incident = _load_case_file(case_dir).get("incident")
    if not isinstance(incident, dict) or not incident.get("number") or not incident.get("title"):
        raise PublishError("case.json: the incident has no number or title")
    redactor = Redactor()

    def safe(text: str) -> str:
        return _neutralise(redactor.text(_one_line(str(text))))

    cause = _top_cause(report)
    lines = [f"{safe(incident['number'])}: {safe(incident['title'])}",
             "Status: " + ("cause found" if cause else "unresolved")]
    if cause:
        lines.append(f"Top cause ({safe(_field(cause, 'label', 'the top cause'))}): "
                     f"{safe(_field(cause, 'statement', 'the top cause'))}")
    else:
        lines.append("No cause was established.")
    actions = [a for a in report.get("actions", []) if isinstance(a, dict)][:SLACK_ACTION_LIMIT]
    if actions:
        lines.append("Actions:")
        for index, action in enumerate(actions, start=1):
            where = f"action {action.get('id') or index}"
            lines.append(f"- {safe(_field(action, 'title', where))} ({safe(_field(action, 'label', where))})")
    if not confluence_url:
        footer = NO_LINK_LINE
    elif len(confluence_url) > SLACK_LINK_LIMIT:
        footer = LINK_TOO_LONG_LINE
    else:
        footer = "Full report: " + safe(confluence_url)
    text = _cap("\n".join(lines), SLACK_LIMIT - len(footer) - 1) + "\n" + footer
    (case_dir / "slack-message.md").write_text(text)
    return text


def _publish_section(case: dict, case_dir: Path) -> dict:
    section = case.setdefault("publish", {})
    if not isinstance(section, dict):
        raise PublishError(f"{case_dir / 'case.json'}: damaged, publish must be an object")
    return section


def record_confluence(case_dir: Path, page_id: str, url: str, now: datetime) -> None:
    case = _load_case_file(case_dir)
    _publish_section(case, case_dir)["confluence"] = {"page_id": page_id, "url": url, "at": format_time(now)}
    save_case(case_dir, case)


def record_slack(case_dir: Path, destination: str, now: datetime) -> None:
    case = _load_case_file(case_dir)
    entries = _publish_section(case, case_dir).setdefault("slack", [])
    if not isinstance(entries, list):
        raise PublishError(f"{case_dir / 'case.json'}: damaged, publish.slack must be a list")
    entries.append({"destination": destination, "at": format_time(now)})
    save_case(case_dir, case)
