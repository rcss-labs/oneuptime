"""Check what is published for secrets, prepare the Confluence request and the Slack message, and record what was published."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path

from triage.audit_scan import scan
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


def _read_regular(path: Path) -> bytes | None:
    """Read a regular file without following a link; None when it does not exist.

    The checks run on the open descriptor, so a swap after the open cannot change what is read.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise PublishError(f"{path.name}: is a symbolic link; use a regular file inside the run folder") from error
        raise PublishError(f"{path.name}: {error.strerror or error}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PublishError(f"{path.name}: is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    except OSError as error:
        raise PublishError(f"{path.name}: {error.strerror or error}") from error
    finally:
        os.close(descriptor)


def _read_text(path: Path) -> str:
    data = _read_regular(path)
    if data is None:
        raise PublishError(f"{path.name}: file not found")
    return _decode(path.name, data)


def _write_text(path: Path, text: str) -> None:
    """Write a file in the run folder; a symbolic link or a non-regular file is refused, never followed."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise PublishError(f"{path.name}: is a symbolic link; it is not written through") from error
        raise PublishError(f"{path.name}: {error.strerror or error}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PublishError(f"{path.name}: is not a regular file")
        os.ftruncate(descriptor, 0)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(text)
    except OSError as error:
        raise PublishError(f"{path.name}: {error.strerror or error}") from error
    finally:
        os.close(descriptor)


def _read_json(case_dir: Path, name: str) -> dict:
    path = case_dir / name
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
    return _read_regular(case_dir / name)


def _decode(name: str, data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublishError(f"{name}: not valid UTF-8 ({error.reason})") from error


ACCEPT_VALUE_RE = re.compile(r"[0-9a-f]{64}")
ACCEPT_VALUE_RULE = "the --accept-hits value must be 64 lower-case hex characters"
# Account ids that may appear in these files; the Slack message and the title always use an empty set.
ACCOUNT_ID_FILES = ("report.md", "work-order.json")


def _hit_records(redact_hits: list, scan_hits: list) -> tuple[list[dict], list[dict]]:
    """Positions and kinds only. The redactor does not report a length, so its entries carry none."""
    redact = [{"kind": h.category, "line": h.line, "column": h.column, "length": None} for h in redact_hits]
    second = [{"kind": h.kind, "line": h.line, "column": h.column, "length": h.length} for h in scan_hits]
    return redact, second


def _file_entry(data: bytes, text: str, allowed_account_ids: frozenset[str]) -> dict:
    redact, second = _hit_records(audit_text(text), scan(text, allowed_account_ids))
    return {"sha256": hashlib.sha256(data).hexdigest(), "redact_hits": redact, "scan_hits": second}


def _has_hits(entry: dict) -> bool:
    return bool(entry["redact_hits"] or entry["scan_hits"])


def _set_digest(files: dict[str, dict]) -> str:
    """One digest of the whole audited set: the sorted `<item name>:<item sha256>` lines."""
    lines = sorted(f"{name}:{entry['sha256']}" for name, entry in files.items())
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _earlier_acceptances(case_dir: Path) -> list:
    try:
        data = _read_regular(case_dir / "audit.json")
        previous = json.loads(data.decode("utf-8")) if data is not None else {}
    except (PublishError, ValueError):
        return []
    acceptances = previous.get("acceptances") if isinstance(previous, dict) else None
    return acceptances if isinstance(acceptances, list) else []


def _audit(case_dir: Path, title: str | None = None, accept_hits: str | None = None,
           allowed_account_ids: frozenset[str] = frozenset()) -> dict:
    """Read each published file once, run both detectors on those exact bytes, and write audit.json.

    --accept-hits is honoured only when it equals the set digest of everything audited.
    """
    if accept_hits is not None and not ACCEPT_VALUE_RE.fullmatch(accept_hits):
        raise PublishError(ACCEPT_VALUE_RULE)
    contents = {name: _regular_file_bytes(case_dir, name) for name in PUBLISHED_FILES}
    if contents["report.md"] is None:
        raise PublishError(f"report.md: file not found in {case_dir}")
    checked, files, digests = [], {}, {}
    for name, data in contents.items():
        digests[name] = None if data is None else hashlib.sha256(data).hexdigest()
        if data is None:
            continue
        checked.append(name)
        allowed = allowed_account_ids if name in ACCOUNT_ID_FILES else frozenset()
        files[name] = _file_entry(data, _decode(name, data), allowed)
    if title is not None:
        files["title"] = _file_entry(title.encode("utf-8"), title, frozenset())
    with_hits = {name: entry for name, entry in files.items() if _has_hits(entry)}
    digest = _set_digest(files)
    acceptances = _earlier_acceptances(case_dir)
    result = {"clean": not with_hits, "checked": checked, "files": files, "sha256": digests, "set_sha256": digest}
    if with_hits and accept_hits == digest:
        result["accepted_by_flag"] = True
        result["accepted_sha256"] = digest
        acceptances.append({"set_sha256": digest, "items": {name: entry["sha256"] for name, entry in with_hits.items()}})
    result["acceptances"] = acceptances
    _write_text(case_dir / "audit.json", json.dumps(result, indent=2) + "\n")
    return result


def audit_case(case_dir: Path, accept_hits: str | None = None,
               allowed_account_ids: frozenset[str] = frozenset()) -> dict:
    """Audit every published file that exists and write audit.json. Reports positions, never values."""
    return _audit(case_dir, accept_hits=accept_hits, allowed_account_ids=allowed_account_ids)


def may_proceed(result: dict) -> bool:
    return bool(result["clean"] or result.get("accepted_by_flag"))


def hit_lines(result: dict) -> list[str]:
    """`<file>:<line>:<column> <kind>` for every hit of either detector."""
    lines = []
    for name, entry in result["files"].items():
        for hit in entry["redact_hits"] + entry["scan_hits"]:
            lines.append(f"{name}:{hit['line']}:{hit['column']} {hit['kind']}")
    return lines


def load_audit(case_dir: Path) -> dict:
    """audit.json as written, read without following a link."""
    return json.loads(_read_text(case_dir / "audit.json"))


def read_audited(case_dir: Path, name: str, result: dict) -> str:
    """The text of a published file, only when its bytes are the ones the audit covered."""
    data = _regular_file_bytes(case_dir, name)
    if data is None or hashlib.sha256(data).hexdigest() != result["sha256"].get(name):
        raise PublishError(f"{name}: changed since it was audited")
    return _decode(name, data)


def page_title(case: dict) -> str:
    incident = case.get("incident")
    if not isinstance(incident, dict) or not incident.get("number") or not incident.get("title"):
        raise PublishError("case.json: the incident has no number or title")
    return _one_line(f"{incident['number']} Triage: {incident['title']}")[:TITLE_LIMIT]


def _refusal(result: dict) -> str:
    return ("the audit found secrets, nothing is prepared: " + "; ".join(hit_lines(result))
            + "; set sha256 of the audited items: " + result["set_sha256"])


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


def publish_digests(case_dir: Path, confluence_url: str | None) -> dict[str, str | None]:
    """The --accept-hits value each publishing command would need, from the files as they are now.

    The Slack digest assumes the command rewrites slack-message.md with exactly the text built here.
    It is None when that text cannot be built.
    """
    items = {}
    for name in ("report.md", "work-order.json"):
        data = _regular_file_bytes(case_dir, name)
        if data is not None:
            items[name] = {"sha256": hashlib.sha256(data).hexdigest()}
    slack_items = dict(items)
    try:
        text = _slack_text(case_dir, confluence_url)
        slack_items["slack-message.md"] = {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
        slack_digest = _set_digest(slack_items)
    except PublishError:
        slack_digest = None
    on_disk = _regular_file_bytes(case_dir, "slack-message.md")
    if on_disk is not None:
        items["slack-message.md"] = {"sha256": hashlib.sha256(on_disk).hexdigest()}
    title = page_title(_load_case_file(case_dir))
    items["title"] = {"sha256": hashlib.sha256(title.encode("utf-8")).hexdigest()}
    return {"confluence": _set_digest(items), "slack-message": slack_digest}


def configured_account_ids(config: TriageConfig) -> frozenset[str]:
    return frozenset(account.account_id for account in config.accounts.values())


def confluence_request(case_dir: Path, config: TriageConfig, accept_hits: str | None = None) -> dict:
    """Audit the files and the title now, and return the request only when the audit is clean.

    Nothing is trusted from an earlier audit: the request carries the sha256 of the report bytes audited here.
    """
    title = page_title(_load_case_file(case_dir))
    result = _audit(case_dir, title, accept_hits, configured_account_ids(config))
    if not may_proceed(result):
        raise PublishError(_refusal(result))
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


def _slack_text(case_dir: Path, confluence_url: str | None) -> str:
    """Build the Slack text, redact and neutralise it, and keep it within the limit. Writes nothing."""
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
    footer = NO_LINK_LINE
    if confluence_url:
        footer = "Full report: " + safe(confluence_url)
        if len(footer) > SLACK_LINK_LIMIT:
            footer = LINK_TOO_LONG_LINE
    return _cap("\n".join(lines), SLACK_LIMIT - len(footer) - 1) + "\n" + footer


def slack_message(case_dir: Path, confluence_url: str | None) -> str:
    """Build the Slack text and write it to slack-message.md."""
    text = _slack_text(case_dir, confluence_url)
    _write_text(case_dir / "slack-message.md", text)
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
