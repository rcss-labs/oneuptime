"""The case folder: one folder per run that holds the incident, the target, and every later file."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from triage.config import TriageConfig
from triage.redact import Redactor
from triage.service_map import MatchKeys, ServiceMap, match_incident
from triage.window import WindowError, format_time, parse_time, window_around

TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "templates" / "case.md"
SUBFOLDERS = ("evidence", "findings", "judgments")
INCIDENT_SUMMARY_KEYS = ("number", "title", "url", "severity", "state", "declared_at", "impact_started_at", "resolved_at")
_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_-]")
_BARE_HOST_RE = re.compile(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")


class CaseError(Exception):
    """Raised with every problem found, not just the first."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _normalised_time(data: dict, key: str, errors: list[str], required: bool) -> str | None:
    value = data.get(key)
    if value is None:
        if required:
            errors.append(f"{key}: missing")
        return None
    try:
        return format_time(parse_time(value))
    except WindowError as error:
        errors.append(f"{key}: {error}")
        return None


def _text_field(data: dict, key: str, errors: list[str], required: bool) -> str:
    value = data.get(key)
    if value is None or value == "":
        if required:
            errors.append(f"{key}: missing")
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool) and key == "number":
        return str(value)
    if not isinstance(value, str):
        errors.append(f"{key}: must be text")
        return ""
    return value


def _string_list(data: dict, key: str, errors: list[str]) -> list[str]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{key}: must be a list of strings")
        return []
    return list(value)


def _object_list(data: dict, key: str, errors: list[str]) -> list[dict]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        errors.append(f"{key}: must be a list of objects")
        return []
    return [dict(item) for item in value]


def parse_incident(data: Any) -> dict:
    """Validate an incident and return a normalised copy. Every problem is reported at once."""
    if not isinstance(data, dict):
        raise CaseError(["incident: must be a JSON object"])
    errors: list[str] = []
    incident = {
        "number": _text_field(data, "number", errors, required=True).strip(),
        "title": _text_field(data, "title", errors, required=True),
        "url": _text_field(data, "url", errors, required=False),
        "description": _text_field(data, "description", errors, required=False),
        "severity": _text_field(data, "severity", errors, required=False),
        "state": _text_field(data, "state", errors, required=False),
        "declared_at": _normalised_time(data, "declared_at", errors, required=True),
        "impact_started_at": _normalised_time(data, "impact_started_at", errors, required=False),
        "resolved_at": _normalised_time(data, "resolved_at", errors, required=False),
        "monitors": _object_list(data, "monitors", errors),
        "labels": _string_list(data, "labels", errors),
        "hostnames": _string_list(data, "hostnames", errors),
        "timeline": _object_list(data, "timeline", errors),
        "notes": _object_list(data, "notes", errors),
    }
    if errors:
        raise CaseError(errors)
    return incident


def _host_of(target: Any) -> str | None:
    if not isinstance(target, str) or not target.strip():
        return None
    text = target.strip()
    if "://" in text:
        return urlparse(text).hostname
    return text if _BARE_HOST_RE.fullmatch(text) else None


def incident_keys(incident: dict) -> MatchKeys:
    """The names an incident can be matched on: monitors, labels, and hostnames."""
    monitors = [monitor.get("name") for monitor in incident.get("monitors", []) if isinstance(monitor.get("name"), str)]
    hosts = list(incident.get("hostnames", []))
    hosts += [host for monitor in incident.get("monitors", []) if (host := _host_of(monitor.get("target")))]
    keys = MatchKeys.build(monitors, incident.get("labels", []), hosts)
    return MatchKeys(keys.monitors, keys.labels, tuple(dict.fromkeys(keys.hostnames)))


def skill_version(skill_dir: Path) -> str:
    path = skill_dir / "VERSION"
    return path.read_text().strip() if path.is_file() else "unknown"


def _folder_name(number: str) -> str:
    return _UNSAFE_NAME_RE.sub("-", number)


def _match_record(result: Any) -> dict:
    return {
        "status": result.status,
        "candidates": [
            {"service": c.service, "environment": c.environment, "reasons": list(c.reasons)}
            for c in result.candidates
        ],
    }


def create_case(incident: dict, config: TriageConfig, service_map: ServiceMap, now: datetime, skill_dir: Path) -> Path:
    """Create the run folder and write incident.json, case.json, and case.md. Returns the folder."""
    name = _folder_name(str(incident.get("number", "")))
    if not name:
        raise CaseError(["number: nothing usable for a folder name"])
    incident_start = incident.get("impact_started_at") or incident["declared_at"]
    try:
        window = window_around(incident_start, incident.get("resolved_at"), now, config.limits["max_window_hours"])
    except WindowError as error:
        raise CaseError([f"window: {error}"]) from error
    case_dir = config.cases_dir / name / now.strftime("%Y%m%d-%H%M%S")
    if case_dir.exists():
        raise CaseError([f"{case_dir}: this run folder already exists"])
    redactor = Redactor()
    safe_incident = redactor.value(incident)
    keys = incident_keys(incident)
    case = {
        "skill_version": skill_version(skill_dir),
        "created_at": format_time(now),
        "case_dir": str(case_dir),
        "incident": {**{key: safe_incident.get(key) for key in INCIDENT_SUMMARY_KEYS}, "hostnames": list(keys.hostnames)},
        "incident_start": incident_start,
        "window": window.iso(),
        "match": _match_record(match_incident(service_map, keys)),
        "target": None,
    }
    case_dir.mkdir(parents=True)
    for sub in SUBFOLDERS:
        (case_dir / sub).mkdir()
    (case_dir / "incident.json").write_text(json.dumps(safe_incident, indent=2) + "\n")
    save_case(case_dir, case)
    return case_dir


def load_case(case_dir: Path) -> dict:
    path = case_dir / "case.json"
    if not path.is_file():
        raise CaseError([f"{path}: file not found"])
    return json.loads(path.read_text())


def save_case(case_dir: Path, case: dict) -> None:
    """Write case.json and render case.md from it."""
    (case_dir / "case.json").write_text(json.dumps(case, indent=2) + "\n")
    (case_dir / "case.md").write_text(render_case(case))


def _bullets(pairs: list[tuple[str, Any]]) -> str:
    return "\n".join(f"- {label}: {value if value not in (None, '') else '-'}" for label, value in pairs)


def _describe_target(target: dict | None) -> str:
    if not target:
        return "No target has been chosen yet."
    lines = [("Source", target["source"]), ("Service", target.get("service")), ("Environment", target.get("environment")),
             ("Account", target["account"]), ("Region", target["region"]),
             ("Depends on", ", ".join(target.get("depends_on", [])))]
    text = _bullets(lines) + "\n- Resources:"
    resources = target.get("resources") or {}
    if not resources:
        return text + " none"
    return text + "\n" + "\n".join(f"  - {key}: {json.dumps(value)}" for key, value in resources.items())


def _describe_match(match: dict) -> str:
    lines = [f"Status: {match['status']}"]
    for candidate in match["candidates"]:
        lines.append(f"- {candidate['service']} / {candidate['environment']} ({', '.join(candidate['reasons'])})")
    return "\n".join(lines)


def render_case(case: dict) -> str:
    incident = case["incident"]
    values = {
        "number": incident["number"],
        "case_dir": case["case_dir"],
        "incident": _bullets([
            ("Title", incident["title"]), ("URL", incident["url"]), ("Severity", incident["severity"]),
            ("State", incident["state"]), ("Declared", incident["declared_at"]),
            ("Impact started", incident["impact_started_at"]), ("Resolved", incident["resolved_at"]),
        ]),
        "window": _bullets([("Start", case["window"]["start"]), ("End", case["window"]["end"]),
                            ("Incident start", case["incident_start"])]),
        "match": _describe_match(case["match"]),
        "target": _describe_target(case["target"]),
    }
    text = TEMPLATE_PATH.read_text()
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", str(value))
    return text


def _store_target(case_dir: Path, target: dict) -> dict:
    case = load_case(case_dir)
    case["target"] = target
    save_case(case_dir, case)
    return target


def set_target_from_map(case_dir: Path, service_map: ServiceMap, config: TriageConfig, service: str, environment: str) -> dict:
    entry = service_map.services.get(service)
    if entry is None:
        raise CaseError([f"unknown service '{service}'; known: {', '.join(service_map.services) or 'none'}"])
    env = entry.environments.get(environment)
    if env is None:
        raise CaseError([f"service '{service}' has no environment '{environment}'; known: {', '.join(entry.environments)}"])
    return _store_target(case_dir, {
        "source": "map",
        "service": service,
        "environment": environment,
        "account": env.account,
        "region": env.region,
        "resources": dict(env.resources),
        "depends_on": list(env.depends_on),
    })


def set_target_from_discovery(case_dir: Path, config: TriageConfig, discovery: dict) -> dict:
    account, region = discovery.get("account"), discovery.get("region")
    errors = []
    if not account or not region:
        errors.append("discovery: account and region must both be set")
    elif account not in config.accounts:
        errors.append(f"discovery: unknown account '{account}'")
    elif region not in config.accounts[account].regions:
        errors.append(f"discovery: region '{region}' is not listed for account '{account}'")
    if errors:
        raise CaseError(errors)
    return _store_target(case_dir, {
        "source": "discovered",
        "service": None,
        "environment": None,
        "account": account,
        "region": region,
        "resources": dict(discovery.get("resources") or {}),
        "depends_on": [],
    })
