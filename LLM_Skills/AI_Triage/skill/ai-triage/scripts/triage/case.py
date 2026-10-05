"""The case folder: one folder per run that holds the incident, the target, and every later file."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from triage.config import TriageConfig
from triage.fixtures import FIXTURE_ENV
from triage.redact import Redactor
from triage.service_map import MatchKeys, ServiceMap, _check_resources, match_incident
from triage.window import WindowError, format_time, parse_time, window_around

TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "templates" / "case.md"
SUBFOLDERS = ("evidence", "findings", "judgments")
INCIDENT_SUMMARY_KEYS = ("number", "title", "url", "severity", "state", "declared_at", "impact_started_at", "resolved_at")
NUMBER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
RUN_NAME_ATTEMPTS = 5
SCALAR_RESOURCES = ("ecs_service", "auto_scaling_group", "load_balancer", "api_gateway", "cloudfront_distribution",
                    "rds", "elasticache", "efs")
LIST_RESOURCES = ("ec2_instances", "lambda_functions", "dynamodb_tables", "sqs_queues", "sns_topics", "log_groups")
_WHITESPACE_RE = re.compile(r"\s+")
_LEADING_NUMBER_RE = re.compile(r"(\d+)\.")
MAX_TEXT = 2000
MAX_TITLE = 300
_MARKER_START = ("#", ">", "-", "*", "+", "|", "```", "~~~")
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
    if not errors and not NUMBER_RE.fullmatch(incident["number"]):
        errors.append("number: must start with a letter or digit and use only letters, digits, '.', '_' and '-', at most 64 characters")
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


REPLAY_NOTICE = "REPLAY: the evidence in this case comes from recordings, not from live systems."


def replay_active() -> bool:
    """True when this session answers from recordings (AI_TRIAGE_FIXTURES is set)."""
    return bool(os.environ.get(FIXTURE_ENV, "").strip())


def check_replay(case: dict) -> None:
    """Refuse a case whose replay state differs from the environment's: a recorded case must never be extended
    with live evidence, and a live case never with recorded answers."""
    was_replay = bool(case.get("replay", False))
    if was_replay != replay_active():
        raise CaseError([
            "this case was made in replay mode, but " + FIXTURE_ENV + " is not set now" if was_replay
            else "this case was made from live systems, but " + FIXTURE_ENV + " is set now (replay mode)"
        ])


def skill_version(skill_dir: Path) -> str:
    path = skill_dir / "VERSION"
    return path.read_text().strip() if path.is_file() else "unknown"


def _match_record(result: Any) -> dict:
    return {
        "status": result.status,
        "candidates": [
            {"service": c.service, "environment": c.environment, "reasons": list(c.reasons)}
            for c in result.candidates
        ],
    }


def _make_run_folder(base: Path, now: datetime) -> Path:
    """Create <base>/<run timestamp>, moving to the next second when that name is taken."""
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise CaseError([f"{base}: cannot create the case folder ({error.strerror or error})"]) from error
    for attempt in range(RUN_NAME_ATTEMPTS):
        case_dir = base / (now + timedelta(seconds=attempt)).strftime("%Y%m%d-%H%M%S")
        try:
            case_dir.mkdir()
        except FileExistsError:
            continue
        except OSError as error:
            raise CaseError([f"{case_dir}: cannot create the run folder ({error.strerror or error})"]) from error
        return case_dir
    raise CaseError([f"{base}: the run folder names for {RUN_NAME_ATTEMPTS} consecutive seconds are all taken"])


def create_case(incident: dict, config: TriageConfig, service_map: ServiceMap, now: datetime, skill_dir: Path) -> Path:
    """Create the run folder and write incident.json, case.json, and case.md. Returns the folder."""
    number = str(incident.get("number", ""))
    if not NUMBER_RE.fullmatch(number):
        raise CaseError(["number: must start with a letter or digit and use only letters, digits, '.', '_' and '-', at most 64 characters"])
    incident_start = incident.get("impact_started_at") or incident["declared_at"]
    try:
        window = window_around(incident_start, incident.get("resolved_at"), now, config.limits["max_window_hours"])
    except WindowError as error:
        raise CaseError([f"window: {error}"]) from error
    case_dir = _make_run_folder(config.cases_dir / number, now)
    redactor = Redactor()
    safe_incident = redactor.value(incident)
    keys = incident_keys(incident)
    case = {
        "skill_version": skill_version(skill_dir),
        "created_at": format_time(now),
        "replay": replay_active(),
        "case_dir": str(case_dir),
        "incident": {**{key: safe_incident.get(key) for key in INCIDENT_SUMMARY_KEYS}, "hostnames": list(keys.hostnames)},
        "incident_start": incident_start,
        "window": window.iso(),
        "match": _match_record(match_incident(service_map, keys)),
        "target": None,
    }
    try:
        for sub in SUBFOLDERS:
            (case_dir / sub).mkdir()
        (case_dir / "incident.json").write_text(json.dumps(safe_incident, indent=2) + "\n")
    except OSError as error:
        raise CaseError([f"{case_dir}: cannot write the case ({error.strerror or error})"]) from error
    save_case(case_dir, case)
    return case_dir


def _is_text(value: Any) -> bool:
    return isinstance(value, str)


def _is_text_or_none(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _is_text_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _has(value: Any, **checks: Any) -> bool:
    """True when value is a mapping that has every key and each value passes its check."""
    return isinstance(value, dict) and all(key in value and check(value[key]) for key, check in checks.items())


def _check_case_shape(case: Any, path: Path) -> None:
    summary_checks = {key: _is_text_or_none for key in INCIDENT_SUMMARY_KEYS}
    sound = (
        _has(case, case_dir=_is_text, incident_start=_is_text, incident=lambda v: isinstance(v, dict),
             window=lambda v: isinstance(v, dict), match=lambda v: isinstance(v, dict), target=lambda v: v is None or isinstance(v, dict))
        and _has(case["incident"], **summary_checks)
        and _is_text(case["incident"]["number"])
        and ("hostnames" not in case["incident"] or _is_text_list(case["incident"]["hostnames"]))
        and _has(case["window"], start=_is_text, end=_is_text)
        and _has(case["match"], status=_is_text, candidates=lambda v: isinstance(v, list))
        and all(_has(c, service=_is_text, environment=_is_text, reasons=_is_text_list) for c in case["match"]["candidates"])
        and (case["target"] is None or (
            _has(case["target"], source=_is_text, account=_is_text, region=_is_text, resources=lambda v: isinstance(v, dict))
            and _is_text_or_none(case["target"].get("service"))
            and _is_text_or_none(case["target"].get("environment"))
            and _is_text_list(case["target"].get("depends_on", []))))
    )
    if not sound:
        raise CaseError([f"{path}: is not a valid case file"])


def resolve_case_dir(path: Path, config: TriageConfig) -> Path:
    """The real path of a case folder, or a CaseError.

    A case folder is exactly <cases root>/<incident folder>/<run folder> after links are resolved, an existing
    folder with a case.json. The guard protects the script-owned files only at that depth, so a copy of a run
    anywhere else must never be read, validated, rendered, or published."""
    root = config.cases_dir.resolve()
    refusal = CaseError([f"{path}: not a case folder under {root}"])
    try:
        real = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        raise refusal from None
    if real.parent.parent != root or not real.is_dir() or not (real / "case.json").is_file():
        raise refusal
    return real


def load_case(case_dir: Path) -> dict:
    path = case_dir / "case.json"
    if not path.is_file():
        raise CaseError([f"{path}: file not found"])
    try:
        case = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise CaseError([f"{path}: cannot be read as JSON ({error})"]) from error
    _check_case_shape(case, path)
    return case


def save_case(case_dir: Path, case: dict) -> None:
    """Write case.json and render case.md from it."""
    try:
        (case_dir / "case.json").write_text(json.dumps(case, indent=2) + "\n")
        (case_dir / "case.md").write_text(render_case(case))
    except OSError as error:
        raise CaseError([f"{case_dir}: cannot write the case ({error.strerror or error})"]) from error


_ENTITIES = {"<": "&lt;", ">": "&gt;"}


def _line(value: Any, limit: int = MAX_TEXT) -> str:
    """One bounded line of text, at most `limit` characters as written (entities included) plus a " (cut)" mark.
    A leading Markdown marker is escaped and angle brackets are written as entities, so that a value can neither
    start a block nor open a tag or comment."""
    text = _WHITESPACE_RE.sub(" ", str(value)).strip()
    if text.startswith(_MARKER_START):
        text = "\\" + text
    elif _LEADING_NUMBER_RE.match(text):
        text = _LEADING_NUMBER_RE.sub(r"\1\\.", text, count=1)
    pieces, used = [], 0
    for index, char in enumerate(text):
        piece = _ENTITIES.get(char, char)
        if used + len(piece) > limit:
            return "".join(pieces) + " (cut)"
        pieces.append(piece)
        used += len(piece)
    return "".join(pieces)


def _bullets(pairs: list[tuple[str, Any]], limits: dict[str, int] | None = None) -> str:
    limits = limits or {}
    return "\n".join(
        f"- {label}: {_line(value, limits.get(label, MAX_TEXT)) if value not in (None, '') else '-'}"
        for label, value in pairs
    )


def _describe_target(target: dict | None) -> str:
    if not target:
        return "No target has been chosen yet."
    lines = [("Source", target["source"]), ("Service", target.get("service")), ("Environment", target.get("environment")),
             ("Account", target["account"]), ("Region", target["region"]),
             ("Depends on", ", ".join(str(d) for d in target.get("depends_on", [])))]
    text = _bullets(lines) + "\n- Resources:"
    resources = target.get("resources") or {}
    if not resources:
        return text + " none"
    return text + "\n" + "\n".join(f"  - {_line(key)}: {_line(json.dumps(value))}" for key, value in resources.items())


def _describe_match(match: dict) -> str:
    lines = [f"Status: {_line(match['status'])}"]
    for candidate in match["candidates"]:
        reasons = ", ".join(str(r) for r in candidate["reasons"])
        lines.append(f"- {_line(candidate['service'])} / {_line(candidate['environment'])} ({_line(reasons)})")
    return "\n".join(lines)


def render_case(case: dict) -> str:
    incident = case["incident"]
    values = {
        "number": _line(incident["number"]),
        "replay_mark": " (REPLAY: recorded, not live)" if case.get("replay") else "",
        "case_dir": _line(case["case_dir"]),
        "incident": _bullets([
            ("Title", incident["title"]), ("URL", incident["url"]), ("Severity", incident["severity"]),
            ("State", incident["state"]), ("Declared", incident["declared_at"]),
            ("Impact started", incident["impact_started_at"]), ("Resolved", incident["resolved_at"]),
        ], {"Title": MAX_TITLE}),
        "window": _bullets([("Start", case["window"]["start"]), ("End", case["window"]["end"]),
                            ("Incident start", case["incident_start"])]),
        "match": _describe_match(case["match"]),
        "target": _describe_target(case["target"]),
    }
    # One pass, so a value that contains {{name}} is never expanded.
    return re.sub(r"\{\{(\w+)\}\}", lambda found: values.get(found.group(1), found.group(0)), TEMPLATE_PATH.read_text())


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


def _text_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _discovery_shape_errors(resources: dict) -> list[str]:
    errors = []
    for key in SCALAR_RESOURCES:
        if key in resources and not (isinstance(resources[key], str) and resources[key].strip()):
            errors.append(f"discovery.resources.{key}: must be a non-empty string")
    for key in LIST_RESOURCES:
        if key in resources and not _text_list(resources[key]):
            errors.append(f"discovery.resources.{key}: must be a list of strings")
    eks = resources.get("eks")
    if isinstance(eks, dict) and "workloads" in eks and not _text_list(eks["workloads"]):
        errors.append("discovery.resources.eks.workloads: must be a list of strings")
    search = resources.get("opensearch")
    if isinstance(search, dict) and not isinstance(search.get("filter", {}), dict):
        errors.append("discovery.resources.opensearch.filter: must be a mapping")
    return errors


def _discovery_errors(config: TriageConfig, discovery: Any) -> list[str]:
    if not isinstance(discovery, dict):
        return ["discovery: must be a JSON object"]
    account, region, resources = discovery.get("account"), discovery.get("region"), discovery.get("resources", {})
    errors = []
    if not isinstance(account, str) or not isinstance(region, str) or not account or not region:
        errors.append("discovery: account and region must both be set as text")
    elif account not in config.accounts:
        errors.append(f"discovery: unknown account '{account}'")
    elif region not in config.accounts[account].regions:
        errors.append(f"discovery: region '{region}' is not listed for account '{account}'")
    if resources is None:
        resources = {}
    if not isinstance(resources, dict):
        return errors + ["discovery.resources: must be a mapping"]
    errors += _discovery_shape_errors(resources)
    # The same checks the service map applies to its own resources (cluster, namespace, index pattern).
    _check_resources(resources, "discovery", config, errors)
    return errors


def set_target_from_discovery(case_dir: Path, config: TriageConfig, discovery: dict) -> dict:
    errors = _discovery_errors(config, discovery)
    if errors:
        raise CaseError(errors)
    return _store_target(case_dir, {
        "source": "discovered",
        "service": None,
        "environment": None,
        "account": discovery["account"],
        "region": discovery["region"],
        "resources": dict(discovery.get("resources") or {}),
        "depends_on": [],
    })
