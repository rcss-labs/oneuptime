"""Propose a service map entry from a discovered target, and append it after a backup."""
from __future__ import annotations

import copy
import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from triage.case import CaseError, load_case, save_case
from triage.config import TriageConfig, is_simple_name
from triage.service_map import MapError, load_map, parse_map
from triage.window import format_time

ENTRY_KEYS = ("match", "environments", "source", "last_verified")
BACKUP_SUFFIX_FORMAT = "%Y%m%d-%H%M%S"
INDENT = "  "


class SuggestError(Exception):
    """The suggestion cannot be made or applied."""


def _monitor_names(incident: dict) -> list[str]:
    names = []
    for monitor in incident.get("monitors") or []:
        name = monitor.get("name") if isinstance(monitor, dict) else monitor
        if isinstance(name, str) and name.strip():
            names.append(name)
    return list(dict.fromkeys(names))


def proposed_entry(case: dict, service_name: str, environment: str, today: date) -> dict:
    """The map entry for a case whose target was discovered, with keys in the order they are written."""
    target = case.get("target")
    if not target or target.get("source") != "discovered":
        raise SuggestError("this run used the service map; there is nothing to add")
    incident = case["incident"]
    match = {"monitors": _monitor_names(incident), "hostnames": list(incident.get("hostnames") or [])}
    environment_entry: dict[str, Any] = {
        "account": target["account"],
        "region": target["region"],
        "resources": copy.deepcopy(target.get("resources") or {}),
    }
    if target.get("depends_on"):
        environment_entry["depends_on"] = list(target["depends_on"])
    return {
        "match": {key: values for key, values in match.items() if values},
        "environments": {environment: environment_entry},
        "source": "discovered",
        "last_verified": today.isoformat(),
    }


def entry_yaml(service_name: str, entry: dict) -> str:
    """The entry as a block indented under `services:`, keys in the order the engineer reads them."""
    ordered = {key: entry[key] for key in ENTRY_KEYS if key in entry}
    body = yaml.safe_dump(ordered, default_flow_style=False, sort_keys=False)
    indented = "".join(f"{INDENT * 2}{line}\n" for line in body.splitlines())
    return f"{INDENT}{service_name}:\n{indented}"


def _case_with_monitors(case_dir: Path) -> dict:
    """case.json keeps no monitor names, so read them from the incident file next to it."""
    case = load_case(case_dir)
    incident_path = case_dir / "incident.json"
    if incident_path.is_file():
        case["incident"] = {**case["incident"], "monitors": json.loads(incident_path.read_text()).get("monitors", [])}
    return case


def _existing_map_data(map_path: Path) -> dict:
    if not map_path.is_file():
        raise SuggestError(f"{map_path}: file not found")
    try:
        data = yaml.safe_load(map_path.read_text())
    except yaml.YAMLError as error:
        raise SuggestError(f"{map_path}: not valid YAML ({error})") from error
    if data is None:
        return {"services": {}}
    if not isinstance(data, dict) or not isinstance(data.get("services") or {}, dict):
        raise SuggestError(f"{map_path}: must be a mapping with a 'services' mapping")
    return data


def _check_names(service_name: str, environment: str) -> None:
    if not is_simple_name(service_name):
        raise SuggestError(f"service name '{service_name}' must use lower-case letters, digits, and dashes only")
    if not is_simple_name(environment):
        raise SuggestError(f"environment '{environment}' must use lower-case letters, digits, and dashes only")


def _prepare(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str,
             environment: str, today: date) -> tuple[str, dict]:
    """Validate the suggestion against the current map. Returns the block and the existing map data."""
    _check_names(service_name, environment)
    entry = proposed_entry(_case_with_monitors(case_dir), service_name, environment, today)
    block = entry_yaml(service_name, entry)
    data = _existing_map_data(map_path)
    services = data.get("services") or {}
    if service_name in services:
        raise SuggestError(f"service '{service_name}' is already in the service map; edit the entry by hand")
    for key, resource in entry["environments"][environment]["resources"].items():
        if key == "opensearch" and isinstance(resource, dict) and not resource.get("index_pattern"):
            raise SuggestError(
                "the discovered OpenSearch resource has a cluster but no index pattern; "
                "fill the index pattern in by hand. Entry to complete and add:\n" + block
            )
    merged = {**data, "services": {**services, service_name: entry}}
    try:
        parse_map(merged, config)
    except MapError as error:
        raise SuggestError("the suggested entry is not valid: " + "; ".join(error.errors)) from error
    return block, data


def propose(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str,
            environment: str, today: date) -> dict:
    block, _ = _prepare(case_dir, config, map_path, service_name, environment, today)
    return {"service_name": service_name, "yaml": block, "valid": True}


def _leading_comments(text: str) -> str:
    kept = []
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            break
        kept.append(line)
    return "".join(f"{line}\n" for line in kept)


def _new_content(original: bytes, data: dict, block: str) -> bytes:
    text = original.decode("utf-8")
    holds_no_services = not data.get("services") and set(data) <= {"services"}
    if holds_no_services:
        return (_leading_comments(text) + "services:\n" + block).encode("utf-8")
    separator = b"" if original.endswith(b"\n") else b"\n"
    return original + separator + block.encode("utf-8")


def apply(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str,
          environment: str, today: date, now: datetime) -> Path:
    """Append the entry after a backup. If the result does not load, restore the original byte for byte."""
    block, data = _prepare(case_dir, config, map_path, service_name, environment, today)
    original = map_path.read_bytes()
    backup = map_path.with_name(f"{map_path.name}.bak-{now.strftime(BACKUP_SUFFIX_FORMAT)}")
    backup.write_bytes(original)
    map_path.write_bytes(_new_content(original, data, block))
    try:
        load_map(map_path, config)
    except MapError as error:
        map_path.write_bytes(backup.read_bytes())
        raise SuggestError("the service map could not be updated automatically; add the entry by hand") from error
    try:
        case = load_case(case_dir)
        case["map_change"] = {"service_name": service_name, "backup": str(backup), "at": format_time(now)}
        save_case(case_dir, case)
    except CaseError as error:
        raise SuggestError("the map was updated but the case could not record it: " + "; ".join(error.errors)) from error
    return backup
