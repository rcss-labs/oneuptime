"""Propose a service map entry from a discovered target, and append it after a backup."""
from __future__ import annotations

import copy
import json
import os
import re
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
    """The entry as a block indented under `services:`, keys in the order the engineer reads them.

    The service name is always double-quoted so YAML cannot read it as a number, date, or boolean.
    """
    ordered = {key: entry[key] for key in ENTRY_KEYS if key in entry}
    body = yaml.safe_dump(ordered, default_flow_style=False, sort_keys=False)
    indented = "".join(f"{INDENT * 2}{line}\n" for line in body.splitlines())
    return f'{INDENT}{json.dumps(service_name)}:\n{indented}'


def _case_with_monitors(case_dir: Path) -> dict:
    """case.json keeps no monitor names, so read them from the incident file next to it."""
    case = load_case(case_dir)
    incident_path = case_dir / "incident.json"
    if incident_path.is_file():
        try:
            monitors = json.loads(incident_path.read_text()).get("monitors", [])
        except (OSError, ValueError) as error:
            raise SuggestError(f"{incident_path}: cannot be read ({error})") from error
        case["incident"] = {**case["incident"], "monitors": monitors}
    return case


def _existing_map_data(map_path: Path) -> dict:
    """The parsed map. A map file that does not exist yet counts as an empty one."""
    if not map_path.exists():
        return {}
    try:
        data = yaml.safe_load(map_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise SuggestError(f"{map_path}: not valid YAML ({error})") from error
    except (OSError, UnicodeDecodeError) as error:
        raise SuggestError(f"{map_path}: cannot be read ({error})") from error
    if data is None:
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("services") or {}, dict):
        raise SuggestError(f"{map_path}: must be a mapping with a 'services' mapping")
    return data


def _check_names(service_name: str, environment: str) -> None:
    if not is_simple_name(service_name):
        raise SuggestError(f"service name '{service_name}' must use lower-case letters, digits, and dashes only")
    if not is_simple_name(environment):
        raise SuggestError(f"environment '{environment}' must use lower-case letters, digits, and dashes only")


def _check_opensearch(resources: dict, block: str) -> None:
    search = resources.get("opensearch")
    if not isinstance(search, dict):
        return
    missing = [label for key, label in (("cluster", "cluster"), ("index_pattern", "index pattern")) if not search.get(key)]
    if missing:
        raise SuggestError(
            f"the discovered OpenSearch resource is incomplete (missing: {', '.join(missing)}); "
            "fill it in by hand. Entry to complete and add:\n" + block
        )


def _prepare(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str,
             environment: str, today: date) -> tuple[str, dict, dict]:
    """Validate the suggestion against the current map. Returns the block, the entry, and the existing map data."""
    _check_names(service_name, environment)
    entry = proposed_entry(_case_with_monitors(case_dir), service_name, environment, today)
    block = entry_yaml(service_name, entry)
    data = _existing_map_data(map_path)
    services = data.get("services") or {}
    if service_name in {str(key) for key in services}:
        raise SuggestError(f"service '{service_name}' is already in the service map; edit the entry by hand")
    _check_opensearch(entry["environments"][environment]["resources"], block)
    merged = {**data, "services": {**services, service_name: entry}}
    try:
        parse_map(merged, config)
    except MapError as error:
        raise SuggestError("the suggested entry is not valid: " + "; ".join(error.errors)) from error
    return block, entry, data


def propose(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str,
            environment: str, today: date) -> dict:
    block, _, _ = _prepare(case_dir, config, map_path, service_name, environment, today)
    return {"service_name": service_name, "yaml": block, "valid": True}


_EMPTY_SERVICES_LINE = re.compile(r"services:[ \t]*(?:\{[ \t]*\}|~|null)?[ \t]*(#.*)?")


def _line_ending(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _new_content(original: bytes, data: dict, block: str) -> bytes | None:
    """The map text with the block added, or None when an empty services mapping cannot be edited exactly."""
    text = original.decode("utf-8")
    eol = _line_ending(text)
    block = block.replace("\n", eol)
    if "services" not in data:
        separator = "" if not text or text.endswith("\n") else eol
        return (text + separator + "services:" + eol + block).encode("utf-8")
    if data["services"]:
        separator = "" if text.endswith("\n") else eol
        return (text + separator + block).encode("utf-8")
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if _EMPTY_SERVICES_LINE.fullmatch(line.rstrip("\r\n"))]
    if len(hits) != 1:
        return None
    index = hits[0]
    match = _EMPTY_SERVICES_LINE.fullmatch(lines[index].rstrip("\r\n"))
    comment = f" {match.group(1)}" if match.group(1) else ""
    rewritten = lines[index] if lines[index].rstrip("\r\n") == "services:" else f"services:{comment}{eol}"
    if not rewritten.endswith("\n"):
        rewritten += eol
    lines[index] = rewritten + block
    return "".join(lines).encode("utf-8")


def _new_backup(map_path: Path, original: bytes, now: datetime) -> Path:
    """Create the backup with exclusive create, so no earlier backup is ever overwritten."""
    stem = f"{map_path.name}.bak-{now.strftime(BACKUP_SUFFIX_FORMAT)}"
    for counter in range(1000):
        backup = map_path.with_name(stem if counter == 0 else f"{stem}-{counter}")
        try:
            with open(backup, "xb") as handle:
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
            return backup
        except FileExistsError:
            continue
    raise SuggestError(f"{map_path}: could not find a free backup name")


def _check_writable(map_path: Path) -> None:
    folder = map_path.parent
    if not os.access(folder, os.W_OK) or (map_path.exists() and not os.access(map_path, os.W_OK)):
        raise SuggestError(f"{map_path} is not writable; nothing was changed")


def _acquire_lock(map_path: Path) -> Path:
    lock = map_path.with_name(f"{map_path.name}.lock")
    try:
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644))
    except FileExistsError as error:
        raise SuggestError(f"another run is applying a suggestion ({lock} exists); nothing was changed") from error
    except OSError as error:
        raise SuggestError(f"{lock}: cannot be created ({error})") from error
    return lock


def _write_checked(map_path: Path, content: bytes, intended: dict, entry: dict, name: str,
                   config: TriageConfig, backup_note: str) -> None:
    """Write to a temporary file, check it, then replace the map. The map is untouched on any failure."""
    temporary = map_path.with_name(f".{map_path.name}.tmp-{os.getpid()}")
    try:
        with open(temporary, "xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if map_path.exists():
            os.chmod(temporary, map_path.stat().st_mode & 0o777)
        load_map(temporary, config)
        loaded = yaml.safe_load(content.decode("utf-8"))["services"]
        if loaded.get(name) != entry or {key: value for key, value in loaded.items() if key != name} != intended:
            raise MapError(["the new map does not hold exactly the old entries plus the new one"])
        os.replace(temporary, map_path)
    except (MapError, yaml.YAMLError) as error:
        raise SuggestError("the service map could not be updated automatically; add the entry by hand"
                           f"{backup_note}") from error
    except (OSError, UnicodeError) as error:
        raise SuggestError(f"the service map could not be written ({error}); it is unchanged{backup_note}") from error
    finally:
        if temporary.exists():
            temporary.unlink()


def apply(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str,
          environment: str, today: date, now: datetime) -> Path | None:
    """Append the entry after a backup. The map is replaced only by a checked copy, so it never holds a half write.

    Returns the backup path, or None when the map file did not exist and was created.
    """
    map_path = map_path.resolve()
    lock = _acquire_lock(map_path)
    try:
        _check_writable(map_path)
        block, entry, data = _prepare(case_dir, config, map_path, service_name, environment, today)
        original = map_path.read_bytes() if map_path.exists() else b""
        content = _new_content(original, data, block)
        if content is None:
            raise SuggestError("the empty services entry in the map could not be edited exactly; "
                               "paste this block under services: by hand:\n" + block)
        backup = _new_backup(map_path, original, now) if map_path.exists() else None
        note = f"; backup: {backup}" if backup else ""
        _write_checked(map_path, content, data.get("services") or {}, entry, service_name, config, note)
        try:
            case = load_case(case_dir)
            case["map_change"] = {"service_name": service_name, "backup": str(backup) if backup else None,
                                  "at": format_time(now)}
            save_case(case_dir, case)
        except (CaseError, OSError) as error:
            detail = "; ".join(error.errors) if isinstance(error, CaseError) else str(error)
            raise SuggestError(f"the map was updated but the case could not record it ({detail}){note}") from error
        return backup
    finally:
        lock.unlink(missing_ok=True)
