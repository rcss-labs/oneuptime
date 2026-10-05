"""The evidence document a collector writes: timed, redacted, bounded facts."""
from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from triage.redact import Redactor
from triage.window import Window, format_time, parse_time

INCIDENT_TIME = "incident_time"
CURRENT = "current"
DERIVED = "derived"
KINDS = (INCIDENT_TIME, CURRENT, DERIVED)
MAX_EXCERPT = 500
MAX_FACTS = 200
MAX_ERROR_MESSAGE = 300
MAX_SUMMARY = 500
MAX_DATA_STRING = 500
MAX_DATA_KEYS = 50
MAX_KEY_LENGTH = 100
MAX_NESTED_ENTRIES = 50
NOT_A_NUMBER = "not a number"
OMITTED_SUFFIX = "_omitted"
SUMMARY_CUT_MARKER = "… [summary cut]"
_SUFFIX_CLEANER = re.compile(r"[^A-Za-z0-9-]")


@dataclass
class Fact:
    id: str
    kind: str
    time: str | None
    resource: str
    summary: str
    data: dict[str, Any]
    command: str
    excerpt: str


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _cut_summary(text: str) -> str:
    """Cut to MAX_SUMMARY characters, ending with a marker that says the summary was cut."""
    if len(text) <= MAX_SUMMARY:
        return text
    return text[: MAX_SUMMARY - len(SUMMARY_CUT_MARKER)] + SUMMARY_CUT_MARKER


def _first_entries(collection: list | dict) -> list | dict:
    if isinstance(collection, list):
        return collection[:MAX_NESTED_ENTRIES]
    return dict(list(collection.items())[:MAX_NESTED_ENTRIES])


def _bound_dict(value: dict) -> dict:
    """Keys cut to MAX_KEY_LENGTH; a key equal to an earlier one after the cut is dropped and counted in
    keys_omitted. A nested list or dict longer than MAX_NESTED_ENTRIES is cut, and its count of dropped
    entries is put beside it as "<key>_omitted"."""
    bounded: dict[str, Any] = {}
    collisions = 0
    for key, item in value.items():
        cut_key = str(key)[:MAX_KEY_LENGTH]
        if cut_key in bounded:
            collisions += 1
            continue
        if isinstance(item, (list, dict)) and len(item) > MAX_NESTED_ENTRIES:
            bounded[cut_key] = _bound(_first_entries(item))
            omitted_key = cut_key[: MAX_KEY_LENGTH - len(OMITTED_SUFFIX)] + OMITTED_SUFFIX
            bounded.setdefault(omitted_key, len(item) - MAX_NESTED_ENTRIES)
        else:
            bounded[cut_key] = _bound(item)
    if collisions:
        earlier = bounded.get("keys_omitted")
        bounded["keys_omitted"] = collisions + (earlier if isinstance(earlier, int) else 0)
    return bounded


def _bound_list_entry(item: Any) -> Any:
    """A list inside a list has no key to put a count beside: a long one ends with a marker entry,
    and a long dict counts its dropped entries in keys_omitted."""
    if isinstance(item, list) and len(item) > MAX_NESTED_ENTRIES:
        return _bound(_first_entries(item)) + [f"{len(item) - MAX_NESTED_ENTRIES} more entries omitted"]
    if isinstance(item, dict) and len(item) > MAX_NESTED_ENTRIES:
        kept = _bound(_first_entries(item))
        kept["keys_omitted"] = kept.get("keys_omitted", 0) + len(item) - MAX_NESTED_ENTRIES
        return kept
    return _bound(item)


def _bound(value: Any) -> Any:
    """Cut every string, key, and nested collection inside value, at any depth; non-finite numbers become text."""
    if isinstance(value, str):
        return _cut(value, MAX_DATA_STRING)
    if isinstance(value, float) and not math.isfinite(value):
        return NOT_A_NUMBER
    if isinstance(value, dict):
        return _bound_dict(value)
    if isinstance(value, list):
        return [_bound_list_entry(item) for item in value]
    return value


def _limit_data(data: dict) -> dict:
    """At most MAX_DATA_KEYS keys; extra keys are dropped and counted in keys_omitted."""
    cut = _bound(data)
    if len(cut) <= MAX_DATA_KEYS:
        return cut
    omitted = cut.pop("keys_omitted", 0)
    kept = dict(list(cut.items())[: MAX_DATA_KEYS - 1])
    kept["keys_omitted"] = len(cut) - len(kept) + (omitted if isinstance(omitted, int) else 0)
    return kept


class Evidence:
    """Collects the facts and errors of one collector for one account and region."""

    def __init__(self, collector: str, account: str, region: str, window: Window, redactor: Redactor | None = None):
        self.collector = collector
        self.account = account
        self.region = region
        self.window = window
        self.redactor = redactor or Redactor()
        self.facts: list[Fact] = []
        self.errors: list[dict] = []
        self.truncated = False
        self.asked: dict | None = None

    def add(
        self,
        *,
        kind: str,
        resource: str,
        summary: str,
        time: datetime | str | None = None,
        data: dict | None = None,
        command: str = "",
        excerpt: str = "",
    ) -> Fact | None:
        if kind not in KINDS:
            raise ValueError(f"unknown fact kind: {kind!r}")
        if len(self.facts) >= MAX_FACTS:
            self.truncated = True
            return None
        if isinstance(time, str):
            time = parse_time(time)
        fact = Fact(
            id=f"{self.collector}-{len(self.facts) + 1:04d}",
            kind=kind,
            time=format_time(time) if time is not None else None,
            resource=self.redactor.text(resource),
            summary=_cut_summary(self.redactor.text(summary)),
            data=_limit_data(self.redactor.value(data or {})),
            command=self.redactor.text(command),
            excerpt=_cut(self.redactor.text(excerpt), MAX_EXCERPT),
        )
        self.facts.append(fact)
        return fact

    def set_asked(self, targets: dict[str, Any], window: dict[str, str]) -> None:
        """Record what was asked (targets as given, window arguments), so a finding that only quotes it can be refused."""
        self.asked = _bound(self.redactor.value({"targets": dict(targets), "window": dict(window)}))

    def add_error(self, command: str, code: str, message: str) -> None:
        self.errors.append(
            {"command": self.redactor.text(command), "code": code, "message": _cut(self.redactor.text(message), MAX_ERROR_MESSAGE)}
        )

    def to_dict(self) -> dict:
        document = {
            "collector": self.collector,
            "account": self.account,
            "region": self.region,
            "window": self.window.iso(),
            "facts": [asdict(fact) for fact in self.facts],
            "errors": list(self.errors),
            "truncated": self.truncated,
        }
        if self.asked is not None:
            document["asked"] = self.asked
        return document

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, allow_nan=False)

    def write(self, case_dir: Path, suffix: str = "") -> Path:
        name = "-".join(_SUFFIX_CLEANER.sub("", part) for part in (self.collector, self.account, self.region))
        cleaned = _SUFFIX_CLEANER.sub("", suffix)
        if cleaned:
            name += f"-{cleaned}"
        directory = case_dir / "evidence"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{name}.json"
        text = self.to_json() + "\n"
        try:
            with path.open("x") as handle:
                handle.write(text)
        except FileExistsError:
            raise FileExistsError(f"{path} already exists; pass another --suffix to keep both") from None
        return path


def load_evidence(path: Path) -> dict:
    return json.loads(path.read_text())
