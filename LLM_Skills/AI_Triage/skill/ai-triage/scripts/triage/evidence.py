"""The evidence document a collector writes: timed, redacted, bounded facts."""
from __future__ import annotations

import json
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
            summary=self.redactor.text(summary),
            data=self.redactor.value(data or {}),
            command=self.redactor.text(command),
            excerpt=_cut(self.redactor.text(excerpt), MAX_EXCERPT),
        )
        self.facts.append(fact)
        return fact

    def add_error(self, command: str, code: str, message: str) -> None:
        self.errors.append(
            {"command": self.redactor.text(command), "code": code, "message": _cut(self.redactor.text(message), MAX_ERROR_MESSAGE)}
        )

    def to_dict(self) -> dict:
        return {
            "collector": self.collector,
            "account": self.account,
            "region": self.region,
            "window": self.window.iso(),
            "facts": [asdict(fact) for fact in self.facts],
            "errors": list(self.errors),
            "truncated": self.truncated,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def write(self, case_dir: Path, suffix: str = "") -> Path:
        name = "-".join(_SUFFIX_CLEANER.sub("", part) for part in (self.collector, self.account, self.region))
        cleaned = _SUFFIX_CLEANER.sub("", suffix)
        if cleaned:
            name += f"-{cleaned}"
        directory = case_dir / "evidence"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{name}.json"
        path.write_text(self.to_json() + "\n")
        return path


def load_evidence(path: Path) -> dict:
    return json.loads(path.read_text())
