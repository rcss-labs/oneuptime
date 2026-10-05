"""Decide about connector (MCP) tool calls during a triage session.

- OneUptime: only reads (get_, list_, count_, oneuptime_whoami) are allowed; the skill never changes OneUptime.
- Slack: anything that sends or changes something asks; reads pass.
- Confluence (Atlassian): a page create or update is allowed only with the exact body that publish.py audited,
  recorded in <cases root>/.publish-state.json less than 30 minutes ago; any other write asks; reads pass.
- Every other connector tool passes to the normal permission flow.
Names are compared without letter case.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Any, Iterator

from triage.verdict import ALLOW, ASK, DENY, PASS, Verdict

PUBLISH_STATE_NAME = ".publish-state.json"
STATE_MAX_AGE = timedelta(minutes=30)
ONEUPTIME_READ_PREFIXES = ("get_", "list_", "count_")
ONEUPTIME_READ_EXACT = frozenset({"oneuptime_whoami"})
SLACK_WRITE_WORDS = ("send", "post", "reply", "schedule", "create", "update", "delete", "add", "remove", "invite",
                     "upload", "react")
ATLASSIAN_READ_PREFIXES = ("get", "list", "search", "fetch", "read", "lookup", "find", "query")
ATLASSIAN_WRITE_WORDS = ("create", "update", "delete", "move", "comment", "label", "attachment", "add", "remove",
                         "edit", "upload", "publish", "transition", "set", "put", "post")
SLACK_REASON = "posting to Slack is the engineer's decision"
BODY_REASON = "the page body is not the report that was audited"


def _split_tool(tool: str) -> tuple[str, str]:
    rest = tool[len("mcp__"):] if tool.startswith("mcp__") else tool
    server, _, name = rest.partition("__")
    return server.lower(), name.lower()


def _is_oneuptime(server: str, oneuptime_server: str | None) -> bool:
    if oneuptime_server:
        return server == oneuptime_server.lower()
    return "oneuptime" in server


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _audited_body_sha256(cases_dir: str, now: datetime) -> str:
    """The body digest of a Confluence publish recorded less than 30 minutes ago, or ""."""
    if not cases_dir:
        return ""
    try:
        with open(os.path.join(os.path.expanduser(cases_dir), PUBLISH_STATE_NAME), encoding="utf-8") as handle:
            entry = json.load(handle).get("confluence")
        written = datetime.fromisoformat(entry["written_at"])
        digest = entry["body_sha256"]
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return ""
    if written.tzinfo is None or not isinstance(digest, str):
        return ""
    age = now - written
    return digest.lower() if timedelta(0) <= age < STATE_MAX_AGE else ""


def _confluence_verdict(name: str, tool_input: Any, cases_dir: str, now: datetime) -> Verdict:
    compact = name.replace("_", "").replace("-", "")
    if compact.startswith(ATLASSIAN_READ_PREFIXES):
        return Verdict(PASS)
    if "page" in compact and ("create" in compact or "update" in compact):
        digest = _audited_body_sha256(cases_dir, now)
        if digest and any(hashlib.sha256(value.encode("utf-8")).hexdigest() == digest
                          for value in _string_values(tool_input)):
            return Verdict(ALLOW, "the page body is the report that publish.py audited")
        return Verdict(ASK, BODY_REASON)
    if any(word in compact for word in ATLASSIAN_WRITE_WORDS):
        return Verdict(ASK, f"{name} changes Confluence or Jira; the engineer decides")
    return Verdict(PASS)


def decide_mcp(tool: str, tool_input: Any, cases_dir: str, oneuptime_server: str | None, now: datetime) -> Verdict:
    """Allow, ask, deny, or pass for one connector tool call. now must be timezone-aware."""
    server, name = _split_tool(tool)
    if _is_oneuptime(server, oneuptime_server):
        if name.startswith(ONEUPTIME_READ_PREFIXES) or name in ONEUPTIME_READ_EXACT:
            return Verdict(ALLOW, f"OneUptime read {name}")
        return Verdict(DENY, "the skill never changes OneUptime")
    if "slack" in server or "slack" in name:
        return Verdict(ASK, SLACK_REASON) if any(word in name for word in SLACK_WRITE_WORDS) else Verdict(PASS)
    if any(word in server or word in name for word in ("atlassian", "confluence")):
        return _confluence_verdict(name, tool_input, cases_dir, now)
    return Verdict(PASS)
