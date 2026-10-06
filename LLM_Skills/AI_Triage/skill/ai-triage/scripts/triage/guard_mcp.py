"""Decide about connector (MCP) tool calls during a triage session.

- OneUptime (a server whose name holds "oneuptime", or the configured oneuptime.mcp_server): only reads (a name that
  starts with get, list or count and holds no write word, or oneuptime_whoami) are allowed; the rest is denied.
- Slack: anything that sends or changes something asks; reads pass.
- Confluence (Atlassian): a page create or update is allowed only with the exact body, the title and (for an update)
  the page that publish.py recorded in <cases root>/.publish-state.json less than 30 minutes ago; any other write
  asks; reads pass.
- Every other connector tool passes to the normal permission flow.
Operation names are compared by words (split on separators and camel case), without letter case.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from typing import Any, Iterator

from triage.verdict import ALLOW, ASK, DENY, PASS, Verdict

PUBLISH_STATE_NAME = ".publish-state.json"
STATE_MAX_AGE = timedelta(minutes=30)
ONEUPTIME_READ_WORDS = frozenset({"get", "list", "count"})
ONEUPTIME_READ_EXACT = frozenset({"oneuptime_whoami"})
# Words that change something, in any connector's tool name.
WRITE_WORDS = frozenset({
    "send", "post", "reply", "schedule", "create", "update", "delete", "add", "remove", "invite", "upload", "react",
    "archive", "unarchive", "pin", "unpin", "edit", "set", "rename", "kick", "leave", "join", "mark", "move", "write",
    "save", "put", "patch", "publish", "comment", "label", "attachment", "transition", "acknowledge", "resolve",
    "assign", "close", "open", "restore", "share", "import", "upsert", "replace", "insert", "modify", "change",
})
SLACK_WRITE_WORDS = WRITE_WORDS
# OneUptime reads may name what they read (get_open_incidents, list_incident_comments), so fewer words count there.
ONEUPTIME_WRITE_WORDS = WRITE_WORDS - {"open", "close", "mark", "join", "leave", "share", "label", "attachment",
                                       "comment", "schedule", "pin", "unpin", "react", "reply", "kick", "transition"}
ATLASSIAN_WRITE_WORDS = WRITE_WORDS
# Words that, with "page", put a body on a Confluence page; an update also needs the recorded page id.
PAGE_WRITE_WORDS = frozenset({"create", "update", "edit", "write", "save", "put", "publish", "replace", "upsert"})
PAGE_UPDATE_WORDS = PAGE_WRITE_WORDS - {"create"}
PAGE_ID_KEYS = frozenset({"pageid", "page_id"})
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
SLACK_REASON = "posting to Slack is the engineer's decision"
BODY_REASON = "the page body is not the report that was audited"


def _split_tool(tool: str) -> tuple[str, str]:
    rest = tool[len("mcp__"):] if tool.startswith("mcp__") else tool
    server, _, name = rest.partition("__")
    return server.lower(), name.lower()


def _words(name: str) -> list[str]:
    """getOrCreatePage -> [get, or, create, page]; slack_chat_postMessage -> [slack, chat, post, message]."""
    return [word.lower() for word in re.split(r"[^A-Za-z0-9]+", _CAMEL_RE.sub(" ", name)) if word]


def _raw_split(tool: str) -> tuple[str, str]:
    rest = tool[len("mcp__"):] if tool.startswith("mcp__") else tool
    server, _, name = rest.partition("__")
    return server, name


def _is_oneuptime(server: str, oneuptime_server: str | None) -> bool:
    """The word test always applies; a configured server name adds one more server, never replaces the test."""
    return "oneuptime" in server or bool(oneuptime_server) and server == oneuptime_server.lower()


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _keyed_values(value: Any, keys: frozenset[str]) -> Iterator[Any]:
    """Every value stored under one of keys (compared without letter case), at any depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in keys:
                yield item
            yield from _keyed_values(item, keys)
    elif isinstance(value, list):
        for item in value:
            yield from _keyed_values(item, keys)


def _audited_page(cases_dir: str, now: datetime) -> dict | None:
    """The Confluence publish recorded less than 30 minutes ago (body digest, title, page id), or None."""
    if not cases_dir:
        return None
    try:
        with open(os.path.join(os.path.expanduser(cases_dir), PUBLISH_STATE_NAME), encoding="utf-8") as handle:
            entry = json.load(handle).get("confluence")
        written = datetime.fromisoformat(entry["written_at"])
        digest = entry["body_sha256"]
        title = entry["title"]
        page_id = entry.get("page_id")
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None
    if written.tzinfo is None or not isinstance(digest, str) or not isinstance(title, str):
        return None
    if not timedelta(0) <= now - written < STATE_MAX_AGE:
        return None
    return {"body_sha256": digest.lower(), "title": title,
            "page_id": str(page_id) if isinstance(page_id, (str, int)) and str(page_id) else None}


def _page_write_verdict(words: list[str], tool_input: Any, cases_dir: str, now: datetime) -> Verdict:
    audited = _audited_page(cases_dir, now)
    if audited is None or not any(hashlib.sha256(value.encode("utf-8")).hexdigest() == audited["body_sha256"]
                                  for value in _string_values(tool_input)):
        return Verdict(ASK, BODY_REASON)
    titles = [value for value in _keyed_values(tool_input, frozenset({"title"}))]
    if not titles or any(value != audited["title"] for value in titles):
        return Verdict(ASK, "the page title is not the title publish.py recorded")
    page_ids = [str(value) for value in _keyed_values(tool_input, PAGE_ID_KEYS)]
    if any(value != audited["page_id"] for value in page_ids):
        return Verdict(ASK, "the page is not the page publish.py recorded for this incident")
    if PAGE_UPDATE_WORDS.intersection(words) and "create" not in words and not page_ids:
        return Verdict(ASK, "an update must name the page publish.py recorded for this incident")
    return Verdict(ALLOW, "the page body, title and page are what publish.py audited and recorded")


def _confluence_verdict(name: str, tool_input: Any, cases_dir: str, now: datetime) -> Verdict:
    words = _words(name)
    writes = WRITE_WORDS.intersection(words)
    if not writes:
        return Verdict(PASS)
    if "page" in words and writes <= PAGE_WRITE_WORDS and not {"get", "fetch", "or", "and"}.intersection(words):
        return _page_write_verdict(words, tool_input, cases_dir, now)
    return Verdict(ASK, f"{name} changes Confluence or Jira; the engineer decides")


def decide_mcp(tool: str, tool_input: Any, cases_dir: str, oneuptime_server: str | None, now: datetime) -> Verdict:
    """Allow, ask, deny, or pass for one connector tool call. now must be timezone-aware."""
    server, name = _split_tool(tool)
    words = _words(_raw_split(tool)[1])
    if _is_oneuptime(server, oneuptime_server):
        if name in ONEUPTIME_READ_EXACT or (words and words[0] in ONEUPTIME_READ_WORDS
                                            and not ONEUPTIME_WRITE_WORDS.intersection(words)):
            return Verdict(ALLOW, f"OneUptime read {name}")
        return Verdict(DENY, "the skill never changes OneUptime")
    if "slack" in server or "slack" in name:
        return Verdict(ASK, SLACK_REASON) if SLACK_WRITE_WORDS.intersection(words) else Verdict(PASS)
    if any(word in server or word in name for word in ("atlassian", "confluence")):
        return _confluence_verdict(_raw_split(tool)[1], tool_input, cases_dir, now)
    return Verdict(PASS)
