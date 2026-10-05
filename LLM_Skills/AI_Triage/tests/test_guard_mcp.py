import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from triage.guard_mcp import PUBLISH_STATE_NAME, decide_mcp
from triage.verdict import ALLOW, ASK, DENY, PASS

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
BODY = "# Incident INC-1\n\nThe deploy at 10:02 broke checkout.\n"


def mcp(tool, tool_input=None, cases_dir="", oneuptime_server=None, now=NOW):
    return decide_mcp(tool, tool_input or {}, cases_dir, oneuptime_server, now)


@pytest.mark.parametrize("tool", ["mcp__oneuptime__get_incident", "mcp__oneuptime__list_monitors",
                                  "mcp__oneuptime__count_incidents", "mcp__oneuptime__oneuptime_whoami",
                                  "mcp__claude_ai_OneUptime__get_incident_timeline"])
def test_oneuptime_reads_are_allowed(tool):
    assert mcp(tool).kind == ALLOW


@pytest.mark.parametrize("tool", ["mcp__oneuptime__update_incident", "mcp__oneuptime__create_incident_note",
                                  "mcp__oneuptime__delete_monitor", "mcp__oneuptime__acknowledge_incident",
                                  "mcp__oneuptime__resolve", "mcp__oneuptime__whoami_get"])
def test_every_other_oneuptime_tool_is_denied(tool):
    result = mcp(tool)
    assert result.kind == DENY and "never changes OneUptime" in result.reason


def test_a_configured_oneuptime_server_name_is_used_instead_of_the_word():
    assert mcp("mcp__status-tool__update_incident", oneuptime_server="status-tool").kind == DENY
    assert mcp("mcp__status-tool__get_incident", oneuptime_server="status-tool").kind == ALLOW
    # with a configured name, another server that merely contains "oneuptime" is not treated as OneUptime
    assert mcp("mcp__oneuptime-mirror__update_incident", oneuptime_server="status-tool").kind == PASS


@pytest.mark.parametrize("tool", ["mcp__slack__send_message", "mcp__claude_ai_Slack__post_message",
                                  "mcp__slack__reply_to_thread", "mcp__slack__schedule_message",
                                  "mcp__slack__create_channel", "mcp__slack__update_message",
                                  "mcp__slack__delete_message", "mcp__slack__add_reaction", "mcp__slack__remove_user",
                                  "mcp__slack__invite_user", "mcp__slack__upload_file", "mcp__slack__react",
                                  "mcp__chat__slack_send"])
def test_slack_sends_and_changes_ask(tool):
    result = mcp(tool)
    assert result.kind == ASK and result.reason == "posting to Slack is the engineer's decision"


@pytest.mark.parametrize("tool", ["mcp__slack__read_channel", "mcp__slack__search_messages", "mcp__slack__get_thread"])
def test_slack_reads_pass(tool):
    assert mcp(tool).kind == PASS


def write_state(cases_dir, body=BODY, written=NOW - timedelta(minutes=5)):
    state = {"confluence": {"case_dir": str(cases_dir / "INC-1" / "r"), "title": "INC-1",
                            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                            "written_at": written.isoformat()}}
    (cases_dir / PUBLISH_STATE_NAME).write_text(json.dumps(state))


@pytest.mark.parametrize("tool", ["mcp__atlassian__createConfluencePage", "mcp__atlassian__updateConfluencePage",
                                  "mcp__claude_ai_Atlassian__update_confluence_page", "mcp__confluence__create_page"])
def test_a_confluence_page_write_with_the_audited_body_is_allowed(tool, tmp_path):
    write_state(tmp_path)
    payload = {"cloudId": "c", "spaceId": "1", "title": "INC-1", "body": BODY}
    assert mcp(tool, payload, str(tmp_path)).kind == ALLOW
    nested = {"page": {"content": [{"value": BODY}]}, "title": "INC-1"}
    assert mcp(tool, nested, str(tmp_path)).kind == ALLOW


def test_a_body_one_byte_off_asks(tmp_path):
    write_state(tmp_path)
    for body in (BODY + " ", BODY[:-1], BODY.replace("10:02", "10:03")):
        result = mcp("mcp__atlassian__createConfluencePage", {"body": body}, str(tmp_path))
        assert result.kind == ASK and result.reason == "the page body is not the report that was audited"


def test_a_stale_or_missing_or_broken_state_asks(tmp_path):
    payload = {"body": BODY}
    assert mcp("mcp__atlassian__createConfluencePage", payload, str(tmp_path)).kind == ASK  # no state file
    write_state(tmp_path, written=NOW - timedelta(minutes=31))
    assert mcp("mcp__atlassian__createConfluencePage", payload, str(tmp_path)).kind == ASK
    write_state(tmp_path, written=NOW + timedelta(minutes=5))
    assert mcp("mcp__atlassian__createConfluencePage", payload, str(tmp_path)).kind == ASK
    (tmp_path / PUBLISH_STATE_NAME).write_text("{not json")
    assert mcp("mcp__atlassian__createConfluencePage", payload, str(tmp_path)).kind == ASK
    (tmp_path / PUBLISH_STATE_NAME).write_text(json.dumps({"slack": {}}))
    assert mcp("mcp__atlassian__createConfluencePage", payload, str(tmp_path)).kind == ASK
    assert mcp("mcp__atlassian__createConfluencePage", payload, "").kind == ASK


def test_the_body_must_be_given_exactly_as_audited(tmp_path):
    write_state(tmp_path)
    assert mcp("mcp__atlassian__createConfluencePage", {"body": BODY.encode().hex()}, str(tmp_path)).kind == ASK
    assert mcp("mcp__atlassian__createConfluencePage", {"body": [BODY[:10], BODY[10:]]}, str(tmp_path)).kind == ASK


@pytest.mark.parametrize("tool", ["mcp__atlassian__deleteConfluencePage", "mcp__atlassian__moveConfluencePage",
                                  "mcp__atlassian__createConfluenceFooterComment", "mcp__atlassian__addLabel",
                                  "mcp__atlassian__uploadAttachment", "mcp__atlassian__createJiraIssue",
                                  "mcp__atlassian__editJiraIssue"])
def test_other_atlassian_writes_ask(tool, tmp_path):
    write_state(tmp_path)
    assert mcp(tool, {"body": BODY}, str(tmp_path)).kind == ASK


@pytest.mark.parametrize("tool", ["mcp__atlassian__getConfluencePage", "mcp__atlassian__searchConfluenceUsingCql",
                                  "mcp__atlassian__getConfluencePageFooterComments",
                                  "mcp__atlassian__getAccessibleAtlassianResources", "mcp__confluence__list_spaces"])
def test_atlassian_reads_pass(tool):
    assert mcp(tool).kind == PASS


@pytest.mark.parametrize("tool", ["mcp__github__create_issue", "mcp__claude-in-chrome__navigate", "mcp__notion__notion-search",
                                  "mcp__weird", "mcp__"])
def test_every_other_mcp_tool_passes(tool):
    assert mcp(tool).kind == PASS
