import json
import os
from datetime import datetime, timezone

import pytest

from triage.case import load_case, save_case
from triage.config import parse_config
from triage.publish import (
    PUBLISHED_FILES,
    PublishError,
    audit_case,
    confluence_request,
    page_title,
    previous_page,
    record_confluence,
    record_slack,
    slack_message,
)

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def case_data(number="INC-123", title="Checkout API is down", **extra):
    incident = {"number": number, "title": title, "url": "", "severity": "Critical", "state": "Acknowledged",
                "declared_at": "2026-10-04T10:45:00Z", "impact_started_at": None, "resolved_at": None}
    return {"skill_version": "0.1.0", "created_at": "2026-10-04T11:00:00Z", "case_dir": "", "incident": incident,
            "incident_start": "2026-10-04T10:45:00Z",
            "window": {"start": "2026-10-04T09:45:00Z", "end": "2026-10-04T11:00:00Z"},
            "match": {"status": "none", "candidates": []}, "target": None, **extra}


def report_data(status="cause_found", labels=("recommended",), cause_label="confirmed"):
    causes = [{"id": "C1", "statement": "Deploy 42 exited with code 137", "label": cause_label,
               "supporting": [], "contradicting": []}]
    return {
        "status": status,
        "summary": {"what_broke": "", "impact": "", "scope": "", "top_cause": "C1" if status == "cause_found" else None},
        "causes": causes if status == "cause_found" else [],
        "actions": [{"id": f"A{i}", "type": "mitigation", "label": label, "cause": "C1", "title": f"Action {i}"}
                    for i, label in enumerate(labels, start=1)],
    }


def make_run(cases_dir, number="INC-123", stamp="20261004-110000", report=None, case=None):
    run = cases_dir / number / stamp
    run.mkdir(parents=True)
    save_case(run, case or case_data(number=number))
    (run / "report.md").write_text("# Report\n\nAll clear.\n")
    (run / "report.json").write_text(json.dumps(report or report_data()))
    (run / "work-order.json").write_text(json.dumps({"actions": []}))
    return run


@pytest.fixture
def cases_dir(tmp_path):
    return tmp_path / "cases"


@pytest.fixture
def run_dir(cases_dir):
    return make_run(cases_dir)


@pytest.fixture
def config(config_data, tmp_path):
    config_data["cases_dir"] = str(tmp_path / "cases")
    return parse_config(config_data)


def set_mtime(path, seconds):
    os.utime(path, (seconds, seconds))


# audit_case

def test_published_files_are_the_three_documents():
    assert PUBLISHED_FILES == ("report.md", "work-order.json", "slack-message.md")


def test_clean_files_give_a_clean_audit_that_is_written(run_dir):
    result = audit_case(run_dir)
    assert result == {"clean": True, "checked": ["report.md", "work-order.json"], "hits": []}
    assert json.loads((run_dir / "audit.json").read_text()) == result


@pytest.mark.parametrize("name", PUBLISHED_FILES)
def test_a_secret_in_each_published_file_is_a_hit(run_dir, name):
    (run_dir / name).write_text("first line\nkey " + AWS_KEY + "\n")
    result = audit_case(run_dir)
    assert result["clean"] is False
    assert len(result["hits"]) == 1
    hit = result["hits"][0]
    assert hit["file"] == name and hit["line"] == 2 and hit["column"] == 5 and hit["category"]
    assert name in result["checked"]


def test_audit_never_stores_the_matched_value(run_dir):
    (run_dir / "report.md").write_text("key " + AWS_KEY + "\n")
    audit_case(run_dir)
    assert AWS_KEY not in (run_dir / "audit.json").read_text()


def test_audit_needs_report_md(run_dir):
    (run_dir / "report.md").unlink()
    with pytest.raises(PublishError, match="report.md"):
        audit_case(run_dir)


# page_title

def test_page_title_joins_number_and_title():
    assert page_title(case_data()) == "INC-123 Triage: Checkout API is down"


def test_page_title_is_cut_at_200_characters():
    title = page_title(case_data(title="x" * 500))
    assert len(title) == 200 and title.startswith("INC-123 Triage: xxx")


# confluence_request

def test_confluence_request_without_an_audit_is_refused(run_dir, config):
    with pytest.raises(PublishError, match="run the audit again"):
        confluence_request(run_dir, config)


def test_confluence_request_with_a_dirty_audit_is_refused(run_dir, config):
    (run_dir / "report.md").write_text("key " + AWS_KEY + "\n")
    audit_case(run_dir)
    with pytest.raises(PublishError, match="run the audit again"):
        confluence_request(run_dir, config)


def test_confluence_request_with_an_audit_older_than_the_report_is_refused(run_dir, config):
    audit_case(run_dir)
    set_mtime(run_dir / "audit.json", 1_000)
    set_mtime(run_dir / "report.md", 2_000)
    with pytest.raises(PublishError, match="run the audit again"):
        confluence_request(run_dir, config)


def test_confluence_request_with_a_clean_fresh_audit(run_dir, config):
    audit_case(run_dir)
    set_mtime(run_dir / "report.md", 1_000)
    set_mtime(run_dir / "audit.json", 2_000)
    request = confluence_request(run_dir, config)
    assert request == {
        "space_key": config.confluence_space_key,
        "parent_page_id": config.confluence_parent_page_id,
        "title": "INC-123 Triage: Checkout API is down",
        "body_file": str((run_dir / "report.md").resolve()),
        "existing_page": None,
    }


def test_confluence_request_carries_the_existing_page(run_dir, config):
    record_confluence(run_dir, "555", "https://wiki.example.com/pages/555", NOW)
    audit_case(run_dir)
    set_mtime(run_dir / "report.md", 1_000)
    set_mtime(run_dir / "audit.json", 2_000)
    assert confluence_request(run_dir, config)["existing_page"] == {
        "page_id": "555", "url": "https://wiki.example.com/pages/555"}


# previous_page

def test_previous_page_none(run_dir):
    assert previous_page(run_dir) is None


def test_previous_page_in_this_run(run_dir):
    record_confluence(run_dir, "1", "https://wiki.example.com/1", NOW)
    assert previous_page(run_dir) == {"page_id": "1", "url": "https://wiki.example.com/1"}


def test_previous_page_in_an_older_sibling_run(cases_dir):
    older = make_run(cases_dir, stamp="20261004-090000")
    newer = make_run(cases_dir, stamp="20261004-110000")
    record_confluence(older, "7", "https://wiki.example.com/7", NOW)
    assert previous_page(newer) == {"page_id": "7", "url": "https://wiki.example.com/7"}


def test_the_newest_sibling_wins(cases_dir):
    oldest = make_run(cases_dir, stamp="20261004-080000")
    middle = make_run(cases_dir, stamp="20261004-090000")
    current = make_run(cases_dir, stamp="20261004-110000")
    record_confluence(oldest, "1", "https://wiki.example.com/1", NOW)
    record_confluence(middle, "2", "https://wiki.example.com/2", NOW)
    assert previous_page(current)["page_id"] == "2"


def test_this_run_wins_over_siblings(cases_dir):
    older = make_run(cases_dir, stamp="20261004-090000")
    current = make_run(cases_dir, stamp="20261004-110000")
    record_confluence(older, "1", "https://wiki.example.com/1", NOW)
    record_confluence(current, "9", "https://wiki.example.com/9", NOW)
    assert previous_page(current)["page_id"] == "9"


def test_other_incidents_are_not_siblings(cases_dir):
    other = make_run(cases_dir, number="INC-999")
    current = make_run(cases_dir)
    record_confluence(other, "1", "https://wiki.example.com/1", NOW)
    assert previous_page(current) is None


# slack_message

def test_message_for_a_found_cause(run_dir):
    text = slack_message(run_dir, "https://wiki.example.com/pages/1")
    lines = text.splitlines()
    assert lines[0] == "INC-123: Checkout API is down"
    assert "cause found" in text
    assert "Deploy 42 exited with code 137" in text and "confirmed" in text
    assert "Action 1" in text and "recommended" in text
    assert lines[-1] == "Full report: https://wiki.example.com/pages/1"


def test_message_for_an_unresolved_incident(cases_dir):
    run = make_run(cases_dir, report=report_data(status="unresolved", labels=()))
    text = slack_message(run, None)
    assert "unresolved" in text
    assert "No cause was established" in text
    assert "Deploy 42" not in text


def test_message_without_a_link(run_dir):
    assert slack_message(run_dir, None).splitlines()[-1] == "Full report: not published to Confluence"


def test_message_lists_at_most_three_actions(cases_dir):
    run = make_run(cases_dir, report=report_data(labels=("recommended", "candidate", "recommended", "candidate")))
    text = slack_message(run, None)
    assert "Action 3" in text and "Action 4" not in text


def test_message_is_capped_at_1500_characters_and_keeps_the_link(cases_dir):
    report = report_data()
    report["causes"][0]["statement"] = "long " * 600
    run = make_run(cases_dir, report=report)
    text = slack_message(run, "https://wiki.example.com/pages/1")
    assert len(text) <= 1500
    assert text.splitlines()[-1] == "Full report: https://wiki.example.com/pages/1"


def test_message_is_redacted(cases_dir):
    report = report_data()
    report["causes"][0]["statement"] = "leaked " + AWS_KEY
    run = make_run(cases_dir, report=report)
    text = slack_message(run, None)
    assert AWS_KEY not in text


def test_message_is_written_to_slack_message_md(run_dir):
    text = slack_message(run_dir, None)
    assert (run_dir / "slack-message.md").read_text() == text


def test_message_needs_report_json(run_dir):
    (run_dir / "report.json").unlink()
    with pytest.raises(PublishError, match="report.json"):
        slack_message(run_dir, None)


# recording

def test_confluence_record_overwrites(run_dir):
    record_confluence(run_dir, "1", "https://wiki.example.com/1", NOW)
    record_confluence(run_dir, "2", "https://wiki.example.com/2", NOW)
    assert load_case(run_dir)["publish"]["confluence"] == {
        "page_id": "2", "url": "https://wiki.example.com/2", "at": "2026-10-04T12:00:00Z"}


def test_slack_record_accumulates(run_dir):
    record_slack(run_dir, "#incidents", NOW)
    record_slack(run_dir, "#oncall", NOW)
    assert load_case(run_dir)["publish"]["slack"] == [
        {"destination": "#incidents", "at": "2026-10-04T12:00:00Z"},
        {"destination": "#oncall", "at": "2026-10-04T12:00:00Z"}]


def test_recording_keeps_the_other_publish_entry_and_rewrites_case_md(run_dir):
    record_confluence(run_dir, "1", "https://wiki.example.com/1", NOW)
    record_slack(run_dir, "#incidents", NOW)
    publish = load_case(run_dir)["publish"]
    assert publish["confluence"]["page_id"] == "1" and len(publish["slack"]) == 1
    assert (run_dir / "case.md").is_file()
