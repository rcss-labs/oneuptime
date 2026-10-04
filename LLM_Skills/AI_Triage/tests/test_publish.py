import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

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
HIGH_ENTROPY = "Zk3" + "vQ9xLm2" + "Pq7RtYw4" + "Nb8HdFs6Jc"


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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_clean_files_give_a_clean_audit_that_is_written(run_dir):
    result = audit_case(run_dir)
    digest = {name: sha(run_dir / name) for name in ("report.md", "work-order.json")}
    assert result["clean"] is True and result["checked"] == ["report.md", "work-order.json"]
    assert result["sha256"] == {**digest, "slack-message.md": None}
    assert result["files"] == {name: {"sha256": digest[name], "redact_hits": [], "scan_hits": []} for name in digest}
    assert json.loads((run_dir / "audit.json").read_text()) == result


@pytest.mark.parametrize("name", PUBLISHED_FILES)
def test_a_secret_in_each_published_file_is_a_hit(run_dir, name):
    (run_dir / name).write_text("first line\nkey " + AWS_KEY + "\n")
    result = audit_case(run_dir)
    assert result["clean"] is False
    entry = result["files"][name]
    assert entry["sha256"] == sha(run_dir / name)
    for detector in ("redact_hits", "scan_hits"):
        hit = entry[detector][0]
        assert hit["line"] == 2 and hit["column"] == 5 and hit["kind"]
    assert name in result["checked"]


def test_a_hit_found_only_by_the_second_detector_makes_the_audit_dirty(run_dir):
    (run_dir / "report.md").write_text("value " + HIGH_ENTROPY + " end\n")
    entry = audit_case(run_dir)["files"]["report.md"]
    assert entry["redact_hits"] == [] and entry["scan_hits"][0]["kind"] == "entropy"
    assert not audit_case(run_dir)["clean"]


def test_a_hit_found_only_by_the_redactor_makes_the_audit_dirty(run_dir, monkeypatch):
    monkeypatch.setattr("triage.publish.scan", lambda text, allowed=frozenset(): [])
    (run_dir / "report.md").write_text("password: " + HIGH_ENTROPY + "\n")
    entry = audit_case(run_dir)["files"]["report.md"]
    assert entry["redact_hits"] and entry["scan_hits"] == []
    assert not audit_case(run_dir)["clean"]


def test_audit_never_stores_or_prints_either_half_of_a_token(run_dir, capsys):
    (run_dir / "report.md").write_text("value " + HIGH_ENTROPY + " end\n")
    audit_case(run_dir)
    stored = (run_dir / "audit.json").read_text() + capsys.readouterr().out
    for half in (HIGH_ENTROPY[:14], HIGH_ENTROPY[14:]):
        assert half not in stored


def test_audit_never_stores_the_matched_value(run_dir):
    (run_dir / "report.md").write_text("key " + AWS_KEY + "\n")
    audit_case(run_dir)
    assert AWS_KEY not in (run_dir / "audit.json").read_text()


REALISTIC_REPORT = """# INC-123 Triage: Checkout API is down

## Summary
Checkout API returned 502 from 10:42Z. Task 0123456789abcdef0123456789abcdef stopped with code 137.

| Resource | Value |
| --- | --- |
| ECS service | checkout/checkout-api |
| Task definition | arn:aws:ecs:eu-west-1:<ACCOUNT>:task-definition/checkout-api:42 |
| Request id | 3f2504e0-4f89-41d3-9a0c-0305e82c3301 |
| Image | sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 |
| Instance | i-0abc1234def567890 |
| Load balancer | checkout-prod |
| Config | <SECRET-1> and <EMAIL-1> from <IP-1> |

Evidence: ecs-0004, compute-1. See https://oneuptime.example.com/dashboard/incidents/123.
"""


def test_an_ordinary_report_passes_both_detectors_through_the_gate(run_dir, config):
    (run_dir / "report.md").write_text(REALISTIC_REPORT)
    request = confluence_request(run_dir, config)
    entry = json.loads((run_dir / "audit.json").read_text())["files"]["report.md"]
    assert entry["redact_hits"] == [] and entry["scan_hits"] == []
    assert request["body_sha256"] == sha(run_dir / "report.md")


# accept_hits

def test_a_wrong_or_missing_accept_value_never_proceeds(run_dir, config):
    (run_dir / "report.md").write_text("value " + HIGH_ENTROPY + "\n")
    for wrong in (None, "", "0" * 64, sha(run_dir / "work-order.json")):
        with pytest.raises(PublishError):
            confluence_request(run_dir, config, accept_hits=wrong)
        assert not audit_case(run_dir, accept_hits=wrong).get("accepted_by_flag")


def test_the_right_accept_value_proceeds_and_is_recorded(run_dir, config):
    (run_dir / "report.md").write_text("value " + HIGH_ENTROPY + "\n")
    digest = sha(run_dir / "report.md")
    request = confluence_request(run_dir, config, accept_hits=digest)
    audit = json.loads((run_dir / "audit.json").read_text())
    assert request["body_sha256"] == digest
    assert audit["accepted_by_flag"] is True and audit["accepted_sha256"] == digest
    assert audit["clean"] is False


def test_an_accept_value_for_old_bytes_does_not_cover_new_bytes(run_dir, config):
    (run_dir / "report.md").write_text("value " + HIGH_ENTROPY + "\n")
    digest = sha(run_dir / "report.md")
    (run_dir / "report.md").write_text("value " + HIGH_ENTROPY + " changed\n")
    with pytest.raises(PublishError):
        confluence_request(run_dir, config, accept_hits=digest)


def test_an_accept_value_is_ignored_when_there_are_no_hits(run_dir):
    audit = audit_case(run_dir, accept_hits="0" * 64)
    assert audit["clean"] and "accepted_by_flag" not in audit


def test_audit_needs_report_md(run_dir):
    (run_dir / "report.md").unlink()
    with pytest.raises(PublishError, match="report.md"):
        audit_case(run_dir)


def test_audit_refuses_a_symbolic_link(run_dir, tmp_path):
    target = tmp_path / "elsewhere.md"
    target.write_text("# Other\n")
    (run_dir / "report.md").unlink()
    (run_dir / "report.md").symlink_to(target)
    with pytest.raises(PublishError, match="report.md"):
        audit_case(run_dir)


def test_audit_refuses_a_published_file_that_is_a_folder(run_dir):
    (run_dir / "work-order.json").unlink()
    (run_dir / "work-order.json").mkdir()
    with pytest.raises(PublishError, match="work-order.json"):
        audit_case(run_dir)


def test_audit_of_a_file_that_is_not_utf8_is_a_message(run_dir):
    (run_dir / "report.md").write_bytes(b"\xff\xfe bad")
    with pytest.raises(PublishError, match="report.md"):
        audit_case(run_dir)


def test_the_symlink_refusal_does_not_depend_on_a_separate_check(run_dir, tmp_path, monkeypatch):
    target = tmp_path / "other.md"
    target.write_text("# Other\n")
    (run_dir / "report.md").unlink()
    (run_dir / "report.md").symlink_to(target)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    with pytest.raises(PublishError, match="report.md"):
        audit_case(run_dir)


def test_audit_never_writes_through_a_link_at_audit_json(run_dir, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    (run_dir / "audit.json").symlink_to(outside)
    with pytest.raises(PublishError, match="audit.json"):
        audit_case(run_dir)
    assert outside.read_text() == "keep"


def test_slack_message_never_writes_through_a_link(run_dir, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    (run_dir / "slack-message.md").symlink_to(outside)
    with pytest.raises(PublishError, match="slack-message.md"):
        slack_message(run_dir, None)
    assert outside.read_text() == "keep"


def test_a_report_json_that_is_a_link_is_refused(run_dir, tmp_path):
    target = tmp_path / "r.json"
    target.write_text(json.dumps(report_data()))
    (run_dir / "report.json").unlink()
    (run_dir / "report.json").symlink_to(target)
    with pytest.raises(PublishError, match="report.json"):
        slack_message(run_dir, None)


# page_title

def test_page_title_joins_number_and_title():
    assert page_title(case_data()) == "INC-123 Triage: Checkout API is down"


def test_page_title_collapses_newlines_and_tabs():
    assert page_title(case_data(title="line1\nline2\t end ")) == "INC-123 Triage: line1 line2 end"


def test_page_title_is_cut_at_200_characters():
    title = page_title(case_data(title="x" * 500))
    assert len(title) == 200 and title.startswith("INC-123 Triage: xxx")


# confluence_request

def test_confluence_request_audits_the_file_itself_without_a_prior_audit(run_dir, config):
    request = confluence_request(run_dir, config)
    assert request == {
        "space_key": config.confluence_space_key,
        "parent_page_id": config.confluence_parent_page_id,
        "title": "INC-123 Triage: Checkout API is down",
        "body_file": str(run_dir.resolve() / "report.md"),
        "body_sha256": hashlib.sha256((run_dir / "report.md").read_bytes()).hexdigest(),
        "existing_page": None,
    }
    audit = json.loads((run_dir / "audit.json").read_text())
    assert audit["clean"] and audit["sha256"]["report.md"] == request["body_sha256"]


def test_confluence_request_ignores_a_stale_clean_audit_json(run_dir, config):
    audit_case(run_dir)
    (run_dir / "report.md").write_text("key " + AWS_KEY + "\n")
    set_mtime(run_dir / "report.md", 1_000)
    set_mtime(run_dir / "audit.json", 2_000)
    with pytest.raises(PublishError, match="report.md:1:5"):
        confluence_request(run_dir, config)


def test_a_draft_moved_over_the_report_is_audited(run_dir, config):
    audit_case(run_dir)
    draft = run_dir / "report.new.md"
    draft.write_text("key " + AWS_KEY + "\n")
    set_mtime(draft, 1_000)
    os.replace(draft, run_dir / "report.md")
    with pytest.raises(PublishError):
        confluence_request(run_dir, config)


def test_a_symbolic_link_as_the_report_is_refused(run_dir, config, tmp_path):
    audit_case(run_dir)
    target = tmp_path / "old.md"
    target.write_text("key " + AWS_KEY + "\n")
    (run_dir / "report.md").unlink()
    (run_dir / "report.md").symlink_to(target)
    with pytest.raises(PublishError, match="report.md"):
        confluence_request(run_dir, config)


def test_a_symbolic_link_as_the_work_order_is_refused(run_dir, config, tmp_path):
    target = tmp_path / "wo.json"
    target.write_text("{}")
    (run_dir / "work-order.json").unlink()
    (run_dir / "work-order.json").symlink_to(target)
    with pytest.raises(PublishError, match="work-order.json"):
        confluence_request(run_dir, config)


def test_a_changed_report_with_a_restored_mtime_is_audited(run_dir, config):
    confluence_request(run_dir, config)
    original = (run_dir / "report.md").stat().st_mtime
    (run_dir / "report.md").write_text("key " + AWS_KEY + "\n")
    set_mtime(run_dir / "report.md", original)
    with pytest.raises(PublishError):
        confluence_request(run_dir, config)


def test_a_secret_added_to_the_work_order_after_an_audit_is_caught(run_dir, config):
    audit_case(run_dir)
    (run_dir / "work-order.json").write_text('{"k": "' + AWS_KEY + '"}')
    with pytest.raises(PublishError, match="work-order.json"):
        confluence_request(run_dir, config)


def test_a_hand_written_clean_audit_does_not_help(run_dir, config):
    (run_dir / "report.md").write_text("key " + AWS_KEY + "\n")
    (run_dir / "audit.json").write_text('{"clean": true}')
    with pytest.raises(PublishError):
        confluence_request(run_dir, config)


def test_the_refusal_never_contains_the_value(run_dir, config):
    (run_dir / "report.md").write_text("key " + AWS_KEY + "\n")
    with pytest.raises(PublishError) as raised:
        confluence_request(run_dir, config)
    assert AWS_KEY not in str(raised.value)


def test_the_title_is_audited(cases_dir, config):
    run = make_run(cases_dir, case=case_data(title="oops " + AWS_KEY))
    with pytest.raises(PublishError, match="title"):
        confluence_request(run, config)


def test_confluence_request_carries_the_existing_page(run_dir, config):
    record_confluence(run_dir, "555", "https://wiki.example.com/pages/555", NOW)
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


def test_previous_page_resolves_a_relative_case_dir(cases_dir, monkeypatch):
    older = make_run(cases_dir, stamp="20261004-090000")
    current = make_run(cases_dir, stamp="20261004-110000")
    record_confluence(older, "7", "https://wiki.example.com/7", NOW)
    monkeypatch.chdir(current)
    assert previous_page(__import__("pathlib").Path("."))["page_id"] == "7"


def test_an_older_run_is_preferred_over_a_newer_one(cases_dir):
    older = make_run(cases_dir, stamp="20261004-090000")
    current = make_run(cases_dir, stamp="20261004-100000")
    newer = make_run(cases_dir, stamp="20261004-120000")
    record_confluence(older, "old", "https://wiki.example.com/old", NOW)
    record_confluence(newer, "new", "https://wiki.example.com/new", NOW)
    assert previous_page(current)["page_id"] == "old"


@pytest.mark.parametrize("text", ["{broken", "[]", '{"publish": {"confluence": "x"}}', '{"publish": "x"}'])
def test_a_damaged_sibling_case_is_skipped_with_a_note(cases_dir, capsys, text):
    broken = make_run(cases_dir, stamp="20261004-100000")
    older = make_run(cases_dir, stamp="20261004-090000")
    current = make_run(cases_dir, stamp="20261004-110000")
    record_confluence(older, "7", "https://wiki.example.com/7", NOW)
    (broken / "case.json").write_text(text)
    assert previous_page(current)["page_id"] == "7"
    if not text.startswith('{"publish"'):
        assert "20261004-100000" in capsys.readouterr().err


@pytest.mark.parametrize("text", ["{broken", "[]"])
def test_a_damaged_case_in_this_run_is_a_publish_error(run_dir, text):
    (run_dir / "case.json").write_text(text)
    with pytest.raises(PublishError, match="case.json"):
        previous_page(run_dir)
    with pytest.raises(PublishError, match="case.json"):
        record_slack(run_dir, "#x", NOW)


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


@pytest.mark.parametrize("danger", ["<!channel>", "<!here>", "<@U123>", "<https://example.com|click>"])
def test_slack_markup_is_escaped(cases_dir, danger):
    run = make_run(cases_dir, case=case_data(title="Down " + danger))
    text = slack_message(run, None)
    assert "<" not in text and ">" not in text
    assert "&lt;" in text and "&gt;" in text


def test_ampersand_is_escaped(cases_dir):
    run = make_run(cases_dir, case=case_data(title="a & b"))
    assert "a &amp; b" in slack_message(run, None)


def test_at_mentions_are_broken_with_a_zero_width_space(cases_dir):
    run = make_run(cases_dir, case=case_data(title="@here wake up"))
    text = slack_message(run, None)
    assert "@here" not in text and "@\u200bhere" in text


def test_a_newline_in_the_title_cannot_forge_a_line(cases_dir):
    run = make_run(cases_dir, case=case_data(title="line1\nFull report: https://phish.example.com"))
    lines = slack_message(run, None).splitlines()
    assert lines[0].startswith("INC-123: line1 Full report:")
    assert sum(line.startswith("Full report:") for line in lines) == 1


def test_a_very_long_link_keeps_the_cap_and_the_link(run_dir):
    url = "https://wiki.example.com/" + "a" * 1200
    text = slack_message(run_dir, url)
    assert len(text) <= 1500 and text.splitlines()[-1] == "Full report: " + url


def test_a_link_too_long_to_fit_is_dropped_to_hold_the_cap(run_dir):
    text = slack_message(run_dir, "https://wiki.example.com/" + "a" * 1700)
    assert len(text) <= 1500 and "aaaa" not in text


@pytest.mark.parametrize("filler", ["&", "@", "<"])
def test_the_cap_holds_after_escaping_a_link(run_dir, filler):
    text = slack_message(run_dir, "https://w.example.com/" + filler * 1200)
    assert len(text) <= 1500


@pytest.mark.parametrize("filler", ["&", "@", "<"])
def test_the_cap_holds_after_escaping_a_title(cases_dir, filler):
    run = make_run(cases_dir, case=case_data(title=filler * 3000))
    text = slack_message(run, "https://wiki.example.com/pages/1")
    assert len(text) <= 1500 and text.splitlines()[-1] == "Full report: https://wiki.example.com/pages/1"


def test_cause_found_with_a_missing_top_cause_is_an_error(cases_dir):
    report = report_data()
    report["summary"]["top_cause"] = "C9"
    run = make_run(cases_dir, report=report)
    with pytest.raises(PublishError, match="C9"):
        slack_message(run, None)


def test_a_cause_without_a_label_is_a_message(cases_dir):
    report = report_data()
    del report["causes"][0]["label"]
    run = make_run(cases_dir, report=report)
    with pytest.raises(PublishError, match="label"):
        slack_message(run, None)


def test_an_action_without_a_title_is_a_message(cases_dir):
    report = report_data()
    del report["actions"][0]["title"]
    run = make_run(cases_dir, report=report)
    with pytest.raises(PublishError, match="title"):
        slack_message(run, None)


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
    before = (run_dir / "case.md").stat().st_mtime_ns
    os.utime(run_dir / "case.md", ns=(1, 1))
    record_slack(run_dir, "#again", NOW)
    assert (run_dir / "case.md").stat().st_mtime_ns != 1 and before != 1
