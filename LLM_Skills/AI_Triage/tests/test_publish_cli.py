import json
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC
from triage.case import load_case, save_case

COMMAND = SKILL_SRC / "scripts" / "publish.py"
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
HIGH_ENTROPY = "Zk3" + "vQ9xLm2" + "Pq7RtYw4" + "Nb8HdFs6Jc"
CASE = {
    "skill_version": "0.1.0", "created_at": "2026-10-04T11:00:00Z", "case_dir": "",
    "incident": {"number": "INC-123", "title": "Checkout API is down", "url": "", "severity": "Critical",
                 "state": "Acknowledged", "declared_at": "2026-10-04T10:45:00Z", "impact_started_at": None,
                 "resolved_at": None},
    "incident_start": "2026-10-04T10:45:00Z",
    "window": {"start": "2026-10-04T09:45:00Z", "end": "2026-10-04T11:00:00Z"},
    "match": {"status": "none", "candidates": []}, "target": None,
}
REPORT = {
    "status": "cause_found",
    "summary": {"top_cause": "C1"},
    "causes": [{"id": "C1", "statement": "Deploy 42 exited with code 137", "label": "confirmed"}],
    "actions": [{"id": "A1", "label": "recommended", "title": "Roll back to deploy 41"}],
}


@pytest.fixture
def skill_dir(tmp_path, config_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return root


@pytest.fixture
def case_dir(tmp_path):
    run = tmp_path / "cases" / "INC-123" / "20261004-110000"
    run.mkdir(parents=True)
    save_case(run, CASE)
    (run / "report.md").write_text("# Report\n")
    (run / "report.json").write_text(json.dumps(REPORT))
    (run / "work-order.json").write_text("{}")
    return run


def run(skill_dir, *args):
    return subprocess.run([sys.executable, str(COMMAND), *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True)


def test_help_exits_zero():
    result = subprocess.run([sys.executable, str(COMMAND), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "confluence" in result.stdout


def test_no_subcommand_is_a_usage_error():
    result = subprocess.run([sys.executable, str(COMMAND)], capture_output=True, text=True)
    assert result.returncode == 2


def test_audit_clean(skill_dir, case_dir):
    result = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 0 and result.stdout.strip() == "clean"


def test_audit_prints_one_line_per_hit_and_never_the_value(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nkey " + AWS_KEY + "\n")
    result = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 1
    lines = result.stdout.strip().splitlines()
    assert lines and all(line.startswith("report.md:2:5 ") for line in lines)
    assert AWS_KEY not in result.stdout + result.stderr


def test_audit_without_a_report_exits_one(skill_dir, case_dir):
    (case_dir / "report.md").unlink()
    result = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "report.md" in result.stderr


def test_confluence_with_a_secret_exits_one_and_prints_no_request(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nkey " + AWS_KEY + "\n")
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir))
    assert result.returncode == 1 and result.stdout == ""
    assert "report.md:2:5" in result.stderr and AWS_KEY not in result.stderr


def test_confluence_prints_the_request_as_json(skill_dir, case_dir):
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir))
    assert result.returncode == 0, result.stderr
    request = json.loads(result.stdout)
    assert set(request) == {"space_key", "parent_page_id", "title", "body_file", "body_sha256", "existing_page"}
    assert request["title"] == "INC-123 Triage: Checkout API is down"
    assert request["existing_page"] is None


def test_confluence_with_a_damaged_case_json_is_one_line_without_a_traceback(skill_dir, case_dir):
    (case_dir / "case.json").write_text("{broken")
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "Traceback" not in result.stderr
    assert len(result.stderr.strip().splitlines()) == 1


def test_confluence_with_a_bad_config_exits_two(tmp_path, case_dir):
    empty = tmp_path / "empty-skill"
    empty.mkdir()
    result = run(empty, "confluence", "--case-dir", str(case_dir))
    assert result.returncode == 2


def test_slack_message_prints_writes_and_audits(skill_dir, case_dir):
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir),
                 "--confluence-url", "https://wiki.example.com/pages/1")
    assert result.returncode == 0, result.stderr
    assert result.stdout.rstrip("\n") == (case_dir / "slack-message.md").read_text()
    assert result.stdout.rstrip("\n").endswith("Full report: https://wiki.example.com/pages/1")
    audit = json.loads((case_dir / "audit.json").read_text())
    assert audit["clean"] and "slack-message.md" in audit["checked"]


def test_slack_message_prints_nothing_when_the_audit_is_not_clean(skill_dir, case_dir):
    (case_dir / "work-order.json").write_text('{"note": "' + AWS_KEY + '"}')
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir))
    assert result.returncode == 1 and result.stdout == ""
    assert "work-order.json:1:" in result.stderr
    assert AWS_KEY not in result.stdout + result.stderr


def test_slack_message_without_report_json_exits_one(skill_dir, case_dir):
    (case_dir / "report.json").unlink()
    assert run(skill_dir, "slack-message", "--case-dir", str(case_dir)).returncode == 1


def test_record_confluence(skill_dir, case_dir):
    result = run(skill_dir, "record-confluence", "--case-dir", str(case_dir), "--page-id", "42",
                 "--url", "https://wiki.example.com/pages/42", "--now", "2026-10-04T12:00:00Z")
    assert result.returncode == 0, result.stderr
    assert load_case(case_dir)["publish"]["confluence"] == {
        "page_id": "42", "url": "https://wiki.example.com/pages/42", "at": "2026-10-04T12:00:00Z"}


def test_record_slack_accumulates(skill_dir, case_dir):
    for destination in ("#incidents", "#oncall"):
        result = run(skill_dir, "record-slack", "--case-dir", str(case_dir), "--destination", destination,
                     "--now", "2026-10-04T12:00:00Z")
        assert result.returncode == 0, result.stderr
    assert [s["destination"] for s in load_case(case_dir)["publish"]["slack"]] == ["#incidents", "#oncall"]


def test_record_with_a_missing_case_exits_one(skill_dir, tmp_path):
    result = run(skill_dir, "record-slack", "--case-dir", str(tmp_path / "nope"), "--destination", "#x")
    assert result.returncode == 1


def test_missing_required_option_is_a_usage_error(skill_dir, case_dir):
    assert run(skill_dir, "record-confluence", "--case-dir", str(case_dir)).returncode == 2


def test_audit_through_a_link_at_audit_json_exits_one(skill_dir, case_dir, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    (case_dir / "audit.json").symlink_to(outside)
    result = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "audit.json" in result.stderr
    assert outside.read_text() == "keep"


def _digest(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_no_output_or_audit_json_holds_either_half_of_a_planted_token(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    outputs = []
    for args in (("audit",), ("confluence",), ("slack-message",)):
        result = run(skill_dir, *args, "--case-dir", str(case_dir))
        assert result.returncode == 1
        outputs += [result.stdout, result.stderr, (case_dir / "audit.json").read_text()]
    joined = "\n".join(outputs)
    for half in (HIGH_ENTROPY[:14], HIGH_ENTROPY[14:]):
        assert half not in joined
    assert "report.md:2:7 entropy" in joined


def test_confluence_proceeds_with_the_matching_accept_hits_flag(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    digest = _digest(case_dir / "report.md")
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir), f"--accept-hits={digest}")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["body_sha256"] == digest
    assert "report.md:2:7 entropy" in result.stderr and HIGH_ENTROPY[:14] not in result.stderr
    assert json.loads((case_dir / "audit.json").read_text())["accepted_by_flag"] is True


def test_the_confluence_request_alias_works_and_a_wrong_flag_refuses(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    result = run(skill_dir, "confluence-request", "--case-dir", str(case_dir), "--accept-hits=" + "0" * 64)
    assert result.returncode == 1 and result.stdout == ""


def test_slack_message_proceeds_with_the_matching_accept_hits_flag(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    refused = run(skill_dir, "slack-message", "--case-dir", str(case_dir), "--accept-hits=" + "0" * 64)
    assert refused.returncode == 1 and refused.stdout == ""
    digest = _digest(case_dir / "report.md")
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir), f"--accept-hits={digest}")
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("INC-123:") and "report.md:2:7 entropy" in result.stderr
