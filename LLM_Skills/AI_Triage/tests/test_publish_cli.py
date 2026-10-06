import json
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC
from triage.case import load_case, save_case
from triage.report import input_hashes, write_render_marker

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


def resign(case_dir):
    """Record the files as they are in render.json, with the report code's own marker writer."""
    write_render_marker(case_dir, input_hashes(case_dir))


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
    resign(run)
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
    resign(case_dir)
    result = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 1
    lines = result.stdout.strip().splitlines()
    assert lines and all(line.startswith("report.md:2:5 ") for line in lines)
    assert AWS_KEY not in result.stdout + result.stderr


def test_audit_without_a_report_exits_one(skill_dir, case_dir):
    (case_dir / "report.md").unlink()
    resign(case_dir)
    result = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "report.md" in result.stderr


def test_confluence_with_a_secret_exits_one_and_prints_no_request(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nkey " + AWS_KEY + "\n")
    resign(case_dir)
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir))
    assert result.returncode == 1 and result.stdout == ""
    assert "report.md:2:5" in result.stderr and AWS_KEY not in result.stderr


def test_confluence_prints_the_request_as_json(skill_dir, case_dir):
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir))
    assert result.returncode == 0, result.stderr
    request = json.loads(result.stdout)
    assert set(request) == {"space_key", "parent_page_id", "title", "body_file", "body_format", "body_sha256",
                           "existing_page", "space_id_note"}
    assert request["body_format"] == "markdown"
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
    resign(case_dir)
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir))
    assert result.returncode == 1 and result.stdout == ""
    assert "work-order.json:1:" in result.stderr
    assert AWS_KEY not in result.stdout + result.stderr


def test_slack_message_without_report_json_exits_one(skill_dir, case_dir):
    (case_dir / "report.json").unlink()
    resign(case_dir)
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


def test_record_with_a_missing_case_exits_two(skill_dir, tmp_path):
    result = run(skill_dir, "record-slack", "--case-dir", str(tmp_path / "nope"), "--destination", "#x")
    assert result.returncode == 2 and "not a case folder" in result.stderr


def test_missing_required_option_is_a_usage_error(skill_dir, case_dir):
    assert run(skill_dir, "record-confluence", "--case-dir", str(case_dir)).returncode == 2


def test_audit_through_a_link_at_audit_json_exits_one(skill_dir, case_dir, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    (case_dir / "audit.json").symlink_to(outside)
    result = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 1 and "audit.json" in result.stderr
    assert outside.read_text() == "keep"


def _set_digest(case_dir, names):
    import hashlib
    lines = sorted(f"{name}:{hashlib.sha256((case_dir / name).read_bytes()).hexdigest()}" for name in names)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


PLANTED = {"report.md": "a\nvalue " + HIGH_ENTROPY + "\n"}


def test_no_output_or_audit_json_holds_either_half_of_a_planted_token(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    outputs = []
    for args in (("audit",), ("confluence",), ("slack-message",)):
        result = run(skill_dir, *args, "--case-dir", str(case_dir))
        assert result.returncode == 1
        outputs += [result.stdout, result.stderr, (case_dir / "audit.json").read_text()]
    joined = "\n".join(outputs)
    for half in (HIGH_ENTROPY[:14], HIGH_ENTROPY[14:]):
        assert half not in joined
    assert "report.md:2:7 entropy" in joined


def test_both_refusals_print_the_set_digest(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    slack = run(skill_dir, "slack-message", "--case-dir", str(case_dir))
    digest = _set_digest(case_dir, ("report.md", "work-order.json", "slack-message.md"))
    assert slack.returncode == 1 and digest in slack.stderr
    confluence = run(skill_dir, "confluence", "--case-dir", str(case_dir))
    assert confluence.returncode == 1 and "sha256" in confluence.stderr
    audit = json.loads((case_dir / "audit.json").read_text())
    assert confluence.stderr.strip().endswith(audit["set_sha256"])


def test_confluence_proceeds_with_the_set_digest(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    refused = run(skill_dir, "confluence", "--case-dir", str(case_dir))
    digest = refused.stderr.strip().split()[-1]
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir), f"--accept-hits={digest}")
    assert result.returncode == 0, result.stderr
    assert "report.md:2:7 entropy" in result.stderr and HIGH_ENTROPY[:14] not in result.stderr
    assert json.loads((case_dir / "audit.json").read_text())["accepted_by_flag"] is True


def test_the_confluence_request_alias_works_and_a_wrong_flag_refuses(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    result = run(skill_dir, "confluence-request", "--case-dir", str(case_dir), "--accept-hits=" + "0" * 64)
    assert result.returncode == 1 and result.stdout == ""


def test_slack_message_proceeds_with_the_set_digest_and_prints_the_audited_bytes(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    refused = run(skill_dir, "slack-message", "--case-dir", str(case_dir), "--accept-hits=" + "0" * 64)
    assert refused.returncode == 1 and refused.stdout == ""
    digest = _set_digest(case_dir, ("report.md", "work-order.json", "slack-message.md"))
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir), f"--accept-hits={digest}")
    assert result.returncode == 0, result.stderr
    assert result.stdout == (case_dir / "slack-message.md").read_text() + "\n"
    assert "report.md:2:7 entropy" in result.stderr


@pytest.mark.parametrize("flag", ["--acc", "--accept", "--accept-h"])
@pytest.mark.parametrize("subcommand", ["confluence", "slack-message"])
def test_abbreviated_override_flags_are_errors(skill_dir, case_dir, flag, subcommand):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    result = run(skill_dir, subcommand, "--case-dir", str(case_dir), f"{flag}={'0' * 64}")
    assert result.returncode == 2 and "unrecognized" in result.stderr
    assert result.stdout == ""


def test_an_abbreviated_case_dir_is_an_error_too(skill_dir, case_dir):
    result = run(skill_dir, "audit", "--case", str(case_dir))
    assert result.returncode == 2


def test_a_malformed_accept_value_says_why(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir), "--accept-hits=" + "A" * 64)
    assert result.returncode == 1 and "64 lower-case hex" in result.stderr


def test_a_configured_account_id_passes_in_the_report_but_not_an_unconfigured_one(skill_dir, case_dir):
    (case_dir / "report.md").write_text("- Account: prod (" + "1" * 12 + ")\n")
    resign(case_dir)
    assert run(skill_dir, "audit", "--case-dir", str(case_dir)).returncode == 0
    (case_dir / "report.md").write_text("- Account: other (" + "333" * 4 + ")\n")
    resign(case_dir)
    assert run(skill_dir, "audit", "--case-dir", str(case_dir)).returncode == 1


def _digests_printed_by_audit(stderr):
    found = {}
    for line in stderr.splitlines():
        for label in ("confluence", "slack-message"):
            if line.startswith(f"for {label}: "):
                found[label] = line.split(": ", 1)[1].strip()
    return found


def test_audit_prints_one_labelled_digest_per_command_and_each_is_accepted_only_by_its_command(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    audit = run(skill_dir, "audit", "--case-dir", str(case_dir))
    assert audit.returncode == 1
    digests = _digests_printed_by_audit(audit.stderr)
    assert set(digests) == {"confluence", "slack-message"} and digests["confluence"] != digests["slack-message"]
    assert HIGH_ENTROPY[:14] not in audit.stdout + audit.stderr

    wrong_for_confluence = run(skill_dir, "confluence", "--case-dir", str(case_dir),
                               f"--accept-hits={digests['slack-message']}")
    assert wrong_for_confluence.returncode == 1 and wrong_for_confluence.stdout == ""
    right_for_confluence = run(skill_dir, "confluence", "--case-dir", str(case_dir),
                               f"--accept-hits={digests['confluence']}")
    assert right_for_confluence.returncode == 0, right_for_confluence.stderr

    wrong_for_slack = run(skill_dir, "slack-message", "--case-dir", str(case_dir),
                          f"--accept-hits={digests['confluence']}")
    assert wrong_for_slack.returncode == 1 and wrong_for_slack.stdout == ""
    right_for_slack = run(skill_dir, "slack-message", "--case-dir", str(case_dir),
                          f"--accept-hits={digests['slack-message']}")
    assert right_for_slack.returncode == 0, right_for_slack.stderr


def test_the_slack_digest_follows_the_confluence_url_given_to_audit(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nvalue " + HIGH_ENTROPY + "\n")
    resign(case_dir)
    url = "https://wiki.example.com/pages/9"
    audit = run(skill_dir, "audit", "--case-dir", str(case_dir), "--confluence-url", url)
    digest = _digests_printed_by_audit(audit.stderr)["slack-message"]
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir), "--confluence-url", url,
                 f"--accept-hits={digest}")
    assert result.returncode == 0, result.stderr


def test_audit_without_a_readable_config_exits_two(tmp_path, case_dir):
    empty = tmp_path / "empty-skill"
    empty.mkdir()
    result = run(empty, "audit", "--case-dir", str(case_dir))
    assert result.returncode == 2 and result.stdout == ""


# case folders, replay, publish state, verify-confluence

SUBCOMMANDS = (("audit",), ("confluence",), ("slack-message",), ("record-confluence", "--page-id", "1", "--url", "https://x.example.com/1"),
               ("record-slack", "--destination", "#x"), ("verify-confluence", "--body-file", "x"))


@pytest.mark.parametrize("command", SUBCOMMANDS)
def test_every_subcommand_refuses_a_folder_that_is_not_a_run_under_the_cases_root(skill_dir, case_dir, tmp_path, command):
    import shutil
    copy_dir = tmp_path / "copy" / "INC-123" / "20261004-110000"
    shutil.copytree(case_dir, copy_dir)
    result = run(skill_dir, command[0], "--case-dir", str(copy_dir), *command[1:])
    assert result.returncode == 2 and "not a case folder" in result.stderr and result.stdout == ""
    assert not (copy_dir / "audit.json").exists() and not (copy_dir / "slack-message.md").exists()


def test_a_link_to_a_run_outside_the_root_is_refused(skill_dir, case_dir, tmp_path):
    import shutil
    outside = tmp_path / "outside" / "INC-123" / "20261004-110000"
    shutil.copytree(case_dir, outside)
    link = case_dir.parent / "20261004-120000"
    link.symlink_to(outside)
    assert run(skill_dir, "audit", "--case-dir", str(link)).returncode == 2


def _make_replay(case_dir):
    case = load_case(case_dir)
    case["replay"] = True
    save_case(case_dir, case)


@pytest.mark.parametrize("command", [("audit",), ("confluence",), ("slack-message",),
                                     ("record-confluence", "--page-id", "1", "--url", "https://x.example.com/1"),
                                     ("record-slack", "--destination", "#x")])
def test_a_replay_case_is_refused_unless_allowed(skill_dir, case_dir, command):
    _make_replay(case_dir)
    result = run(skill_dir, command[0], "--case-dir", str(case_dir), *command[1:])
    assert result.returncode == 1 and "this case is a replay" in result.stderr and result.stdout == ""
    assert not (case_dir / "slack-message.md").exists()
    assert not (case_dir.parent.parent / ".publish-state.json").exists()


@pytest.mark.parametrize("command", ["audit", "confluence", "slack-message"])
def test_the_command_line_has_no_replay_bypass(skill_dir, case_dir, command):
    _make_replay(case_dir)
    result = run(skill_dir, command, "--case-dir", str(case_dir), "--allow-replay")
    assert result.returncode == 2 and "--allow-replay" in result.stderr and result.stdout == ""
    assert not (case_dir.parent.parent / ".publish-state.json").exists()


def _publish_main():
    import importlib.util
    spec = importlib.util.spec_from_file_location("publish_script", COMMAND)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main


def test_a_replay_case_publishes_only_through_the_module_function(skill_dir, case_dir, capsys):
    _make_replay(case_dir)
    main = _publish_main()
    assert main(["confluence", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir)]) == 1
    assert main(["confluence", "--case-dir", str(case_dir), "--skill-dir", str(skill_dir)], allow_replay=True) == 0
    assert json.loads(capsys.readouterr().out)["title"]


def test_confluence_writes_the_publish_state_after_a_clean_audit(skill_dir, case_dir):
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir), "--now", "2026-10-04T12:00:00Z")
    assert result.returncode == 0, result.stderr
    request = json.loads(result.stdout)
    state = json.loads((case_dir.parent.parent / ".publish-state.json").read_text())
    assert state["confluence"] == {"case_dir": str(case_dir.resolve()), "title": request["title"], "page_id": None,
                                   "body_sha256": request["body_sha256"], "written_at": "2026-10-04T12:00:00Z"}
    assert "slack" not in state


def test_a_refused_confluence_request_writes_no_state(skill_dir, case_dir):
    (case_dir / "report.md").write_text("a\nkey " + AWS_KEY + "\n")
    resign(case_dir)
    assert run(skill_dir, "confluence", "--case-dir", str(case_dir)).returncode == 1
    assert not (case_dir.parent.parent / ".publish-state.json").exists()


def test_slack_message_adds_its_state_next_to_the_confluence_state(skill_dir, case_dir):
    import hashlib
    assert run(skill_dir, "confluence", "--case-dir", str(case_dir)).returncode == 0
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir), "--now", "2026-10-04T12:05:00Z")
    assert result.returncode == 0, result.stderr
    state = json.loads((case_dir.parent.parent / ".publish-state.json").read_text())
    text = (case_dir / "slack-message.md").read_text()
    assert state["slack"] == {"case_dir": str(case_dir.resolve()), "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                              "written_at": "2026-10-04T12:05:00Z"}
    assert "confluence" in state


def test_slack_output_names_the_default_channel_and_incident_url(skill_dir, case_dir):
    case = load_case(case_dir)
    case["incident"]["url"] = "https://oneuptime.example.com/incident/abc"
    save_case(case_dir, case)
    result = run(skill_dir, "slack-message", "--case-dir", str(case_dir))
    assert result.returncode == 0, result.stderr
    assert result.stdout == (case_dir / "slack-message.md").read_text() + "\n"
    assert "default_channel: #incidents" in result.stderr
    assert "incident_url: https://oneuptime.example.com/incident/abc" in result.stderr


def _intake(case_dir, text, name="readback.md"):
    intake = case_dir.parent.parent.parent / "intake"
    intake.mkdir(exist_ok=True)
    (intake / name).write_text(text)
    return intake / name


def test_verify_confluence_reports_a_match(skill_dir, case_dir):
    assert run(skill_dir, "audit", "--case-dir", str(case_dir)).returncode == 0
    path = _intake(case_dir, (case_dir / "report.md").read_text() + "\n\n")
    result = run(skill_dir, "verify-confluence", "--case-dir", str(case_dir), "--body-file", str(path))
    assert result.returncode == 0 and "matches" in result.stdout


def test_verify_confluence_prints_the_first_differing_line(skill_dir, case_dir):
    assert run(skill_dir, "audit", "--case-dir", str(case_dir)).returncode == 0
    path = _intake(case_dir, "# Report\nchanged\n")
    result = run(skill_dir, "verify-confluence", "--case-dir", str(case_dir), "--body-file", str(path))
    assert result.returncode == 1 and "line 2" in result.stdout and "changed" in result.stdout


def test_verify_confluence_refuses_a_path_outside_the_intake_folder(skill_dir, case_dir, tmp_path):
    assert run(skill_dir, "audit", "--case-dir", str(case_dir)).returncode == 0
    outside = tmp_path / "elsewhere.md"
    outside.write_text("# Report\n")
    result = run(skill_dir, "verify-confluence", "--case-dir", str(case_dir), "--body-file", str(outside))
    assert result.returncode == 1 and "intake" in result.stderr


def test_the_publish_state_records_the_page_an_update_may_change(skill_dir, case_dir):
    case = load_case(case_dir)
    case["publish"] = {"confluence": {"page_id": "98765", "url": "https://wiki.example.com/p/98765", "at": "x"}}
    save_case(case_dir, case)
    resign(case_dir)
    result = run(skill_dir, "confluence", "--case-dir", str(case_dir), "--now", "2026-10-04T12:00:00Z")
    assert result.returncode == 0, result.stderr
    state = json.loads((case_dir.parent.parent / ".publish-state.json").read_text())
    assert state["confluence"]["page_id"] == "98765"
