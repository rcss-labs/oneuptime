"""The permissions document must describe exactly what the policy grants."""
import json
import re

from conftest import ROOT
from triage.policy_check import REQUIRED_DENIES

DOC = ROOT / "docs" / "aws-permissions.md"
POLICY = ROOT / "iam" / "ai-triage-inline-policy.json"
README = ROOT / "README.md"


def statements(effect):
    return [s for s in json.loads(POLICY.read_text())["Statement"] if s["Effect"] == effect]


def test_every_granted_action_is_documented():
    text = DOC.read_text()
    missing = [
        action
        for statement in statements("Allow")
        for action in statement["Action"]
        if not re.search(rf"`(?:{re.escape(action)}|{re.escape(action.split(':', 1)[1])})`", text)
    ]
    assert missing == []


def test_every_explicit_deny_is_documented():
    text = DOC.read_text()
    assert [action for action in sorted(REQUIRED_DENIES) if f"`{action}`" not in text] == []


def test_documents_name_the_policies_they_were_checked_against():
    text = DOC.read_text()
    assert "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess" in text
    assert "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy" in text
    assert re.search(r"`ViewOnlyAccess` version \d+", text)


def test_readme_covers_the_required_sections():
    text = README.read_text()
    for heading in ("## Prerequisites", "## Install", "## Configure", "## Verify", "## Use", "## Upgrade", "## Uninstall", "## Troubleshooting"):
        assert heading in text
    for script in ("run.py validate_map", "run.py preflight", "run.py verify_access", "install.sh"):
        assert script in text


def test_documents_say_that_api_keys_are_not_readable():
    text = DOC.read_text()
    assert "**API Gateway** usage plans and API keys are not readable, because they expose key values." in text
    api_row = next(line for line in text.splitlines() if line.startswith("| API Gateway"))
    assert "usage plan" not in api_row.lower()


def test_cloudfront_is_rated_medium_with_a_reason_and_codebuild_is_not_granted():
    rows = {line.split("|")[1].strip(): line for line in DOC.read_text().splitlines() if line.startswith("| ")}
    assert rows["CloudFront"].rstrip().endswith("| Medium: custom origin headers |")
    assert "codebuild" not in rows["CodePipeline"].lower()


def test_sensitive_decisions_say_collectors_do_not_store_origin_values_and_codebuild_is_not_granted():
    assert "- **CloudFront** custom origin headers are readable; collectors do not store those values. CodeBuild is not granted." in DOC.read_text()


NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8}
SCRIPTS = ROOT / "skill" / "ai-triage" / "scripts"


def test_readme_counts_the_recorded_incidents_in_tests_replay():
    folders = [entry for entry in (ROOT / "tests" / "replay").iterdir() if entry.is_dir()]
    match = re.search(r"\b(\w+) recorded incidents", README.read_text())
    assert match, "the README must say how many recorded incidents there are"
    assert NUMBER_WORDS[match.group(1).lower()] == len(folders)
    for folder in folders:
        assert f"`{folder.name}`" in README.read_text()


def test_every_script_the_readme_names_exists():
    names = {name for name in re.findall(r"\b([a-z_]+)\.py\b", README.read_text()) if not name.startswith("test_")}
    tools = ROOT / "tools"
    missing = [name for name in sorted(names) if not (SCRIPTS / f"{name}.py").exists() and not (tools / f"{name}.py").exists()]
    assert missing == []


def test_every_command_and_subcommand_the_readme_names_is_in_the_help():
    import subprocess
    import sys

    from triage.commands import COMMANDS

    named = set(re.findall(r"\brun\.py ([a-z_]+)(?: ([a-z][a-z-]+))?", README.read_text()))
    problems = []
    for command, sub in sorted(named):
        if command not in COMMANDS:
            problems.append(f"run.py {command}")
            continue
        if not sub:
            continue
        out = subprocess.run([sys.executable, str(SCRIPTS / "run.py"), command, "--help"], capture_output=True, text=True,
                             cwd=SCRIPTS).stdout
        if sub not in out:
            problems.append(f"run.py {command} {sub}")
    assert problems == []
    assert ("publish", "verify-confluence") in named and ("case", "collect") in named


def test_readme_does_not_name_a_timeline_file_that_nothing_writes():
    assert "timeline.md" not in README.read_text()
    assert "timeline.json" in README.read_text()


def test_readme_lists_exactly_the_service_map_resource_keys():
    from triage.service_map import RESOURCE_KEYS

    line = next((l for l in README.read_text().splitlines() if l.strip().startswith("Resource keys:")), "")
    assert set(re.findall(r"`([a-z0-9_]+)`", line)) == set(RESOURCE_KEYS)
