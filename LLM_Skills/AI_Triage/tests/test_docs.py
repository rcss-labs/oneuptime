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
    for script in ("validate_map.py", "preflight.py", "verify_access.py", "install.sh"):
        assert script in text


def test_documents_say_that_api_keys_are_not_readable():
    text = DOC.read_text()
    assert "**API Gateway** usage plans and API keys are not readable, because they expose key values." in text
    api_row = next(line for line in text.splitlines() if line.startswith("| API Gateway"))
    assert "usage plan" not in api_row.lower()
