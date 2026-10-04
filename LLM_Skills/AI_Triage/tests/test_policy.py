import copy
import json

import pytest

from conftest import ROOT
from triage.policy_check import check_policy

POLICY_PATH = ROOT / "iam" / "ai-triage-inline-policy.json"


@pytest.fixture
def policy():
    return json.loads(POLICY_PATH.read_text())


def problems(document):
    return check_policy(document, json.dumps(document, indent=2))


def test_shipped_policy_has_no_problems():
    raw = POLICY_PATH.read_text()
    assert check_policy(json.loads(raw), raw) == []


def test_shipped_policy_covers_the_documented_areas(policy):
    allowed = {a for s in policy["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
    for action in (
        "logs:GetLogEvents",
        "logs:StartQuery",
        "cloudwatch:DescribeAlarmHistory",
        "ecr:DescribeImages",
        "rds:DownloadDBLogFilePortion",
        "es:DescribeDomain",
        "lambda:GetFunctionConfiguration",
        "elasticfilesystem:DescribeMountTargets",
        "config:GetResourceConfigHistory",
        "iam:SimulatePrincipalPolicy",
        "ssm:GetParameter",
        "secretsmanager:DescribeSecret",
    ):
        assert action in allowed


def allow(policy, *actions):
    document = copy.deepcopy(policy)
    document["Statement"][0]["Action"].extend(actions)
    return document


@pytest.mark.parametrize(
    "action, expected",
    [
        ("ecs:UpdateService", "'ecs:UpdateService' is not a read action"),
        ("ec2:TerminateInstances", "is not a read action"),
        ("s3:PutObject", "is not a read action"),
        ("s3:GetObject", "'s3:GetObject' must never be granted"),
        ("secretsmanager:GetSecretValue", "must never be granted"),
        ("lambda:GetFunction", "must never be granted"),
        ("logs:Get*", "uses a wildcard"),
        ("ecs:*", "uses a wildcard"),
        ("nonsense", "is not a service:Action pair"),
    ],
)
def test_bad_allow_actions_are_reported(policy, action, expected):
    assert any(expected in problem for problem in problems(allow(policy, action)))


def test_missing_required_deny_is_reported(policy):
    document = copy.deepcopy(policy)
    deny = next(s for s in document["Statement"] if s["Effect"] == "Deny")
    deny["Action"].remove("kms:Decrypt")
    assert "missing explicit deny for 'kms:Decrypt'" in problems(document)


def test_scoped_deny_is_reported(policy):
    document = copy.deepcopy(policy)
    deny = next(s for s in document["Statement"] if s["Effect"] == "Deny")
    deny["Resource"] = "arn:aws:kms:*:*:key/abc"
    assert any("a Deny must apply to every resource" in p for p in problems(document))


def test_duplicate_sid_and_not_action_are_reported(policy):
    document = copy.deepcopy(policy)
    document["Statement"][1]["Sid"] = document["Statement"][0]["Sid"]
    document["Statement"][2]["NotAction"] = ["iam:*"]
    found = problems(document)
    assert any("needs a unique Sid" in p for p in found)
    assert any("NotAction and NotResource are not allowed" in p for p in found)


def test_size_limit_is_enforced(policy):
    document = allow(policy, *[f"ec2:DescribeSomethingVeryLongNumber{i:05d}" for i in range(400)])
    assert any("non-whitespace bytes" in p for p in problems(document))


def test_account_id_is_reported(policy):
    document = copy.deepcopy(policy)
    document["Statement"][0]["Resource"] = "arn:aws:logs:eu-west-1:" + "9" * 12 + ":*"
    assert "policy contains an account id" in problems(document)


@pytest.mark.parametrize("document", [None, [], {"Version": "2008-10-17", "Statement": []}, {"Version": "2012-10-17"}])
def test_malformed_documents_are_reported(document):
    assert check_policy(document, json.dumps(document)) != []
