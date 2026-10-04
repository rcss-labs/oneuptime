import pytest

from fakes import SSO_EXPIRED_ERROR, access_denied
from helpers import assert_read_only, make_context
from triage.collectors.access import COLLECTOR
from triage.context import SignInExpired

ACCOUNT = "111111111111"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/checkout-task"
KEY_ARN = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/1234abcd"


def role_reply(last_used=None):
    role = {
        "RoleName": "checkout-task", "Arn": ROLE_ARN, "CreateDate": "2026-01-02T03:04:05+00:00",
        "AssumeRolePolicyDocument": {"Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"AWS": [f"arn:aws:iam::{ACCOUNT}:root"]}, "Action": "sts:AssumeRole"},
        ]},
    }
    if last_used:
        role["RoleLastUsed"] = {"LastUsedDate": last_used, "Region": "eu-west-1"}
    return {"Role": role}


def role_answers(**extra):
    answers = {
        "iam get-role": role_reply("2026-10-04T09:00:00+00:00"),
        "iam list-attached-role-policies": {"AttachedPolicies": [{"PolicyName": "ReadOrders", "PolicyArn": "x"}]},
        "iam list-role-policies": {"PolicyNames": ["inline-queue"]},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers, targets):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="access")
    COLLECTOR.run(ctx, dict(targets))
    return ctx, aws, kube


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "access"
    assert COLLECTOR.required == ()
    assert set(COLLECTOR.optional) == {"role", "action", "resource_arn", "kms_key", "secret"}


def test_needs_at_least_one_target(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {}, {})
    assert ctx.evidence.errors[0]["code"] == "MissingTarget"
    assert aws.calls == []


def test_role_facts(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, role_answers(), {"role": "checkout-task"})
    role = by_summary(ctx, "Role checkout-task")[0]
    assert role.kind == "current"
    assert "created 2026-01-02T03:04:05Z" in role.summary
    assert "last used 2026-10-04T09:00:00Z in eu-west-1" in role.summary
    assert "ecs-tasks.amazonaws.com" in role.summary and f"arn:aws:iam::{ACCOUNT}:root" in role.summary
    policies = by_summary(ctx, "policies")[0]
    assert policies.kind == "current"
    assert "ReadOrders" in policies.summary and "inline-queue" in policies.summary
    assert aws.called("iam", "simulate-principal-policy") == []
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)
    for operation in ("list-attached-role-policies", "list-role-policies"):
        assert aws.called("iam", operation)[0][aws.called("iam", operation)[0].index("--max-items") + 1] == "20"


def test_role_never_used(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, role_answers(**{"iam get-role": role_reply()}), {"role": "checkout-task"})
    assert "never been used" in by_summary(ctx, "Role checkout-task")[0].summary


def simulation(decision, matched=None):
    return {"EvaluationResults": [{
        "EvalActionName": "s3:GetObject", "EvalResourceName": "arn:aws:s3:::orders-bucket/*",
        "EvalDecision": decision, "MatchedStatements": matched or [],
    }]}


def test_simulation_allowed(config_data, tmp_path):
    answers = role_answers(**{"iam simulate-principal-policy": simulation("allowed")})
    ctx, aws, kube = run(config_data, tmp_path, answers,
                         {"role": "checkout-task", "action": "s3:GetObject", "resource_arn": "arn:aws:s3:::orders-bucket/*"})
    fact = by_summary(ctx, "s3:GetObject")[0]
    assert fact.kind == "derived" and "allowed" in fact.summary
    call = aws.called("iam", "simulate-principal-policy")[0]
    assert call[call.index("--policy-source-arn") + 1] == ROLE_ARN
    assert call[call.index("--action-names") + 1] == "s3:GetObject"
    assert call[call.index("--resource-arns") + 1] == "arn:aws:s3:::orders-bucket/*"
    assert_read_only(ctx, aws, kube)


def test_simulation_denied_names_the_statement(config_data, tmp_path):
    matched = [{"SourcePolicyId": "deny-prod-data", "SourcePolicyType": "IAM Policy"}]
    answers = role_answers(**{"iam simulate-principal-policy": simulation("explicitDeny", matched)})
    ctx, aws, _ = run(config_data, tmp_path, answers, {"role": "checkout-task", "action": "s3:GetObject"})
    fact = by_summary(ctx, "s3:GetObject")[0]
    assert "explicitDeny" in fact.summary and "deny-prod-data" in fact.summary
    assert "--resource-arns" not in aws.called("iam", "simulate-principal-policy")[0]


def test_implicit_deny_without_statements(config_data, tmp_path):
    answers = role_answers(**{"iam simulate-principal-policy": simulation("implicitDeny")})
    ctx, _, _ = run(config_data, tmp_path, answers, {"role": "checkout-task", "action": "s3:GetObject"})
    assert "no statement allows it" in by_summary(ctx, "s3:GetObject")[0].summary


def test_no_simulation_when_the_role_cannot_be_read(config_data, tmp_path):
    answers = role_answers(**{"iam get-role": access_denied("GetRole")})
    ctx, aws, _ = run(config_data, tmp_path, answers, {"role": "checkout-task", "action": "s3:GetObject"})
    assert aws.called("iam", "simulate-principal-policy") == []
    assert ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert by_summary(ctx, "policies")


def key_reply(**overrides):
    metadata = {"KeyId": "1234abcd", "Arn": KEY_ARN, "KeyState": "Enabled", "Enabled": True, "Origin": "AWS_KMS"}
    metadata.update(overrides)
    return {"KeyMetadata": metadata}


def test_enabled_key_has_no_derived_fact(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, {"kms describe-key": key_reply()}, {"kms_key": "1234abcd"})
    assert [f.kind for f in ctx.evidence.facts] == ["current"]
    assert "Enabled" in ctx.evidence.facts[0].summary and "AWS_KMS" in ctx.evidence.facts[0].summary
    assert "1234abcd" in aws.called("kms", "describe-key")[0]
    assert_read_only(ctx, aws, kube)


def test_disabled_key(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"kms describe-key": key_reply(KeyState="Disabled", Enabled=False)},
                    {"kms_key": "1234abcd"})
    derived = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert len(derived) == 1 and "disabled" in derived[0].summary


def test_key_pending_deletion(config_data, tmp_path):
    reply = key_reply(KeyState="PendingDeletion", Enabled=False, DeletionDate="2026-10-20T00:00:00+00:00")
    ctx, _, _ = run(config_data, tmp_path, {"kms describe-key": reply}, {"kms_key": "1234abcd"})
    derived = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert "pending deletion" in derived[0].summary and "2026-10-20T00:00:00Z" in derived[0].summary


def secret_reply(**overrides):
    body = {"Name": "orders/db", "RotationEnabled": True, "RotationRules": {"AutomaticallyAfterDays": 30},
            "LastRotatedDate": "2026-09-20T00:00:00+00:00", "LastChangedDate": "2026-09-20T00:00:00+00:00",
            "NextRotationDate": "2026-10-20T00:00:00+00:00"}
    body.update(overrides)
    return body


def test_healthy_secret(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, {"secretsmanager describe-secret": secret_reply()}, {"secret": "orders/db"})
    assert [f.kind for f in ctx.evidence.facts] == ["current"]
    summary = ctx.evidence.facts[0].summary
    assert "rotation enabled" in summary and "2026-09-20T00:00:00Z" in summary and "2026-10-20T00:00:00Z" in summary
    assert_read_only(ctx, aws, kube)


def test_overdue_rotation(config_data, tmp_path):
    reply = secret_reply(LastRotatedDate="2026-07-01T00:00:00+00:00", LastChangedDate="2026-07-01T00:00:00+00:00")
    ctx, _, _ = run(config_data, tmp_path, {"secretsmanager describe-secret": reply}, {"secret": "orders/db"})
    derived = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert len(derived) == 1 and "overdue" in derived[0].summary and "30 days" in derived[0].summary


def test_secret_changed_inside_the_window(config_data, tmp_path):
    reply = secret_reply(LastChangedDate="2026-10-04T10:30:00+00:00")
    ctx, _, _ = run(config_data, tmp_path, {"secretsmanager describe-secret": reply}, {"secret": "orders/db"})
    derived = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert len(derived) == 1 and "changed inside the incident window" in derived[0].summary
    assert derived[0].time == "2026-10-04T10:30:00Z"


def test_secret_value_is_never_requested(config_data, tmp_path):
    answers = {**role_answers(), "kms describe-key": key_reply(), "secretsmanager describe-secret": secret_reply()}
    ctx, aws, _ = run(config_data, tmp_path, answers,
                      {"role": "checkout-task", "kms_key": "k", "secret": "orders/db"})
    assert "get-secret-value" not in ctx.evidence.to_json()
    assert aws.called("secretsmanager", "get-secret-value") == []
    assert [c[2] for c in aws.calls if c[1] == "secretsmanager"] == ["describe-secret"]


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = {"kms describe-key": access_denied("DescribeKey"), "secretsmanager describe-secret": secret_reply()}
    ctx, aws, kube = run(config_data, tmp_path, answers, {"kms_key": "k", "secret": "orders/db"})
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert by_summary(ctx, "orders/db")
    assert_read_only(ctx, aws, kube)


def test_expired_sign_in_stops_the_run(config_data, tmp_path):
    with pytest.raises(SignInExpired):
        run(config_data, tmp_path, {"iam get-role": SSO_EXPIRED_ERROR}, {"role": "checkout-task"})
