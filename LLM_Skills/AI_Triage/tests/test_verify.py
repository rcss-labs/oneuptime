import pytest

from fakes import SSO_EXPIRED_ERROR, FakeAws, access_denied
from triage.config import parse_config
from triage.verify import (
    EXPIRED,
    FAILED,
    PASSED,
    SIMULATED_READS,
    SIMULATED_DENIED,
    SKIPPED,
    exit_code,
    render_table,
    verify_account,
    verify_all,
)

ROLE = "AWSReservedSSO_ai-triage-read-only_0123456789abcdef"
ROLE_ARN = f"arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/eu-west-1/{ROLE}"


def identity(account_id="111111111111", role=ROLE):
    return {"Account": account_id, "Arn": f"arn:aws:sts::{account_id}:assumed-role/{role}/engineer@example.com"}


def simulation(overrides=None):
    decisions = {action: "allowed" for action in SIMULATED_READS}
    decisions.update({action: "implicitDeny" for action in SIMULATED_DENIED})
    decisions["kms:Decrypt"] = "explicitDeny"
    decisions.update(overrides or {})
    return {"EvaluationResults": [{"EvalActionName": a, "EvalDecision": d} for a, d in decisions.items()]}


def healthy(**extra):
    answers = {
        "sts get-caller-identity": identity(),
        "iam list-roles": {"Roles": [{"RoleName": ROLE, "Arn": ROLE_ARN}]},
        "iam simulate-principal-policy": simulation(),
    }
    answers.update(extra)
    return FakeAws(answers)


@pytest.fixture
def account(config_data):
    return parse_config(config_data).accounts["prod-main"]


def by_name(results):
    return {result.name: result for result in results}


def test_healthy_account_passes_every_check(account):
    fake = healthy()
    results = verify_account(account, "ai-triage-read-only", fake)
    assert {r.status for r in results} == {PASSED}
    assert exit_code(results) == 0
    assert by_name(results)["Identity"].detail == ROLE
    assert all("--profile" in argv and "--region" in argv for argv in fake.calls)


def test_simulator_is_asked_about_the_role_behind_the_profile(account):
    fake = healthy()
    verify_account(account, "ai-triage-read-only", fake)
    calls = fake.called("iam", "simulate-principal-policy")
    assert all(argv[argv.index("--policy-source-arn") + 1] == ROLE_ARN for argv in calls)
    asked = {word for argv in calls for word in argv}
    assert "ecs:UpdateService" in asked and "logs:GetLogEvents" in asked


def test_no_write_operation_is_ever_called(account):
    fake = healthy()
    verify_account(account, "ai-triage-read-only", fake)
    read_starts = ("describe-", "list-", "get-", "lookup-", "simulate-")
    assert all(argv[2].startswith(read_starts) for argv in fake.calls)


def test_wrong_account_stops_after_identity(account):
    fake = healthy(**{"sts get-caller-identity": identity(account_id="222222222222")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert len(results) == 1 and results[0].status == FAILED
    assert "different account" in results[0].detail


def test_wrong_permission_set_stops_after_identity(account):
    fake = healthy(**{"sts get-caller-identity": identity(role="AWSReservedSSO_AdministratorAccess_abc")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert len(results) == 1 and "does not use the ai-triage-read-only permission set" in results[0].detail


def test_expired_sign_in_is_reported_with_its_own_exit_code(account):
    fake = healthy(**{"sts get-caller-identity": SSO_EXPIRED_ERROR})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert results[0].status == EXPIRED and exit_code(results) == 3


def test_denied_read_fails(account):
    fake = healthy(**{"cloudwatch describe-alarms": access_denied("DescribeAlarms")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Read: Alarms"].status == FAILED
    assert by_name(results)["Read: Alarms"].detail == "AccessDeniedException"
    assert exit_code(results) == 1


def test_health_without_a_support_plan_is_skipped_not_failed(account):
    error = (254, "An error occurred (SubscriptionRequiredException) when calling the DescribeEvents operation")
    results = verify_account(account, "ai-triage-read-only", healthy(**{"health describe-events": error}))
    assert by_name(results)["Read: AWS Health"].status == SKIPPED
    assert exit_code(results) == 0


def test_health_is_queried_in_its_home_region(account):
    fake = healthy()
    verify_account(account, "ai-triage-read-only", fake)
    [argv] = fake.called("health", "describe-events")
    assert argv[argv.index("--region") + 1] == "us-east-1"


def test_an_allowed_write_fails(account):
    fake = healthy(**{"iam simulate-principal-policy": simulation({"ecs:UpdateService": "allowed"})})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Denied: ecs:UpdateService"].status == FAILED
    assert exit_code(results) == 1


def test_a_denied_read_in_the_simulator_fails(account):
    fake = healthy(**{"iam simulate-principal-policy": simulation({"logs:GetLogEvents": "implicitDeny"})})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Allowed: logs:GetLogEvents"].status == FAILED


def test_missing_simulator_answer_fails(account):
    fake = healthy(**{"iam simulate-principal-policy": {"EvaluationResults": []}})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Denied: kms:Decrypt"].detail == "no answer"
    assert by_name(results)["Denied: kms:Decrypt"].status == FAILED


def test_role_not_found_fails_the_simulator_check(account):
    fake = healthy(**{"iam list-roles": {"Roles": []}})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Simulator"].status == FAILED


def test_simulator_denied_fails_the_simulator_check(account):
    fake = healthy(**{"iam simulate-principal-policy": access_denied("SimulatePrincipalPolicy")})
    results = verify_account(account, "ai-triage-read-only", fake)
    assert by_name(results)["Simulator"].detail == "AccessDeniedException"


def test_verify_all_covers_every_account_or_only_the_named_ones(config_data):
    config = parse_config(config_data)
    fake = FakeAws(
        {
            "triage-prod-main sts get-caller-identity": identity(),
            "triage-staging sts get-caller-identity": identity(account_id="222222222222"),
            "iam list-roles": {"Roles": [{"RoleName": ROLE, "Arn": ROLE_ARN}]},
            "iam simulate-principal-policy": simulation(),
        }
    )
    assert {r.account for r in verify_all(config, runner=fake)} == {"prod-main", "staging"}
    assert {r.account for r in verify_all(config, ["staging"], runner=fake)} == {"staging"}


def test_table_lists_every_result(account):
    table = render_table(verify_account(account, "ai-triage-read-only", healthy()))
    lines = table.splitlines()
    assert lines[0].split() == ["ACCOUNT", "CHECK", "RESULT", "DETAIL"]
    assert any("Denied: ecs:UpdateService" in line and "pass" in line for line in lines)


# fix wave: reads that rest on ViewOnlyAccess

VIEW_ONLY_READS = (
    "sqs:GetQueueUrl", "sqs:GetQueueAttributes", "sqs:ListDeadLetterSourceQueues",
    "eks:DescribeCluster", "eks:DescribeNodegroup", "eks:DescribeAddon", "eks:DescribeUpdate",
    "eks:ListNodegroups", "eks:ListAddons", "eks:ListUpdates", "acm:ListCertificates",
    "cloudwatch:GetMetricData", "cloudtrail:LookupEvents", "autoscaling:DescribeAutoScalingGroups",
    "ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeNatGateways", "ec2:DescribeNetworkAcls",
    "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets", "ec2:DescribeVpcEndpoints",
    "ecs:DescribeServices", "ecs:DescribeTasks", "ecs:ListTasks", "ecr:DescribeRepositories",
    "elasticache:DescribeCacheClusters", "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth", "elasticfilesystem:DescribeFileSystems", "es:ListDomainNames",
    "iam:ListRoles", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "lambda:ListEventSourceMappings",
    "logs:DescribeLogGroups", "rds:DescribeDBInstances", "route53:ListHostedZones",
    "route53:ListResourceRecordSets", "dynamodb:DescribeTable", "dynamodb:ListTables",
    "logs:DescribeLogStreams", "ecr:GetLifecyclePolicy", "es:ListDomainMaintenances", "wafv2:ListWebACLs",
    "sns:ListSubscriptionsByTopic", "lambda:ListAliases", "lambda:ListVersionsByFunction",
    "autoscaling:DescribePolicies", "autoscaling:DescribeScheduledActions",
)


def test_every_read_that_rests_on_view_only_access_is_simulated():
    assert set(VIEW_ONLY_READS) <= set(SIMULATED_READS)
    assert len(set(SIMULATED_READS)) == len(SIMULATED_READS)


def test_the_simulator_is_asked_in_batches_that_cover_every_action(account):
    fake = healthy()
    verify_account(account, "ai-triage-read-only", fake)
    calls = fake.called("iam", "simulate-principal-policy")
    assert len(calls) > 1
    asked = []
    for argv in calls:
        names = argv[argv.index("--action-names") + 1:]
        names = names[: next((i for i, n in enumerate(names) if n.startswith("--")), len(names))]
        assert len(names) <= 50
        asked.extend(names)
    assert set(asked) == set(SIMULATED_READS) | set(SIMULATED_DENIED)


def test_missing_grants_are_listed_by_collector(account):
    fake = healthy(**{"iam simulate-principal-policy": simulation({
        "eks:DescribeCluster": "implicitDeny", "eks:ListAddons": "implicitDeny", "sqs:GetQueueUrl": "implicitDeny",
    })})
    results = by_name(verify_account(account, "ai-triage-read-only", fake))
    assert results["Missing grants: eks"].status == FAILED
    assert results["Missing grants: eks"].detail == "eks:DescribeCluster, eks:ListAddons"
    assert results["Missing grants: messaging"].detail == "sqs:GetQueueUrl"
    assert not any(name.startswith("Missing grants") and "ecs" in name for name in results)


def test_no_missing_grants_line_when_everything_is_granted(account):
    results = verify_account(account, "ai-triage-read-only", healthy())
    assert not any(result.name.startswith("Missing grants") for result in results)
