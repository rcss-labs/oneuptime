import shlex

import pytest

from triage.guard_aws import check_aws
from triage.verdict import ALLOW, ASK, DENY

PROFILES = frozenset({"triage-prod-main", "triage-staging"})
OK = "--profile triage-prod-main --region eu-west-1"


def verdict(command, env=()):
    return check_aws(tuple(shlex.split(command)), tuple(env), PROFILES)


@pytest.mark.parametrize(
    "command",
    [
        f"aws ecs describe-services --cluster a --services b {OK}",
        f"aws --profile triage-staging --region eu-west-1 --output json rds describe-db-instances",
        f"aws logs filter-log-events --log-group-name /x {OK}",
        f"aws logs start-query --log-group-name /x --start-time 1 --end-time 2 --query-string 'fields @message' {OK}",
        f"aws logs get-query-results --query-id abc {OK}",
        f"aws cloudtrail lookup-events --max-results 5 {OK}",
        f"aws rds download-db-log-file-portion --db-instance-identifier d --log-file-name f {OK}",
        f"aws iam simulate-principal-policy --policy-source-arn arn --action-names ecs:StopTask {OK}",
        f"aws sts get-caller-identity {OK}",
        f"aws lambda get-function-configuration --function-name f {OK}",
        f"aws ssm get-parameter --name /app/url {OK}",
        f"aws ecr batch-get-repository-scanning-configuration --repository-names r {OK}",
        f"aws s3 ls {OK}",
        f"aws ecs describe-services --profile=triage-prod-main --region=eu-west-1 --cluster a",
        f"aws ecs help {OK}",
        "aws --version",
        "aws configure list-profiles",
        f"/usr/local/bin/aws ecs list-clusters {OK}",
    ],
)
def test_reads_with_a_triage_profile_are_allowed(command):
    assert verdict(command).kind == ALLOW


@pytest.mark.parametrize(
    "command, reason",
    [
        ("aws ecs describe-services --cluster a --region eu-west-1", "must set --profile"),
        ("aws ecs describe-services --cluster a --profile admin --region eu-west-1", "not a triage profile"),
        ("aws ecs describe-services --cluster a --profile triage-prod-main", "must set --region"),
        (f"aws ecs update-service --cluster a --service b --desired-count 0 {OK}", "not a known read"),
        (f"aws ecs stop-task --task t {OK}", "not a known read"),
        (f"aws ec2 terminate-instances --instance-ids i-1 {OK}", "not a known read"),
        (f"aws s3 rm s3://bucket/key {OK}", "not a read-only listing"),
        (f"aws s3 cp s3://bucket/key - {OK}", "not a read-only listing"),
        (f"aws secretsmanager get-secret-value --secret-id s {OK}", "returns secrets"),
        (f"aws secretsmanager batch-get-secret-value --secret-id-list s {OK}", "returns secrets"),
        (f"aws ecr get-login-password {OK}", "returns secrets"),
        (f"aws lambda get-function --function-name f {OK}", "returns secrets"),
        (f"aws s3api get-object --bucket b --key k out {OK}", "returns secrets"),
        (f"aws dynamodb get-item --table-name t --key x {OK}", "returns secrets"),
        (f"aws sts get-session-token {OK}", "returns secrets"),
        (f"aws ssm get-parameter --name /app/secret --with-decryption {OK}", "--with-decryption"),
        (f"aws ssm start-session --target i-1 {OK}", "not a known read"),
        (f"aws ecs execute-command --cluster a --task t --command sh {OK}", "not a known read"),
        (f"aws ecs describe-services --debug {OK}", "--debug"),
        ("aws configure set region eu-west-1", "changes local AWS CLI settings"),
        ("aws ecs list-clusters --profile triage-prod-main --profile admin --region eu-west-1", "profile 'admin' is not a triage profile"),
        ("aws ecs list-clusters --profile admin --profile=triage-prod-main --region eu-west-1", "profile 'admin' is not a triage profile"),
        ("aws ecs list-clusters --profile $TRIAGE_PROFILE --region eu-west-1", "is not a triage profile"),
        ("aws sso login --profile triage-prod-main", "sign in yourself"),
    ],
)
def test_everything_else_is_denied_with_a_reason(command, reason):
    result = verdict(command)
    assert result.kind == DENY
    assert reason in result.reason


@pytest.mark.parametrize(
    "command, env",
    [
        (f"aws ecs describe-services {OK}", ("AWS_PROFILE=admin",)),
        (f"aws ecs describe-services --endpoint-url http://localhost:4566 {OK}", ()),
        (f"aws ecs {OK}", ()),
        ("aws", ()),
    ],
)
def test_ambiguous_invocations_ask(command, env):
    assert verdict(command, env).kind == ASK
