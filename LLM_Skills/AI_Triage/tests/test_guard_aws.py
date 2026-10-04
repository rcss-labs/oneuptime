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


# ---- fix round 1 -------------------------------------------------------------

from triage.guard_aws import classify


@pytest.mark.parametrize(
    "command",
    [
        "aws ecs list-clusters --profile triage-prod-main --profil admin --region eu-west-1",
        "aws ecs list-clusters --profile triage-prod-main --profil=admin --region eu-west-1",
        "aws ecs list-clusters --profil admin --region eu-west-1",
        "aws ecs list-clusters --profile triage-prod-main --regio us-east-1",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --regi us-east-1",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --endpoint http://localhost:4566",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --endpoint-ur http://localhost:4566",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --deb",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --debu",
        "aws ssm get-parameter --name n --with-decrypt --profile triage-prod-main --region eu-west-1",
        "aws ssm get-parameter --name n --with-decryptio --profile triage-prod-main --region eu-west-1",
        "aws apigateway get-api-key --api-key k --include-valu --profile triage-prod-main --region eu-west-1",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --no-verify",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --no-verify-ss",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --p",
        "aws ecs list-clusters --profile triage-prod-main --region eu-west-1 --out text",
    ],
)
def test_abbreviated_options_ask_because_the_cli_accepts_them(command):
    result = verdict(command)
    assert result.kind == ASK
    assert "could be an abbreviation the guard cannot check" in result.reason


def test_the_abbreviation_reason_names_the_option():
    result = verdict("aws ecs list-clusters --profil=admin --region eu-west-1")
    assert result.reason == "option --profil could be an abbreviation the guard cannot check"


def test_the_abbreviation_check_comes_before_the_profile_check():
    # Without it, --profil admin would be missed and the triage profile would pass.
    assert verdict(f"aws ecs list-clusters {OK} --profil admin").kind == ASK


def test_full_option_names_are_not_abbreviations():
    assert verdict(f"aws ecs list-clusters {OK} --output json --query 'x'").kind == ALLOW


def test_the_environment_check_still_comes_first():
    result = verdict(f"aws ecs list-clusters {OK} --profil admin", env=("AWS_PROFILE=admin",))
    assert result.kind == ASK and "AWS_*" in result.reason


@pytest.mark.parametrize(
    "command",
    [
        f"aws ssm get-parameter --name n --with-decryption {OK}",
        f"aws apigateway get-api-key --api-key k --include-value {OK}",
        f"aws apigateway get-api-keys --include-values {OK}",
        f"aws apigateway get-api-keys --include-values=true {OK}",
        f"aws ecr-public get-login-password {OK}",
        f"aws ecr-public get-authorization-token {OK}",
        f"aws codeartifact get-authorization-token --domain d {OK}",
        f"aws ecr get-login {OK}",
        f"aws redshift get-cluster-credentials --db-user u {OK}",
        f"aws redshift get-cluster-credentials-with-iam {OK}",
        f"aws redshift-serverless get-credentials --workgroup-name w {OK}",
        f"aws lightsail get-relational-database-master-user-password --relational-database-name d {OK}",
        f"aws lightsail get-instance-access-details --instance-name i {OK}",
        f"aws cognito-identity get-credentials-for-identity --identity-id i {OK}",
        f"aws iam list-service-specific-credentials {OK}",
        f"aws emr get-cluster-session-credentials --cluster-id c {OK}",
        f"aws sts get-service-bearer-token {OK}",
        f"aws sso-oidc create-token {OK}",
        f"aws glue get-connection --name c {OK}",
        f"aws glue get-connections {OK}",
        f"aws athena get-query-results --query-execution-id q {OK}",
        f"aws appconfig get-configuration --application a {OK}",
        f"aws appconfigdata get-latest-configuration --configuration-token t {OK}",
        f"aws s3control get-data-access --account-id 111111111111 {OK}",
        f"aws lambda get-layer-version --layer-name l --version-number 1 {OK}",
        f"aws lambda get-layer-version-by-arn --arn a {OK}",
        f"aws codecommit get-folder --repository-name r --folder-path / {OK}",
        f"aws ec2 get-console-screenshot --instance-id i {OK}",
    ],
)
def test_value_revealing_flags_and_secret_returning_reads_are_denied(command):
    assert verdict(command).kind == DENY


def test_secret_name_patterns_are_denied_for_services_nobody_listed():
    for operation in ("get-secret-value-x", "describe-password-policy-x", "get-new-credentials", "create-access-token", "do-login"):
        assert classify("madeup", operation, []).kind == DENY, operation


def test_ordinary_reads_with_neighbouring_names_stay_allowed():
    assert verdict(f"aws secretsmanager describe-secret --secret-id s {OK}").kind == ALLOW
    assert verdict(f"aws iam get-credential-report {OK}").kind == ALLOW
    assert verdict(f"aws ssm get-parameter --name n --no-with-decryption {OK}").kind == ALLOW
    assert verdict(f"aws ecs list-clusters --max-items 5 --no-paginate {OK}").kind == ALLOW


def test_classify_allows_a_read():
    assert classify("ecs", "describe-services", ["--cluster", "a"]).kind == ALLOW
    assert classify("s3", "ls", []).kind == ALLOW
    assert classify("logs", "start-query", []).kind == ALLOW


def test_classify_denies_a_write_and_an_unknown_operation():
    assert classify("ecs", "stop-task", ["--task", "t"]).kind == DENY
    assert classify("ec2", "terminate-instances", []).kind == DENY
    assert classify("ecs", "frobnicate", []).kind == DENY
    assert classify("s3", "cp", []).kind == DENY


def test_classify_denies_a_secret_read_and_value_revealing_flags():
    assert classify("secretsmanager", "get-secret-value", []).kind == DENY
    assert classify("ssm", "get-parameter", ["--with-decryption"]).kind == DENY
    assert classify("ssm", "get-parameter", ["--name", "x"]).kind == ALLOW
    assert classify("apigateway", "get-api-keys", ["--include-values"]).kind == DENY


# ---- fix round 2 ------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"aws ecs list-clusters {OK} --no-verify-ssl",
        f"aws ecs list-clusters {OK} --ca-bundle /tmp/ca.pem",
        f"aws ecs list-clusters {OK} --ca-bundle=/tmp/ca.pem",
        f"aws ecs list-clusters {OK} --ca-bun /tmp/ca.pem",
        f"aws ecs list-clusters {OK} --ca /tmp/ca.pem",
    ],
)
def test_tls_options_ask(command):
    assert verdict(command).kind == ASK


def test_tls_options_do_not_hide_a_deny():
    assert verdict(f"aws ecs stop-task {OK} --no-verify-ssl").kind == ASK  # asked, never allowed
