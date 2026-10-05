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
        f"aws ecs list-clusters {OK} --ca-bundle ca.pem",
        f"aws ecs list-clusters {OK} --ca-bundle=ca.pem",
        f"aws ecs list-clusters {OK} --ca-bun ca.pem",
        f"aws ecs list-clusters {OK} --ca ca.pem",
    ],
)
def test_tls_options_ask(command):
    assert verdict(command).kind == ASK


def test_tls_options_do_not_hide_a_deny():
    assert verdict(f"aws ecs stop-task {OK} --no-verify-ssl").kind == ASK  # asked, never allowed



# ---- fix round 5, ruling 1: aws calls that write a local file ------------------

import json
import sys
from pathlib import Path

from triage.guard_aws import STREAMING_OUTPUT_OPERATIONS

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import list_streaming_operations  # noqa: E402


@pytest.mark.parametrize(
    "command",
    [
        # re-review round 4, C1: each writes its response body to the last positional
        f'aws apigateway get-export --rest-api-id abc --stage-name prod --export-type swagger {OK} service-map.yaml',
        f"aws apigateway get-export --rest-api-id abc --stage-name prod --export-type swagger {OK} settings.json",
        f"aws apigateway get-sdk --rest-api-id abc --stage-name prod --sdk-type java {OK} sdk.zip",
        f"aws s3api get-object-torrent --bucket b --key k {OK} t.torrent",
        f"aws appsync get-introspection-schema --api-id a --format SDL {OK} schema.graphql",
        f"aws glacier get-job-output --account-id - --vault-name v --job-id j {OK} out.bin",
        f"aws lakeformation get-work-unit-results --query-id q --work-unit-id 1 --work-unit-token t {OK} r",
        f"aws kinesis-video-media get-media --start-selector StartSelectorType=NOW {OK} m.mkv",
        f"aws codeartifact get-package-version-asset --domain d --repository r --format npm --package p "
        f"--package-version 1 --asset a {OK} a.tgz",
    ],
)
def test_operations_that_write_an_output_file_are_denied(command):
    result = verdict(command)
    assert result.kind == DENY
    assert "output file" in result.reason


def test_the_review_reproductions_onto_protected_files_are_denied(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    for target in ("/home/eng/.claude/skills/ai-triage/config/service-map.yaml", "/home/eng/.claude/settings.json"):
        command = f"aws apigateway get-export --rest-api-id abc --stage-name prod --export-type swagger {OK} {target}"
        assert verdict(command).kind == DENY


def test_streaming_output_set_holds_the_known_writers():
    for entry in ("apigateway get-export", "apigateway get-sdk", "s3api get-object", "s3api get-object-torrent",
                  "appsync get-introspection-schema", "glacier get-job-output", "lambda invoke",
                  "kinesis-video-media get-media", "lakeformation get-work-unit-results"):
        assert entry in STREAMING_OUTPUT_OPERATIONS


def test_the_committed_list_covers_every_streaming_operation_of_the_installed_cli():
    data_dir = list_streaming_operations.find_data_dir()
    if data_dir is None:
        pytest.skip("no AWS CLI service models were found on this machine, so the list cannot be regenerated")
    missing = set(list_streaming_operations.streaming_operations(data_dir)) - STREAMING_OUTPUT_OPERATIONS
    assert not missing, f"add these to STREAMING_OUTPUT_OPERATIONS (run tools/list_streaming_operations.py): {sorted(missing)}"


def test_the_listing_tool_reads_a_model_folder(tmp_path):
    model_dir = tmp_path / "s3" / "2006-03-01"
    model_dir.mkdir(parents=True)
    (tmp_path / "endpoints.json").write_text("{}")
    model = {
        "operations": {"GetObjectTorrent": {"output": {"shape": "Out"}}, "ListBuckets": {"output": {"shape": "List"}},
                       "PutThing": {}},
        "shapes": {"Out": {"type": "structure", "payload": "Body", "members": {"Body": {"shape": "Blob"}}},
                   "Blob": {"type": "blob"}, "List": {"type": "structure", "members": {}}},
    }
    (model_dir / "service-2.json").write_text(json.dumps(model))
    assert list_streaming_operations.streaming_operations(tmp_path) == ["s3api get-object-torrent"]
    assert list_streaming_operations.cli_operation_name("GetSnapshotBlock") == "get-snapshot-block"
    assert list_streaming_operations.cli_operation_name("ListAWSAccounts") == "list-aws-accounts"


@pytest.mark.parametrize(
    "path",
    ["/home/eng/x", "/Users/someone/x", "/tmp/x", "/tmp", "/private/tmp/x", "/var/folders/x", "/etc/hosts",
     "/opt/x", "/Volumes/usb/x", "./x", "../x", "~/x", "~", "file:///tmp/in.json", "fileb://blob.bin",
     "FILE://x.json", "/users/someone/x"],
)
def test_no_aws_argument_may_be_a_local_path(path, monkeypatch):
    # follow-up N3: under an option, a path that could be an AWS name asks; home, ~, relative and file:// still deny
    monkeypatch.setenv("HOME", "/home/eng")
    always_deny = path.casefold().startswith(("/home/eng", "~", "./", "../", "file://", "fileb://"))
    for command in (f"aws ecs describe-services --cluster {path} {OK}", f"aws ecs describe-services --cluster={path} {OK}"):
        result = check_aws(tuple(shlex.split(command)), (), PROFILES)
        assert result.kind == (DENY if always_deny else ASK), command
        assert "local path" in result.reason
    positional = f"aws logs filter-log-events --log-group-name g {OK} {path}"
    assert check_aws(tuple(shlex.split(positional)), (), PROFILES).kind == DENY


def test_the_home_directory_counts_as_a_local_path_wherever_it_is(monkeypatch):
    monkeypatch.setenv("HOME", "/srv/people/eng")
    assert verdict(f"aws ecs describe-services --cluster /srv/people/eng/x {OK}").kind == DENY
    assert verdict(f"aws ecs describe-services --cluster /srv/people/engineer {OK}").kind == ALLOW


@pytest.mark.parametrize(
    "value",
    ["/aws/ecs/checkout", "/ecs/orders", "/aws/lambda/f", "/app/url", "arn:aws:ecs:eu-west-1:111111111111:cluster/c",
     "Name=tag:env,Values=prod", "services[0].events[:5]", "/tmpl-like-but-not", "tmp/x"],
)
def test_aws_values_that_look_like_paths_stay_allowed(value, monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    command = ("aws", "logs", "filter-log-events", "--log-group-name", value, "--profile", "triage-prod-main",
               "--region", "eu-west-1")
    # a --log-group-name value may look like a path (adjusted ruling 1b), so even /tmpl... is allowed here
    assert check_aws(command, (), PROFILES).kind == ALLOW
    assert check_aws(("aws", "ecs", "describe-services", "--cluster", value) + command[5:], (), PROFILES).kind == (
        ASK if value.startswith("/tmp") else ALLOW)


def test_a_tls_bundle_given_as_a_local_path_is_not_allowed():
    assert verdict(f"aws ecs list-clusters {OK} --ca-bundle /tmp/ca.pem").kind == ASK


# ---- fix round 5, ruling 1b adjustment: log groups named after file paths -------


@pytest.mark.parametrize(
    "command",
    [
        f"aws logs filter-log-events --log-group-name /var/log/messages {OK}",
        f"aws logs describe-log-streams --log-group-name /opt/app/logs/out.log {OK}",
        f"aws logs filter-log-events --log-group-name=/var/log/app/error.log --log-stream-names /var/log/a /tmp/b {OK}",
        f"aws logs describe-log-groups --log-group-name-prefix /var/log/ {OK}",
        f"aws logs describe-log-groups --log-group-name-pattern /etc/x {OK}",
        f"aws logs get-log-events --log-group-identifier /opt/a --log-stream-name /private/x {OK}",
        f"aws logs start-query --log-group-names /var/log/a /opt/b --query-string q --start-time 1 --end-time 2 {OK}",
        f"aws logs start-query --log-group-identifiers /var/log/a /Volumes/b --query-string q --start-time 1 --end-time 2 {OK}",
        f"aws logs describe-log-streams --log-group-name g --log-stream-name-prefix /var/log/ {OK}",
    ],
)
def test_log_group_and_stream_options_may_hold_file_like_names(command, monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    assert verdict(command).kind == ALLOW


@pytest.mark.parametrize(
    "command",
    [
        f"aws logs filter-log-events --log-group-name g {OK} /var/log/messages",
        f"aws logs filter-log-events /var/log/messages --log-group-name g {OK}",
        f"aws logs filter-log-events --log-group-name /home/eng/x {OK}",
        f"aws logs filter-log-events --log-group-name=/home/eng/x {OK}",
        f"aws logs filter-log-events --log-group-name ~/x {OK}",
        f"aws logs filter-log-events --log-group-name ./x {OK}",
        f"aws logs filter-log-events --log-group-name ../x {OK}",
        f"aws logs filter-log-events --log-group-name file:///var/log/x {OK}",
        f"aws logs filter-log-events --log-group-name fileb://x {OK}",
        f"aws logs start-query --log-group-names /var/log/a /home/eng/b --query-string q {OK}",
        f"aws logs filter-log-events --log-group-name /var/log/a /var/log/b {OK}",
    ],
)
def test_the_log_exemption_never_covers_home_relative_files_or_positionals(command, monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    result = verdict(command)
    assert result.kind == DENY and "local path" in result.reason


def test_a_log_group_under_home_given_with_dollar_home_is_denied(monkeypatch):
    from triage.guard import GuardContext, decide

    monkeypatch.setenv("HOME", "/home/eng")
    context = GuardContext(frozenset({"triage-prod-main"}), "/k", frozenset(), frozenset(), "/s")
    assert decide(f'aws logs filter-log-events --log-group-name "$HOME/x" {OK}', context).kind == DENY


# ---- round 5 minor follow-up, N1: --cli-auto-prompt ------------------------------


@pytest.mark.parametrize("flag", ["--cli-auto-prompt", "--cli-auto-p", "--cli-a", "--cli-auto-prompt=on"])
def test_cli_auto_prompt_is_denied(flag):
    result = verdict(f"aws ecs list-clusters {OK} {flag}")
    assert result.kind == DENY and "auto-prompt" in result.reason
    assert verdict(f"aws {flag} ecs list-clusters {OK}").kind == DENY


def test_turning_auto_prompt_off_is_still_allowed():
    assert verdict(f"aws ecs list-clusters {OK} --no-cli-auto-prompt").kind == ALLOW



# ---- round 5 minor follow-up, N3: AWS names that look like paths ask ------------


@pytest.mark.parametrize(
    "command",
    [
        f"aws ssm get-parameter --name /opt/app/feature-flag {OK}",
        f"aws ssm get-parameters-by-path --path /var/app {OK}",
        f"aws iam list-roles --path-prefix /etc/ {OK}",
        f"aws iam list-users --path-prefix /home/ {OK}",
        f"aws s3api list-objects-v2 --bucket b --prefix /tmp/x {OK}",
        f"aws ssm get-parameter --name /var/log/messages {OK}",
        f"aws ssm get-parameter --name=/opt/app/logs/out.log {OK}",
    ],
)
def test_a_path_like_value_under_another_option_asks(command, monkeypatch):
    monkeypatch.setenv("HOME", "/Users/eng")
    result = verdict(command)
    assert result.kind == ASK
    assert "looks like a local path" in result.reason and "SSM parameter" in result.reason


@pytest.mark.parametrize(
    "command",
    [
        f"aws ssm get-parameter {OK} /opt/app/feature-flag",
        f"aws ssm get-parameter --name /Users/eng/x {OK}",
        f"aws ssm get-parameter --name=/Users/eng {OK}",
        f"aws ssm get-parameter --name ~/x {OK}",
        f"aws ssm get-parameter --name ./x {OK}",
        f"aws ssm get-parameter --name ../x {OK}",
        f"aws ssm get-parameter --name file:///opt/x {OK}",
        f"aws ssm get-parameter --document fileb://x {OK}",  # --cli-input-json is denied by its own rule
        f"aws ssm get-parameter --name /opt/a /opt/b {OK}",
    ],
)
def test_positionals_home_relative_and_file_forms_still_deny(command, monkeypatch):
    monkeypatch.setenv("HOME", "/Users/eng")
    result = verdict(command)
    assert result.kind == DENY and "local path" in result.reason


def test_names_that_do_not_look_like_paths_stay_allowed(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/eng")
    for value in ("/app/db-host", "/service-role/", "tmp/2026"):
        assert verdict(f"aws ssm get-parameter --name {value} {OK}").kind == ALLOW


# ---- final review fixes, item 3: reads that could return secrets or run something else ----

from triage.guard_aws import AWS_SERVICE_NAMES  # noqa: E402

import list_aws_services  # noqa: E402


@pytest.mark.parametrize(
    "flag",
    ["--cli-input-json '{\"Name\":\"/prod/db/password\",\"WithDecryption\":true}'", "--cli-input-yaml 'Name: x'",
     "--cli-input-json={}", "--cli-input-j {}", "--cli-input-y x", "--cli-i {}"],
)
def test_cli_input_json_and_yaml_are_denied(flag):
    result = verdict(f"aws ssm get-parameter {OK} {flag}")
    assert result.kind == DENY and "cli-input" in result.reason


@pytest.mark.parametrize("attribute", ["--attribute userData", "--attribute=userData", "--attribute USERDATA"])
def test_ec2_user_data_is_denied(attribute):
    result = verdict(f"aws ec2 describe-instance-attribute --instance-id i-1 {attribute} {OK}")
    assert result.kind == DENY
    assert verdict(f"aws ec2 describe-instance-attribute --instance-id i-1 --attribute instanceType {OK}").kind == ALLOW


@pytest.mark.parametrize("operation", ["get-records --shard-iterator x", "get-shard-iterator --stream-arn a --shard-id s "
                                       "--shard-iterator-type LATEST"])
def test_dynamodb_stream_records_are_denied(operation):
    assert verdict(f"aws dynamodbstreams {operation} {OK}").kind == DENY
    assert verdict(f"aws dynamodbstreams describe-stream --stream-arn a {OK}").kind == ALLOW


@pytest.mark.parametrize("service", ["myalias", "ecs-read", "whoami", "S3API"])
def test_a_word_that_is_not_a_cli_service_is_denied(service):
    result = verdict(f"aws {service} describe-anything {OK}")
    assert result.kind == DENY and "not a service" in result.reason


def test_real_services_and_cli_commands_are_known():
    for name in ("ecs", "s3api", "s3", "logs", "configservice", "deploy", "configure", "sso", "dynamodbstreams"):
        assert name in AWS_SERVICE_NAMES


def test_the_committed_service_list_covers_the_installed_cli():
    data_dir = list_streaming_operations.find_data_dir()
    if data_dir is None:
        pytest.skip("no AWS CLI service models were found on this machine, so the list cannot be regenerated")
    missing = set(list_aws_services.service_names(data_dir)) - AWS_SERVICE_NAMES
    assert not missing, f"add these to AWS_SERVICE_NAMES (run tools/list_aws_services.py): {sorted(missing)}"


def test_the_service_tool_renames_like_the_cli(tmp_path):
    for folder in ("s3", "config", "codedeploy", "ecs"):
        (tmp_path / folder / "2020-01-01").mkdir(parents=True)
        (tmp_path / folder / "2020-01-01" / "service-2.json").write_text("{}")
    names = list_aws_services.service_names(tmp_path)
    assert {"s3api", "configservice", "deploy", "ecs", "s3", "configure"} <= set(names)
    assert "config" not in names and "codedeploy" not in names
