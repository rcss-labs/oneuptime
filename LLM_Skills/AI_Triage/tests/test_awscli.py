import subprocess

import pytest

from triage.awscli import REFUSED, AwsResult, run_aws


def runner_returning(code, stdout="", stderr=""):
    def runner(argv, timeout):
        runner.argv, runner.timeout = argv, timeout
        return code, stdout, stderr

    return runner


def test_profile_region_and_json_output_are_always_passed():
    runner = runner_returning(0, '{"clusterArns": []}')
    result = run_aws("ecs", "list-clusters", ["--max-items", "1"], profile="triage-a", region="eu-west-1", runner=runner)
    assert runner.argv == [
        "aws", "ecs", "list-clusters", "--max-items", "1",
        "--profile", "triage-a", "--region", "eu-west-1", "--output", "json", "--no-cli-pager",
    ]
    assert result == AwsResult(True, {"clusterArns": []}, None, None, tuple(runner.argv))


def test_empty_output_is_success_without_data():
    result = run_aws("logs", "stop-query", profile="triage-p", region="r", runner=runner_returning(0, "  \n"))
    assert result.ok and result.data is None


def test_service_error_code_is_extracted():
    stderr = "An error occurred (AccessDeniedException) when calling the ListClusters operation: no"
    result = run_aws("ecs", "list-clusters", profile="triage-p", region="r", runner=runner_returning(254, "", stderr))
    assert not result.ok and result.error_code == "AccessDeniedException" and "ListClusters" in result.error_message


def test_expired_sign_in_is_recognised():
    stderr = "Error loading SSO Token: Token for my-sso does not exist"
    result = run_aws("sts", "get-caller-identity", profile="triage-p", region="r", runner=runner_returning(255, "", stderr))
    assert result.error_code == "SsoSessionExpired"


def test_unrecognised_failure_is_unknown():
    result = run_aws("ecs", "list-clusters", profile="triage-p", region="r", runner=runner_returning(1, "", "boom"))
    assert result.error_code == "Unknown" and result.error_message == "boom"


def test_non_json_output_is_a_failure():
    result = run_aws("ecs", "list-clusters", profile="triage-p", region="r", runner=runner_returning(0, "not json"))
    assert not result.ok and result.error_code == "UnreadableOutput"


def test_missing_cli_is_reported():
    def runner(argv, timeout):
        raise FileNotFoundError("aws")

    assert run_aws("ecs", "list-clusters", profile="triage-p", region="r", runner=runner).error_code == "AwsCliMissing"


def test_timeout_is_reported():
    def runner(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    result = run_aws("ecs", "list-clusters", profile="triage-p", region="r", runner=runner, timeout=5)
    assert result.error_code == "Timeout" and "5 seconds" in result.error_message


def refusing_runner():
    def runner(argv, timeout):
        raise AssertionError("the runner must not be called for a refused command")

    return runner


def test_a_write_operation_is_refused_and_never_run():
    result = run_aws("ecs", "stop-task", ["--task", "t"], profile="triage-a", region="eu-west-1", runner=refusing_runner())
    assert result.ok is False and result.data is None
    assert result.error_code == REFUSED == "RefusedByGuard"
    assert "not a known read" in result.error_message
    assert result.argv[:3] == ("aws", "ecs", "stop-task")


def test_a_secret_read_is_refused_and_never_run():
    result = run_aws("secretsmanager", "get-secret-value", ["--secret-id", "s"], profile="triage-a", region="eu-west-1", runner=refusing_runner())
    assert result.error_code == REFUSED and "returns secrets" in result.error_message


def test_a_value_revealing_flag_is_refused():
    result = run_aws("ssm", "get-parameter", ["--name", "n", "--with-decryption"], profile="triage-a", region="eu-west-1", runner=refusing_runner())
    assert result.error_code == REFUSED


def test_a_non_triage_profile_is_refused_and_never_run():
    for profile in ("admin", "default", "", "Triage-a", "my-triage-a"):
        result = run_aws("ecs", "list-clusters", profile=profile, region="eu-west-1", runner=refusing_runner())
        assert result.error_code == REFUSED and "triage-" in result.error_message, profile


def test_a_read_with_a_triage_profile_still_runs():
    runner = runner_returning(0, "{}")
    result = run_aws("ecs", "describe-services", ["--cluster", "c"], profile="triage-a", region="eu-west-1", runner=runner)
    assert result.ok and runner.argv[:3] == ["aws", "ecs", "describe-services"]


# ---- fix round 2 ------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["--profile", "admin"],
        ["--profile=admin"],
        ["--profil", "admin"],
        ["--prof=admin"],
        ["--region", "us-east-1"],
        ["--regio=us-east-1"],
        ["--reg", "x"],
        ["--endpoint-url", "http://localhost:4566"],
        ["--endpoint-url=http://localhost:4566"],
        ["--endpoint", "http://x"],
        ["--debug"],
        ["--deb"],
        ["--no-verify-ssl"],
        ["--no-verify"],
        ["--ca-bundle", "/tmp/ca.pem"],
        ["--ca-bundle=/tmp/ca.pem"],
        ["--ca"],
        ["--max-items", "1", "--profile", "triage-b"],
        ["--"],
    ],
)
def test_global_options_in_args_are_refused_and_never_run(args):
    result = run_aws("ecs", "list-clusters", args, profile="triage-a", region="eu-west-1", runner=refusing_runner())
    assert result.ok is False and result.error_code == REFUSED
    assert "run_aws" in result.error_message or "option" in result.error_message


def test_ordinary_options_that_start_alike_are_not_refused():
    runner = runner_returning(0, "{}")
    args = ["--start-time", "1", "--end-time", "2", "--metric-data-queries", "x", "--max-items", "5", "--query", "q"]
    assert run_aws("cloudwatch", "get-metric-data", args, profile="triage-a", region="eu-west-1", runner=runner).ok
