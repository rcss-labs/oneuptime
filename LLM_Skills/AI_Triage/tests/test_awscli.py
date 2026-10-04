import subprocess

from triage.awscli import AwsResult, run_aws


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
    result = run_aws("logs", "stop-query", profile="p", region="r", runner=runner_returning(0, "  \n"))
    assert result.ok and result.data is None


def test_service_error_code_is_extracted():
    stderr = "An error occurred (AccessDeniedException) when calling the ListClusters operation: no"
    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner_returning(254, "", stderr))
    assert not result.ok and result.error_code == "AccessDeniedException" and "ListClusters" in result.error_message


def test_expired_sign_in_is_recognised():
    stderr = "Error loading SSO Token: Token for my-sso does not exist"
    result = run_aws("sts", "get-caller-identity", profile="p", region="r", runner=runner_returning(255, "", stderr))
    assert result.error_code == "SsoSessionExpired"


def test_unrecognised_failure_is_unknown():
    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner_returning(1, "", "boom"))
    assert result.error_code == "Unknown" and result.error_message == "boom"


def test_non_json_output_is_a_failure():
    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner_returning(0, "not json"))
    assert not result.ok and result.error_code == "UnreadableOutput"


def test_missing_cli_is_reported():
    def runner(argv, timeout):
        raise FileNotFoundError("aws")

    assert run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner).error_code == "AwsCliMissing"


def test_timeout_is_reported():
    def runner(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    result = run_aws("ecs", "list-clusters", profile="p", region="r", runner=runner, timeout=5)
    assert result.error_code == "Timeout" and "5 seconds" in result.error_message
