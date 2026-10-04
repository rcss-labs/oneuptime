import json

import pytest

from triage.fixtures import (
    FIXTURE_ENV,
    FixtureError,
    FixtureRunner,
    fixture_dir,
    fixture_transport,
    kube_runner_from_env,
    runner_from_env,
    transport_from_env,
)

LOG_ENV = "AI_TRIAGE_FIXTURE_LOG"
KUBE_PREFIX = ["kubectl", "--kubeconfig", "/tmp/kubeconfig", "--context", "triage-demo"]


def write(directory, name, entries):
    (directory / name).write_text(json.dumps(entries))


def aws(runner, service, operation, *extra):
    return runner(["aws", service, operation, *extra, "--profile", "triage-demo", "--region", "eu-west-1"], 60)


# fixture_dir

def test_fixture_dir_unset_and_empty_mean_no_replay():
    assert fixture_dir({}) is None
    assert fixture_dir({FIXTURE_ENV: ""}) is None


def test_fixture_dir_valid_directory(tmp_path):
    assert fixture_dir({FIXTURE_ENV: str(tmp_path)}) == tmp_path


def test_fixture_dir_missing_directory_is_an_error(tmp_path):
    with pytest.raises(FixtureError, match="not a directory"):
        fixture_dir({FIXTURE_ENV: str(tmp_path / "nowhere")})


def test_fixture_dir_file_is_an_error(tmp_path):
    (tmp_path / "f").write_text("x")
    with pytest.raises(FixtureError):
        fixture_dir({FIXTURE_ENV: str(tmp_path / "f")})


def test_from_env_functions_return_none_when_unset():
    assert runner_from_env({}) is None
    assert kube_runner_from_env({}) is None
    assert transport_from_env({}) is None


def test_from_env_functions_build_replay_objects(tmp_path):
    env = {FIXTURE_ENV: str(tmp_path)}
    assert isinstance(runner_from_env(env), FixtureRunner)
    assert isinstance(kube_runner_from_env(env), FixtureRunner)
    assert callable(transport_from_env(env))


def test_from_env_functions_fail_on_a_bad_directory(tmp_path):
    env = {FIXTURE_ENV: str(tmp_path / "nowhere")}
    for build in (runner_from_env, kube_runner_from_env, transport_from_env):
        with pytest.raises(FixtureError):
            build(env)


# aws

def test_aws_matches_service_and_operation(tmp_path):
    write(tmp_path, "aws.json", [
        {"match": ["ecs", "describe-services"], "result": {"services": [{"serviceName": "checkout-api"}]}},
        {"match": ["ecs", "list-clusters"], "result": {"clusterArns": []}},
    ])
    code, out, err = aws(FixtureRunner(tmp_path), "ecs", "list-clusters")
    assert (code, json.loads(out), err) == (0, {"clusterArns": []}, "")


def test_aws_contains_narrows_between_entries_for_one_operation(tmp_path):
    write(tmp_path, "aws.json", [
        {"match": ["ecs", "describe-services"], "contains": ["checkout-api"], "result": {"which": "checkout"}},
        {"match": ["ecs", "describe-services"], "contains": ["billing-api"], "result": {"which": "billing"}},
    ])
    runner = FixtureRunner(tmp_path)
    assert json.loads(aws(runner, "ecs", "describe-services", "--services", "billing-api")[1]) == {"which": "billing"}
    assert json.loads(aws(runner, "ecs", "describe-services", "--services", "checkout-api")[1]) == {"which": "checkout"}


def test_aws_every_contains_string_must_match(tmp_path):
    write(tmp_path, "aws.json", [
        {"match": ["ecs", "describe-services"], "contains": ["checkout-api", "prod-cluster"], "result": {"which": "both"}},
    ])
    runner = FixtureRunner(tmp_path)
    assert aws(runner, "ecs", "describe-services", "--services", "checkout-api")[1] == "{}"
    both = aws(runner, "ecs", "describe-services", "--cluster", "prod-cluster", "--services", "checkout-api")
    assert json.loads(both[1]) == {"which": "both"}


def test_aws_contains_matches_substring_of_one_element(tmp_path):
    write(tmp_path, "aws.json", [
        {"match": ["logs", "filter-log-events"], "contains": ["checkout"], "result": {"events": []}},
    ])
    out = aws(FixtureRunner(tmp_path), "logs", "filter-log-events", "--log-group-name", "/ecs/checkout-api")[1]
    assert json.loads(out) == {"events": []}


def test_aws_first_match_wins(tmp_path):
    write(tmp_path, "aws.json", [
        {"match": ["sts", "get-caller-identity"], "result": {"n": 1}},
        {"match": ["sts", "get-caller-identity"], "result": {"n": 2}},
    ])
    assert json.loads(aws(FixtureRunner(tmp_path), "sts", "get-caller-identity")[1]) == {"n": 1}


def test_aws_error_entry(tmp_path):
    stderr = "An error occurred (AccessDeniedException) when calling the DescribeServices operation: denied"
    write(tmp_path, "aws.json", [{"match": ["ecs", "describe-services"], "error": {"code": 254, "stderr": stderr}}])
    assert aws(FixtureRunner(tmp_path), "ecs", "describe-services") == (254, "", stderr)


def test_aws_no_match_gives_an_empty_object(tmp_path):
    write(tmp_path, "aws.json", [{"match": ["ecs", "list-clusters"], "result": {}}])
    assert aws(FixtureRunner(tmp_path), "rds", "describe-db-instances") == (0, "{}", "")


def test_aws_missing_file_behaves_as_an_empty_list(tmp_path):
    assert aws(FixtureRunner(tmp_path), "ecs", "list-clusters") == (0, "{}", "")


def test_files_are_read_once(tmp_path):
    write(tmp_path, "aws.json", [{"match": ["ecs", "list-clusters"], "result": {"n": 1}}])
    runner = FixtureRunner(tmp_path)
    aws(runner, "ecs", "list-clusters")
    write(tmp_path, "aws.json", [{"match": ["ecs", "list-clusters"], "result": {"n": 2}}])
    assert json.loads(aws(runner, "ecs", "list-clusters")[1]) == {"n": 1}


@pytest.mark.parametrize("content", ["not json", '{"a": 1}', "[1, 2]", '[{"result": {}}]'])
def test_a_malformed_file_is_an_error_at_construction(tmp_path, content):
    (tmp_path / "aws.json").write_text(content)
    with pytest.raises(FixtureError, match="aws.json"):
        FixtureRunner(tmp_path)


def test_a_malformed_opensearch_file_is_an_error_at_construction(tmp_path):
    (tmp_path / "opensearch.json").write_text("not json")
    with pytest.raises(FixtureError, match="opensearch.json"):
        fixture_transport(tmp_path)


def test_an_unknown_program_is_refused(tmp_path):
    with pytest.raises(FixtureError, match="curl"):
        FixtureRunner(tmp_path)(["curl", "https://example.com"], 5)


# kubectl

@pytest.mark.parametrize("scope", [
    [],
    ["-n", "payments"],
    ["--namespace", "payments"],
    ["-A"],
])
def test_kubectl_verb_detection_skips_every_option_form(tmp_path, scope):
    write(tmp_path, "kubectl.json", [{"match": ["get", "pods"], "stdout": "pod-list"}])
    argv = [*KUBE_PREFIX, *scope, "get", "pods", "-o", "json"]
    assert FixtureRunner(tmp_path)(argv, 60) == (0, "pod-list", "")


def test_kubectl_contains_and_stdout(tmp_path):
    write(tmp_path, "kubectl.json", [
        {"match": ["get", "pods"], "contains": ["payments"], "stdout": "payments-pods"},
        {"match": ["get", "pods"], "contains": ["orders"], "stdout": "orders-pods"},
    ])
    runner = FixtureRunner(tmp_path)
    assert runner([*KUBE_PREFIX, "-n", "orders", "get", "pods"], 60)[1] == "orders-pods"
    assert runner([*KUBE_PREFIX, "-n", "payments", "get", "pods"], 60)[1] == "payments-pods"


def test_kubectl_error_entry(tmp_path):
    write(tmp_path, "kubectl.json", [{"match": ["describe", "pod"], "error": {"code": 1, "stderr": "Error from server (Forbidden)"}}])
    assert FixtureRunner(tmp_path)([*KUBE_PREFIX, "describe", "pod", "web-1"], 60) == (1, "", "Error from server (Forbidden)")


def test_kubectl_no_match(tmp_path):
    write(tmp_path, "kubectl.json", [{"match": ["get", "pods"], "stdout": "x"}])
    assert FixtureRunner(tmp_path)([*KUBE_PREFIX, "get", "nodes"], 60) == (0, "", "")


def test_kubectl_missing_file(tmp_path):
    assert FixtureRunner(tmp_path)([*KUBE_PREFIX, "get", "pods"], 60) == (0, "", "")


# opensearch

def send(transport, method, url, body=None):
    return transport(method, url, body, 15, True, None)


def test_transport_match_by_method_and_path(tmp_path):
    write(tmp_path, "opensearch.json", [
        {"method": "GET", "path_contains": "_cluster/health", "status": 200, "body": {"status": "yellow"}},
        {"method": "POST", "path_contains": "_cluster/health", "status": 500, "body": {"status": "wrong"}},
    ])
    status, text = send(fixture_transport(tmp_path), "GET", "https://logs.example.com/_cluster/health")
    assert (status, json.loads(text)) == (200, {"status": "yellow"})


def test_transport_string_body_is_returned_as_is(tmp_path):
    write(tmp_path, "opensearch.json", [{"method": "GET", "path_contains": "_cat/shards", "status": 200, "body": "a b c"}])
    assert send(fixture_transport(tmp_path), "GET", "https://logs.example.com/_cat/shards?v=true") == (200, "a b c")


def test_transport_error_status(tmp_path):
    write(tmp_path, "opensearch.json", [{"method": "GET", "path_contains": "_cluster", "status": 503, "body": {"error": "down"}}])
    assert send(fixture_transport(tmp_path), "GET", "https://logs.example.com/_cluster/health")[0] == 503


def test_transport_no_match_is_404(tmp_path):
    status, text = send(fixture_transport(tmp_path), "GET", "https://logs.example.com/_cluster/health")
    assert (status, json.loads(text)) == (404, {"error": "no fixture"})


# call log

def test_every_call_is_logged_in_order(tmp_path, monkeypatch):
    log = tmp_path / "calls.log"
    monkeypatch.setenv(LOG_ENV, str(log))
    runner = FixtureRunner(tmp_path)
    transport = fixture_transport(tmp_path)
    aws(runner, "ecs", "list-clusters")
    runner([*KUBE_PREFIX, "get", "pods"], 60)
    send(transport, "GET", "https://logs.example.com/_cluster/health")
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    assert [line["tool"] for line in lines] == ["aws", "kubectl", "opensearch"]
    assert lines[0]["argv"][:3] == ["aws", "ecs", "list-clusters"]
    assert lines[1]["argv"] == [*KUBE_PREFIX, "get", "pods"]
    assert lines[2] == {"tool": "opensearch", "method": "GET", "url": "https://logs.example.com/_cluster/health"}


def test_nothing_is_logged_when_the_log_variable_is_unset(tmp_path, monkeypatch):
    monkeypatch.delenv(LOG_ENV, raising=False)
    aws(FixtureRunner(tmp_path), "ecs", "list-clusters")
    assert not (tmp_path / "calls.log").exists()
