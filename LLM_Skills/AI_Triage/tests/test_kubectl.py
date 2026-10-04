import subprocess
from pathlib import Path

import pytest

from triage.guard_kubectl import check_kubectl
from triage.kubectl import KubectlResult, run_kubectl
from triage.verdict import ALLOW

KUBECONFIG = Path("/home/eng/.claude/skills/ai-triage/config/kubeconfig")
CONTEXT = "triage-platform-prod"
BASE = ["kubectl", "--kubeconfig", str(KUBECONFIG), "--context", CONTEXT]


def runner_returning(code, stdout="", stderr=""):
    def runner(argv, timeout):
        runner.argv, runner.timeout = argv, timeout
        return code, stdout, stderr

    return runner


def call(args, runner=None, **kwargs):
    return run_kubectl(args, kubeconfig=KUBECONFIG, context=CONTEXT, runner=runner or runner_returning(0, "ok"), **kwargs)


def test_namespace_is_passed_with_n():
    runner = runner_returning(0, "pods")
    result = call(["get", "pods"], runner, namespace="payments")
    assert runner.argv == [*BASE, "-n", "payments", "get", "pods"]
    assert result == KubectlResult(True, "pods", None, tuple(runner.argv))


def test_all_namespaces_is_passed_with_a():
    runner = runner_returning(0)
    call(["get", "pods"], runner, all_namespaces=True)
    assert runner.argv == [*BASE, "-A", "get", "pods"]


def test_no_namespace_part_for_cluster_scoped_reads():
    runner = runner_returning(0)
    call(["get", "nodes"], runner)
    assert runner.argv == [*BASE, "get", "nodes"]


def test_namespace_and_all_namespaces_together_are_rejected():
    runner = runner_returning(0)
    with pytest.raises(ValueError):
        call(["get", "pods"], runner, namespace="payments", all_namespaces=True)
    assert not hasattr(runner, "argv")


def test_timeout_is_passed_to_the_runner():
    runner = runner_returning(0)
    call(["get", "nodes"], runner, timeout=7)
    assert runner.timeout == 7


def test_failure_carries_trimmed_stderr():
    result = call(["get", "pods"], runner_returning(1, "", "  Error from server (Forbidden): nope\n"))
    assert not result.ok
    assert result.error_message == "Error from server (Forbidden): nope"
    assert result.stdout == ""


def test_missing_binary_is_reported():
    def runner(argv, timeout):
        raise FileNotFoundError("kubectl")

    result = call(["get", "pods"], runner)
    assert not result.ok
    assert result.error_message == "the kubectl command was not found"


def test_timeout_is_reported():
    def runner(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    result = call(["get", "pods"], runner, timeout=5)
    assert not result.ok
    assert result.error_message == "no answer within 5 seconds"


@pytest.mark.parametrize(
    "args, scope",
    [
        (["get", "pods", "-o", "json"], {"namespace": "payments"}),
        (["get", "pods", "-o", "json"], {"all_namespaces": True}),
        (["get", "nodes", "-o", "json"], {}),
        (["describe", "deployment", "payments-api"], {"namespace": "payments"}),
        (["logs", "payments-api-1", "--since", "30m", "--tail", "200"], {"namespace": "payments"}),
        (["events"], {"namespace": "payments"}),
        (["rollout", "status", "deployment/payments-api"], {"namespace": "payments"}),
        (["top", "pods"], {"namespace": "payments"}),
    ],
)
def test_every_built_argv_for_a_read_verb_is_allowed_by_the_guard(args, scope):
    runner = runner_returning(0)
    call(args, runner, **scope)
    verdict = check_kubectl(tuple(runner.argv), (), str(KUBECONFIG), frozenset({CONTEXT}))
    assert verdict.kind == ALLOW, verdict
