import shlex

import pytest

from triage.guard_kubectl import check_kubectl
from triage.verdict import ALLOW, ASK, DENY

KUBECONFIG = "/home/eng/.claude/skills/ai-triage/config/kubeconfig"
CONTEXTS = frozenset({"triage-platform-prod"})
OK = f"--kubeconfig {KUBECONFIG} --context triage-platform-prod"


def verdict(command, env=()):
    return check_kubectl(tuple(shlex.split(command)), tuple(env), KUBECONFIG, CONTEXTS)


@pytest.mark.parametrize(
    "command",
    [
        f"kubectl {OK} -n payments get pods -o wide",
        f"kubectl {OK} get pods -A",
        f"kubectl {OK} --namespace payments describe deployment payments-api",
        f"kubectl {OK} -n payments logs payments-api-123 --since 30m --tail 200",
        f"kubectl {OK} -n payments logs deploy/payments-api --previous --tail=100",
        f"kubectl {OK} -n payments events --for deployment/payments-api",
        f"kubectl {OK} -n payments rollout status deployment/payments-api",
        f"kubectl {OK} -n payments rollout history deployment/payments-api",
        f"kubectl {OK} -n payments get pods,deployments,events",
        f"kubectl {OK} get namespaces",
        f"kubectl {OK} get nodes -o wide",
        f"kubectl {OK} top nodes",
        f"kubectl {OK} -n payments top pods",
        f"kubectl {OK} auth can-i list pods -n payments",
        f"kubectl {OK} version",
        f"kubectl {OK} api-resources",
        f"kubectl --kubeconfig={KUBECONFIG} --context=triage-platform-prod -n payments get configmap app-config -o yaml",
    ],
)
def test_bounded_reads_with_the_triage_kubeconfig_are_allowed(command):
    assert verdict(command).kind == ALLOW


@pytest.mark.parametrize(
    "command, reason",
    [
        ("kubectl --context triage-platform-prod -n payments get pods", "must set --kubeconfig"),
        ("kubectl --kubeconfig /home/eng/.kube/config --context triage-platform-prod -n payments get pods", "must use the triage kubeconfig"),
        (f"kubectl --kubeconfig {KUBECONFIG} -n payments get pods", "must set --context"),
        (f"kubectl --kubeconfig {KUBECONFIG} --context admin-prod -n payments get pods", "not a triage context"),
        (f"kubectl {OK} get pods", "set a namespace"),
        (f"kubectl {OK} --context admin-prod -n payments get pods", "not a triage context"),
        (f"kubectl {OK} --kubeconfig=/home/eng/.kube/config -n payments get pods", "must use the triage kubeconfig"),
        (f"kubectl {OK} -n payments delete pod p", "kubectl delete is not a read"),
        (f"kubectl {OK} -n payments apply -f manifest.yaml", "kubectl apply is not a read"),
        (f"kubectl {OK} -n payments exec -it p -- sh", "kubectl exec is not a read"),
        (f"kubectl {OK} -n payments port-forward svc/x 8080:80", "kubectl port-forward is not a read"),
        (f"kubectl {OK} -n payments scale deployment/x --replicas=0", "kubectl scale is not a read"),
        (f"kubectl {OK} -n payments edit deployment x", "kubectl edit is not a read"),
        (f"kubectl {OK} -n payments rollout restart deployment/x", "kubectl rollout restart is not a read"),
        (f"kubectl {OK} -n payments rollout undo deployment/x", "kubectl rollout undo is not a read"),
        (f"kubectl {OK} config view", "kubectl config is not a read"),
        (f"kubectl {OK} -n payments get secrets", "secrets is not allowed"),
        (f"kubectl {OK} -n payments get secret/db -o yaml", "secrets is not allowed"),
        (f"kubectl {OK} -n payments get pods,secrets", "secrets is not allowed"),
        (f"kubectl {OK} -n payments describe secret db", "secrets is not allowed"),
        (f"kubectl {OK} -n payments logs p", "must be bounded"),
        (f"kubectl {OK} -n payments logs p --tail 10 -f", "never ends"),
        (f"kubectl {OK} -n payments get pods -w", "never ends"),
        (f"kubectl {OK} get --raw /api/v1/namespaces/payments/secrets", "--raw is not allowed"),
        (f"kubectl {OK} -n payments get pods --as system:admin", "--as is not allowed"),
        (f"kubectl {OK} -n payments get pods --token abc", "--token is not allowed"),
    ],
)
def test_everything_else_is_denied_with_a_reason(command, reason):
    result = verdict(command)
    assert result.kind == DENY
    assert reason in result.reason


def test_kubeconfig_environment_override_asks():
    assert verdict(f"kubectl {OK} -n payments get pods", env=("KUBECONFIG=/tmp/other",)).kind == ASK


def test_no_verb_asks():
    assert verdict(f"kubectl {OK}").kind == ASK


def test_home_relative_kubeconfig_is_accepted(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    command = "kubectl --kubeconfig ~/.claude/skills/ai-triage/config/kubeconfig --context triage-platform-prod -n p get pods"
    assert verdict(command).kind == ALLOW
