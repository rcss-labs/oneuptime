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
        (f"kubectl {OK} -n payments apply manifest.yaml", "kubectl apply is not a read"),
        (f"kubectl {OK} -n payments exec p", "kubectl exec is not a read"),
        (f"kubectl {OK} -n payments port-forward svc/x 8080:80", "kubectl port-forward is not a read"),
        (f"kubectl {OK} -n payments scale deployment/x", "kubectl scale is not a read"),
        (f"kubectl {OK} -n payments edit deployment x", "kubectl edit is not a read"),
        (f"kubectl {OK} -n payments rollout restart deployment/x", "kubectl rollout restart is not a read"),
        (f"kubectl {OK} -n payments rollout undo deployment/x", "kubectl rollout undo is not a read"),
        (f"kubectl {OK} config view", "kubectl config is not a read"),
        (f"kubectl {OK} -n payments get secrets", "secrets is not allowed"),
        (f"kubectl {OK} -n payments get secret/db -o yaml", "secrets is not allowed"),
        (f"kubectl {OK} -n payments get pods,secrets", "secrets is not allowed"),
        (f"kubectl {OK} -n payments describe secret db", "secrets is not allowed"),
        (f"kubectl {OK} -n payments logs p", "must be bounded"),
        (f"kubectl {OK} -n payments logs p --tail 10 -f", "kubectl option -f is not allowed during triage"),
        (f"kubectl {OK} -n payments get pods -w", "kubectl option -w is not allowed during triage"),
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


def test_a_kubeconfig_path_that_still_has_a_tilde_is_not_trusted():
    # The shell parser expands an unquoted ~ before the guard sees it. A ~ that
    # arrives here was quoted, so the shell will not expand it and it is not the triage file.
    command = "kubectl --kubeconfig ~/.claude/skills/ai-triage/config/kubeconfig --context triage-platform-prod -n p get pods"
    assert verdict(command).kind == DENY


# ---- fix round 1 -------------------------------------------------------------

@pytest.mark.parametrize(
    "command",
    [
        # wave A C3: an unknown option before the verb must not steer verb detection
        f"kubectl --cache-dir /x {OK} -n payments get pods",
        f"kubectl {OK} --cache-dir /x -n payments get pods",
        f"kubectl {OK} -n payments get pods --cache-dir /x",
        f"kubectl --certificate-authority /x {OK} -n payments get pods",
        f"kubectl --client-key /x delete {OK} -n payments pods",
        f"kubectl --username u {OK} -n payments get pods",
        f"kubectl --tls-server-name x {OK} -n payments get pods",
        f"kubectl -v 9 {OK} -n payments get pods",
        f"kubectl {OK} -n payments --field-manager x get pods",
        f"kubectl --cache-dir /x patch {OK} -n payments deployment/x",
        # wave A I1: bundled and attached short flags, and credential redirection
        f"kubectl {OK} -n payments logs p --tail 5 -pf",
        f"kubectl {OK} -n payments get pods -shttp://x.example.com",
        f"kubectl {OK} -n payments get pods -s http://x.example.com",
        f"kubectl {OK} -n payments get pods --as-uid 0",
        f"kubectl {OK} -n payments get pods --as=x",
        f"kubectl {OK} -n payments get pods --server=http://x.example.com",
        f"kubectl {OK} -n payments get pods --token=abc",
        f"kubectl {OK} -n payments get pods -nother",
        f"kubectl {OK} -n payments get pods -n=other",
        f"kubectl {OK} -n payments get pods -ojson",
        f"kubectl {OK} -n payments get pods --",
        f"kubectl {OK} -n payments get pods -",
        f"kubectl {OK} -n payments get pods --follow=true",
        f"kubectl {OK} -n payments get pods --watch",
        f"kubectl {OK} -n payments get pods --raw=/x",
        f"kubectl {OK} -n payments get pods --show-managed-fields",
    ],
)
def test_options_not_on_the_lists_are_denied_wherever_they_are(command):
    result = verdict(command)
    assert result.kind == DENY
    assert result.reason.startswith("kubectl option ") and result.reason.endswith(" is not allowed during triage")


def test_the_option_reason_names_the_word():
    assert verdict(f"kubectl {OK} -n p get pods -pf").reason == "kubectl option -pf is not allowed during triage"


@pytest.mark.parametrize(
    "command",
    [
        f"kubectl {OK} -n payments logs p --tail=-1",
        f"kubectl {OK} -n payments logs p --tail 0",
        f"kubectl {OK} -n payments logs p --tail 99999",
        f"kubectl {OK} -n payments logs p --tail 5001",
        f"kubectl {OK} -n payments logs p --tail abc",
        f"kubectl {OK} -n payments logs p --tail",
        f"kubectl {OK} -n payments logs p --since 1d",
        f"kubectl {OK} -n payments logs p --since 30",
        f"kubectl {OK} -n payments logs p --since=-5m",
        f"kubectl {OK} -n payments logs p --tail 10 --limit-bytes 0",
        f"kubectl {OK} -n payments logs p --tail 10 --limit-bytes=-1",
        f"kubectl {OK} -n payments logs p --tail 10 --limit-bytes 1.5",
        f"kubectl {OK} -n payments get pods -o go-template={{{{.items}}}}",
        f"kubectl {OK} -n payments get pods --output=go-template-file=/x",
        f"kubectl {OK} -n payments get pods -o template=x",
        f"kubectl {OK} -n payments get pods -o",
    ],
)
def test_option_values_are_validated(command):
    assert verdict(command).kind == DENY


@pytest.mark.parametrize(
    "command",
    [
        f"kubectl {OK} -n payments logs p --tail 1",
        f"kubectl {OK} -n payments logs p --tail 5000",
        f"kubectl {OK} -n payments logs p --since 45s --tail=10",
        f"kubectl {OK} -n payments logs p --since 2h",
        f"kubectl {OK} -n payments logs p --since-time 2026-10-01T00:00:00Z",
        f"kubectl {OK} -n payments logs p --limit-bytes 100000",
        f"kubectl {OK} -n payments logs p --tail 10 --previous --timestamps --all-containers --prefix -c app",
        f"kubectl {OK} -n payments logs -l app=x --tail 10 --max-log-requests 3",
        f"kubectl {OK} -n payments logs p --tail 10 -p",
        f"kubectl {OK} -n payments get pods -o json",
        f"kubectl {OK} -n payments get pods -o yaml",
        f"kubectl {OK} -n payments get pods -o name",
        f"kubectl {OK} -n payments get pods --output wide",
        f"kubectl {OK} -n payments get pods -o jsonpath={{.items[*].metadata.name}}",
        f"kubectl {OK} -n payments get pods --output=custom-columns=NAME:.metadata.name",
        f"kubectl {OK} -n payments get pods -l app=x --field-selector status.phase=Running --sort-by=.metadata.name",
        f"kubectl {OK} -n payments get pods --show-labels --no-headers --ignore-not-found",
        f"kubectl {OK} -A get pods --request-timeout 10s",
        f"kubectl {OK} --all-namespaces get pods",
        f"kubectl {OK} -n payments top pod --containers",
        f"kubectl {OK} -n payments rollout history deployment/x --revision 2",
        f"kubectl {OK} -n payments events --types Warning --for pod/x",
    ],
)
def test_listed_options_with_valid_values_are_allowed(command):
    assert verdict(command).kind == ALLOW


@pytest.mark.parametrize(
    "command",
    [
        f"kubectl {OK} -n payments get pod/a secret/b",
        f"kubectl {OK} -n payments get pods secret",
        f"kubectl {OK} -n payments get pods,secrets",
        f"kubectl {OK} -n payments get pod/a,secret/b",
        f"kubectl {OK} -n payments get pods SECRETS",
        f"kubectl {OK} -n payments get secrets.v1",
        f"kubectl {OK} -n payments get pod/a secret.v1/b",
        f"kubectl {OK} -n payments describe pod/a secret/b",
        f"kubectl {OK} -n payments describe pods secrets",
        f"kubectl {OK} -n payments get pod/a -o yaml secret/b",
    ],
)
def test_secrets_are_denied_in_any_position(command):
    result = verdict(command)
    assert result.kind == DENY and "secrets is not allowed" in result.reason


def test_a_resource_with_secret_only_in_its_name_is_not_treated_as_a_secret():
    assert verdict(f"kubectl {OK} -n payments get pod/secret-store").kind == ALLOW
    assert verdict(f"kubectl {OK} -n payments get pods -l app=secrets").kind == ALLOW


def test_a_repeated_kubeconfig_or_context_must_always_be_the_triage_one():
    assert verdict(f"kubectl {OK} --context=admin -n p get pods").kind == DENY
    assert verdict(f"kubectl {OK} --kubeconfig /x -n p get pods").kind == DENY
