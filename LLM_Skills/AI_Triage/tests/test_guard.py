import pytest

from triage.config import parse_config
from triage.guard import GuardContext, context_from_config, decide
from triage.verdict import ALLOW, ASK, DENY, PASS

SKILL = "/home/eng/.claude/skills/ai-triage"
PY = f"{SKILL}/.venv/bin/python"
CONTEXT = GuardContext(
    profiles=frozenset({"triage-prod-main"}),
    kubeconfig=f"{SKILL}/config/kubeconfig",
    kube_contexts=frozenset({"triage-platform-prod"}),
    opensearch_hosts=frozenset({"opensearch.internal.example.com"}),
    skill_dir=SKILL,
)
AWS_OK = "--profile triage-prod-main --region eu-west-1"
KUBE_OK = f"--kubeconfig {SKILL}/config/kubeconfig --context triage-platform-prod -n payments"


def kind(command, context=CONTEXT):
    return decide(command, context).kind


@pytest.mark.parametrize(
    "command",
    [
        f"aws ecs describe-services --cluster a --services b {AWS_OK}",
        f"aws ecs describe-services --cluster a {AWS_OK} | jq '.services[0].events[:5]'",
        f"aws ecs list-tasks --cluster a {AWS_OK} 2>/dev/null | head -20",
        f"aws ecs list-clusters {AWS_OK} && aws rds describe-db-instances {AWS_OK}",
        f"kubectl {KUBE_OK} get pods -o wide | grep -v Running",
        f"{PY} {SKILL}/scripts/preflight.py --json",
        f"{PY} {SKILL}/scripts/opensearch_query.py --cluster logs-prod health",
        f'"{PY}" "{SKILL}/scripts/validate_map.py"',
    ],
)
def test_validated_reads_are_approved(command):
    assert kind(command) == ALLOW


@pytest.mark.parametrize(
    "command",
    [
        "aws ecs describe-services --cluster a --profile admin --region eu-west-1",
        f"aws ecs list-clusters {AWS_OK} && aws ecs stop-task --task t {AWS_OK}",
        f"aws ecs list-clusters {AWS_OK}; aws s3 rm s3://b/k {AWS_OK}",
        f"kubectl {KUBE_OK} delete pod p",
        "curl -s https://opensearch.internal.example.com/_cat/indices",
        "curl -XDELETE https://opensearch.internal.example.com/app-logs-2026",
        f"{PY} {SKILL}/scripts/preflight.py https://opensearch.internal.example.com",
        "python3 -c \"import urllib.request as u; u.urlopen('http://opensearch.internal.example.com/_search')\"",
    ],
)
def test_writes_wrong_identities_and_side_routes_are_blocked(command):
    assert kind(command) == DENY


@pytest.mark.parametrize(
    "command",
    [
        f"echo $(aws sts get-caller-identity {AWS_OK})",
        f"bash -c 'aws ecs list-clusters {AWS_OK}'",
        f"xargs aws ecs describe-tasks {AWS_OK}",
        "cat ~/.aws/config",
        f"aws ecs list-clusters {AWS_OK}\naws ecs list-services {AWS_OK}",
        f"AWS_PROFILE=admin aws ecs list-clusters {AWS_OK}",
    ],
)
def test_commands_the_guard_cannot_check_force_a_prompt(command):
    assert kind(command) == ASK


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status",
        "npm test",
        "echo $(date)",
        f"aws ecs list-clusters {AWS_OK} > clusters.json",
        f"aws ecs list-clusters {AWS_OK} | tee clusters.json",
        f"aws ecs list-clusters {AWS_OK} | xargs rm -rf",
        f"aws ecs list-clusters {AWS_OK}; grep -r password /etc",
        f"/usr/bin/python3 {SKILL}/scripts/preflight.py",
        f"{PY} /tmp/other.py",
        f"{PY} {SKILL}/scripts/../../evil.py",
    ],
)
def test_unrelated_or_mixed_commands_fall_through_to_the_normal_flow(command):
    assert kind(command) == PASS


def test_opensearch_host_is_matched_whatever_its_letter_case():
    assert kind("curl -s https://OpenSearch.Internal.Example.com/_cat/indices") == DENY


def test_absolute_path_to_aws_is_checked_like_aws():
    assert kind(f"/usr/local/bin/aws ecs list-clusters {AWS_OK}") == ALLOW
    assert kind(f"/usr/local/bin/aws ecs stop-task --task t {AWS_OK}") == DENY


def test_skill_folder_with_a_space_in_its_path_is_recognised():
    skill = "/Users/First Last/.claude/skills/ai-triage"
    context = GuardContext(
        profiles=CONTEXT.profiles,
        kubeconfig=f"{skill}/config/kubeconfig",
        kube_contexts=CONTEXT.kube_contexts,
        opensearch_hosts=CONTEXT.opensearch_hosts,
        skill_dir=skill,
    )
    assert kind(f'"{skill}/.venv/bin/python" "{skill}/scripts/preflight.py" --json', context) == ALLOW
    kubectl = f'kubectl --kubeconfig "{skill}/config/kubeconfig" --context triage-platform-prod -n payments get pods'
    assert kind(kubectl, context) == ALLOW


def test_deny_outranks_ask_and_reason_names_the_problem():
    verdict = decide(f"cat ~/.aws/config; aws ecs stop-task --task t {AWS_OK}", CONTEXT)
    assert verdict.kind == DENY and "not a known read" in verdict.reason


def test_without_a_valid_config_aws_and_kubectl_are_denied():
    verdict = decide(f"aws ecs list-clusters {AWS_OK}", None, "config file not found")
    assert verdict.kind == DENY and "config file not found" in verdict.reason
    assert decide("kubectl get pods", None, "x").kind == DENY
    assert decide("ls -la", None, "x").kind == PASS


def test_context_is_built_from_config(config_data, tmp_path):
    context = context_from_config(parse_config(config_data), tmp_path)
    assert context.profiles == frozenset({"triage-prod-main", "triage-staging"})
    assert context.kubeconfig == str(tmp_path / "config" / "kubeconfig")
    assert context.kube_contexts == frozenset({"triage-platform-prod"})
    assert context.opensearch_hosts == frozenset({"opensearch.internal.example.com"})


def test_home_relative_script_paths_are_recognised(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    command = '"$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/preflight.py"'
    assert kind(command) == ALLOW
    assert kind("~/.claude/skills/ai-triage/.venv/bin/python ~/.claude/skills/ai-triage/scripts/preflight.py") == ALLOW
