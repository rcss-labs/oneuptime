import json
import shlex

import pytest

from fakes import SSO_EXPIRED_ERROR, FakeAws, access_denied
from triage.config import parse_config
from triage.context import CollectContext, SignInExpired
from triage.evidence import Evidence
from triage.guard import KUBECONFIG_NAME
from triage.window import make_window


class KubeRunner:
    def __init__(self, code=0, stdout="", stderr=""):
        self.code, self.stdout, self.stderr = code, stdout, stderr
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        return self.code, self.stdout, self.stderr


def make_ctx(tmp_path, config_data, aws=None, kube=None):
    config = parse_config(config_data)
    window = make_window("2026-10-04T10:00:00Z", "2026-10-04T12:00:00Z", 6)
    evidence = Evidence("ecs", "prod-main", "eu-west-1", window)
    return CollectContext(
        config, config.accounts["prod-main"], "eu-west-1", window, evidence, tmp_path,
        runner=aws or FakeAws({}), kube_runner=kube or KubeRunner(),
    )


def test_aws_success_returns_data_and_records_command(tmp_path, config_data):
    ctx = make_ctx(tmp_path, config_data, FakeAws({"ecs list-clusters": {"clusterArns": ["a"]}}))
    assert ctx.aws("ecs", "list-clusters", ["--max-items", "5"]) == {"clusterArns": ["a"]}
    words = shlex.split(ctx.last_command)
    assert words[:3] == ["aws", "ecs", "list-clusters"]
    assert words[words.index("--profile") + 1] == "triage-prod-main"
    assert words[words.index("--region") + 1] == "eu-west-1"
    assert ctx.evidence.errors == []


def test_aws_region_override(tmp_path, config_data):
    aws = FakeAws({})
    ctx = make_ctx(tmp_path, config_data, aws)
    ctx.aws("ecs", "list-clusters", region="us-east-1")
    assert aws.calls[0][aws.calls[0].index("--region") + 1] == "us-east-1"
    assert "us-east-1" in ctx.last_command


def test_aws_failure_records_one_error_and_returns_none(tmp_path, config_data):
    ctx = make_ctx(tmp_path, config_data, FakeAws({"ecs list-clusters": access_denied("ListClusters")}))
    assert ctx.aws("ecs", "list-clusters") is None
    assert len(ctx.evidence.errors) == 1
    assert ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert ctx.evidence.errors[0]["command"] == ctx.last_command


def test_sso_expiry_raises_and_records_nothing(tmp_path, config_data):
    ctx = make_ctx(tmp_path, config_data, FakeAws({"ecs list-clusters": SSO_EXPIRED_ERROR}))
    with pytest.raises(SignInExpired) as raised:
        ctx.aws("ecs", "list-clusters")
    assert raised.value.profile == "triage-prod-main"
    assert ctx.evidence.errors == []


def test_kubectl_uses_skill_kubeconfig_and_cluster_context(tmp_path, config_data):
    kube = KubeRunner(stdout="pods")
    ctx = make_ctx(tmp_path, config_data, kube=kube)
    assert ctx.kubectl("platform-prod", ["get", "pods"], namespace="web") == "pods"
    assert kube.calls[0] == [
        "kubectl", "--kubeconfig", str(tmp_path / "config" / KUBECONFIG_NAME),
        "--context", "triage-platform-prod", "-n", "web", "get", "pods",
    ]
    assert shlex.split(ctx.last_command) == kube.calls[0]


def test_kubectl_all_namespaces(tmp_path, config_data):
    kube = KubeRunner(stdout="x")
    ctx = make_ctx(tmp_path, config_data, kube=kube)
    ctx.kubectl("platform-prod", ["get", "pods"], all_namespaces=True)
    assert "-A" in kube.calls[0]


def test_kubectl_unknown_cluster(tmp_path, config_data):
    ctx = make_ctx(tmp_path, config_data)
    with pytest.raises(KeyError, match="nowhere"):
        ctx.kubectl("nowhere", ["get", "pods"])


def test_kubectl_failure_is_an_evidence_error(tmp_path, config_data):
    ctx = make_ctx(tmp_path, config_data, kube=KubeRunner(code=1, stderr="forbidden"))
    assert ctx.kubectl("platform-prod", ["get", "pods"], namespace="web") is None
    assert len(ctx.evidence.errors) == 1
    assert ctx.evidence.errors[0]["code"] == "KubectlError"
    assert "forbidden" in ctx.evidence.errors[0]["message"]


def test_kubectl_json_parses_output(tmp_path, config_data):
    kube = KubeRunner(stdout=json.dumps({"items": []}))
    ctx = make_ctx(tmp_path, config_data, kube=kube)
    assert ctx.kubectl_json("platform-prod", ["get", "pods"], namespace="web") == {"items": []}
    assert kube.calls[0][-2:] == ["-o", "json"]


def test_kubectl_json_bad_output(tmp_path, config_data):
    ctx = make_ctx(tmp_path, config_data, kube=KubeRunner(stdout="not json"))
    assert ctx.kubectl_json("platform-prod", ["get", "pods"], namespace="web") is None
    assert ctx.evidence.errors[0]["code"] == "UnreadableOutput"
