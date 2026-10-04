"""What a collector needs to run: config, account, window, evidence, and guarded call helpers."""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from triage.awscli import BAD_OUTPUT, SSO_EXPIRED, Runner, run_aws, subprocess_runner
from triage.config import Account, TriageConfig
from triage.evidence import Evidence
from triage.guard import KUBECONFIG_NAME
from triage.kubectl import run_kubectl
from triage.window import Window

KUBECTL_ERROR = "KubectlError"


class SignInExpired(Exception):
    """The AWS sign-in for a profile has expired; the run must stop."""

    def __init__(self, profile: str):
        self.profile = profile
        super().__init__(f"sign-in expired for profile {profile}")


@dataclass
class CollectContext:
    config: TriageConfig
    account: Account
    region: str
    window: Window
    evidence: Evidence
    skill_dir: Path
    runner: Runner = subprocess_runner
    kube_runner: Runner = subprocess_runner
    last_command: str = field(default="", init=False)

    def aws(self, service: str, operation: str, args: Sequence[str] = (), *, region: str | None = None) -> Any | None:
        result = run_aws(
            service, operation, args,
            profile=self.account.profile, region=region or self.region, runner=self.runner,
        )
        self.last_command = shlex.join(result.argv)
        if result.ok:
            return result.data
        if result.error_code == SSO_EXPIRED:
            raise SignInExpired(self.account.profile)
        self.evidence.add_error(self.last_command, result.error_code or "Unknown", result.error_message or "")
        return None

    def kubectl(
        self,
        cluster: str,
        args: Sequence[str],
        *,
        namespace: str | None = None,
        all_namespaces: bool = False,
    ) -> str | None:
        if cluster not in self.config.eks_clusters:
            raise KeyError(f"unknown EKS cluster: {cluster}")
        result = run_kubectl(
            args,
            kubeconfig=self.skill_dir / "config" / KUBECONFIG_NAME,
            context=self.config.eks_clusters[cluster].context,
            namespace=namespace,
            all_namespaces=all_namespaces,
            runner=self.kube_runner,
        )
        self.last_command = shlex.join(result.argv)
        if result.ok:
            return result.stdout
        self.evidence.add_error(self.last_command, KUBECTL_ERROR, result.error_message or "")
        return None

    def kubectl_json(
        self,
        cluster: str,
        args: Sequence[str],
        *,
        namespace: str | None = None,
        all_namespaces: bool = False,
    ) -> Any | None:
        output = self.kubectl(cluster, [*args, "-o", "json"], namespace=namespace, all_namespaces=all_namespaces)
        if output is None:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            self.evidence.add_error(self.last_command, BAD_OUTPUT, "kubectl did not print JSON")
            return None
