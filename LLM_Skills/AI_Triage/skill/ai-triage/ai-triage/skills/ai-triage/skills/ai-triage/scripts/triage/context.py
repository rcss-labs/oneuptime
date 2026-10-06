"""What a collector needs to run: config, account, window, evidence, and guarded call helpers."""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from triage.awscli import BAD_OUTPUT, REFUSED, SSO_EXPIRED, SSO_EXPIRED_MARKERS, Runner, run_aws, subprocess_runner
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
    last_error: tuple[str, str] | None = field(default=None, init=False)

    def aws(
        self,
        service: str,
        operation: str,
        args: Sequence[str] = (),
        *,
        region: str | None = None,
        not_found: Sequence[str] = (),
    ) -> Any | None:
        """Run one AWS read. Failures with a code in not_found are not recorded as evidence errors."""
        result = run_aws(
            service, operation, args,
            profile=self.account.profile, region=region or self.region, runner=self.runner,
        )
        self.last_command = shlex.join(result.argv)
        if result.ok:
            self.last_error = None
            return result.data
        if result.error_code == SSO_EXPIRED:
            raise SignInExpired(self.account.profile)
        code = result.error_code or "Unknown"
        self.last_error = (code, result.error_message or "")
        if code not in not_found:
            self.evidence.add_error(self.last_command, code, result.error_message or "")
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
        eks_cluster = self.config.eks_clusters[cluster]
        result = run_kubectl(
            args,
            kubeconfig=self.skill_dir / "config" / KUBECONFIG_NAME,
            context=eks_cluster.context,
            namespace=namespace,
            all_namespaces=all_namespaces,
            runner=self.kube_runner,
        )
        self.last_command = shlex.join(result.argv)
        if result.ok:
            self.last_error = None
            return result.stdout
        message = result.error_message or ""
        if any(marker in message for marker in SSO_EXPIRED_MARKERS):
            raise SignInExpired(self.config.accounts[eks_cluster.account].profile)
        code = REFUSED if message.startswith(REFUSED) else KUBECTL_ERROR
        self.last_error = (code, message)
        self.evidence.add_error(self.last_command, code, message)
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
            self.last_error = (BAD_OUTPUT, "kubectl did not print JSON")
            self.evidence.add_error(self.last_command, BAD_OUTPUT, "kubectl did not print JSON")
            return None
