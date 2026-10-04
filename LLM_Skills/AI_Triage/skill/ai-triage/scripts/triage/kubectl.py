"""Run one read-only kubectl call with the triage kubeconfig and an explicit context."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from triage.awscli import Runner, subprocess_runner


@dataclass(frozen=True)
class KubectlResult:
    ok: bool
    stdout: str
    error_message: str | None
    argv: tuple[str, ...]


def run_kubectl(
    args: Sequence[str],
    *,
    kubeconfig: Path,
    context: str,
    namespace: str | None = None,
    all_namespaces: bool = False,
    runner: Runner = subprocess_runner,
    timeout: int = 60,
) -> KubectlResult:
    if namespace and all_namespaces:
        raise ValueError("pass a namespace or all_namespaces, not both")
    scope = ["-n", namespace] if namespace else ["-A"] if all_namespaces else []
    argv = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", context, *scope, *args]
    frozen = tuple(argv)
    try:
        code, stdout, stderr = runner(argv, timeout)
    except FileNotFoundError:
        return KubectlResult(False, "", "the kubectl command was not found", frozen)
    except subprocess.TimeoutExpired:
        return KubectlResult(False, "", f"no answer within {timeout} seconds", frozen)
    if code != 0:
        return KubectlResult(False, "", stderr.strip(), frozen)
    return KubectlResult(True, stdout, None, frozen)
