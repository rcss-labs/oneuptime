"""Check that everything a triage run needs is in place before it starts."""
from __future__ import annotations

import os
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from triage.awscli import Runner, subprocess_runner
from triage.config import ConfigError, TriageConfig, default_config_path, load_config
from triage.guard import KUBECONFIG_NAME
from triage.service_map import MapError, default_map_path, load_map
from triage.verify import EXPIRED, PASSED, check_identity

OK = "ok"
WARN = "warn"
FAIL = "fail"
SIGN_IN = "sign-in"
SKIPPED = "skipped"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str = ""
    fix: str = ""


def _load(skill_dir: Path) -> tuple[TriageConfig | None, list[Check]]:
    try:
        config = load_config(default_config_path(skill_dir))
    except ConfigError as exc:
        return None, [Check("Config", FAIL, "; ".join(exc.errors), "Edit config/triage-config.yaml in the skill folder.")]
    checks = [Check("Config", OK, f"{len(config.accounts)} accounts")]
    try:
        service_map = load_map(default_map_path(skill_dir), config)
        checks.append(Check("Service map", OK, f"{len(service_map.services)} services"))
    except MapError as exc:
        checks.append(Check("Service map", FAIL, "; ".join(exc.errors), "Edit config/service-map.yaml in the skill folder."))
    return config, checks


def run_preflight(
    skill_dir: Path,
    accounts: Sequence[str] = (),
    *,
    runner: Runner = subprocess_runner,
    env: Mapping[str, str] = os.environ,
    which: Callable[[str], str | None] = shutil.which,
    replay: bool = False,
) -> list[Check]:
    config, checks = _load(skill_dir)
    if config is None:
        return checks
    unknown = [alias for alias in accounts if alias not in config.accounts]
    if unknown:
        checks.append(Check("Accounts", FAIL, f"unknown account: {', '.join(unknown)}"))
        return checks

    if which("aws") is None:
        checks.append(Check("AWS CLI", FAIL, "the aws command was not found", "Install AWS CLI version 2."))
    else:
        checks.append(Check("AWS CLI", OK))
        for alias, account in config.accounts.items():
            if accounts and alias not in accounts:
                continue
            identity, _ = check_identity(account, config.permission_set, runner)
            name = f"Sign-in: {alias}"
            if identity.status == PASSED:
                checks.append(Check(name, OK, identity.detail))
            elif identity.status == EXPIRED:
                checks.append(Check(name, SIGN_IN, "the sign-in session has expired", f"aws sso login --profile {account.profile}"))
            else:
                checks.append(Check(name, FAIL, identity.detail, f"Check the profile {account.profile} in your AWS config."))

    if config.eks_clusters:
        kubeconfig = skill_dir / "config" / KUBECONFIG_NAME
        if replay:
            checks.append(Check("kubectl", SKIPPED, "replay mode: kubectl is not run"))
        elif which("kubectl") is None:
            checks.append(Check("kubectl", FAIL, "the kubectl command was not found", "Install kubectl."))
        elif not kubeconfig.is_file():
            checks.append(Check("kubectl", FAIL, "the triage kubeconfig does not exist", "Create it with the commands in the README."))
        else:
            checks.append(Check("kubectl", OK))

    try:
        config.cases_dir.mkdir(parents=True, exist_ok=True)
        writable = os.access(config.cases_dir, os.W_OK)
    except OSError:
        writable = False
    if writable:
        checks.append(Check("Cases folder", OK, str(config.cases_dir)))
    else:
        checks.append(Check("Cases folder", FAIL, f"cannot write to {config.cases_dir}", "Fix cases_dir in the config."))

    if env.get("TYPESAFE_API_KEY"):
        checks.append(Check("TypeSafe key", OK))
    else:
        checks.append(
            Check("TypeSafe key", WARN, "TYPESAFE_API_KEY is not set; causes will be capped at 'probable'", "Export TYPESAFE_API_KEY in your shell profile.")
        )
    return checks


def exit_code(checks: Sequence[Check]) -> int:
    """0 ready (warnings allowed), 1 something failed, 3 only sign-in is needed."""
    statuses = {check.status for check in checks}
    if FAIL in statuses:
        return 1
    if SIGN_IN in statuses:
        return 3
    return 0


def render_text(checks: Sequence[Check]) -> str:
    lines = []
    for check in checks:
        line = f"[{check.status:<7}] {check.name}"
        if check.detail:
            line += f": {check.detail}"
        lines.append(line)
        if check.fix and check.status != OK:
            lines.append(f"          fix: {check.fix}")
    return "\n".join(lines)


def as_dicts(checks: Sequence[Check]) -> list[dict[str, str]]:
    return [asdict(check) for check in checks]
