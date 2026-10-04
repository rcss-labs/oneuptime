"""Prove that a triage profile can read what triage needs and cannot write."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from triage.awscli import SSO_EXPIRED, Runner, run_aws, subprocess_runner
from triage.config import Account, TriageConfig

PASSED = "pass"
FAILED = "fail"
SKIPPED = "skipped"
EXPIRED = "expired"

SSO_ROLE_PATH = "/aws-reserved/sso.amazonaws.com/"
SSO_ROLE_PREFIX = "AWSReservedSSO_"


@dataclass(frozen=True)
class Probe:
    name: str
    service: str
    operation: str
    args: tuple[str, ...] = ()
    region: str | None = None  # a fixed region for services that live in one place
    skip_on: tuple[str, ...] = ()  # error codes that mean "not available here", not "denied"


# Calls that need no resource identifier, one per permission area.
READ_PROBES: tuple[Probe, ...] = (
    Probe("ECS", "ecs", "list-clusters", ("--max-items", "1")),
    Probe("EC2", "ec2", "describe-instances", ("--max-items", "1")),
    Probe("ECR", "ecr", "describe-repositories", ("--max-items", "1")),
    Probe("EKS", "eks", "list-clusters", ("--max-items", "1")),
    Probe("Lambda settings", "lambda", "get-account-settings"),
    Probe("Auto Scaling", "autoscaling", "describe-auto-scaling-groups", ("--max-items", "1")),
    Probe("Service scaling", "application-autoscaling", "describe-scalable-targets", ("--service-namespace", "ecs", "--max-items", "1")),
    Probe("RDS", "rds", "describe-db-instances", ("--max-items", "1")),
    Probe("ElastiCache", "elasticache", "describe-cache-clusters", ("--max-items", "1")),
    Probe("OpenSearch domains", "opensearch", "list-domain-names"),
    Probe("DynamoDB", "dynamodb", "list-tables", ("--max-items", "1")),
    Probe("EFS access points", "efs", "describe-access-points", ("--max-items", "1")),
    Probe("SQS", "sqs", "list-queues", ("--max-items", "1")),
    Probe("Load balancers", "elbv2", "describe-load-balancers", ("--max-items", "1")),
    Probe("Log groups", "logs", "describe-log-groups", ("--max-items", "1")),
    Probe("Alarms", "cloudwatch", "describe-alarms", ("--max-items", "1")),
    Probe("CloudTrail events", "cloudtrail", "lookup-events", ("--max-items", "1")),
    Probe("Tag search", "resourcegroupstaggingapi", "get-resources", ("--max-items", "1")),
    Probe("Service quotas", "service-quotas", "list-service-quotas", ("--service-code", "ecs", "--max-items", "1")),
    Probe("Parameter Store", "ssm", "describe-parameters", ("--max-items", "1")),
    Probe("Secrets metadata", "secretsmanager", "list-secrets", ("--max-items", "1")),
    Probe("AWS Health", "health", "describe-events", ("--max-items", "1"), region="us-east-1", skip_on=("SubscriptionRequiredException",)),
)

# The simulator must answer "allowed" for each of these.
SIMULATED_READS: tuple[str, ...] = (
    "logs:GetLogEvents",
    "logs:StartQuery",
    "ecs:DescribeServices",
    "ecr:DescribeImages",
    "rds:DownloadDBLogFilePortion",
    "es:DescribeDomain",
    "lambda:GetFunctionConfiguration",
    "cloudformation:DescribeStackEvents",
    "config:GetResourceConfigHistory",
    "cloudtrail:LookupEvents",
)
# The simulator must not answer "allowed" for any of these.
SIMULATED_WRITES: tuple[str, ...] = (
    "ecs:UpdateService",
    "ecs:StopTask",
    "ecs:ExecuteCommand",
    "ec2:TerminateInstances",
    "ec2:StopInstances",
    "rds:DeleteDBInstance",
    "rds:RebootDBInstance",
    "elasticache:DeleteCacheCluster",
    "es:DeleteDomain",
    "lambda:UpdateFunctionCode",
    "eks:DeleteCluster",
    "dynamodb:DeleteTable",
    "sqs:DeleteQueue",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:GetObject",
    "logs:DeleteLogGroup",
    "iam:CreateUser",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "ssm:StartSession",
)


@dataclass(frozen=True)
class CheckResult:
    account: str
    name: str
    status: str
    detail: str = ""


def _role_name(caller_arn: str) -> str | None:
    """arn:aws:sts::<id>:assumed-role/<role name>/<session> -> <role name>."""
    parts = caller_arn.split(":", 5)
    if len(parts) != 6 or not parts[5].startswith("assumed-role/"):
        return None
    return parts[5].split("/")[1]


def check_identity(account: Account, permission_set: str, runner: Runner) -> tuple[CheckResult, str | None]:
    """Confirm the profile lands in the right account with the triage permission set."""
    region = account.regions[0]
    result = run_aws("sts", "get-caller-identity", profile=account.profile, region=region, runner=runner)
    if not result.ok:
        status = EXPIRED if result.error_code == SSO_EXPIRED else FAILED
        return CheckResult(account.alias, "Identity", status, result.error_message or result.error_code or ""), None
    data = result.data or {}
    if data.get("Account") != account.account_id:
        return CheckResult(account.alias, "Identity", FAILED, f"profile {account.profile} signs in to a different account"), None
    role_name = _role_name(str(data.get("Arn", "")))
    expected_prefix = f"{SSO_ROLE_PREFIX}{permission_set}_"
    if role_name is None or not role_name.startswith(expected_prefix):
        return CheckResult(account.alias, "Identity", FAILED, f"profile {account.profile} does not use the {permission_set} permission set"), None
    return CheckResult(account.alias, "Identity", PASSED, role_name), role_name


def run_read_probes(account: Account, runner: Runner, probes: Sequence[Probe] = READ_PROBES) -> list[CheckResult]:
    results: list[CheckResult] = []
    for probe in probes:
        region = probe.region or account.regions[0]
        result = run_aws(probe.service, probe.operation, probe.args, profile=account.profile, region=region, runner=runner)
        if result.ok:
            results.append(CheckResult(account.alias, f"Read: {probe.name}", PASSED))
        elif result.error_code in probe.skip_on:
            results.append(CheckResult(account.alias, f"Read: {probe.name}", SKIPPED, f"not available ({result.error_code})"))
        else:
            results.append(CheckResult(account.alias, f"Read: {probe.name}", FAILED, result.error_code or "failed"))
    return results


def run_simulation(account: Account, role_name: str, runner: Runner) -> list[CheckResult]:
    """Ask the IAM policy simulator about sample reads and writes. Nothing is attempted."""
    region = account.regions[0]
    roles = run_aws(
        "iam", "list-roles", ("--path-prefix", SSO_ROLE_PATH), profile=account.profile, region=region, runner=runner
    )
    arn = next((r.get("Arn") for r in (roles.data or {}).get("Roles", []) if r.get("RoleName") == role_name), None) if roles.ok else None
    if arn is None:
        return [CheckResult(account.alias, "Simulator", FAILED, "could not find the role behind the triage profile")]
    actions = SIMULATED_READS + SIMULATED_WRITES
    simulation = run_aws(
        "iam",
        "simulate-principal-policy",
        ("--policy-source-arn", arn, "--action-names", *actions),
        profile=account.profile,
        region=region,
        runner=runner,
    )
    if not simulation.ok:
        return [CheckResult(account.alias, "Simulator", FAILED, simulation.error_code or "failed")]
    decisions = {
        entry.get("EvalActionName"): entry.get("EvalDecision")
        for entry in (simulation.data or {}).get("EvaluationResults", [])
    }
    results: list[CheckResult] = []
    for action in SIMULATED_READS:
        decision = decisions.get(action, "no answer")
        status = PASSED if decision == "allowed" else FAILED
        results.append(CheckResult(account.alias, f"Allowed: {action}", status, "" if status == PASSED else decision))
    for action in SIMULATED_WRITES:
        decision = decisions.get(action, "no answer")
        status = PASSED if decision in ("implicitDeny", "explicitDeny") else FAILED
        results.append(CheckResult(account.alias, f"Denied: {action}", status, "" if status == PASSED else decision))
    return results


def verify_account(account: Account, permission_set: str, runner: Runner = subprocess_runner) -> list[CheckResult]:
    identity, role_name = check_identity(account, permission_set, runner)
    if role_name is None:
        return [identity]
    return [identity, *run_read_probes(account, runner), *run_simulation(account, role_name, runner)]


def verify_all(config: TriageConfig, aliases: Sequence[str] = (), runner: Runner = subprocess_runner) -> list[CheckResult]:
    results: list[CheckResult] = []
    for alias, account in config.accounts.items():
        if aliases and alias not in aliases:
            continue
        results.extend(verify_account(account, config.permission_set, runner))
    return results


def render_table(results: Sequence[CheckResult]) -> str:
    width_account = max([len("ACCOUNT"), *(len(r.account) for r in results)])
    width_name = max([len("CHECK"), *(len(r.name) for r in results)])
    lines = [f"{'ACCOUNT':<{width_account}}  {'CHECK':<{width_name}}  RESULT   DETAIL"]
    for r in results:
        lines.append(f"{r.account:<{width_account}}  {r.name:<{width_name}}  {r.status:<7}  {r.detail}".rstrip())
    return "\n".join(lines)


def exit_code(results: Sequence[CheckResult]) -> int:
    """0 all good, 1 something failed, 3 a sign-in session has expired."""
    statuses = {r.status for r in results}
    if FAILED in statuses:
        return 1
    if EXPIRED in statuses:
        return 3
    return 0
