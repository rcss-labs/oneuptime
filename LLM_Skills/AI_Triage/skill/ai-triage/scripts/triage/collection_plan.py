"""Turn a case's target into the exact collector commands, so a run never relies on remembered option names."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from triage.case import CaseError
from triage.collectors import all_collectors
from triage.config import TriageConfig
from triage.evidence import SUFFIX_CLEANER

DOMAINS = ("changes", "compute", "data", "edge", "logs")
COLLECTOR_DOMAIN = {
    "changes": "changes", "platform": "changes", "access": "changes",
    "ecs": "compute", "ec2": "compute", "ecr": "compute", "lambda": "compute", "autoscaling": "compute", "eks": "compute",
    "rds": "data", "elasticache": "data", "opensearch_domain": "data", "dynamodb": "data", "efs": "data", "messaging": "data",
    "edge": "edge", "vpc": "edge", "apigateway": "edge", "cloudfront_waf": "edge",
    "logs": "logs", "alarms": "logs", "opensearch": "logs",
}
# The collector that a resource key feeds, used to name a skipped resource.
RESOURCE_COLLECTOR = {
    "ecs_service": "ecs", "ec2_instances": "ec2", "auto_scaling_group": "autoscaling", "lambda_functions": "lambda",
    "eks": "eks", "load_balancer": "edge", "api_gateway": "apigateway", "cloudfront_distribution": "cloudfront_waf",
    "rds": "rds", "elasticache": "elasticache", "dynamodb_tables": "dynamodb", "efs": "efs",
    "alarms": "alarms", "ecr_repository": "ecr", "opensearch_domain": "opensearch_domain",
    "sqs_queues": "messaging", "sns_topics": "messaging", "log_groups": "logs", "opensearch": "opensearch",
}
MAX_RESOURCE_NAMES = 10
MAX_ALARM_NAMES = 50  # what the alarms collector reads
# CloudTrail event sources of each resource kind, in the order they are passed to the changes collector.
EVENT_SOURCES = {
    "ecs_service": ("ecs.amazonaws.com", "application-autoscaling.amazonaws.com"),
    "load_balancer": ("elasticloadbalancing.amazonaws.com",),
    "rds": ("rds.amazonaws.com",),
    "elasticache": ("elasticache.amazonaws.com",),
    "lambda_functions": ("lambda.amazonaws.com",),
    "eks": ("eks.amazonaws.com",),
    "auto_scaling_group": ("autoscaling.amazonaws.com",),
    "ec2_instances": ("ec2.amazonaws.com",),
    "dynamodb_tables": ("dynamodb.amazonaws.com",),
    "sqs_queues": ("sqs.amazonaws.com",),
    "sns_topics": ("sns.amazonaws.com",),
    "api_gateway": ("apigateway.amazonaws.com",),
    "cloudfront_distribution": ("cloudfront.amazonaws.com",),
    "efs": ("elasticfilesystem.amazonaws.com",),
}
COLLECT_WORKERS = 4
COMMAND_TIMEOUT_SECONDS = 300
STDERR_LINE_LIMIT = 300
OPENSEARCH_QUERIES = ("histogram", "top-messages", "search")
SKIPPED = "skipped"
# The evidence writer drops every other character from a file name suffix.
FILTER_KEY_RE = re.compile(r"[A-Za-z_@][A-Za-z0-9_.@-]*")


MAX_FILE_NAME_BYTES = 200
EVIDENCE_EXTENSION = ".json"
HASH_LENGTH = 6


def _suffix_for(name: str, budget: int) -> str:
    """A file name suffix of at most `budget` characters for a resource.

    A name that cleaning would change, that has an upper-case letter (volumes that ignore case would merge it
    with its lower-case twin), or that is too long gets a short hash of the raw name, so that two names that
    clean to the same text still write different evidence files."""
    cleaned = SUFFIX_CLEANER.sub("", name)
    if cleaned == name and name == name.lower() and len(name) <= budget:
        return name
    digest = hashlib.sha256(name.encode()).hexdigest()[:HASH_LENGTH]
    room = budget - HASH_LENGTH - 1
    kept = cleaned[:room].rstrip("-") if room > 0 else ""
    return f"{kept}-{digest}" if kept else digest


def _evidence_path(collector: str, account: str, region: str, suffix: str) -> str:
    """Where Evidence.write puts the file for this collector, account, region (or cluster), and suffix."""
    name = "-".join(SUFFIX_CLEANER.sub("", part) for part in (collector, account, region))
    cleaned = SUFFIX_CLEANER.sub("", suffix)
    if cleaned:
        name += f"-{cleaned}"
    return f"evidence/{name}.json"


@dataclass(frozen=True)
class PlannedCommand:
    domain: str
    tool: str
    name: str
    argv: list[str]
    reason: str
    suffix: str = ""
    evidence: str = ""  # the evidence file this command writes, relative to the case folder

    def shell(self) -> str:
        return shlex.join(self.argv)


class _Planner:
    def __init__(self, case: dict, config: TriageConfig, skill_dir: Path):
        self.case, self.config = case, config
        target = case["target"]
        self.account, self.region, self.resources = target["account"], target["region"], target["resources"]
        self.python = str(skill_dir / ".venv" / "bin" / "python")
        self.run_script = str(skill_dir / "scripts" / "run.py")
        self.hostnames = list(case["incident"].get("hostnames", []))
        self.commands: list[PlannedCommand] = []
        self.evidence_files: set[tuple[str, str, str]] = set()

    def suffix_budget(self, collector: str, account: str | None = None, region: str | None = None) -> int:
        """How many characters of suffix keep the evidence file name within MAX_FILE_NAME_BYTES."""
        stem = "-".join(SUFFIX_CLEANER.sub("", part) for part in (collector, account or self.account, region or self.region))
        return MAX_FILE_NAME_BYTES - len(EVIDENCE_EXTENSION) - len(stem) - 1

    def _claim_file(self, name: str, scope: str, suffix: str) -> None:
        identity = (name.lower(), scope.lower(), SUFFIX_CLEANER.sub("", suffix).lower())
        if identity in self.evidence_files:
            raise CaseError([f"{name} with suffix '{suffix}' would write the same evidence file as another planned command"])
        self.evidence_files.add(identity)

    def collect(self, name: str, targets: dict[str, str], reason: str, suffix: str = "",
                account: str | None = None, region: str | None = None) -> None:
        account, region = account or self.account, region or self.region
        argv = [self.python, self.run_script, "collect", name, "--account", account, "--region", region,
                "--start", self.case["window"]["start"], "--end", self.case["window"]["end"],
                "--case-dir", self.case["case_dir"]]
        # Every collector that declares an optional incident_start gets the case's, in the form changes takes.
        if "incident_start" in all_collectors()[name].optional:
            targets = {**targets, "incident_start": self.case["incident_start"]}
        for key, value in targets.items():
            argv += ["--target", f"{key}={value}"]
        self._claim_file(name, f"{account}/{region}", suffix)
        if suffix:
            argv.append(f"--suffix={suffix}")
        self.commands.append(PlannedCommand(
            COLLECTOR_DOMAIN[name], "collect", name, argv, reason, suffix, _evidence_path(name, account, region, suffix)))

    def opensearch(self, subcommand: str, spec: dict, reason: str) -> None:
        argv = [self.python, self.run_script, "opensearch_query", subcommand, "--cluster", spec["cluster"],
                "--index", spec["index_pattern"], "--start", self.case["window"]["start"],
                "--end", self.case["window"]["end"], "--case-dir", self.case["case_dir"]]
        for key, value in (spec.get("filter") or {}).items():
            text = value if isinstance(value, str) else json.dumps(value)
            argv += ["--filter", f"{key}={text}"]
        self._claim_file("opensearch", f"{spec['cluster']}", subcommand)
        argv.append(f"--suffix={subcommand}")
        cluster = self.config.opensearch_clusters[spec["cluster"]]
        self.commands.append(PlannedCommand(
            COLLECTOR_DOMAIN["opensearch"], "opensearch_query", "opensearch", argv, reason, subcommand,
            _evidence_path("opensearch", cluster.account, cluster.name, subcommand)))

    def skip_note(self, why: str) -> None:
        self.commands.append(PlannedCommand("changes", SKIPPED, "changes", [], why))

    def skip(self, key: str, why: str) -> None:
        name = RESOURCE_COLLECTOR.get(key, key)
        domain = COLLECTOR_DOMAIN.get(name, "changes")
        self.commands.append(PlannedCommand(domain, SKIPPED, name, [], f"{key}: {why}"))


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _text_list(value: Any) -> list[str] | None:
    """The list when every item is text, else None. An empty list is a valid list."""
    if isinstance(value, list) and all(_is_text(item) for item in value):
        return list(value)
    return None


def _split_ecs(value: Any) -> tuple[str, str] | None:
    if not _is_text(value):
        return None
    cluster, _, service = (part.strip() for part in value.partition("/"))
    return (cluster, service) if cluster and service and "/" not in service else None


def _plan_ecs(p: _Planner, value: Any) -> None:
    parts = _split_ecs(value)
    if parts is None:
        p.skip("ecs_service", "must look like cluster/service")
        return
    p.collect("ecs", {"cluster": parts[0], "service": parts[1]}, "ECS service events, tasks, and deployments")


def _plan_ec2(p: _Planner, value: Any) -> None:
    ids = _text_list(value)
    if ids is None:
        p.skip("ec2_instances", "must be a list of instance ids")
    elif ids:
        p.collect("ec2", {"instance_ids": ",".join(ids)}, "instance state and status checks")


def _plan_asg(p: _Planner, value: Any) -> None:
    if not _is_text(value):
        p.skip("auto_scaling_group", "must be a group name")
        return
    targets = {"group": value}
    parts = _split_ecs(p.resources.get("ecs_service"))
    if parts:
        targets.update({"ecs_cluster": parts[0], "ecs_service": parts[1]})
    p.collect("autoscaling", targets, "scaling activities and capacity")


def _plan_each(p: _Planner, key: str, collector: str, target_key: str, reason: str, value: Any) -> None:
    items = _text_list(value)
    if items is None:
        p.skip(key, "must be a list of names")
        return
    budget = p.suffix_budget(collector)
    for item in dict.fromkeys(items):
        p.collect(collector, {target_key: item}, reason, suffix=_suffix_for(item, budget))


def _plan_eks(p: _Planner, value: Any) -> None:
    if not isinstance(value, dict) or not _is_text(value.get("cluster")) or not _is_text(value.get("namespace")):
        p.skip("eks", "must be a mapping with cluster and namespace")
        return
    workloads = _text_list(value.get("workloads", []))
    if workloads is None:
        p.skip("eks", "workloads must be a list of names")
        return
    if value["cluster"] not in p.config.eks_clusters:
        p.skip("eks", f"cluster '{value['cluster']}' is not in the config")
        return
    targets = {"cluster": value["cluster"], "namespace": value["namespace"]}
    if workloads:
        targets["workloads"] = ",".join(workloads)
    p.collect("eks", targets, "pods, events, and rollouts in the namespace")


def _plan_load_balancer(p: _Planner, value: Any) -> None:
    if not _is_text(value):
        p.skip("load_balancer", "must be a load balancer name")
        return
    targets = {"load_balancer": value}
    if len(p.hostnames) == 1:
        targets["hostname"] = p.hostnames[0]
    p.collect("edge", targets, "target health, listeners, and error rates")


def _plan_single(collector: str, key: str, target_key: str, reason: str):
    def plan(p: _Planner, value: Any) -> None:
        if not _is_text(value):
            p.skip(key, "must be a single name")
            return
        p.collect(collector, {target_key: value}, reason)
    return plan


def _plan_log_groups(p: _Planner, value: Any) -> None:
    groups = _text_list(value)
    if groups is None:
        p.skip("log_groups", "must be a list of log group names")
    elif groups:
        p.collect("logs", {"log_groups": ",".join(groups)}, "error and volume patterns in the logs")


def _plan_alarms(p: _Planner, value: Any) -> None:
    names = _text_list(value)
    if names is None:
        p.skip("alarms", "must be a list of alarm names")
    elif names:
        p.collect("alarms", {"alarm_names": ",".join(names[:MAX_ALARM_NAMES])}, "alarm state and state changes in the window")


def _plan_opensearch(p: _Planner, value: Any) -> None:
    if (not isinstance(value, dict) or not _is_text(value.get("cluster")) or not _is_text(value.get("index_pattern"))
            or not isinstance(value.get("filter") or {}, dict)):
        p.skip("opensearch", "must be a mapping with cluster, index_pattern, and an optional filter mapping")
        return
    for key in value.get("filter") or {}:
        if not FILTER_KEY_RE.fullmatch(key):
            raise CaseError([f"resources.opensearch.filter: key {key!r} must start with a letter, '_' or '@' and use only letters, digits, '_', '.', '@' and '-'"])
    if value["cluster"] not in p.config.opensearch_clusters:
        p.skip("opensearch", f"cluster '{value['cluster']}' is not in the config")
        return
    reasons = {
        "histogram": "log volume over time",
        "top-messages": "most frequent log messages",
        "search": "matching log lines",
    }
    for subcommand in OPENSEARCH_QUERIES:
        p.opensearch(subcommand, value, reasons[subcommand])


def _plan_messaging(p: _Planner) -> None:
    targets: dict[str, str] = {}
    for key, target_key in (("sqs_queues", "queues"), ("sns_topics", "topics")):
        if key not in p.resources:
            continue
        names = _text_list(p.resources[key])
        if names is None:
            p.skip(key, "must be a list of names")
        elif names:
            targets[target_key] = ",".join(names)
    if targets:
        p.collect("messaging", targets, "queue depth, age, and topic delivery")


def _resource_names(resources: dict) -> list[str]:
    """Every resource name worth a CloudTrail lookup, most specific first, without duplicates."""
    names: list[str] = []

    def add_text(value: Any) -> None:
        if _is_text(value):
            names.append(value)

    parts = _split_ecs(resources.get("ecs_service"))
    if parts:
        names.append(parts[1])
    if isinstance(resources.get("eks"), dict):
        add_text(resources["eks"].get("cluster"))  # the namespace is not an AWS resource
    for key in ("load_balancer", "rds", "elasticache", "auto_scaling_group"):
        add_text(resources.get(key))
    for key in ("lambda_functions", "dynamodb_tables", "sqs_queues", "sns_topics", "ec2_instances"):
        names += _text_list(resources.get(key)) or []
    for key in ("api_gateway", "cloudfront_distribution", "efs"):
        add_text(resources.get(key))
    return list(dict.fromkeys(names))


def _event_sources(resources: dict) -> list[str]:
    sources: list[str] = []
    for key, kinds in EVENT_SOURCES.items():
        if resources.get(key):
            sources += kinds
    return sources


def _changes_request(resources: dict, incident_start: str, subject: str = "") -> tuple[dict[str, str], str]:
    """The targets and the note of a changes run: names (capped), event sources, and the incident start."""
    every_name = _resource_names(resources)
    names, left_out = every_name[:MAX_RESOURCE_NAMES], every_name[MAX_RESOURCE_NAMES:]
    targets: dict[str, str] = {}
    if names:
        targets["resource_names"] = ",".join(names)
        targets["event_sources"] = ",".join(_event_sources(resources))
    targets["incident_start"] = incident_start
    reason = "deployments and configuration changes before the incident" + subject
    if left_out:
        reason += f"; {len(left_out)} resource names left out: {', '.join(left_out)}"
    return targets, reason


def _plan_dependency(p: _Planner, dependency: dict) -> None:
    """One level of dependency: a changes run and, when alarms are mapped, an alarms run, each in the
    dependency's own account and region, with the dependency's name in the evidence file name."""
    service = dependency["service"]
    label = f"dependency {service}"
    if not dependency.get("environment"):
        p.skip_note(f"{label}: has no matching environment in the service map")
        return
    resources = dependency.get("resources") or {}
    names = _resource_names(resources)
    alarms = _text_list(resources.get("alarms")) or []
    if not names and not alarms:
        p.skip_note(f"{label}: has no resources in the service map to look up")
        return
    account, region = dependency["account"], dependency["region"]
    budget = p.suffix_budget("changes", account, region)
    suffix = _suffix_for(f"dep-{service}", budget)
    if names:
        targets, reason = _changes_request(resources, p.case["incident_start"], f" ({label})")
        p.collect("changes", targets, reason, suffix, account, region)
    if alarms:
        p.collect("alarms", {"alarm_names": ",".join(alarms[:MAX_ALARM_NAMES])}, f"alarm state and changes ({label})",
                  _suffix_for(f"dep-{service}", p.suffix_budget("alarms", account, region)), account, region)


def plan_collection(case: dict, config: TriageConfig, skill_dir: Path) -> list[PlannedCommand]:
    """The commands to run for the case's target, in a fixed order."""
    if not case.get("target"):
        raise CaseError(["the case has no target; run run.py case target first"])
    p = _Planner(case, config, skill_dir)
    handlers = {
        "ecs_service": _plan_ecs,
        "ec2_instances": _plan_ec2,
        "auto_scaling_group": _plan_asg,
        "lambda_functions": lambda pl, v: _plan_each(pl, "lambda_functions", "lambda", "function", "configuration, errors, and throttles", v),
        "eks": _plan_eks,
        "load_balancer": _plan_load_balancer,
        "api_gateway": _plan_single("apigateway", "api_gateway", "api_id", "API stages, errors, and latency"),
        "cloudfront_distribution": _plan_single("cloudfront_waf", "cloudfront_distribution", "distribution_id", "distribution status, errors, and WAF blocks"),
        "rds": _plan_single("rds", "rds", "db", "instance state, events, and connections"),
        "elasticache": _plan_single("elasticache", "elasticache", "replication_group", "cache state, events, and memory"),
        "dynamodb_tables": lambda pl, v: _plan_each(pl, "dynamodb_tables", "dynamodb", "table", "table status and throttling", v),
        "efs": _plan_single("efs", "efs", "file_system", "file system state and burst credits"),
        "log_groups": _plan_log_groups,
        "opensearch": _plan_opensearch,
        "alarms": _plan_alarms,
        "ecr_repository": _plan_single("ecr", "ecr_repository", "repository", "image push times and scan results"),
        "opensearch_domain": _plan_single("opensearch_domain", "opensearch_domain", "domain", "domain health, configuration changes, and resources"),
    }
    for key, handler in handlers.items():
        if key in p.resources:
            handler(p, p.resources[key])
    if "sqs_queues" in p.resources or "sns_topics" in p.resources:
        _plan_messaging(p)
    for key in p.resources:
        if key not in handlers and key not in ("sqs_queues", "sns_topics"):
            p.skip(key, "unknown resource key")
    if p.resources.get("alarms", []) == []:
        p.collect("alarms", {"in_alarm": "true"},
                  "alarms in ALARM now; alarms that fired and cleared need names in the service map")
    p.collect("changes", *_changes_request(p.resources, case["incident_start"]))
    p.collect("platform", {}, "known AWS service events")
    for dependency in case["target"].get("dependencies", []):
        _plan_dependency(p, dependency)
    return p.commands


def _launch(argv: list[str], timeout: int) -> tuple[int, str]:
    """Run one planned command with this interpreter and this environment. Returns (exit code, stderr)."""
    done = subprocess.run([sys.executable, *argv[1:]], capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    return done.returncode, done.stderr


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:STDERR_LINE_LIMIT] if lines else ""


def _counts(path: Path) -> tuple[int | None, int | None]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        return len(document["facts"]), len(document["errors"])
    except (OSError, ValueError, KeyError, TypeError):
        return None, None


def _run_one(command: PlannedCommand, case_dir: Path, timeout: int, launch: Any) -> dict:
    entry: dict[str, Any] = {"name": command.name, "tool": command.tool, "suffix": command.suffix,
                             "status": "", "exit_code": None, "evidence": None, "facts": None, "errors": None,
                             "stderr": ""}
    if command.tool == SKIPPED:
        return {**entry, "status": "skipped", "stderr": command.reason}
    path = case_dir / command.evidence
    if path.is_file():
        facts, errors = _counts(path)
        return {**entry, "status": "already collected", "evidence": command.evidence, "facts": facts, "errors": errors}
    try:
        code, stderr = launch(command.argv, timeout)
    except subprocess.TimeoutExpired:
        return {**entry, "status": "timed out", "stderr": f"no answer after {timeout} seconds"}
    except OSError as error:
        return {**entry, "status": "not started", "stderr": str(error).replace("\n", " ")[:STDERR_LINE_LIMIT]}
    entry.update(exit_code=code, stderr=_last_line(stderr))
    if code != 0:
        return {**entry, "status": "failed"}
    if path.is_file():
        entry["evidence"] = command.evidence
        entry["facts"], entry["errors"] = _counts(path)
    return {**entry, "status": "collected"}


def run_collection(commands: list[PlannedCommand], case_dir: Path, timeout: int = COMMAND_TIMEOUT_SECONDS,
                   workers: int = COLLECT_WORKERS, launch: Any = None) -> list[dict]:
    """Run the planned commands, at most `workers` at a time, and report each in plan order. A command whose
    evidence file already exists is not run again. A command that fails, cannot start, or times out never stops
    the others."""
    launcher = launch or _launch
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda command: _run_one(command, case_dir, timeout, launcher), commands))
