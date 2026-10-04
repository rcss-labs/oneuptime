"""Load, validate, and match the service map (service-map.yaml)."""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from triage.config import INDEX_PATTERN_RULE, SIMPLE_NAME_RE, TriageConfig, is_index_pattern, is_simple_name

MAP_FILE_NAME = "service-map.yaml"
MAX_SERVICE_NAME_LENGTH = 63
SOURCES = ("confirmed", "discovered")
RESOURCE_KEYS = frozenset(
    {
        "ecs_service",
        "ec2_instances",
        "auto_scaling_group",
        "lambda_functions",
        "eks",
        "load_balancer",
        "api_gateway",
        "cloudfront_distribution",
        "rds",
        "elasticache",
        "dynamodb_tables",
        "efs",
        "sqs_queues",
        "sns_topics",
        "log_groups",
        "opensearch",
    }
)


class MapError(Exception):
    """Raised with every problem found, not just the first."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _normalise(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(str(v).strip().lower().rstrip(".") for v in values if str(v).strip())


@dataclass(frozen=True)
class MatchKeys:
    monitors: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()

    @classmethod
    def build(cls, monitors: Any = (), labels: Any = (), hostnames: Any = ()) -> "MatchKeys":
        return cls(_normalise(monitors), _normalise(labels), _normalise(hostnames))

    def is_empty(self) -> bool:
        return not (self.monitors or self.labels or self.hostnames)

    def hits(self, incident: "MatchKeys") -> tuple[str, ...]:
        """Return one reason per key this block shares with the incident."""
        reasons = [f"monitor:{m}" for m in self.monitors if m in incident.monitors]
        reasons += [f"label:{l}" for l in self.labels if l in incident.labels]
        reasons += [f"hostname:{h}" for h in self.hostnames if h in incident.hostnames]
        return tuple(reasons)


@dataclass(frozen=True)
class Environment:
    name: str
    account: str
    region: str
    resources: dict[str, Any]
    depends_on: tuple[str, ...]
    match: MatchKeys = field(default_factory=MatchKeys)


@dataclass(frozen=True)
class Service:
    name: str
    match: MatchKeys
    environments: dict[str, Environment]
    source: str
    last_verified: str


@dataclass(frozen=True)
class ServiceMap:
    services: dict[str, Service]


@dataclass(frozen=True)
class Candidate:
    service: str
    environment: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MatchResult:
    status: str  # "one" | "many" | "none"
    candidates: tuple[Candidate, ...]


def _parse_match(raw: Any, where: str, errors: list[str]) -> MatchKeys:
    if raw is None:
        return MatchKeys()
    if not isinstance(raw, dict):
        errors.append(f"{where}.match: must be a mapping")
        return MatchKeys()
    for key in raw:
        if key not in ("monitors", "labels", "hostnames"):
            errors.append(f"{where}.match.{key}: unknown key")
    return MatchKeys.build(raw.get("monitors"), raw.get("labels"), raw.get("hostnames"))


def _check_resources(resources: dict[str, Any], where: str, config: TriageConfig, errors: list[str]) -> None:
    for key in resources:
        if key not in RESOURCE_KEYS:
            errors.append(f"{where}.resources.{key}: unknown resource key")
    search = resources.get("opensearch")
    if search is not None:
        if not isinstance(search, dict):
            errors.append(f"{where}.resources.opensearch: must be a mapping")
        else:
            cluster = config.opensearch_clusters.get(str(search.get("cluster")))
            pattern = search.get("index_pattern", "")
            if cluster is None:
                errors.append(f"{where}.resources.opensearch.cluster: unknown cluster '{search.get('cluster')}'")
            if not is_index_pattern(pattern):
                errors.append(
                    f"{where}.resources.opensearch.index_pattern: {pattern!r} {INDEX_PATTERN_RULE}"
                )
            elif cluster is not None and not any(fnmatchcase(pattern, allowed) for allowed in cluster.allowed_index_patterns):
                errors.append(
                    f"{where}.resources.opensearch.index_pattern: '{pattern}' is outside the allowed patterns"
                )
    eks = resources.get("eks")
    if eks is not None:
        if not isinstance(eks, dict):
            errors.append(f"{where}.resources.eks: must be a mapping")
        else:
            if str(eks.get("cluster")) not in config.eks_clusters:
                errors.append(f"{where}.resources.eks.cluster: unknown cluster '{eks.get('cluster')}'")
            namespace = eks.get("namespace")
            if not isinstance(namespace, str) or not namespace.strip():
                errors.append(f"{where}.resources.eks.namespace: must be set")
            elif not is_simple_name(namespace):
                errors.append(
                    f"{where}.resources.eks.namespace: must use lower-case letters, digits, and dashes only"
                )


def _parse_environment(name: str, raw: Any, where: str, config: TriageConfig, errors: list[str]) -> Environment | None:
    if not isinstance(raw, dict):
        errors.append(f"{where}: must be a mapping")
        return None
    account = str(raw.get("account", ""))
    region = str(raw.get("region", ""))
    if account not in config.accounts:
        errors.append(f"{where}.account: unknown account '{account}'")
    elif region not in config.accounts[account].regions:
        errors.append(f"{where}.region: '{region}' is not listed for account '{account}'")
    resources = raw.get("resources") or {}
    if not isinstance(resources, dict):
        errors.append(f"{where}.resources: must be a mapping")
        resources = {}
    _check_resources(resources, where, config, errors)
    depends_on = raw.get("depends_on") or []
    if not isinstance(depends_on, list):
        errors.append(f"{where}.depends_on: must be a list")
        depends_on = []
    return Environment(
        name=name,
        account=account,
        region=region,
        resources=resources,
        depends_on=tuple(str(d) for d in depends_on),
        match=_parse_match(raw.get("match"), where, errors),
    )


def parse_map(data: Any, config: TriageConfig) -> ServiceMap:
    errors: list[str] = []
    if not isinstance(data, dict) or not isinstance(data.get("services", {}), dict):
        raise MapError(["service map: must be a mapping with a 'services' mapping"])
    services: dict[str, Service] = {}
    for name, raw in (data.get("services") or {}).items():
        where = f"services.{name}"
        if not isinstance(name, str):
            errors.append("services: every service name must be a string; quote it")
            continue
        if len(name) > MAX_SERVICE_NAME_LENGTH or SIMPLE_NAME_RE.fullmatch(name) is None:
            errors.append(
                f"{where}: name must start with a lower-case letter or digit, use only lower-case letters, "
                f"digits, and dashes, and be at most {MAX_SERVICE_NAME_LENGTH} characters"
            )
        if not isinstance(raw, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        match = _parse_match(raw.get("match"), where, errors)
        raw_envs = raw.get("environments")
        if not isinstance(raw_envs, dict) or not raw_envs:
            errors.append(f"{where}.environments: at least one environment is required")
            raw_envs = {}
        environments: dict[str, Environment] = {}
        for env_name, env_raw in raw_envs.items():
            env = _parse_environment(str(env_name), env_raw, f"{where}.environments.{env_name}", config, errors)
            if env is not None:
                environments[str(env_name)] = env
        if match.is_empty() and any(env.match.is_empty() for env in environments.values()):
            errors.append(f"{where}: needs a match block on the service or on every environment")
        source = raw.get("source", "confirmed")
        if source not in SOURCES:
            errors.append(f"{where}.source: must be one of {', '.join(SOURCES)}")
        last_verified = raw.get("last_verified")
        if isinstance(last_verified, datetime.date):
            last_verified = last_verified.isoformat()
        try:
            datetime.date.fromisoformat(str(last_verified))
        except ValueError:
            errors.append(f"{where}.last_verified: must be a date such as 2026-10-04")
        services[str(name)] = Service(str(name), match, environments, str(source), str(last_verified))

    for service in services.values():
        for env in service.environments.values():
            for dependency in env.depends_on:
                if dependency not in services:
                    errors.append(
                        f"services.{service.name}.environments.{env.name}.depends_on: unknown service '{dependency}'"
                    )
    if errors:
        raise MapError(errors)
    return ServiceMap(services)


def load_map(path: Path, config: TriageConfig) -> ServiceMap:
    if not path.is_file():
        raise MapError([f"{path}: file not found"])
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise MapError([f"{path}: not valid YAML ({exc})"]) from exc
    return parse_map(data if data is not None else {"services": {}}, config)


def default_map_path(skill_dir: Path) -> Path:
    return skill_dir / "config" / MAP_FILE_NAME


def match_incident(service_map: ServiceMap, incident: MatchKeys) -> MatchResult:
    """Find the service environments an incident points at.

    An environment with its own match block is chosen only when that block
    hits. Environments without one inherit the service-level match.
    """
    candidates: list[Candidate] = []
    for service in service_map.services.values():
        service_hits = service.match.hits(incident)
        own_hits = {name: env.match.hits(incident) for name, env in service.environments.items()}
        if any(own_hits.values()):
            for name, hits in own_hits.items():
                if hits:
                    candidates.append(Candidate(service.name, name, service_hits + hits))
        elif service_hits:
            for name, env in service.environments.items():
                if env.match.is_empty():
                    candidates.append(Candidate(service.name, name, service_hits))
    status = "none" if not candidates else "one" if len(candidates) == 1 else "many"
    return MatchResult(status, tuple(candidates))
