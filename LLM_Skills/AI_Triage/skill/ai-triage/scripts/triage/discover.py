"""Walk from a hostname to the AWS resources behind it, recording the command behind every step."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Sequence
from urllib.parse import urlparse

from triage.awscli import SSO_EXPIRED, Runner, run_aws, subprocess_runner
from triage.config import Account, TriageConfig
from triage.context import SignInExpired
from triage.redact import Redactor

MAX_TARGET_GROUPS = 10
MAX_DNS_FOLLOWS = 3
MAX_CLUSTERS = 10
SERVICE_BATCH = 10
HOSTNAME_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:\d{1,5})?")


@dataclass
class Step:
    account: str
    region: str
    command: str
    found: str


@dataclass
class Discovery:
    hostname: str
    steps: list[Step]
    account: str | None
    region: str | None
    resources: dict[str, Any]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "steps": [vars(step).copy() for step in self.steps],
            "account": self.account,
            "region": self.region,
            "resources": self.resources,
            "notes": self.notes,
        }

    def proposed_entry(self, monitors: Sequence[str] = (), today: date | None = None) -> dict[str, Any]:
        """A service map entry for this discovery. The caller keys it by a service name."""
        if not self.account or not self.region:
            raise ValueError(f"no account and region were found for {self.hostname}; nothing to propose")
        return {
            "match": {"hostnames": [self.hostname], "monitors": list(monitors)},
            "environments": {
                "discovered": {"account": self.account, "region": self.region, "resources": self.resources}
            },
            "source": "discovered",
            "last_verified": (today or datetime.now(timezone.utc).date()).isoformat(),
        }


def normalise_dns(name: str) -> str:
    name = name.strip().lower().rstrip(".")
    return name[len("dualstack."):] if name.startswith("dualstack.") else name


def hostname_from_value(value: str) -> str | None:
    """The host in a redacted environment value, or None. The value itself is never kept."""
    value = value.strip().lower()
    if "://" in value:
        try:
            return urlparse(value).hostname or None
        except ValueError:
            return None
    if HOSTNAME_RE.fullmatch(value):
        return value.split(":")[0]
    return None


class _Walk:
    def __init__(self, hostname: str, config: TriageConfig, runner: Runner):
        self.config = config
        self.runner = runner
        self.discovery = Discovery(hostname, [], None, None, {}, [])

    def call(self, account: Account, region: str, service: str, operation: str, args: Sequence[str] = ()) -> tuple[Any, str]:
        """Returns (data or None, command text). A failure becomes a note."""
        result = run_aws(service, operation, args, profile=account.profile, region=region, runner=self.runner)
        command = shlex.join(result.argv)
        if result.ok:
            return result.data or {}, command
        if result.error_code == SSO_EXPIRED:
            raise SignInExpired(account.profile)
        self.discovery.notes.append(f"{command}: {result.error_code}")
        return None, command

    def note_if_more(self, data: Any, what: str, limit: int) -> None:
        """A list call that hit its --max-items cap returns a NextToken; say so."""
        if isinstance(data, dict) and data.get("NextToken"):
            self.discovery.notes.append(f"Searched only the first {limit} {what}; more exist")

    def note_cut(self, what: str, kept: int, total: int) -> None:
        if total > kept:
            self.discovery.notes.append(f"Searched the first {kept} of {total} {what}")

    def step(self, account: Account, region: str, command: str, found: str) -> None:
        self.discovery.steps.append(Step(account.alias, region, command, found))

    def resolve_dns(self, accounts: list[Account]) -> str:
        hostname = self.discovery.hostname
        zone_seen = False
        for account in accounts:
            region = account.regions[0]
            zones, command = self.call(account, region, "route53", "list-hosted-zones", ["--max-items", "100"])
            self.note_if_more(zones, "hosted zones", 100)
            zone_list = (zones or {}).get("HostedZones", [])
            zone = _best_zone(hostname, zone_list)
            if zone is None:
                continue
            zone_seen = True
            self.step(account, region, command, f"hosted zone {zone['Name'].rstrip('.')} ({zone['Id'].rsplit('/', 1)[-1]})")
            target = self._follow_records(account, region, zone_list, hostname)
            if target:
                return target
        if zone_seen:
            self.discovery.notes.append(f"no alias or CNAME record for {hostname} was found; using the hostname itself")
        else:
            self.discovery.notes.append(f"no hosted zone matches {hostname}; using the hostname itself")
        return hostname

    def _follow_records(self, account: Account, region: str, zone_list: list[dict], hostname: str) -> str | None:
        """Look up the record, then follow CNAMEs that land in a zone of the same account."""
        name, target = hostname, None
        for follow in range(MAX_DNS_FOLLOWS + 1):
            zone = _best_zone(name, zone_list)
            if zone is None:
                break
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            records, command = self.call(account, region, "route53", "list-resource-record-sets", [
                "--hosted-zone-id", zone_id, "--start-record-name", name, "--max-items", "5"])
            found = _record_target(name, (records or {}).get("ResourceRecordSets", []))
            if found is None:
                break
            next_name, is_cname = found
            self.step(account, region, command, f"{name} points at {next_name}")
            target = next_name
            if not is_cname:
                break
            if follow == MAX_DNS_FOLLOWS:
                self.discovery.notes.append(
                    f"Stopped following DNS records after {MAX_DNS_FOLLOWS} hops; {next_name} was not looked up")
                break
            name = next_name
        return target

    def find_load_balancer(self, accounts: list[Account], dns_name: str) -> tuple[Account, str, dict] | None:
        wanted = normalise_dns(dns_name)
        for account in accounts:
            for region in account.regions:
                data, command = self.call(account, region, "elbv2", "describe-load-balancers", ["--max-items", "100"])
                self.note_if_more(data, "load balancers", 100)
                for balancer in (data or {}).get("LoadBalancers", []):
                    if normalise_dns(balancer.get("DNSName", "")) == wanted:
                        name = balancer["LoadBalancerName"]
                        self.step(account, region, command, f"load balancer {name}")
                        return account, region, balancer
        return None

    def target_groups(self, account: Account, region: str, balancer: dict) -> set[str]:
        data, command = self.call(account, region, "elbv2", "describe-target-groups",
                                  ["--load-balancer-arn", balancer["LoadBalancerArn"]])
        all_arns = [group["TargetGroupArn"] for group in (data or {}).get("TargetGroups", [])]
        self.note_cut("target groups", MAX_TARGET_GROUPS, len(all_arns))
        arns = all_arns[:MAX_TARGET_GROUPS]
        if arns:
            self.step(account, region, command, f"{len(arns)} target group(s)")
        return set(arns)

    def find_ecs_service(self, account: Account, region: str, groups: set[str]) -> dict | None:
        clusters, command = self.call(account, region, "ecs", "list-clusters", ["--max-items", "50"])
        self.note_if_more(clusters, "ECS clusters", 50)
        cluster_arns = (clusters or {}).get("clusterArns", [])
        self.note_cut("ECS clusters", MAX_CLUSTERS, len(cluster_arns))
        for cluster_arn in cluster_arns[:MAX_CLUSTERS]:
            cluster = cluster_arn.rsplit("/", 1)[-1]
            listing, _ = self.call(account, region, "ecs", "list-services", ["--cluster", cluster, "--max-items", "100"])
            self.note_if_more(listing, f"ECS services in cluster {cluster}", 100)
            arns = (listing or {}).get("serviceArns", [])
            for start in range(0, len(arns), SERVICE_BATCH):
                described, command = self.call(account, region, "ecs", "describe-services", [
                    "--cluster", cluster, "--services", *arns[start:start + SERVICE_BATCH]])
                for service in (described or {}).get("services", []):
                    if any(lb.get("targetGroupArn") in groups for lb in service.get("loadBalancers", [])):
                        name = f"{cluster}/{service['serviceName']}"
                        self.step(account, region, command, f"ECS service {name}")
                        return {"name": name, "task_definition": service.get("taskDefinition")}
        return None

    def find_auto_scaling_group(self, account: Account, region: str, groups: set[str]) -> str | None:
        data, command = self.call(account, region, "autoscaling", "describe-auto-scaling-groups", ["--max-items", "50"])
        self.note_if_more(data, "Auto Scaling groups", 50)
        for group in (data or {}).get("AutoScalingGroups", []):
            if groups & set(group.get("TargetGroupARNs", [])):
                self.step(account, region, command, f"Auto Scaling group {group['AutoScalingGroupName']}")
                return group["AutoScalingGroupName"]
        return None

    def dependencies(self, account: Account, region: str, task_definition: str) -> None:
        data, command = self.call(account, region, "ecs", "describe-task-definition", ["--task-definition", task_definition])
        if data is None:
            return
        log_groups, hosts = _log_groups_and_hosts(data.get("taskDefinition", {}))
        resources = self.discovery.resources
        if log_groups:
            resources["log_groups"] = log_groups
            self.step(account, region, command, f"log group(s) {', '.join(log_groups)}")
        for cluster in self.config.opensearch_clusters.values():
            if cluster.host.lower() in hosts:
                resources["opensearch"] = {"cluster": cluster.name}
                self.step(account, region, command, f"OpenSearch cluster {cluster.name} named in the task definition")
                self.discovery.notes.append(
                    f"OpenSearch cluster {cluster.name} is used, but its index pattern must be filled in by hand")
                break
        if not hosts:
            return
        self._match_rds(account, region, hosts)
        self._match_elasticache(account, region, hosts)

    def _match_rds(self, account: Account, region: str, hosts: set[str]) -> None:
        for operation, key, id_key, what in (
            ("describe-db-instances", "DBInstances", "DBInstanceIdentifier", "database instances"),
            ("describe-db-clusters", "DBClusters", "DBClusterIdentifier", "database clusters"),
        ):
            data, command = self.call(account, region, "rds", operation, ["--max-items", "100"])
            self.note_if_more(data, what, 100)
            for item in (data or {}).get(key, []):
                addresses = [item.get("Endpoint", {}).get("Address")] if operation == "describe-db-instances" else [
                    item.get("Endpoint"), item.get("ReaderEndpoint")]
                if any(isinstance(a, str) and a.lower() in hosts for a in addresses):
                    self.discovery.resources["rds"] = item[id_key]
                    self.step(account, region, command, f"database {item[id_key]}")
                    return

    def _match_elasticache(self, account: Account, region: str, hosts: set[str]) -> None:
        data, command = self.call(account, region, "elasticache", "describe-replication-groups", ["--max-items", "100"])
        self.note_if_more(data, "cache replication groups", 100)
        for group in (data or {}).get("ReplicationGroups", []):
            endpoints = [group.get("ConfigurationEndpoint") or {}]
            endpoints += [node.get("PrimaryEndpoint") or {} for node in group.get("NodeGroups", [])]
            if any(str(e.get("Address", "")).lower() in hosts for e in endpoints):
                self.discovery.resources["elasticache"] = group["ReplicationGroupId"]
                self.step(account, region, command, f"cache {group['ReplicationGroupId']}")
                return


def _best_zone(hostname: str, zones: list[dict]) -> dict | None:
    matching = [z for z in zones if hostname == z["Name"].rstrip(".").lower()
                or hostname.endswith("." + z["Name"].rstrip(".").lower())]
    return max(matching, key=lambda z: len(z["Name"]), default=None)


def _record_target(hostname: str, records: list[dict]) -> tuple[str, bool] | None:
    """The next DNS name for the record called `hostname`, and whether it came from a CNAME."""
    for record in records:
        if record.get("Name", "").rstrip(".").lower() != hostname:
            continue
        alias = (record.get("AliasTarget") or {}).get("DNSName")
        if alias:
            return alias.rstrip("."), False
        if record.get("Type") == "CNAME" and record.get("ResourceRecords"):
            return record["ResourceRecords"][0]["Value"].rstrip(".").lower(), True
    return None


def _log_groups_and_hosts(task_definition: dict) -> tuple[list[str], set[str]]:
    redactor = Redactor()
    log_groups: list[str] = []
    hosts: set[str] = set()
    for container in task_definition.get("containerDefinitions", []):
        group = ((container.get("logConfiguration") or {}).get("options") or {}).get("awslogs-group")
        if group and group not in log_groups:
            log_groups.append(group)
        for entry in container.get("environment", []):
            value = redactor.value({"name": entry.get("name", ""), "value": entry.get("value", "")}).get("value")
            host = hostname_from_value(value) if isinstance(value, str) else None
            if host:
                hosts.add(host)
    return log_groups, hosts


def discover_hostname(
    hostname: str,
    config: TriageConfig,
    runner: Runner = subprocess_runner,
    accounts: Sequence[str] = (),
) -> Discovery:
    unknown = [alias for alias in accounts if alias not in config.accounts]
    if unknown:
        raise ValueError(f"unknown account {', '.join(unknown)}; configured: {', '.join(config.accounts)}")
    searched = [config.accounts[alias] for alias in accounts] or list(config.accounts.values())
    walk = _Walk(hostname.strip().lower().rstrip("."), config, runner)
    dns_name = walk.resolve_dns(searched)
    located = walk.find_load_balancer(searched, dns_name)
    discovery = walk.discovery
    if located is None:
        discovery.notes.append(f"no load balancer with DNS name {dns_name} was found")
        return discovery
    account, region, balancer = located
    discovery.account, discovery.region = account.alias, region
    discovery.resources["load_balancer"] = balancer["LoadBalancerName"]
    groups = walk.target_groups(account, region, balancer)
    service = walk.find_ecs_service(account, region, groups) if groups else None
    if service:
        discovery.resources["ecs_service"] = service["name"]
        if service["task_definition"]:
            walk.dependencies(account, region, service["task_definition"])
    elif groups:
        asg = walk.find_auto_scaling_group(account, region, groups)
        if asg:
            discovery.resources["auto_scaling_group"] = asg
    return discovery
