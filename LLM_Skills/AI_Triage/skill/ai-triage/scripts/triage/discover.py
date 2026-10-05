"""Walk from a hostname to the AWS resources behind it, recording the command behind every step."""
from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from triage.awscli import SSO_EXPIRED, UNKNOWN, Runner, run_aws, subprocess_runner
from triage.config import Account, TriageConfig
from triage.context import SignInExpired
from triage.guard import KUBECONFIG_NAME
from triage.kubectl import run_kubectl
from triage.redact import Redactor

MAX_TARGET_GROUPS = 10
MAX_DNS_FOLLOWS = 3
MAX_EKS_CLUSTERS = 3
MAX_PODS = 5000
RUNNING_PODS = "status.phase=Running"
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
    tried: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "steps": [vars(step).copy() for step in self.steps],
            "account": self.account,
            "region": self.region,
            "resources": self.resources,
            "notes": self.notes,
            "tried": self.tried,
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
    def __init__(self, hostname: str, config: TriageConfig, runner: Runner,
                 kube_runner: Runner = subprocess_runner, skill_dir: Path | None = None):
        self.config = config
        self.runner = runner
        self.kube_runner = kube_runner
        self.skill_dir = skill_dir
        self.discovery = Discovery(hostname, [], None, None, {}, [])

    def call(self, account: Account, region: str, service: str, operation: str, args: Sequence[str] = ()) -> tuple[Any, str]:
        """Returns (data or None, command text). A failure becomes a note."""
        result = run_aws(service, operation, args, profile=account.profile, region=region, runner=self.runner)
        command = shlex.join(result.argv)
        if result.ok:
            return result.data or {}, command
        if result.error_code == SSO_EXPIRED:
            raise SignInExpired(account.profile)
        code = result.error_code
        if code == UNKNOWN:
            code = _error_class(result.error_message or "") or code
        self.discovery.notes.append(f"{service} {operation} failed: {code}")
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
            self.discovery.tried.append(f"Route 53 hosted zones in account {account.alias}")
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
        name, target, seen = hostname, None, [hostname]
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
            if next_name in seen:
                self.discovery.notes.append(f"DNS records form a loop: {' → '.join([*seen, next_name])}")
                break
            seen.append(next_name)
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
                self.discovery.tried.append(f"load balancers in account {account.alias} region {region} named {wanted}")
                data, command = self.call(account, region, "elbv2", "describe-load-balancers", ["--max-items", "100"])
                self.note_if_more(data, "load balancers", 100)
                for balancer in (data or {}).get("LoadBalancers", []):
                    if normalise_dns(balancer.get("DNSName", "")) == wanted:
                        name = balancer["LoadBalancerName"]
                        self.step(account, region, command, f"load balancer {name}")
                        return account, region, balancer
        return None

    def target_groups(self, account: Account, region: str, balancer: dict) -> tuple[set[str], list[str]]:
        """The target group ARNs (at most 10) and the ARNs of those whose targets are IP addresses."""
        data, command = self.call(account, region, "elbv2", "describe-target-groups",
                                  ["--load-balancer-arn", balancer["LoadBalancerArn"]])
        found = (data or {}).get("TargetGroups", [])
        self.note_cut("target groups", MAX_TARGET_GROUPS, len(found))
        kept = found[:MAX_TARGET_GROUPS]
        if kept:
            self.step(account, region, command, f"{len(kept)} target group(s)")
        arns = {group["TargetGroupArn"] for group in kept}
        ip_arns = [group["TargetGroupArn"] for group in kept if group.get("TargetType") == "ip"]
        return arns, ip_arns

    def target_addresses(self, account: Account, region: str, group_arns: list[str]) -> set[str]:
        addresses: set[str] = set()
        for arn in group_arns:
            data, command = self.call(account, region, "elbv2", "describe-target-health", ["--target-group-arn", arn])
            ids = [(d.get("Target") or {}).get("Id", "") for d in (data or {}).get("TargetHealthDescriptions", [])]
            found = {i for i in ids if i and ":" not in i.split("/")[0] and i.replace(".", "").isdigit()}
            if found:
                self.step(account, region, command, f"{len(found)} IP target(s)")
            addresses |= found
        return addresses

    def find_eks_workload(self, account: Account, region: str, addresses: set[str]) -> None:
        clusters = [c for c in self.config.eks_clusters.values() if c.account == account.alias and c.region == region]
        if not clusters:
            self.discovery.notes.append(
                f"no EKS cluster is configured for account {account.alias} in {region}; the pods behind the IP targets were not looked up")
            return
        if self.skill_dir is None:
            self.discovery.notes.append("no skill directory was given, so the EKS clusters were not asked for pods")
            return
        self.note_cut("EKS clusters", MAX_EKS_CLUSTERS, len(clusters))
        for cluster in clusters[:MAX_EKS_CLUSTERS]:
            self.discovery.tried.append(f"pods in EKS cluster {cluster.name}")
            result = run_kubectl(
                ["get", "pods", "-o", "json", "--field-selector", RUNNING_PODS],
                kubeconfig=self.skill_dir / "config" / KUBECONFIG_NAME, context=cluster.context,
                all_namespaces=True, runner=self.kube_runner)
            command = shlex.join(result.argv)
            try:
                items = json.loads(result.stdout).get("items", []) if result.ok else None
            except (ValueError, AttributeError):
                items = None
            if items is None:
                reason = _error_class(result.error_message or "") if not result.ok else None
                self.discovery.notes.append(
                    f"EKS cluster {cluster.name} could not be read" + (f" ({reason})" if reason else ""))
                continue
            self.note_cut(f"pods in EKS cluster {cluster.name}", MAX_PODS, len(items))
            matched = _matching_pods(items[:MAX_PODS], addresses)
            if not matched:
                self.discovery.notes.append(f"no pod in EKS cluster {cluster.name} has the target IP addresses")
                continue
            namespace = Counter(pod["namespace"] for pod in matched).most_common(1)[0][0]
            workloads = sorted({pod["workload"] for pod in matched if pod["namespace"] == namespace and pod["workload"]})
            others = sorted({pod["namespace"] for pod in matched} - {namespace})
            if others:
                self.discovery.notes.append(
                    f"target IP addresses also match pods in namespace(s) {', '.join(others)}; using {namespace}")
            eks: dict[str, Any] = {"cluster": cluster.name, "namespace": namespace}
            if workloads:
                eks["workloads"] = workloads
            self.discovery.resources["eks"] = eks
            self.step(account, region, command,
                      f"{len(matched)} pod(s) in {cluster.name}/{namespace}"
                      + (f": {', '.join(workloads)}" if workloads else ""))
            return

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


_ERROR_CLASSES = (
    ("forbidden", ("forbidden",)),
    ("unauthorized", ("unauthorized", "must be logged in")),
    ("not found", ("notfound", "not found")),
    ("timeout", ("no answer within", "timeout", "timed out", "deadline exceeded")),
    ("connection", ("unable to connect", "connection refused", "no such host", "unreachable", "could not connect")),
    ("AccessDenied", ("not authorized", "access denied", "accessdenied")),
)


def _error_class(message: str) -> str | None:
    """A short class for an error message; the message itself is never kept."""
    lowered = message.lower()
    return next((name for name, words in _ERROR_CLASSES if any(word in lowered for word in words)), None)


def _owner_workload(pod: dict) -> str | None:
    """The workload that owns a pod, from its own ownerReferences only (no second call)."""
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    owner = next((o for o in owners if o.get("controller")), owners[0] if owners else None)
    if not owner or not owner.get("name"):
        return None
    kind, name = str(owner.get("kind", "")), owner["name"]
    if kind == "ReplicaSet":
        # A Deployment names its ReplicaSets <deployment>-<pod-template-hash>.
        deployment = name.rsplit("-", 1)[0] if "-" in name else None
        return f"deployment/{deployment}" if deployment else f"replicaset/{name}"
    return f"{kind.lower()}/{name}"


def _matching_pods(items: list[dict], addresses: set[str]) -> list[dict]:
    """Keep only name, namespace, IP, node and owner of the pods whose IP is a target."""
    matched = []
    for item in items:
        ip = (item.get("status") or {}).get("podIP")
        if ip in addresses:
            metadata = item.get("metadata") or {}
            matched.append({
                "name": metadata.get("name"), "namespace": metadata.get("namespace"), "ip": ip,
                "node": (item.get("spec") or {}).get("nodeName"), "workload": _owner_workload(item),
            })
    return matched


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
    kube_runner: Runner = subprocess_runner,
    skill_dir: Path | None = None,
) -> Discovery:
    unknown = [alias for alias in accounts if alias not in config.accounts]
    if unknown:
        raise ValueError(f"unknown account {', '.join(unknown)}; configured: {', '.join(config.accounts)}")
    searched = [config.accounts[alias] for alias in accounts] or list(config.accounts.values())
    walk = _Walk(hostname.strip().lower().rstrip("."), config, runner, kube_runner, skill_dir)
    dns_name = walk.resolve_dns(searched)
    located = walk.find_load_balancer(searched, dns_name)
    discovery = walk.discovery
    if located is None:
        discovery.notes.append(f"no load balancer with DNS name {dns_name} was found")
        return discovery
    account, region, balancer = located
    discovery.account, discovery.region = account.alias, region
    discovery.resources["load_balancer"] = balancer["LoadBalancerName"]
    groups, ip_groups = walk.target_groups(account, region, balancer)
    service = walk.find_ecs_service(account, region, groups) if groups else None
    if service:
        discovery.resources["ecs_service"] = service["name"]
        if service["task_definition"]:
            walk.dependencies(account, region, service["task_definition"])
    elif groups:
        asg = walk.find_auto_scaling_group(account, region, groups)
        if asg:
            discovery.resources["auto_scaling_group"] = asg
        elif ip_groups:
            addresses = walk.target_addresses(account, region, ip_groups)
            if addresses:
                walk.find_eks_workload(account, region, addresses)
    return discovery
