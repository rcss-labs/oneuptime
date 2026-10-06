"""EC2 collector: instance state, status checks, scheduled events, console output tail, CPU and status-check metrics."""
from __future__ import annotations

import base64
import binascii

from triage.collectors import Collector
from triage.collectors.common import parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, MAX_EXCERPT
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_INSTANCES = 10


def _split_ids(text: str) -> list[str]:
    return [part.strip() for part in text.split(",") if part.strip()]


def _time_text(value: object) -> str:
    moment = parse_iso(value)
    return format_time(moment) if moment else "unknown"


def _instances(reply: dict) -> list[dict]:
    return [i for reservation in reply.get("Reservations", []) for i in reservation.get("Instances", [])]


def _add_instance(ctx: CollectContext, instance: dict) -> None:
    instance_id = instance.get("InstanceId")
    state = (instance.get("State") or {}).get("Name")
    reason = instance.get("StateReason") or {}
    reason_text = f"; state reason {reason.get('Code')}: {reason.get('Message')}" if reason.get("Code") else ""
    ctx.evidence.add(
        kind=CURRENT, resource=f"instance/{instance_id}", command=ctx.last_command,
        summary=(
            f"Instance {instance_id} is {state}: type {instance.get('InstanceType')}, "
            f"launched {_time_text(instance.get('LaunchTime'))}, "
            f"zone {(instance.get('Placement') or {}).get('AvailabilityZone')}{reason_text}"
        ),
        data={"state": state, "instance_type": instance.get("InstanceType")},
    )


def _check_status(entry: dict, key: str) -> str:
    return (entry.get(key) or {}).get("Status") or "unknown"


def _add_status(ctx: CollectContext, entry: dict) -> bool:
    """Add facts for a status entry; return True when the instance is not healthy."""
    instance_id = entry.get("InstanceId")
    resource = f"instance/{instance_id}"
    system, instance_status = _check_status(entry, "SystemStatus"), _check_status(entry, "InstanceStatus")
    unhealthy = system != "ok" or instance_status != "ok"
    if unhealthy:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=(
                f"Instance {instance_id} status checks: system status {system}, instance status {instance_status} "
                f"(instance state {(entry.get('InstanceState') or {}).get('Name')})"
            ),
            data={"system_status": system, "instance_status": instance_status},
        )
    for event in entry.get("Events", []):
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=(
                f"Instance {instance_id} has a scheduled event {event.get('Code')}: {event.get('Description')}; "
                f"not before {_time_text(event.get('NotBefore'))}, not after {_time_text(event.get('NotAfter'))}"
            ),
        )
    return unhealthy


def _decode(output: str) -> str:
    try:
        return base64.b64decode(output, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return output


def _add_console_tail(ctx: CollectContext, instance_id: str) -> None:
    reply = ctx.aws("ec2", "get-console-output", ["--instance-id", instance_id, "--latest"])
    output = (reply or {}).get("Output")
    if not output:
        return
    # Redact the whole text first so a secret cut by the tail boundary cannot leave a fragment.
    text = ctx.evidence.redactor.text(_decode(output))
    ctx.evidence.add(
        kind=CURRENT, resource=f"instance/{instance_id}", command=ctx.last_command,
        summary=f"Last console output of unhealthy instance {instance_id}",
        excerpt=text[-MAX_EXCERPT:],
    )


def _add_metrics(ctx: CollectContext, instance_id: str) -> None:
    dimensions = {"InstanceId": instance_id}
    specs = [
        MetricSpec("CPUUtilization", "AWS/EC2", "CPUUtilization", dimensions),
        MetricSpec("StatusCheckFailed", "AWS/EC2", "StatusCheckFailed", dimensions, stat="Maximum"),
    ]
    add_metric_facts(ctx, f"instance/{instance_id}", specs)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    requested = _split_ids(targets["instance_ids"])
    ids = requested[:MAX_INSTANCES]
    if len(requested) > MAX_INSTANCES:
        ctx.evidence.add(
            kind=DERIVED, resource="instances",
            summary=f"{len(requested)} instances were given; only the first {MAX_INSTANCES} were examined",
        )
    reply = ctx.aws("ec2", "describe-instances", ["--instance-ids", *ids])
    if reply is None:
        return
    found = _instances(reply)
    if not found:
        ctx.evidence.add(
            kind=CURRENT, resource="instances", command=ctx.last_command,
            summary=f"Instances {', '.join(ids)} were not found",
        )
        return
    for instance in found:
        _add_instance(ctx, instance)
    unhealthy = {i["InstanceId"] for i in found if (i.get("State") or {}).get("Name") != "running"}
    status = ctx.aws("ec2", "describe-instance-status", ["--instance-ids", *ids, "--include-all-instances"])
    for entry in (status or {}).get("InstanceStatuses", []):
        if _add_status(ctx, entry):
            unhealthy.add(entry.get("InstanceId"))
    for instance in found:
        if instance["InstanceId"] in unhealthy:
            _add_console_tail(ctx, instance["InstanceId"])
    for instance in found:
        _add_metrics(ctx, instance["InstanceId"])


COLLECTOR = Collector(
    name="ec2",
    description="EC2 instance state, status checks, scheduled events, console output tail, CPU and status-check metrics",
    required=("instance_ids",),
    optional=(),
    run=collect,
)
