"""EC2 collector: instance state, status checks, scheduled events, console output tail, CPU and status-check metrics."""
from __future__ import annotations

import re

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso, split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME, MAX_EXCERPT
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

MAX_INSTANCES = 10
# describe-instances states the time of the last state change only inside this free text.
TRANSITION_TIME_RE = re.compile(r"\((\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) GMT\)")
LATEST_RETRY_CODES = ("UnsupportedOperation", "IncorrectInstanceState")


def _time_text(value: object) -> str:
    moment = parse_iso(value)
    return format_time(moment) if moment else "unknown"


def _instances(reply: dict) -> list[dict]:
    return [i for reservation in reply.get("Reservations", []) for i in reservation.get("Instances", [])]


def _add_instance(ctx: CollectContext, instance: dict, entry: dict | None, command: str) -> None:
    """One current fact per instance: state, both status checks, and launch time."""
    instance_id = instance.get("InstanceId")
    resource = f"instance/{instance_id}"
    state = (instance.get("State") or {}).get("Name")
    system, instance_status = _check_status(entry or {}, "SystemStatus"), _check_status(entry or {}, "InstanceStatus")
    reason = instance.get("StateReason") or {}
    reason_text = f"; state reason {reason.get('Code')}: {reason.get('Message')}" if reason.get("Code") else ""
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=command,
        summary=(
            f"Instance {instance_id} is {state}: system status {system}, instance status {instance_status}, "
            f"type {instance.get('InstanceType')}, launched {_time_text(instance.get('LaunchTime'))}, "
            f"zone {(instance.get('Placement') or {}).get('AvailabilityZone')}{reason_text}"
        ),
        data={"state": state, "instance_type": instance.get("InstanceType"),
              "system_status": system, "instance_status": instance_status},
    )
    if in_window(ctx.window, instance.get("LaunchTime")):
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, command=command, time=instance.get("LaunchTime"),
            summary=(f"Instance {instance_id} was launched at {_time_text(instance.get('LaunchTime'))}, "
                     "inside the incident window"),
        )
    match = TRANSITION_TIME_RE.search(instance.get("StateTransitionReason") or "")
    if match:
        moment = f"{match.group(1)}T{match.group(2)}Z"
        if in_window(ctx.window, moment):
            ctx.evidence.add(
                kind=INCIDENT_TIME, resource=resource, command=command, time=moment,
                summary=(f"Instance {instance_id} changed state to {state} at {moment}, inside the incident window "
                         f"({instance.get('StateTransitionReason')})"),
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


def _add_console_tail(ctx: CollectContext, instance_id: str) -> None:
    arguments = ["--instance-id", instance_id]
    reply = ctx.aws("ec2", "get-console-output", [*arguments, "--latest"], not_found=LATEST_RETRY_CODES)
    # Retry without --latest only when it is unsupported, the instance is not ready, or the answer was empty.
    # Any other error (access denied, for one) is already recorded once and a second call would repeat it.
    if was_not_found(ctx, LATEST_RETRY_CODES) or (reply is not None and not reply.get("Output")):
        reply = ctx.aws("ec2", "get-console-output", arguments)
    output = (reply or {}).get("Output")
    if not output:
        return
    # The CLI has already decoded Output. Redact the whole text first so a secret cut by the tail
    # boundary cannot leave a fragment.
    text = ctx.evidence.redactor.text(output)
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
    requested = split_csv(targets["instance_ids"])
    ids = requested[:MAX_INSTANCES]
    if len(requested) > MAX_INSTANCES:
        ctx.evidence.add(
            kind=DERIVED, resource="instances",
            summary=f"{len(requested)} instances were given; only the first {MAX_INSTANCES} were examined",
        )
    # A filter answers unknown ids with fewer results; --instance-ids would fail the whole call.
    reply = ctx.aws("ec2", "describe-instances", ["--filters", f"Name=instance-id,Values={','.join(ids)}"])
    if reply is None:
        return
    describe_command = ctx.last_command
    found = _instances(reply)
    found_ids = {instance.get("InstanceId") for instance in found}
    for instance_id in ids:
        if instance_id not in found_ids:
            ctx.evidence.add(
                kind=CURRENT, resource=f"instance/{instance_id}", command=describe_command,
                summary=f"Instance {instance_id} was not found in {ctx.region}",
            )
    if not found:
        return
    existing = [instance_id for instance_id in ids if instance_id in found_ids]
    unhealthy = {i["InstanceId"] for i in found if (i.get("State") or {}).get("Name") != "running"}
    status = ctx.aws("ec2", "describe-instance-status", ["--instance-ids", *existing, "--include-all-instances"])
    status_command = ctx.last_command if status is not None else ""
    entries = {entry.get("InstanceId"): entry for entry in (status or {}).get("InstanceStatuses", [])}
    for instance in found:
        command = f"{describe_command} ; {status_command}" if status_command else describe_command
        _add_instance(ctx, instance, entries.get(instance["InstanceId"]), command)
    for entry in entries.values():
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
