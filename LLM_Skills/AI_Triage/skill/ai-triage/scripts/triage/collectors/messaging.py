"""Messaging collector: SQS queues (with their dead letter queues) and SNS topics. No message is ever received."""
from __future__ import annotations

import json
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import split_csv, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.metrics import MetricSpec, add_metric_facts

MAX_TARGETS = 10
MAX_SOURCE_QUEUES = "10"
QUEUE_NOT_FOUND = ("QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue")
TOPIC_NOT_FOUND = ("NotFound", "NotFoundException")
QUEUE_METRICS = (
    ("ApproximateAgeOfOldestMessage", "Maximum"), ("ApproximateNumberOfMessagesVisible", "Maximum"),
    ("NumberOfMessagesSent", "Sum"), ("NumberOfMessagesDeleted", "Sum"),
)
TOPIC_METRICS = (("NumberOfNotificationsFailed", "Sum"), ("NumberOfMessagesPublished", "Sum"))
# The only queue attributes a fact may carry; the queue policy and the rest stay out.
SHOWN_ATTRIBUTES = (
    "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible", "ApproximateNumberOfMessagesDelayed",
    "VisibilityTimeout", "MessageRetentionPeriod",
)


def _duration(seconds: int) -> str:
    for size, unit in ((86400, "day"), (3600, "hour")):
        if seconds % size == 0 and seconds:
            count = seconds // size
            return f"{count} {unit}{'s' if count != 1 else ''}"
    return f"{seconds} seconds"


def _counts(attributes: dict[str, Any]) -> tuple[int, int, int]:
    return tuple(  # type: ignore[return-value]
        int(attributes.get(key, 0))
        for key in ("ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible", "ApproximateNumberOfMessagesDelayed")
    )


def _dead_letter_arn(attributes: dict[str, Any]) -> tuple[str | None, Any]:
    policy = attributes.get("RedrivePolicy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            policy = None
    if not isinstance(policy, dict):
        return None, None
    return policy.get("deadLetterTargetArn"), policy.get("maxReceiveCount")


def _queue_summary(name: str, attributes: dict[str, Any]) -> str:
    visible, in_flight, delayed = _counts(attributes)
    target, receives = _dead_letter_arn(attributes)
    dead_letter = f"dead letter queue {target.rsplit(':', 1)[-1]} after {receives} receives" if target else "no dead letter queue"
    return (
        f"Queue {name}: {visible} messages visible, {in_flight} in flight, {delayed} delayed, "
        f"visibility timeout {attributes.get('VisibilityTimeout')} seconds, "
        f"retention {_duration(int(attributes.get('MessageRetentionPeriod', 0)))}, {dead_letter}"
    )


def _collect_queue(ctx: CollectContext, name: str) -> tuple[dict[str, Any] | None, bool]:
    """Read one queue; return its attributes and whether it is the dead letter queue of another queue."""
    resource = f"queue/{name}"
    located = ctx.aws("sqs", "get-queue-url", ["--queue-name", name], not_found=QUEUE_NOT_FOUND)
    url = (located or {}).get("QueueUrl")
    if not url:
        if was_not_found(ctx, QUEUE_NOT_FOUND):
            ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=f"Queue {name} was not found")
        return None, False
    reply = ctx.aws("sqs", "get-queue-attributes", ["--queue-url", url, "--attribute-names", "All"])
    attributes = (reply or {}).get("Attributes")
    if attributes is None:
        return None, False
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        data={"attributes": {key: attributes[key] for key in SHOWN_ATTRIBUTES if key in attributes}},
        summary=_queue_summary(name, attributes),
    )
    sources = ctx.aws("sqs", "list-dead-letter-source-queues", ["--queue-url", url, "--max-items", MAX_SOURCE_QUEUES])
    source_names = [u.rsplit("/", 1)[-1] for u in (sources or {}).get("queueUrls", [])]
    if source_names:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Queue {name} is the dead letter queue for: {', '.join(source_names)}",
        )
    dimensions = {"QueueName": name}
    add_metric_facts(ctx, resource, [MetricSpec(m, "AWS/SQS", m, dimensions, s) for m, s in QUEUE_METRICS])
    return attributes, bool(source_names)


def _flag_dead_letters(ctx: CollectContext, name: str, attributes: dict[str, Any]) -> None:
    visible, in_flight, delayed = _counts(attributes)
    if visible + in_flight + delayed:
        ctx.evidence.add(
            kind=DERIVED, resource=f"queue/{name}",
            summary=f"Dead letter queue {name} holds {visible + in_flight + delayed} messages ({visible} visible, {in_flight} in flight, {delayed} delayed)",
        )


def _collect_queues(ctx: CollectContext, names: list[str]) -> None:
    read: dict[str, dict[str, Any]] = {}
    dead_letter_names: set[str] = set()
    tried: set[str] = set()
    pending = list(names)
    while pending:
        name = pending.pop(0)
        if name in tried:
            continue
        tried.add(name)
        attributes, serves_as_dead_letter = _collect_queue(ctx, name)
        if serves_as_dead_letter:
            dead_letter_names.add(name)
        if attributes is None:
            continue
        read[name] = attributes
        target, _ = _dead_letter_arn(attributes)
        if target:
            dead_letter = target.rsplit(":", 1)[-1]
            dead_letter_names.add(dead_letter)
            pending.append(dead_letter)
    for name in sorted(dead_letter_names & read.keys()):
        _flag_dead_letters(ctx, name, read[name])


def _delivery_text(attributes: dict[str, Any]) -> str:
    for key in ("DeliveryPolicy", "EffectiveDeliveryPolicy"):
        try:
            policy = json.loads(attributes.get(key) or "")
            retries = [p.get("numRetries") for p in policy.get("http", {}).values() if isinstance(p, dict) and "numRetries" in p]
        except (json.JSONDecodeError, AttributeError):
            retries = []
        if retries:
            return f"delivery policy {retries[0]} retries"
    return "default delivery policy"


def _collect_topic(ctx: CollectContext, arn: str) -> None:
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or not parts[3]:
        ctx.evidence.add_error("", "InvalidTarget", f"a topic must be given as an ARN, not {arn!r}")
        return
    name, region = parts[-1], parts[3]
    resource = f"topic/{name}"
    reply = ctx.aws("sns", "get-topic-attributes", ["--topic-arn", arn], region=region, not_found=TOPIC_NOT_FOUND)
    attributes = (reply or {}).get("Attributes")
    if attributes is None:
        if was_not_found(ctx, TOPIC_NOT_FOUND):
            ctx.evidence.add(kind=CURRENT, resource=resource, command=ctx.last_command, summary=f"Topic {name} was not found")
        return
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Topic {name}: {attributes.get('SubscriptionsConfirmed', 0)} subscriptions confirmed, "
            f"{attributes.get('SubscriptionsPending', 0)} pending, {_delivery_text(attributes)}"
        ),
    )
    dimensions = {"TopicName": name}
    add_metric_facts(ctx, resource, [MetricSpec(m, "AWS/SNS", m, dimensions, s) for m, s in TOPIC_METRICS], region=region)


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    _collect_queues(ctx, split_csv(targets.get("queues"))[:MAX_TARGETS])
    for arn in split_csv(targets.get("topics"))[:MAX_TARGETS]:
        _collect_topic(ctx, arn)


COLLECTOR = Collector(
    name="messaging",
    description="SQS queue depth, age, redrive and dead letter queues, and SNS topic subscriptions and failures (no message is received)",
    required=(),
    optional=("queues", "topics"),
    run=collect,
    one_of=("queues", "topics"),
)
