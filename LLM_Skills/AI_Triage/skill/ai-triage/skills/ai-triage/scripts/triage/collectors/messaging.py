"""Messaging collector: SQS queues (with their dead letter queues) and SNS topics. No message is ever received."""
from __future__ import annotations

import json
from typing import Any

from triage.collectors import Collector
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED
from triage.metrics import MetricSpec, add_metric_facts

MAX_TARGETS = 10
MAX_SOURCE_QUEUES = "10"
MISSING_MARKERS = ("NotFound", "NonExistent", "DoesNotExist", "does not exist")
QUEUE_METRICS = (
    ("ApproximateAgeOfOldestMessage", "Maximum"), ("ApproximateNumberOfMessagesVisible", "Maximum"),
    ("NumberOfMessagesSent", "Sum"), ("NumberOfMessagesDeleted", "Sum"),
)
TOPIC_METRICS = (("NumberOfNotificationsFailed", "Sum"), ("NumberOfMessagesPublished", "Sum"))


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()][:MAX_TARGETS]


def _last_call_found_nothing(ctx: CollectContext) -> bool:
    if not ctx.evidence.errors:
        return False
    error = ctx.evidence.errors[-1]
    return any(marker in error["code"] or marker in error["message"] for marker in MISSING_MARKERS)


def _duration(seconds: int) -> str:
    if seconds % 86400 == 0:
        days = seconds // 86400
        return f"{days} day{'s' if days != 1 else ''}"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} hours"
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


def _collect_queue(ctx: CollectContext, name: str) -> dict[str, Any] | None:
    resource = f"queue/{name}"
    located = ctx.aws("sqs", "get-queue-url", ["--queue-name", name])
    url = (located or {}).get("QueueUrl")
    if not url:
        if _last_call_found_nothing(ctx):
            ctx.evidence.add(kind=CURRENT, resource=resource, summary=f"Queue {name} was not found")
        return None
    reply = ctx.aws("sqs", "get-queue-attributes", ["--queue-url", url, "--attribute-names", "All"])
    attributes = (reply or {}).get("Attributes")
    if attributes is None:
        return None
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command, data={"attributes": attributes},
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
    return attributes


def _flag_dead_letters(ctx: CollectContext, name: str, attributes: dict[str, Any]) -> None:
    visible, in_flight, delayed = _counts(attributes)
    if visible + in_flight + delayed:
        ctx.evidence.add(
            kind=DERIVED, resource=f"queue/{name}",
            summary=f"Dead letter queue {name} holds {visible + in_flight + delayed} messages ({visible} visible, {in_flight} in flight, {delayed} delayed)",
        )


def _collect_queues(ctx: CollectContext, names: list[str]) -> None:
    done: set[str] = set()
    for name in names:
        if name in done:
            continue
        done.add(name)
        attributes = _collect_queue(ctx, name)
        target, _ = _dead_letter_arn(attributes or {})
        if target and target.rsplit(":", 1)[-1] not in done:
            dead_letter = target.rsplit(":", 1)[-1]
            done.add(dead_letter)
            dead_attributes = _collect_queue(ctx, dead_letter)
            if dead_attributes is not None:
                _flag_dead_letters(ctx, dead_letter, dead_attributes)


def _delivery_text(attributes: dict[str, Any]) -> str:
    try:
        policy = json.loads(attributes.get("DeliveryPolicy") or "")
        retries = [p.get("numRetries") for p in policy.get("http", {}).values() if isinstance(p, dict) and "numRetries" in p]
    except (json.JSONDecodeError, AttributeError):
        retries = []
    return f"delivery policy {retries[0]} retries" if retries else "default delivery policy"


def _collect_topic(ctx: CollectContext, arn: str) -> None:
    name = arn.rsplit(":", 1)[-1]
    resource = f"topic/{name}"
    reply = ctx.aws("sns", "get-topic-attributes", ["--topic-arn", arn])
    attributes = (reply or {}).get("Attributes")
    if attributes is None:
        if _last_call_found_nothing(ctx):
            ctx.evidence.add(kind=CURRENT, resource=resource, summary=f"Topic {name} was not found")
        return
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Topic {name}: {attributes.get('SubscriptionsConfirmed', 0)} subscriptions confirmed, "
            f"{attributes.get('SubscriptionsPending', 0)} pending, {_delivery_text(attributes)}"
        ),
    )
    dimensions = {"TopicName": name}
    add_metric_facts(ctx, resource, [MetricSpec(m, "AWS/SNS", m, dimensions, s) for m, s in TOPIC_METRICS])


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    queues, topics = _split(targets.get("queues", "")), _split(targets.get("topics", ""))
    if not queues and not topics:
        ctx.evidence.add(
            kind=DERIVED, resource="messaging",
            summary="No queues or topics were given: pass queues (comma-separated queue names) or topics (comma-separated topic ARNs), so nothing was read",
        )
        return
    _collect_queues(ctx, queues)
    for arn in topics:
        _collect_topic(ctx, arn)


COLLECTOR = Collector(
    name="messaging",
    description="SQS queue depth, age, redrive and dead letter queues, and SNS topic subscriptions and failures (no message is received)",
    required=(),
    optional=("queues", "topics"),
    run=collect,
)
