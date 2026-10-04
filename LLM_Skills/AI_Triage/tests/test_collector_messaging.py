import json

from fakes import FakeAws, access_denied
from helpers import assert_read_only, make_context
from triage.collectors.messaging import COLLECTOR

ACCOUNT = "111111111111"
TOPIC_ARN = f"arn:aws:sns:eu-west-1:{ACCOUNT}:order-events"
DLQ_ARN = f"arn:aws:sqs:eu-west-1:{ACCOUNT}:orders-dlq"
NOT_FOUND = (254, "An error occurred (QueueDoesNotExist) when calling the GetQueueUrl operation: The specified queue does not exist.")


def attributes(visible=5, in_flight=2, delayed=0, dead_letter=None, **extra):
    body = {"ApproximateNumberOfMessages": str(visible), "ApproximateNumberOfMessagesNotVisible": str(in_flight),
            "ApproximateNumberOfMessagesDelayed": str(delayed), "VisibilityTimeout": "30", "MessageRetentionPeriod": "345600"}
    if dead_letter:
        body["RedrivePolicy"] = json.dumps({"deadLetterTargetArn": dead_letter, "maxReceiveCount": 5})
    body.update(extra)
    return {"Attributes": body}


class PerQueue(FakeAws):
    """Serves queue URLs and attributes by queue name, so a queue and its dead letter queue can differ."""

    def __init__(self, answers, attribute_replies):
        super().__init__(answers)
        self.attribute_replies = attribute_replies

    def __call__(self, argv, timeout):
        if argv[1:3] == ["sqs", "get-queue-url"]:
            self.answers["sqs get-queue-url"] = {"QueueUrl": f"https://sqs.eu-west-1.example.com/{ACCOUNT}/{argv[argv.index('--queue-name') + 1]}"}
        if argv[1:3] == ["sqs", "get-queue-attributes"]:
            name = argv[argv.index("--queue-url") + 1].rsplit("/", 1)[-1]
            self.answers["sqs get-queue-attributes"] = self.attribute_replies[name]
        return super().__call__(argv, timeout)


def base_answers(**extra):
    answers = {
        "sqs get-queue-url": {"QueueUrl": f"https://sqs.eu-west-1.example.com/{ACCOUNT}/orders"},
        "sqs get-queue-attributes": attributes(),
        "sqs list-dead-letter-source-queues": {"queueUrls": []},
        "sns get-topic-attributes": {"Attributes": {"SubscriptionsConfirmed": "3", "SubscriptionsPending": "1", "DeliveryPolicy": json.dumps({"http": {"defaultHealthyRetryPolicy": {"numRetries": 3}}})}},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, targets, answers=None, fake=None):
    ctx, aws, _ = make_context(config_data, tmp_path, answers or base_answers(), collector="messaging")
    if fake is not None:
        ctx.runner, aws = fake, fake
    COLLECTOR.run(ctx, targets)
    return ctx, aws


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "messaging"
    assert COLLECTOR.required == ()
    assert COLLECTOR.optional == ("queues", "topics")


def test_neither_target_explains_and_makes_no_call(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, {})
    assert aws.calls == []
    assert len(ctx.evidence.facts) == 1
    fact = ctx.evidence.facts[0]
    assert fact.kind == "derived" and "queues" in fact.summary and "topics" in fact.summary
    assert ctx.evidence.errors == []


def test_blank_targets_count_as_missing(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, {"queues": " , ", "topics": ""})
    assert aws.calls == [] and len(ctx.evidence.facts) == 1


def test_healthy_queue(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, {"queues": "orders"})
    state = ctx.evidence.facts[0]
    assert state.kind == "current" and state.id == "messaging-0001"
    for word in ("Queue orders", "5 messages visible", "2 in flight", "0 delayed", "visibility timeout 30 seconds",
                 "retention 4 days", "no dead letter queue"):
        assert word in state.summary
    call = aws.called("sqs", "get-queue-attributes")[0]
    assert call[call.index("--attribute-names") + 1] == "All"
    assert aws.called("sqs", "get-queue-url")[0][aws.called("sqs", "get-queue-url")[0].index("--queue-name") + 1] == "orders"
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws)


def test_no_message_is_ever_received(config_data, tmp_path):
    _, aws = run(config_data, tmp_path, {"queues": "orders", "topics": TOPIC_ARN})
    assert not any("receive-message" in argv for argv in aws.calls)
    assert {argv[2] for argv in aws.calls if argv[1] == "sqs"} <= {"get-queue-url", "get-queue-attributes", "list-dead-letter-source-queues"}


def test_queue_metrics(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [900.0]}]}
    ctx, aws = run(config_data, tmp_path, {"queues": "orders"}, base_answers(**{"cloudwatch get-metric-data": results}))
    assert by_summary(ctx, "ApproximateAgeOfOldestMessage (Maximum): peak 900.0")
    call = aws.called("cloudwatch", "get-metric-data")[0]
    queries = json.loads(call[call.index("--metric-data-queries") + 1])
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stats == {"ApproximateAgeOfOldestMessage": "Maximum", "ApproximateNumberOfMessagesVisible": "Maximum",
                     "NumberOfMessagesSent": "Sum", "NumberOfMessagesDeleted": "Sum"}
    assert queries[0]["MetricStat"]["Metric"]["Namespace"] == "AWS/SQS"
    assert queries[0]["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "QueueName", "Value": "orders"}]


def test_dead_letter_queue_is_inspected_and_flagged_when_it_holds_messages(config_data, tmp_path):
    answers = base_answers()
    fake = PerQueue(answers, {"orders": attributes(dead_letter=DLQ_ARN), "orders-dlq": attributes(visible=12, in_flight=0)})
    ctx, aws = run(config_data, tmp_path, {"queues": "orders"}, answers, fake=fake)
    assert "dead letter queue orders-dlq after 5 receives" in by_summary(ctx, "Queue orders:")[0].summary
    dlq_state = by_summary(ctx, "Queue orders-dlq:")[0]
    assert "12 messages visible" in dlq_state.summary
    derived = by_summary(ctx, "holds")[0]
    assert derived.kind == "derived"
    assert "orders-dlq" in derived.summary and "12" in derived.summary
    names = [argv[argv.index("--queue-name") + 1] for argv in aws.called("sqs", "get-queue-url")]
    assert names == ["orders", "orders-dlq"]
    metric_calls = aws.called("cloudwatch", "get-metric-data")
    assert len(metric_calls) == 4
    assert_read_only(ctx, aws)


def test_empty_dead_letter_queue_has_no_derived_fact(config_data, tmp_path):
    fake = PerQueue(base_answers(), {"orders": attributes(dead_letter=DLQ_ARN), "orders-dlq": attributes(visible=0, in_flight=0)})
    ctx, _ = run(config_data, tmp_path, {"queues": "orders"}, fake=fake)
    assert by_summary(ctx, "holds") == []


def test_dead_letter_queue_that_is_also_a_target_is_read_once(config_data, tmp_path):
    fake = PerQueue(base_answers(), {"orders": attributes(dead_letter=DLQ_ARN), "orders-dlq": attributes(visible=1, in_flight=0)})
    _, aws = run(config_data, tmp_path, {"queues": "orders,orders-dlq"}, fake=fake)
    names = [argv[argv.index("--queue-name") + 1] for argv in aws.called("sqs", "get-queue-url")]
    assert names == ["orders", "orders-dlq"]


def test_source_queues_of_a_dead_letter_queue(config_data, tmp_path):
    sources = {"queueUrls": [f"https://sqs.eu-west-1.example.com/{ACCOUNT}/orders", f"https://sqs.eu-west-1.example.com/{ACCOUNT}/refunds"]}
    ctx, aws = run(config_data, tmp_path, {"queues": "orders-dlq"}, base_answers(**{"sqs list-dead-letter-source-queues": sources}))
    fact = by_summary(ctx, "dead letter queue for")[0]
    assert "orders" in fact.summary and "refunds" in fact.summary
    call = aws.called("sqs", "list-dead-letter-source-queues")[0]
    assert call[call.index("--max-items") + 1] == "10"


def test_healthy_topic(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, {"topics": TOPIC_ARN})
    state = ctx.evidence.facts[0]
    assert state.kind == "current"
    assert "Topic order-events" in state.summary and "3 subscriptions confirmed" in state.summary and "1 pending" in state.summary
    assert "3 retries" in state.summary
    call = aws.called("sns", "get-topic-attributes")[0]
    assert call[call.index("--topic-arn") + 1] == TOPIC_ARN
    metrics = aws.called("cloudwatch", "get-metric-data")[0]
    queries = json.loads(metrics[metrics.index("--metric-data-queries") + 1])
    assert {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries} == {
        "NumberOfNotificationsFailed": "Sum", "NumberOfMessagesPublished": "Sum"}
    assert queries[0]["MetricStat"]["Metric"]["Namespace"] == "AWS/SNS"
    assert queries[0]["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "TopicName", "Value": "order-events"}]
    assert_read_only(ctx, aws)


def test_missing_queue(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, {"queues": "orders"}, base_answers(**{"sqs get-queue-url": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("sqs", "get-queue-attributes") == []


def test_missing_topic(config_data, tmp_path):
    missing = (254, "An error occurred (NotFound) when calling the GetTopicAttributes operation: Topic does not exist")
    ctx, _ = run(config_data, tmp_path, {"topics": TOPIC_ARN}, base_answers(**{"sns get-topic-attributes": missing}))
    assert len(ctx.evidence.facts) == 1 and "not found" in ctx.evidence.facts[0].summary


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = base_answers(**{"sqs list-dead-letter-source-queues": access_denied("ListDeadLetterSourceQueues")})
    ctx, aws = run(config_data, tmp_path, {"queues": "orders"}, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert "Queue orders" in ctx.evidence.facts[0].summary
    assert aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws)


def test_secret_in_queue_attributes_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "1" * 10
    answers = base_answers(**{"sqs get-queue-attributes": attributes(Policy=f"token={secret}")})
    ctx, _ = run(config_data, tmp_path, {"queues": "orders"}, answers)
    assert secret not in ctx.evidence.to_json()


def test_targets_are_capped(config_data, tmp_path):
    queues = ",".join(f"q{n}" for n in range(15))
    _, aws = run(config_data, tmp_path, {"queues": queues})
    assert len(aws.called("sqs", "get-queue-url")) == 10
