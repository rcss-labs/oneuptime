# Messaging playbook

## When to open

The target has queues or topics (SQS, SNS), or evidence names one: a growing backlog,
old messages, a dead letter queue that fills, or notifications that do not arrive. No
message is ever received or read.

## Collect

The plan already runs `messaging` for the mapped queues and topics. It follows each
queue's redrive policy to its dead letter queue and reads that too (up to 10 targets).
A topic must be given as an ARN. Add these when they apply. Take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| A consumer is a Lambda function | `run collect lambda ... --case-dir <case> --target function=<name> --suffix <word>` and read `lambda.md` (its event source mapping facts) |
| A consumer is a service or pod | `run collect ecs ... --case-dir <case> --target cluster=<c> --target service=<s> --suffix <word>` (or `eks` with `cluster=<name>`); read `ecs.md` or `eks.md` |
| A second queue or a topic's subscribed queue is involved | `run collect messaging ... --case-dir <case> --suffix <name> --target queues=<queue names, comma separated>` |
| A topic's failures need a reason | `run collect logs ... --case-dir <case> --target log_groups=<the topic's delivery status log group> --suffix <word>` and read `cloudwatch.md` |
| A policy or redrive change is suspected | `run collect changes ... --case-dir <case> --target resource_names=<name> --suffix <word>` and read `cloudtrail.md` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Queue X: N messages visible, M in flight, D delayed, visibility timeout V seconds, retention R, dead letter queue Q after K receives" (`current`, approximate counts) | the backlog now and the redrive setting | the age and the sent and deleted facts; "no dead letter queue" means a failing message returns until retention ends |
| "ApproximateAgeOfOldestMessage (Maximum): highest N at T" (seconds, with time) | how long the oldest message has waited | rising for the whole window means consumers are not keeping up or have stopped; near the retention period means messages are about to be dropped |
| "ApproximateNumberOfMessagesVisible (Maximum)" | the backlog over time | its peak time against the incident start |
| "NumberOfMessagesSent (Sum)" against "NumberOfMessagesDeleted (Sum)" | arrival against completed processing | sent above deleted for the window grows the backlog; deleted near zero means no consumer finishes messages |
| "M in flight" high | consumers receive messages and do not delete them | the visibility timeout against the consumer's processing time; consumer errors |
| "Queue X is the dead letter queue for: a, b" (`current`) | X is a dead letter queue | the source queues |
| "Dead letter queue X holds N messages (v visible, f in flight, d delayed)" | messages failed K times | what the consumer's errors say; the count is now, and says nothing about when they arrived |
| "Topic X: N subscriptions confirmed, P pending, delivery policy N retries" (`current`) | the subscribers; a pending one never confirmed and receives nothing | the subscription list (Follow a lead) |
| "NumberOfNotificationsFailed (Sum): highest N at T" | deliveries that failed; it does not say which subscriber or why | the delivery status logs; the subscriber's own evidence |
| "NumberOfMessagesPublished (Sum)" | what the topic received | zero with failed also zero means the publisher stopped |
| "Queue X was not found" or "Topic X was not found" | the name or region is wrong, or it was deleted | the plan's mapping; the change evidence |

A `current` fact is the state now. Metric facts carry the time of their peak. Counts
from queue attributes are approximate and lag by about a minute.

## Common causes

1. **Consumers stopped or fell behind.** Evidence: age of the oldest message rising,
   visible messages rising, deleted well below sent or near zero, no spike in sent. Rule
   out: deleted keeping pace with sent. Work order: the queue, the age and backlog
   peaks and times, and the consumer; the consumer's own evidence names why (a deploy,
   a crash, no capacity); mitigation is more consumers; the permanent fix depends
   on that cause.
2. **A message that always fails.** Evidence: a dead letter queue holding messages,
   or in-flight messages cycling, with consumer errors on the same payload. Work order:
   the queue, the dead letter queue, `maxReceiveCount`, the count held; mitigation is
   to redrive after the consumer is fixed (a person does this); the permanent fix is
   the consumer's handling of that input.
3. **A producer surge.** Evidence: `NumberOfMessagesSent` several times its baseline
   with a peak at the incident start, consumers healthy. Work order: the peak,
   the baseline, and the producer; the fix is consumer capacity or producer limits.
4. **The visibility timeout is shorter than the processing time.** Evidence: many
   messages in flight, deleted below what consumers take, duplicates in the logs,
   consumer duration above the timeout (from the consumer's evidence). Work order: both
   values; the fix is a timeout above the processing time (for Lambda, several times
   the function timeout).
5. **Redrive settings.** Evidence: no dead letter queue on a queue that fails messages,
   or a `maxReceiveCount` of 1 or 2 with transient errors, so messages dead-letter at once.
   Work order: the redrive setting and the value wanted.
6. **SNS deliveries failing.** Evidence: failed notifications above zero at the
   incident start, a subscription pending, or a subscribed queue whose policy was
   changed. Rule out: failed is zero. Work order: the topic, the peak, the
   subscription; the reason needs the delivery status logs, so say if they are
   missing.

## Compare with

The same queue one week earlier (age, sent, deleted), a healthy queue of the same
consumer type, and the dead letter queue's count against the time of the last deploy.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws sqs get-queue-attributes --queue-url <queue url> --attribute-names RedrivePolicy RedriveAllowPolicy ReceiveMessageWaitTimeSeconds DelaySeconds --profile <triage profile> --region <region> --query 'Attributes'
aws sqs list-dead-letter-source-queues --queue-url <dead letter queue url> --profile <triage profile> --region <region> --max-items 20
aws sns get-topic-attributes --topic-arn <topic arn> --profile <triage profile> --region <region> --query 'Attributes.{confirmed:SubscriptionsConfirmed,pending:SubscriptionsPending,deleted:SubscriptionsDeleted}'
```
