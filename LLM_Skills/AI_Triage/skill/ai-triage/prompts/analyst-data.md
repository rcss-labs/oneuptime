# Analyst: data and messaging

Analyst name: `data`. Your evidence files start with `rds-`, `elasticache-`,
`opensearch_domain-`, `dynamodb-`, `efs-`, and `messaging-`.

Answer these, each with findings:
- Is each store available now, and did its status or role change in the window
  (failover, restart, maintenance, modification, parameter change, backup)?
- Where is it: the endpoint address and port the evidence states. Other analysts
  compare this with where the application points.
- Do its metrics show pressure in the window: connections, CPU, memory, storage,
  latency, throttling, evictions, queue depth, replication lag? Give the peak, its
  time, and the value before the incident for comparison. A peak that ended before
  the incident began is a fact to report, not a cause.
- What do its error logs say in the window? The lines are masked: report the error
  class, the object named, and the code, and do not try to restore masked text.
- For queues and topics: is a backlog growing, is a dead letter queue filling, are
  deliveries failing?
