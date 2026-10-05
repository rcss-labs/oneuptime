# ElastiCache playbook

## When to open

The target has an `elasticache` resource, or evidence names a Redis or Valkey
replication group: cache timeouts, evictions, a failover, or "OOM command not allowed".

## Collect

The plan already runs `elasticache` for the mapped replication group. It reports
every member (up to 10) with events and metrics per member. Add these when they apply. Take the account, region, and window from the plan's own lines; `<case>` is the case folder.

| When | Command |
|---|---|
| Clients time out rather than get an error reply | `run collect vpc ... --case-dir <case> --target security_group_ids=<groups of the cache and of the client>` |
| The cache is encrypted and calls fail with a key error | `run collect access ... --case-dir <case> --target kms_key=<key id>` |
| The clients are a compute service | `run collect ecs ... --case-dir <case> --target cluster=<c> --target service=<s>` (or `lambda` with `function=<name>`, `eks` with `cluster=<name>`); read `ecs.md`, `lambda.md`, or `eks.md` |
| The application's own errors are needed | `run collect logs ... --case-dir <case> --target log_groups=<application log group>` |
| A setting change is suspected | `run collect changes ... --case-dir <case> --target resource_names=<name>` and read `cloudtrail.md` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Replication group X is available: N node group(s) (0001 available), automatic failover enabled, multi-AZ enabled, primary endpoint HOST:PORT; reader endpoint ..." (`current`) | state and where the group is | a node group not `available`; failover `disabled` means a lost primary is not replaced automatically; compare HOST with the host the application uses |
| "Member X is available: engine, version, node type, nodes 0001 available" (`current`) | the node exists and runs | a member not `available` is replaced, rebooting, or failed |
| "Event on X: ..." (times) naming a failover from a primary node to a replica, a node replaced, rebooted, or a snapshot | the cluster changed at that time | the memory, connection and lag facts after that time |
| "DatabaseMemoryUsagePercentage (Maximum): highest N at T" | how full the memory is | near 100 with evictions, or write errors, is memory pressure |
| "Evictions (Sum): highest N at T" (per 5 minutes) | keys removed to make room; zero is normal for a cache that is not full | the memory fact and the key expiry habits of the application |
| "SwapUsage (Maximum)" above zero | the node pushes memory to disk and slows | memory pressure; node type |
| "EngineCPUUtilization (Average)" | CPU of the engine thread, the number that matters for Redis | one member high and the rest low means one hot shard or key |
| "CurrConnections (Maximum): highest N at T, rose above the range of one week earlier" | connections now against normal | a jump with a deploy or a failover means a connection storm |
| "ReplicationLag (Maximum)" | seconds a replica is behind; meaningful on replicas only | "no data was returned" on the primary is normal |
| "The group has N members; events and metrics cover the first 10" | members beyond 10 were not read | put the other members in the report's open questions |

A `current` fact shows the state now. Events and metric facts carry times: events the
time they happened, metrics the time of the peak.

## Common causes

1. **Memory full.** Evidence: `DatabaseMemoryUsagePercentage` near 100 on the primary,
   `Evictions` above zero, application misses or slowdown (or write errors when the
   eviction policy does not evict). Rule out: memory well below the limit. Work order:
   the node type, the peak memory, the eviction count and times; the eviction policy
   (Follow a lead) because it decides evict or refuse; mitigation is a larger node type
   or shards; permanent fix is expiry on the keys that grow.
2. **Failover or node replacement.** Evidence: a failover or replacement event at the
   incident start, a member not `available`, connection errors that ended. Rule out: no
   event. Work order: the event, time, old and new primary; the permanent fix is
   client reconnect and using the primary endpoint, not a node address.
3. **Connection storm or limit.** Evidence: `CurrConnections` several times its
   baseline with a peak at the incident start, errors about max clients or timeouts
   on connect. Rule out: connections about the same. Work order: the peak, the
   `maxclients` parameter, and which client scaled up (name the service); the fix is
   pooling or fewer clients.
4. **Engine CPU saturation.** Evidence: `EngineCPUUtilization` high with memory and
   evictions normal, latency in the client. Rule out: CPU about the same. Work order:
   the peak and members affected; the commands responsible are not in this evidence,
   so name the owner to ask; the fix is by key and command, or more shards.
5. **A snapshot or backup raised memory.** Evidence: a snapshot event just before a
   memory or swap peak on that member, with memory high already. Work order: the
   snapshot window and the reserved memory setting; the fix is more headroom or a
   different window.
6. **Replication lag.** Evidence: `ReplicationLag` high on a replica, reads from the
   reader endpoint stale. Work order: the replica, the lag and times; the cause is
   usually a write surge or a small node, so cite those facts.

## Compare with

The other members of the same group (a primary against its replicas), the same cache
in another environment, and each metric against one week earlier.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws elasticache describe-cache-clusters --cache-cluster-id <member> --profile <triage profile> --region <region> --query 'CacheClusters[0].{group:CacheParameterGroup.CacheParameterGroupName,type:CacheNodeType,pending:PendingModifiedValues}'
aws elasticache describe-cache-parameters --cache-parameter-group-name <group> --source user --profile <triage profile> --region <region> --max-items 100 --query 'Parameters[].{name:ParameterName,value:ParameterValue}'
aws elasticache describe-events --source-identifier <member> --source-type cache-cluster --duration 1440 --profile <triage profile> --region <region> --max-items 50 --query 'Events[].{at:Date,message:Message}'
```
