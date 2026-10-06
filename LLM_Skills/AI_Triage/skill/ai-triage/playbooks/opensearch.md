# OpenSearch playbook

## When to open

The target has an `opensearch_domain`, or evidence names an OpenSearch domain or
cluster: red or yellow status, write rejections, a full disk, or the application's
logs are kept there and must be searched.

## Collect

The plan runs `opensearch_domain` for the service map's `opensearch_domain` (to run it again:
`run collect opensearch_domain ... --case-dir <case> --target domain=<domain name> --suffix <word>`) and
the query tool for the mapped `opensearch` entry. The collector reads the AWS
control plane only: no document and no node is queried. The query tool reads the
cluster itself; its cluster name comes from the config, not from the domain name. Take the
account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| Is the cluster healthy now | `run opensearch_query health --case-dir <case> --cluster <name>` |
| Which node is short of heap, disk, or rejecting | `run opensearch_query nodes --case-dir <case> --cluster <name>` |
| Which indices are not green | `run opensearch_query indices --case-dir <case> --cluster <name>` |
| Which shards are not started | `run opensearch_query shards --case-dir <case> --cluster <name>` |
| Why a shard is unassigned | `run opensearch_query allocation-explain --case-dir <case> --cluster <name>` |
| Which fields an index has, before querying one | `run opensearch_query mapping --case-dir <case> --cluster <name> --index <pattern>` |
| How many log lines match | `run opensearch_query count --case-dir <case> --cluster <name> --index <pattern> --start <ISO time> --end <ISO time> --query '<Lucene>'` |
| When the matches start and when they are most frequent | `run opensearch_query histogram --case-dir <case> --cluster <name> --index <pattern> --start ... --end ... --interval 5m` |
| Which messages repeat | `run opensearch_query top-messages --case-dir <case> --cluster <name> --index <pattern> --start ... --end ...` |
| The matching lines themselves | `run opensearch_query search --case-dir <case> --cluster <name> --index <pattern> --start ... --end ... --size 20 --order asc` |

`count`, `histogram`, `top-messages` and `search` take `--filter KEY=VALUE` (exact match,
repeatable) and `--query`; the other subcommands take no time range.

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Domain X runs VERSION on N x TYPE, storage V GiB TYPE, processing a change, endpoint ..." (`current`) | configuration now; "processing a change" means a blue/green change is under way | the configuration change fact |
| "Cluster health is red (domain state Active): N data nodes, M master-eligible nodes, T shards, U unassigned" (`current`) | red: a primary shard is unassigned; yellow: a replica is | `shards` and `allocation-explain` through the query tool |
| "Domain configuration change ID is PROCESSING (config change status ..., N stages)" (time of the start) | a change ran, or is running, in or near the window | the time against the first error; a stuck change |
| "FreeStorageSpace (Minimum): lowest A at T, highest B at T ..." (MiB, lowest node; A is the low point) | free disk | A near zero, or a block on writes, is the disk watermark; `nodes` shows free percent per node |
| "JVMMemoryPressure (Maximum): lowest ..., highest ..." | heap use | a sustained high value means rejections and slow GC; `nodes` for which node |
| "ThreadpoolWriteRejected (Sum)", "ThreadpoolSearchRejected (Sum)" | requests refused because the queue was full | the CPU and JVM facts, the indexing or search rate in the logs |
| "ClusterStatus.red (Maximum)" 1, "ClusterStatus.yellow" 1 | the status was red or yellow at some point in the window | the fact's time against the incident start |
| "5xx (Sum)" | the domain returned server errors | the rejection and health facts |
| "Node X: heap N% used, disk N% free, CPU N%, thread pool rejections since node start: write=N" (`current`) | state now; the rejection count is cumulative since the node started, not the window | the metric facts for the window |
| "N documents matched in the window" or "No documents matched in the window" | only that the query as asked matched that many documents in that index pattern and time field | a zero means the query matched nothing; it is not "no problem" (check the field names with `mapping`, the index pattern, the window) |
| "Results are partial, counts are lower bounds: ..." | a timeout or failed shards cut the answer | narrow the window |

## Common causes

1. **Disk watermark reached.** Evidence: free storage near zero on a node, shards
   unassigned or an index blocked for writes, application write errors naming a
   cluster block or read-only index. Rule out: free space far from zero on every node.
   Work order: the node and free percent, the watermark the allocation explanation
   names, the storage size; mitigation is more storage or deleting old indices;
   permanent fix is index retention and a disk alarm.
2. **Heap pressure.** Evidence: `JVMMemoryPressure` high, rejections or slow queries,
   one node high. Work order: the highest value, nodes, instance type; the fix is a larger
   type, fewer shards, or lighter queries.
3. **Write or search rejections.** Evidence: rejection sums above zero at the incident
   start, CPU high, a spike of requests in the logs (`histogram`). Work order: the pool,
   the count, the source of the surge; the fix is backpressure and bulk size.
4. **Unassigned shards after a node loss or a change.** Evidence: yellow or red with
   unassigned shards, a node count lower than before, a configuration change or
   blue/green event near the start. Work order: the shard, the reason, and the decider
   text; do not state a cause the allocation explanation does not name.
5. **A configuration change.** Evidence: a change fact starting before the first
   error, "processing a change" now. Work order: the change id, its time, and what
   changed (read `cloudtrail.md`).
6. **The application misbehaves, the domain is fine.** Evidence: green health, no
   rejections, free space and heap normal, errors only in the client logs. Then the cause is in the
   client; search its logs with `top-messages`.

## Compare with

The same domain one week earlier (the metric facts), other nodes of the cluster (the
`nodes` facts), and the same index pattern in another environment.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws opensearch describe-domain-nodes --domain-name <domain> --profile <triage profile> --region <region> --query 'DomainNodesStatusList[].{id:NodeId,type:NodeType,az:AvailabilityZone,status:NodeStatus,storage:StorageSize}'
aws opensearch describe-domain-config --domain-name <domain> --profile <triage profile> --region <region> --query 'DomainConfig.{cluster:ClusterConfig.Options,ebs:EBSOptions.Options}'
aws opensearch describe-domain-change-progress --domain-name <domain> --profile <triage profile> --region <region> --query 'ChangeProgressStatus.{id:ChangeId,status:Status,started:StartTime,stages:ChangeProgressStages[].{name:ChangeProgressStageName,status:Status}}'
```
