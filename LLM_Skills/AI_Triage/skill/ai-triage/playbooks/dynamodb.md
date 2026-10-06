# DynamoDB playbook

## When to open

The target has `dynamodb_tables`, or evidence names a DynamoDB table: throttling
errors (`ProvisionedThroughputExceededException`), slow reads or writes, or a capacity
change. No item is ever read.

## Collect

The plan already runs `dynamodb` for the mapped table. It reads table state, scaling
activity, four table-level metrics, and three per-operation metrics for nine operations.
Add these when they apply. Take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| The table's clients are a compute service | `run collect ecs ... --case-dir <case> --target cluster=<c> --target service=<s> --suffix <word>` (or `lambda` with `function=<name>`, `eks` with `cluster=<name>`); read `ecs.md`, `lambda.md`, or `eks.md` |
| Calls are denied rather than throttled | `run collect access ... --case-dir <case> --target role=<role that calls the table> --suffix <word>` and read `access.md` |
| A capacity or scaling setting change is suspected | `run collect changes ... --case-dir <case> --target resource_names=<name> --suffix <word>` and read `cloudtrail.md` |
| The application's own errors are needed | `run collect logs ... --case-dir <case> --target log_groups=<application log group> --suffix <word>` |
| A second table is involved (a stream consumer, a replica) | `run collect dynamodb ... --case-dir <case> --suffix <name> --target table=<other table>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Table X is ACTIVE: billing mode PROVISIONED, read capacity N, write capacity M, K items, global secondary indexes: idx ACTIVE" (`current`) | the limits and state now | an index not `ACTIVE`; on-demand tables show capacity 0 |
| "Scaling activity Successful: ..." or "Failed: ..." (times, the cause in the excerpt) | autoscaling changed or tried to change capacity | the time against the first throttle; a failed one means capacity stayed low |
| "ReadThrottleEvents (Sum)" / "WriteThrottleEvents (Sum): highest N at T" | requests refused for the table in a 5-minute period; absent or "no data" means none was emitted | the consumed capacity facts and the per-operation lines |
| "ConsumedReadCapacityUnits (Sum)" / "ConsumedWriteCapacityUnits (Sum)" | capacity used in 5 minutes; divide by 300 for units per second | against the provisioned units: near them is a capacity limit; far below them while throttling is a hot partition |
| "ThrottledRequests PutItem (Sum): highest N at T ..." (one fact per operation with data) | which operation was throttled | the operation's caller in the logs |
| "SystemErrors Query (Sum)" above zero | the service returned a 5xx | AWS Health in `platform.md`; throttling is not this |
| "SuccessfulRequestLatency GetItem (Maximum)" | slowest successful call | high with no throttling points at large items, scans, or the client |
| "No throttling or system error was recorded in the window for any of the 9 operations queried (...); other operations exist and were not queried" | no throttling for GetItem, PutItem, UpdateItem, DeleteItem, Query, Scan, BatchGetItem, BatchWriteItem, TransactWriteItems | it does not cover other operations (PartiQL statements, TransactGetItems, and the like), indexes on their own, streams, or the client's own limits; do not write "the table was not throttled" without that scope |
| "The per-operation ... metrics could not be read (see errors)" | no verdict | say so; do not use the table-level lines alone as a verdict |

A `current` fact is the state now. Scaling and metric facts carry times (the start of
the activity, the peak). The item count is refreshed by DynamoDB about every six hours;
do not use it as a live number.

## Common causes

1. **Provisioned capacity too low.** Evidence: throttle events with consumed capacity
   per second close to the provisioned units, no or slow scaling activity. Rule out:
   consumed far below provisioned. Work order: the provisioned and consumed units and
   the peak time; mitigation is more capacity or on-demand billing; permanent fix is a
   scaling policy with a sufficient maximum.
2. **A hot partition or hot key.** Evidence: throttling although consumed units per
   second stay well below the provisioned units, concentrated in one operation. The
   evidence cannot name the key, so say that and name the owner to ask. Work order: the operation and
   its caller; the fix is a key design that spreads load.
3. **Autoscaling is too slow or at its maximum.** Evidence: a scaling activity that
   starts after the first throttle, or one that failed or reached its maximum in
   its description. Work order: the policy's target, minimum, maximum (Follow a lead)
   and the activity times; the fix is a higher maximum or a scheduled action.
4. **An index is the bottleneck.** Evidence: writes throttled while the table's
   write capacity is not used up, a global secondary index with a low write capacity
   or not `ACTIVE`. Work order: the index name and its capacity; the fix is more
   capacity on that index.
5. **On-demand traffic jumped.** Evidence: billing mode PAY_PER_REQUEST, consumed units
   several times the usual peak within minutes, throttling at that moment. Work order:
   the peak against the earlier peak; a table can throttle when traffic exceeds
   about double its previous peak in a short time; the fix is warm throughput or
   a gentler ramp.
6. **The service side failed.** Evidence: `SystemErrors` above zero, no
   throttling, AWS Health event. Work order: the operation, times, the Health event;
   the application can only retry.

## Compare with

The consumed-capacity facts against one week earlier, the same table in another
environment, and a table with the same access pattern that is not throttled.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws dynamodb describe-table --table-name <table> --profile <triage profile> --region <region> --query 'Table.{mode:BillingModeSummary.BillingMode,throughput:ProvisionedThroughput,indexes:GlobalSecondaryIndexes[].{name:IndexName,status:IndexStatus,throughput:ProvisionedThroughput}}'
aws application-autoscaling describe-scaling-policies --service-namespace dynamodb --resource-id table/<table> --profile <triage profile> --region <region> --max-items 20 --query 'ScalingPolicies[].{dimension:ScalableDimension,target:TargetTrackingScalingPolicyConfiguration.TargetValue}'
aws application-autoscaling describe-scalable-targets --service-namespace dynamodb --resource-ids table/<table> --profile <triage profile> --region <region> --max-items 20 --query 'ScalableTargets[].{dimension:ScalableDimension,min:MinCapacity,max:MaxCapacity}'
```
