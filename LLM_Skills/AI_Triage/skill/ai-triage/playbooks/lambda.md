# Lambda playbook

## When to open

The target has `lambda_functions`, or evidence names a function, an invocation error,
a timeout, throttling, or a queue or stream that stopped being consumed.

## Collect

The plan already runs `lambda` for the mapped function. Add these when they apply; take
the account, region, and window from the plan's own lines; `<case>` is the case folder.

| When | Command |
|---|---|
| The function logs errors or timeouts | `run collect logs ... --case-dir <case> --target log_groups=/aws/lambda/<function name>` |
| The function failed to read a queue | `run collect messaging ... --case-dir <case> --target queues=<queue name>`; see `messaging.md` |
| The function failed to reach a database, cache, or API | `run collect rds ... --case-dir <case> --target db=<identifier>`, or the matching collector from `rds.md`, `elasticache.md`, `dynamodb.md` |
| The execution role was denied something | `run collect access ... --case-dir <case> --target role=<execution role name>` |
| The function runs in a VPC and calls time out | `run collect vpc ... --case-dir <case> --target subnet_ids=<the function's subnets>` |
| A deployment or configuration change is suspected | `run collect changes ... --case-dir <case> --target resource_names=<function name> --target incident_start=<time>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "last modified <time>, modified inside the incident window" | code or configuration changed during the incident | `changes` for who and what; the configuration lead with `--qualifier` for a version's code hash |
| "last update Failed (reason: ...)" or "state Failed (reason: ...)" | the last deploy did not complete, or the function cannot start | the reason text; `access.md` for a role or key problem |
| "Errors (Sum): highest N at T, rose above the range of one week earlier" | invocations fail; the code or a dependency broke | the log lines; the first error in time |
| "Throttles (Sum): highest N at T" with any value above 0 | invocations were refused for lack of concurrency | the concurrency facts below |
| "has reserved concurrency 0" | the function is switched off by its own limit | `changes` for who set it |
| "has reserved concurrency N" and `ConcurrentExecutions` peak near N | the function's own cap is the ceiling | the throttle fact, the cap, the peak |
| "Account concurrency limit L, unreserved U" with U near 0 | other functions' reservations leave nothing for the rest | which functions hold reservations |
| `Duration (Maximum)` peak close to "timeout T s" | invocations end at the timeout (Duration is in milliseconds, timeout in seconds) | the log line "Task timed out after" and the dependency's latency |
| "Event source mapping U ... is Disabled" | the trigger stopped; nothing reaches the function | who disabled it; the state fact |
| "last processing result: PROBLEM: ..." | the mapping cannot invoke or read | the text; permission or batch failure |
| `Invocations` down to zero | the callers stopped sending, or the function is off | the callers' evidence, not Lambda |

The configuration, concurrency, mapping, and account-limit lines are `current`: the
state now. Metric facts carry the peak time. "No data was returned" for `Errors` or
`Throttles` can mean none occurred; check `Invocations` to see that it ran.

## Common causes

1. **A recent code or configuration change.** Evidence: last modified inside or just
   before the window, errors starting at that time, a change event in `changes`.
   Rule out: errors already present a week earlier at the same level. Work order:
   mitigation is to point the alias or caller at the previous version (name both
   versions and the code hashes, from the configuration lead with `--qualifier`); permanent fix is the
   corrected code or setting, named with old and new values.
2. **Timeouts.** Evidence: `Duration` maximum at the timeout, "Task timed out"
   lines, a slow dependency in the logs. Work order: the timeout now, the duration
   peak, and either a higher timeout (mitigation) or a fix for the slow call
   (permanent), stated separately.
3. **Throttling by concurrency.** Evidence: throttles above zero and either
   `ConcurrentExecutions` at the reserved cap or an unreserved account pool near
   zero. Work order: the cap, the account limit, the peak; the change is a higher
   reservation or a limit increase request, or less load.
4. **A failing dependency.** Evidence: errors that name a database, queue, or
   API, no change in the window, the dependency's own facts also bad. Then the cause
   is in that dependency's playbook.
5. **A stuck event source.** Evidence: mapping disabled or `PROBLEM`, a growing
   queue age. Work order: the mapping UUID, its state, the source ARN, and the
   reason; read `messaging.md`.
6. **Memory or permission failure.** Evidence: "Runtime exited" or a memory
   figure at the limit in the logs, or access-denied lines. Work order: memory
   setting now and peak used, or the role and the action denied.

## Compare with

The previous version of the function, the same function in another environment, and
the error and duration facts against one week earlier, which the metric facts state.

## Follow a lead

```bash
aws lambda get-function-configuration --function-name <function> --qualifier <version> --profile <triage profile> --region <region> --query '{version:Version,modified:LastModified,hash:CodeSha256,memory:MemorySize,timeout:Timeout,handler:Handler}'
aws lambda get-alias --function-name <function> --name <alias> --profile <triage profile> --region <region> --query '{version:FunctionVersion,routing:RoutingConfig,revision:RevisionId}'
aws lambda get-function-configuration --function-name <function> --profile <triage profile> --region <region> --query '{handler:Handler,runtime:Runtime,layers:Layers[].Arn,vpc:VpcConfig.SubnetIds,deadLetter:DeadLetterConfig.TargetArn}'
aws lambda get-event-source-mapping --uuid <mapping uuid> --profile <triage profile> --region <region> --query '{state:State,reason:StateTransitionReason,result:LastProcessingResult,batch:BatchSize}'
```

Never print the function's environment variables with your own command; the collector
lists their names only.
