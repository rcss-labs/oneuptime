# Platform playbook

## When to open

Several unrelated services of one account or region failed together, a service
reports a limit or "rate exceeded", or no change and no application fault explains the
incident.

## Collect

The plan already runs `platform` for the account and region. It reads AWS Health
events and the service quotas of `ecs`, `lambda`, `ec2`, `rds`, and
`elasticloadbalancing`. Add these when they apply; take the account, region, window,
and case folder from the plan's own lines.

| When | Command |
|---|---|
| The limit that was hit is of another service | `run collect platform ... --target service_codes=<code1>,<code2>` (for example `dynamodb,sqs`; use a `--suffix`) |
| A quota is named in an error message | `run collect platform ... --target service_codes=<service code of that quota>` |
| One service fails, others are fine | the playbook of that service, not this one |
| The limit is Lambda's account concurrency | `run collect lambda ... --target function=<function name>` shows the account limit |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "AWS Health event for <service> in <region>: <type code>, category issue, status open" | incident-time, with the start time; AWS reports a fault | the type code and the region against yours |
| "... category scheduledChange" | planned maintenance or retirement that overlaps the window | what it names: instance retirement, a certificate, an engine upgrade |
| "... category accountNotification" | something about the account, not a platform fault | the type code |
| status `closed` and an end time before the incident start | resolved before the incident; not the cause | its end time |
| "AWS Health events are not available: AWS Health needs a Business or Enterprise support plan" | the account cannot see Health through the API | the public AWS status page, outside this skill; say the question is open |
| no Health event | no event visible for the account and region and window; the API shows only events that affect the account and may lag | other evidence; do not treat it as proof of no AWS fault |
| "Service S has N quotas with usage tracking, for example: <name> = <value>, ..." | `current`; the quota values only, not the usage | usage from the metric below |

The collector does not read usage or compute how close it is to a limit, and
the list shows only the first ten quotas that have usage tracking. Compare usage
with the value from the lead below. Events that overlap the window are listed
for all regions; check each fact's region. Health facts carry times; quota facts are `current`.

## Common causes

1. **A service quota is exhausted.** Evidence: an error naming a limit or throttling
   ("LimitExceeded", "TooManyRequests"), the quota value from the fact, and usage at
   or near it from the usage metric. Rule out: usage well below the value. Work
   order: the quota name, code, current value, and observed usage; mitigation is a
   quota increase request, the permanent fix is capacity alerting on usage.
2. **An AWS event affects the region or service.** Evidence: a Health event for the
   service in your region starting before or at the incident, and the same symptom in
   resources that share nothing else (different VPCs, different deployments), no
   change in the window. Rule out: the event is in another region, or ended before the
   start. Work order: the event type code and times, the services affected, and that
   mitigation is waiting or failing over by the owner's plan.
3. **A scheduled change reached its date.** Evidence: a scheduledChange event whose
   time falls in the window and a resource it names. Work order: the resource and the event.
4. **A quota was reached because of a runaway process.** Evidence: usage rising
   steadily before the start. Work order: what created the resources (see `cloudtrail.md`).

Do not suspect AWS because the cause is unknown. Require a Health event, or many
unrelated failures starting together in one region with no change anywhere.

## Compare with

The same quota's usage one week earlier, and another region of the account if it runs
the same workload.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws health describe-event-details --event-arns <event ARN> --profile <triage profile> --region us-east-1 --query 'successfulSet[].{type:event.eventTypeCode,start:event.startTime,end:event.endTime,text:eventDescription.latestDescription}' 2>/dev/null
aws service-quotas list-service-quotas --service-code <service code> --profile <triage profile> --region <region> --max-items 50 --query 'Quotas[?contains(QuotaName,`<name fragment>`)].{name:QuotaName,code:QuotaCode,value:Value,adjustable:Adjustable,usageMetric:UsageMetric}' 2>/dev/null
aws cloudwatch get-metric-statistics --namespace AWS/Usage --metric-name ResourceCount --dimensions Name=Type,Value=Resource Name=Resource,Value=<resource name> Name=Service,Value=<service name> Name=Class,Value=None --start-time <window start> --end-time <window end> --period 300 --statistics Maximum --profile <triage profile> --region <region> --query 'Datapoints[].{time:Timestamp,usage:Maximum}' 2>/dev/null
```

The usage metric's namespace, name, and dimensions come from the `UsageMetric` field of the quota.
