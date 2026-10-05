# CloudTrail playbook

## When to open

The report asks who changed something, the plan runs `changes`, or a cause needs a
change in the window to support it (or to be ruled out).

## Collect

The plan already runs `changes` for the mapped resources. This playbook covers its
CloudTrail part. Take the account, region, window, and case folder from the plan's lines.

| When | Command |
|---|---|
| A specific resource is suspected | `run collect changes ... --target resource_names=<name1>,<name2> --target incident_start=<ISO time>` |
| No resource is suspected | `run collect changes ... --target incident_start=<ISO time>` |
| A deployment may be behind the change | the same command with `--target stack=<stack name>` or `--target pipeline=<pipeline name>`; see `deployments.md` |
| The resource is recorded by AWS Config | the same command with `--target config_resource=<resource type>/<resource id>` |
| The change was an identity or key change | `run collect access ... --target role=<role name>`; see `access.md` |

Give up to ten names, and always give `incident_start`: without it the gap to the
incident is not written and the lookup covers the whole window.

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "UpdateService (ecs.amazonaws.com) by <user> on <resource>, 4 minutes before the incident started" | a write call by that identity at that time | what the call changed; the target service's playbook |
| the same with "after the incident started" | a response to the incident, not a cause | whether it made things better |
| "at the same time as the incident started" | within seconds of the start | the strongest candidate; confirm with the service's facts |
| a user such as an assumed role of a pipeline | automation made the change | `deployments.md` for the run |
| "by unknown user" | the event has no user name (a service acting on its own) | the event source and the service's facts |
| "No change was recorded for X between T1 and T2" | the lookup read all events and found no write | the service's own facts; the absence is a result, state it |
| "No change was found among the N newest events for X ...; older events were not read" | 50 events came back and none was a write, but more exist | a narrower `resource_names` |
| "More events exist than the N read; they may include changes" | the list is cut; older writes may exist | name the resource to narrow it |
| "N older changes for X ... were not shown" | more than 40 writes for one name | the newest 40 are shown, newest first |
| "Stack S: <resource> UPDATE_FAILED / ROLLBACK_IN_PROGRESS" | a deployment failed or rolled back | the excerpt's status reason |

All of these carry the event's own time. A write found is a lead, not a verdict: it
is a cause only when the service's facts changed at that time.

### Reading the lookup period

- The lookup starts at the window start. It ends five minutes after `incident_start`
  when that time is inside the window; a change made later than that is not looked for.
- If `incident_start` is before the window start, or is not given, the lookup covers
  the whole window. An incident that began earlier needs a wider window.
- CloudTrail's event history holds management events only, and a recent event can
  appear minutes late. A change in the last few minutes may be missing.
- Events are read per region. A change to IAM or CloudFront is recorded in
  `us-east-1`; run the collector there for them.
- A lookup by resource name finds only events that name that resource. A call
  without the name in its resources is found by the account-wide form, which fills the
  50 events with unrelated changes.

## Common causes

1. **A deploy or configuration change just before the start.** Evidence: a write on
   the resource minutes before the incident, from a person or a pipeline, and the
   service's facts change at that time. Work order: event name, actor, time, resource;
   mitigation is to reverse that change; permanent fix is the review or test that
   would have caught it.
2. **A change by automation on a schedule.** Evidence: the same actor and call at
   the same time of day in earlier events. Work order: the actor, the schedule.
3. **A change to something the service depends on.** Evidence: no write on the
   service, but a write on its role, security group, key, or parameter at the start.
   Work order: the dependency, the call, and the service it feeds.
4. **No change at all.** Evidence: "No change was recorded" with a wide enough
   period. The cause is load, a dependency, or a limit; say so and move on.
5. **The wrong period or region.** Evidence: the window ends before the change or
   `incident_start` is wrong. Work order: the corrected period.

## Compare with

The changes of the previous day for the same resource, if the window allows: a
resource changed daily makes a change an expected event.

## Follow a lead

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<name> --start-time <window start> --end-time <window end> --max-items 50 --profile <triage profile> --region <region> --query 'Events[?ReadOnly==`false`].{t:EventTime,name:EventName,user:Username}' 2>/dev/null
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=<event name> --start-time <window start> --end-time <window end> --max-items 50 --profile <triage profile> --region <region> --query 'Events[].{t:EventTime,user:Username,resource:Resources[0].ResourceName}' 2>/dev/null
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<user name> --start-time <window start> --end-time <window end> --max-items 50 --profile <triage profile> --region <region> --query 'Events[].{t:EventTime,name:EventName,source:EventSource}' 2>/dev/null
```
