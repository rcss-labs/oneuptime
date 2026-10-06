# CloudTrail playbook

## When to open

The report asks who changed something, the plan's change lookup ran, or a cause needs a
change in the window to support it (or to be ruled out).

## Collect

The plan already runs `changes` for the mapped resource names. It looks each name up
exactly and also looks up the CloudTrail event sources of the mapped resource kinds
(`event_sources`, for example `ecs.amazonaws.com`), keeping events whose record names
one of the names. For each dependency of the service it runs `changes` again with the
suffix `dep-<service>`. This playbook covers the CloudTrail part. Take the account,
region, and window from the plan's lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| A specific resource is suspected | `run collect changes ... --case-dir <case> --target resource_names=<name1>,<name2> --target incident_start=<ISO time> --suffix <word>` |
| No resource is suspected | `run collect changes ... --case-dir <case> --target incident_start=<ISO time> --suffix <word>` |
| The absence fact says "looked up by resource name only" | `run collect changes ... --case-dir <case> --target resource_names=<name1>,<name2> --target event_sources=<source>.amazonaws.com --target incident_start=<ISO time> --suffix sources` |
| A deployment may be behind the change | the same command with `--target stack=<stack name>` or `--target pipeline=<pipeline name>`; see `deployments.md` |
| The resource is recorded by AWS Config | the same command with `--target config_resource=<resource type>/<resource id>` |
| The change was an identity or key change | `run collect access ... --case-dir <case> --target role=<role name> --suffix <word>`; see `access.md` |

Give up to ten names, and always give `incident_start`: without it the gap to the
incident is not written and the lookup covers the whole window.

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "UpdateService (ecs.amazonaws.com) by <user> on <resource>, 4 minutes before the incident started" | a write call by that identity at that time | what the call changed; the target service's playbook |
| the same with "after the incident started" | a response to the incident, not a cause | whether it made things better |
| "... on <resource>, recorded in us-east-1, 3 minutes before the incident started" | a global-service change (IAM, CloudFront, Route 53, WAF, Organizations) found in the global region | what the change affected; `access.md` or `cloudfront-waf.md` |
| "at the same time as the incident started" | within seconds of the start | the strongest candidate; confirm with the service's facts |
| a user such as an assumed role of a pipeline | automation made the change | `deployments.md` for the run |
| "by unknown user" | the event has no user name (a service acting on its own) | the event source and the service's facts |
| "CloudTrail returned no write event naming 'X' between T1 and T2 (looked up in R by resource name and by event source S; in us-east-1 by event source G)" | CloudTrail returned no write event naming X by the lookups listed in the fact, each in the region it names; it says nothing about changes those lookups cannot see | the service's own facts; state the absence as exactly this |
| the same "(looked up by resource name only, in R; some services record ARNs or ids instead)" | only the exact-name lookup ran, and some services record ARNs or ids instead of the name | rerun with `event_sources` (Collect table) before treating it as an absence |
| "Search by event source S in R stopped after N events (10 pages) ...; absence of changes naming X is not established" | the source is too busy to read in full | a narrower period or name; no absence may be stated |
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
- Events are read in the collector's region. Outside `us-east-1` it also looks up
  IAM, CloudFront, Route 53, WAF, and Organizations events in `us-east-1`; those
  facts say "recorded in us-east-1". Other global-service events (STS, Route 53
  Domains) are not looked up.
- An `event_sources` search for a global service (IAM, CloudFront, Route 53, Route 53
  Domains, Organizations, WAF Classic) runs in `us-east-1`, where those events are
  recorded; `wafv2` is searched in both the collection region and `us-east-1`. The
  absence fact names the region of each lookup.
- A lookup by resource name finds only events that list that name in their resources.
  The event-source lookup reads up to ten pages of one service's write events and keeps
  those whose record names the resource anywhere, so a change recorded under an ARN or an
  id is found. The account-wide form (no `resource_names`) fills the 50 events with
  unrelated changes.

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
4. **No write event found.** Evidence: "CloudTrail returned no write event naming X"
   for every mapped name, the lookups listed include the event sources, and no
   "stopped after" fact. The cause is then probably load, a dependency, or a limit; say
   "no write event was found by these lookups", not "nothing changed", and move on.
5. **The wrong period or region.** Evidence: the window ends before the change or
   `incident_start` is wrong. Work order: the corrected period.

## Compare with

The changes of the previous day for the same resource, if the window allows: a
resource changed daily makes a change an expected event.

## Follow a lead

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<name> --start-time <window start> --end-time <window end> --max-items 50 --profile <triage profile> --region <region> --query 'Events[?ReadOnly==`false`].{t:EventTime,name:EventName,user:Username}'
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=<event name> --start-time <window start> --end-time <window end> --max-items 50 --profile <triage profile> --region <region> --query 'Events[].{t:EventTime,user:Username,resource:Resources[0].ResourceName}'
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<user name> --start-time <window start> --end-time <window end> --max-items 50 --profile <triage profile> --region <region> --query 'Events[].{t:EventTime,name:EventName,source:EventSource}'
```
