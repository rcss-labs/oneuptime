# Deployments playbook

## When to open

The question is what changed before the incident, or the evidence names a stack, a
pipeline, or a resource that AWS Config records. Plain CloudTrail events are
`cloudtrail.md`.

## Collect

The plan already runs `changes` with CloudTrail write events (by resource name and by
event source). The other sources need their own targets, and the incident start in
`incident_start` so each fact states its gap. Take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| A CloudFormation stack deploys the service | `run collect changes ... --case-dir <case> --target stack=<stack name> --target incident_start=<ISO time with Z> --suffix <word>` |
| A pipeline deploys the service | `run collect changes ... --case-dir <case> --target pipeline=<pipeline name> --target incident_start=<ISO time with Z> --suffix <word>` |
| You need what a resource looked like before and after | `run collect changes ... --case-dir <case> --target config_resource=<resource type>/<resource id> --target incident_start=<ISO time with Z> --suffix <word>` |
| Changes to specific resources (up to 10) | `run collect changes ... --case-dir <case> --target resource_names=<name1>,<name2> --target incident_start=<ISO time with Z> --suffix <word>` |
| A change is found and you need what it did | the playbook of the changed service, for example `ecs.md` or `lambda.md` |

Give each extra run its own `--suffix` word.

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Stack S: S (AWS::CloudFormation::Stack) UPDATE_IN_PROGRESS, N minutes before the incident started" | an update began; incident-time, with a time | the resource events that follow |
| "Stack S: R (type) UPDATE_FAILED" with the reason in the excerpt | a resource change failed; the stack may be half applied | the reason text; `ROLLBACK_IN_PROGRESS` follows |
| "Stack S: ... UPDATE_ROLLBACK_IN_PROGRESS" | the update was undone; the service may have been changed twice | the state after the rollback |
| "Pipeline P execution E is Succeeded/Failed/InProgress, trigger ..., N minutes before the incident started" | a release ran in the window | the trigger detail (commit or manual) |
| "Pipeline P stage X is Failed" | `current`; only stages that are not Succeeded are listed | the stage's action output in the console |
| "AWS Config captured a configuration of T/id with status ResourceDiscovered/OK/ResourceDeleted, N minutes before..." | the resource changed (excerpt lists related CloudTrail events) | CloudTrail for the event and the user |
| "AWS Config does not record T/id ..." | no history exists; absence is not evidence of no change | CloudTrail |
| "No change was recorded for X between A and B" | no write event for that name | not proof for a resource changed under another name |
| "More events exist than the 50 read" | the lookup was cut | narrow with `resource_names` |

"N minutes before the incident started" is the gap between the change event and the
start. A short gap makes a change a lead, not a cause: many changes are harmless.
A gap of hours points at something slower, such as a leak or a scheduled job. A change
after the start is more likely a response than a cause.

## Common causes

1. **The change broke the service.** Evidence: a change minutes before the start that
   touches the failing resource, and other evidence that the new state is bad (task
   revision unhealthy, new setting in the diff, errors beginning at the change time).
   Rule out: the same errors before the change, or no difference in the resource's
   configuration. Work order: the change (stack or pipeline name, event, user), the
   old and new value; mitigation is to restore the previous state through the same
   path; the permanent fix is a test or review that would have caught it.
2. **A stack update failed or rolled back.** Evidence: failed resource events with
   reasons, the service in a half-updated state. Work order: stack name, failed
   resource, the reason, and the state after rollback.
3. **A pipeline released an untested revision.** Evidence: an execution triggered by
   a commit or manual run in the window and a failing stage. Work order: pipeline, execution id, trigger detail, stage.
4. **A change in a dependency, not the failing service.** Evidence: the change is on
   a network, role, or data store the service uses. Work order: that change, and
   the playbook of the affected service.
5. **The change is coincidence.** Evidence: the change succeeded, nothing differs in
   the failing resource, and the errors have another cause. Report it as ruled out
   with its time.

## Compare with

The previous successful execution or the previous stack template, and the same
service's change history for the week before.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws cloudformation describe-stack-events --stack-name <stack> --profile <triage profile> --region <region> --max-items 30 --query 'StackEvents[?contains(ResourceStatus,`FAILED`)].{time:Timestamp,resource:LogicalResourceId,status:ResourceStatus,reason:ResourceStatusReason}'
aws codepipeline get-pipeline-state --name <pipeline> --profile <triage profile> --region <region> --query 'stageStates[].{stage:stageName,status:latestExecution.status}'
aws configservice get-resource-config-history --resource-type <resource type> --resource-id <resource id> --limit 5 --profile <triage profile> --region <region> --query 'configurationItems[].{time:configurationItemCaptureTime,status:configurationItemStatus,events:relatedEvents}'
```
