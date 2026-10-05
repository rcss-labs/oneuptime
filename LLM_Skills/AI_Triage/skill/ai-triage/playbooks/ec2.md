# EC2 playbook

## When to open

The target has an `ec2_instance`, or evidence names an instance id, a failed status
check, a scheduled event, or an unreachable host.

## Collect

The plan already runs `ec2` for the mapped instances. Add these when they apply; take
the account, region, window, and case folder from the plan's own lines.

| When | Command |
|---|---|
| The instance belongs to a group and was replaced or is missing | `run collect autoscaling ... --target group=<Auto Scaling group name>` |
| The instance cannot be reached or reach a dependency | `run collect vpc ... --target security_group_ids=<the instance's groups>` |
| The application on the host logs to CloudWatch | `run collect logs ... --target log_groups=<log group of the host>` |
| The instance profile was denied something | `run collect access ... --target role=<instance profile role name>` |
| A change to the instance or its group is suspected | `run collect changes ... --target resource_names=<instance id> --target incident_start=<time>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Instance X is running: system status ok, instance status ok, type T, launched <time>" | the one line every instance gets: state, both checks, launch time (`current`) | any check other than ok; the launch time against the incident start |
| "Instance X is stopped" or `terminated`, with a state reason | someone or something stopped it; the reason code names who | the state reason text, then `changes` for the actor |
| "Instance X was launched at <time>, inside the incident window" | the instance is new: a replacement or a scale-out | `autoscaling` for why it was launched |
| "Instance X changed state to <state> at <time>, inside the incident window" | a stop, start, or termination during the incident (time read from the transition reason) | `changes` for the actor |
| "Instance X was not found in <region>" | wrong region, or the instance is long gone | the Auto Scaling group for its replacement |
| "status checks: system status impaired" | the host or hardware under the instance failed | the scheduled-event fact; the usual fix is stop and start, which moves the host |
| "status checks: instance status impaired" | the operating system does not answer: crash, full disk, failed network setup | the console output fact, last lines first |
| "has a scheduled event" with `NotBefore` | AWS plans a retirement, reboot, or maintenance at that time | the times in the fact against the incident start |
| "Last console output of unhealthy instance" | boot messages: kernel panic, fsck failure, failed mount, cloud-init error | the excerpt; a cut-off tail may hide the start of the problem |
| `CPUUtilization` peak near 100 and several times higher than a week earlier | resource exhaustion or a runaway process | the peak time against the incident start |
| `StatusCheckFailed` peak 1 | at least one check failed in that 5-minute period | its time, against the status check fact |
| "no data was returned for the window" | the instance was stopped, or reports no data | the instance state fact |

The instance line and the status-check line are `current` facts: the state now. An
unhealthy instance also gets a separate status-check line. The launch and state-change
facts and the metric facts carry times. Scheduled events are `current` and state
their own times.

## Common causes

1. **Instance status check fails after a change on the host.** Evidence: instance
   status impaired, console output with a boot or mount error, a change in the
   `changes` evidence (new AMI, fstab or user data edit, disk resize) shortly before.
   Rule out: system status also impaired (then the host, cause 2). Work order:
   mitigation is to replace the instance from the last good image or fix the
   volume; permanent fix names the change (image id, user data line, mount entry).
2. **Underlying host failure or scheduled retirement.** Evidence: system status
   impaired, or a scheduled event with a code such as `instance-retirement` or
   `system-reboot`. Work order: instance id, event code and `NotBefore`; mitigation is
   a stop and start (a reboot keeps the host) or a replacement; permanent fix is a
   group that replaces failed instances.
3. **Memory, disk, or CPU exhausted.** Evidence: CPU peak far above a week earlier,
   console output with out-of-memory kills or "No space left on device", application
   log lines at the same time. Rule out: a CPU peak that ended before the incident.
   Work order: the instance type and the peak seen; mitigation is a bigger type or
   more volume space; permanent fix is the leak or the growth in the workload.
4. **Burstable credits used up.** Evidence: instance type of a `t` family, CPU
   pinned at one steady level, and a credit balance near zero (read it with the
   lead command below; the collector does not fetch it). Work order: type, balance
   curve, and the choice between unlimited credits and a non-burstable type.
5. **Stopped or terminated by an action.** Evidence: state `stopped` or `terminated`
   and a stop or terminate call in `changes`, or a state reason naming the group.
   Work order: who or what acted and when; mitigation is to start or replace it;
   permanent fix removes the cause of the action (a scale-in rule, a scheduled stop).
6. **Cannot be reached although it runs.** Evidence: both status checks ok, no
   console error, connections time out. The cause is the network: read `vpc.md`.

## Compare with

A healthy instance of the same group or type, and the CPU facts against one week
earlier, which the metric facts state.

## Follow a lead

```bash
aws ec2 describe-instances --instance-ids <instance id> --profile <triage profile> --region <region> --query 'Reservations[].Instances[].{state:State.Name,transition:StateTransitionReason,code:StateReason.Code,profile:IamInstanceProfile.Arn,image:ImageId}' 2>/dev/null
aws ec2 describe-instance-status --instance-ids <instance id> --include-all-instances --profile <triage profile> --region <region> --query 'InstanceStatuses[].{system:SystemStatus.Details,instance:InstanceStatus.Details,events:Events[].{code:Code,before:NotBefore}}' 2>/dev/null
aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=<instance id> --profile <triage profile> --region <region> --query 'Volumes[].{id:VolumeId,state:State,type:VolumeType,size:Size,iops:Iops}' 2>/dev/null
aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUCreditBalance --dimensions Name=InstanceId,Value=<instance id> --start-time <window start> --end-time <window end> --period 300 --statistics Minimum --profile <triage profile> --region <region> --query 'sort_by(Datapoints,&Timestamp)[].{t:Timestamp,min:Minimum}' 2>/dev/null
```
