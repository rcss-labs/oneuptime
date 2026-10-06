# Auto Scaling playbook

## When to open

The target has an `auto_scaling_group`, or evidence names an Auto Scaling group, an
instance refresh, instances that keep being replaced, or an ECS service whose scaling
policy is in question.

## Collect

The plan already runs `autoscaling` for the mapped group. For ECS service scaling the
same collector also needs `ecs_cluster` and `ecs_service`; add them when the plan did
not. Take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| An ECS service scales by policy | `run collect autoscaling ... --case-dir <case> --target group=<capacity provider group, or the service name> --target ecs_cluster=<cluster> --target ecs_service=<service> --suffix <word>` |
| Launches fail or instances are unhealthy | `run collect ec2 ... --case-dir <case> --target instance_ids=<ids from the activities or the group> --suffix <word>` |
| Launches fail on a network error | `run collect vpc ... --case-dir <case> --target subnet_ids=<the group's subnets> --suffix <word>` |
| A launch failed on a key or role | `run collect access ... --case-dir <case> --target kms_key=<key id> --suffix <word>` or `--target role=<role name>` |
| A load balancer health check replaces instances | `run collect edge ... --case-dir <case> --target load_balancer=<load balancer name> --suffix <word>`; see `edge.md` |
| The group, template, or policy was edited | `run collect changes ... --case-dir <case> --target resource_names=<group name> --target incident_start=<time> --suffix <word>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Group G: min A, max B, desired C, N instances, health check T, grace period S s" | the capacity target and the health check type now (`current`) | desired against max and against the instance count |
| "N of M instances are not healthy and in service" | instances launched but failed health or are still starting | the activities and the instance facts |
| "FAILED scaling activity: Launching a new EC2 instance ... status message: ..." | the group could not add capacity; the message names why | the message text, then the causes below |
| "Scaling activity Successful: Terminating EC2 instance ..." repeated | instances are removed and added in a cycle | the activity's cause excerpt for who asked |
| activity cause "an instance was taken out of service in response to an EC2 health check" | the group replaced a host that failed EC2 checks | `ec2` for the status checks |
| activity cause "... in response to an ELB system health check failure" | the load balancer reported it unhealthy | `edge` target health reasons |
| "Instance refresh R InProgress (status now), P% complete" | a rolling replacement is running now | its status reason; the new instances' health |
| "Instance refresh R Failed ... " with a status reason | the rollout stopped, usually on new instances that never became healthy | the new instances' health and the grace period |
| group fact ends "no process is suspended" | no scaling process is switched off | nothing; rule suspension out |
| group fact ends "suspended processes: Launch (User suspended at <time>)" | a process (Launch, Terminate, HealthCheck, ReplaceUnhealthy, AZRebalance) is off; "inside the incident window" means it was suspended during the incident | `changes` for who; the activity facts for what stopped happening |
| "Scalable target ...: min A, max B; scale-in suspended" | someone suspended ECS service scaling | `changes` for who |
| "Scaling policy P (TargetTrackingScaling); target T on <metric>" | the metric and level that move capacity (`current`) | the metric fact of the same metric for the window |

Activity and refresh facts carry times and only cover the window. Group, scalable
target, and policy facts are `current`; they show the state now, not at the incident
start.

## Common causes

1. **Launches fail for capacity or limits.** Evidence: failed activities with
   `InsufficientInstanceCapacity`, an instance or vCPU limit message, or no free
   addresses in the subnet. Work order: the instance type, zones, and subnets used,
   the exact message; mitigation is another type or zone; permanent fix is a
   mixed-instance group or a raised quota (`platform.md` shows the quota).
2. **The launch template points at something gone.** Evidence: failed activities
   naming a missing image, security group, key pair, or an encrypted volume the
   service cannot use, and a template change in `changes`. Work order: template id
   and version, the missing item, the version that worked.
3. **Health check replacement loop.** Evidence: repeated terminate and launch pairs
   with a health check cause, a grace period shorter than the boot time, targets
   unhealthy in the edge evidence. Work order: grace period now, observed boot
   time, health check type; fix the health check path or lengthen the grace period.
4. **A stuck or failed instance refresh.** Evidence: a refresh `InProgress` for much
   longer than its warmup, or `Failed`, new instances not healthy. Work order:
   refresh id, minimum healthy percentage, and why the new instances fail.
5. **Scale-in at the wrong time.** Evidence: terminations whose cause names a policy
   or alarm, or a scheduled action, matching the incident start. Work order: the
   policy or action name, its metric and target, and the time it fired.
6. **Capacity is at the maximum.** Evidence: desired equals max while load is high.
   Work order: max, desired, and the load fact; the change is a higher max.

## Compare with

Another group of the same service, or the group's activities before the window,
which show what a normal week of scaling looks like.

## Follow a lead

```bash
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names <group> --profile <triage profile> --region <region> --query 'AutoScalingGroups[].{template:LaunchTemplate,subnets:VPCZoneIdentifier,protected:Instances[?ProtectedFromScaleIn].InstanceId}'
aws autoscaling describe-policies --auto-scaling-group-name <group> --profile <triage profile> --region <region> --query 'ScalingPolicies[].{name:PolicyName,type:PolicyType,adjust:ScalingAdjustment,cooldown:Cooldown}'
aws autoscaling describe-scheduled-actions --auto-scaling-group-name <group> --profile <triage profile> --region <region> --query 'ScheduledUpdateGroupActions[].{name:ScheduledActionName,at:StartTime,recurrence:Recurrence,desired:DesiredCapacity}'
aws application-autoscaling describe-scaling-activities --service-namespace ecs --resource-id service/<cluster>/<service> --max-results 20 --profile <triage profile> --region <region> --query 'ScalingActivities[].{start:StartTime,status:StatusCode,cause:Cause}'
```
