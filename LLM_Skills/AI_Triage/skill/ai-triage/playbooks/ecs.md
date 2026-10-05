# ECS playbook

## When to open

The target has an `ecs_service`, or evidence names an ECS cluster, service, or task.

## Collect

The plan already runs `ecs` for the mapped service. Add these when they apply; take
the account, region, window, and case folder from the plan's own lines.

| When | Command |
|---|---|
| The service scales by policy, or tasks were replaced | `run collect autoscaling ... --target group=<Auto Scaling group of the capacity provider>` |
| A task could not pull its image, or the image changed | `run collect ecr ... --target repository=<repository name>` |
| Tasks run on EC2 instances and several stopped together | `run collect ec2 ... --target instance_ids=<ids from the stopped tasks>` |
| Tasks cannot reach a dependency | `run collect vpc ... --target security_group_ids=<the service's groups>` |
| The task role was denied something | `run collect access ... --target role=<task role name>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| desired N, running fewer, pending more than 0 | new tasks start and die, or cannot be placed | the stopped-task facts and the service events |
| a deployment `IN_PROGRESS` long after it was created | the new revision never becomes healthy | the revision comparison |
| "The task definition changed between revision A and B" | the full list of changes is in the fact's `data["changes"]` | each changed line; a value shown as hidden changed but cannot be read |
| stopped: `EssentialContainerExited`, exit code 1 | the application itself quit | its log lines in the logs evidence, first error first |
| stopped: exit code 137, or `OutOfMemoryError` | memory limit reached | the memory metric fact and the task's memory setting |
| stopped: `CannotPullContainerError` | image missing, tag moved, or no access to the registry | `ecr` for the repository; `access` for the execution role |
| stopped: `Task failed ELB health checks` | the container runs but does not answer the health check | the edge evidence: target health reasons, health check path and port |
| service event "unable to place a task" | no capacity, or a placement constraint cannot be met | `autoscaling` and, for EC2 capacity, `ec2` |
| service event "has reached a steady state" before the incident and none after | the service itself did not change | look outside ECS: the edge and data evidence |
| CPU or memory peak that ended before the incident start | load that recovered | report it and rule it out with its times |

A `current` fact (the service line, the task definition line) shows the state now.
What happened at the incident start is in the deployment, event, and stopped-task
facts, which carry times.

## Common causes

1. **A new revision points at the wrong place or lacks a setting.** Evidence: a
   deployment created minutes before the incident start; the revision comparison
   shows a changed environment value, secret reference, image, or command; tasks of
   the new revision exit; the logs name what they could not reach. Rule out: the same
   error already present before the deployment. Work order: mitigation is to set the
   service back to the previous revision (name both revisions and the changed
   setting, old and new value); permanent fix is to correct the setting in the
   source of the task definition.
2. **The image is wrong or missing.** Evidence: `CannotPullContainerError`, or an
   image digest that changed without a new revision. Work order: name the repository,
   the tag or digest that was expected, and the one that is there.
3. **The container runs out of memory.** Evidence: exit code 137 or an
   out-of-memory stop reason, memory metric at the limit before each stop. Work
   order: the memory setting now and the peak that was observed; the change is a
   higher limit or a fix for the growth, never both presented as one.
4. **Health checks fail although the task runs.** Evidence: targets unhealthy with a
   reason in the edge evidence, tasks stopped for failed health checks, no
   application error at start. Work order: the health check's path, port, and
   timeout against what the application serves.
5. **No capacity.** Evidence: placement service events, failed scaling activities.
   Work order: which capacity provider or subnet is exhausted and the limit that applies.
6. **A dependency is down and ECS is the messenger.** Evidence: tasks healthy until
   the incident start, errors in the logs naming a database, cache, or API, no
   deployment in the window. Then the cause is in that dependency's playbook.

## Compare with

The previous revision (the collector does this), the same service in another
environment, and the CPU and memory facts against one week earlier, which the
metric facts state.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws ecs describe-tasks --cluster <cluster> --tasks <task id> --profile <triage profile> --region <region> --query 'tasks[0].{stopped:stoppedReason,containers:containers[].{name:name,exit:exitCode,reason:reason}}' 2>/dev/null
aws ecs list-tasks --cluster <cluster> --service-name <service> --desired-status STOPPED --profile <triage profile> --region <region> --max-items 20 2>/dev/null
aws ecs describe-task-definition --task-definition <family>:<revision> --profile <triage profile> --region <region> --query 'taskDefinition.containerDefinitions[].{name:name,image:image,memory:memory,health:healthCheck}' 2>/dev/null
```

Never print a task definition's environment or secrets with your own command; the
collector shows what may be shown.
