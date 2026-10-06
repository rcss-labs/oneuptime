# EKS playbook

## When to open

The target has an `eks` resource, or evidence names a cluster, a node, a namespace, a
pod, or a Kubernetes workload.

## Collect

The plan already runs `eks` for the mapped cluster. The collector reads pods, warning
events, workloads, and logs only when it gets a `namespace`; add it when the plan did
not. Take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| The namespace is known and pods are involved | `run collect eks ... --case-dir <case> --target cluster=<cluster> --target namespace=<namespace> --target workloads=deployment/<name> --suffix <word>` |
| A second namespace is involved | the same command with another `namespace` and `--suffix <namespace>` |
| Nodes are unhealthy or missing | `run collect ec2 ... --case-dir <case> --target instance_ids=<node instance ids> --suffix <word>` |
| The nodegroup did not scale or replace nodes | `run collect autoscaling ... --case-dir <case> --target group=<Auto Scaling group of the nodegroup> --suffix <word>` |
| Pods cannot pull an image | `run collect ecr ... --case-dir <case> --target repository=<repository name> --suffix <word>` |
| Pods cannot reach a dependency | `run collect vpc ... --case-dir <case> --target security_group_ids=<node or pod groups> --suffix <word>` |
| The control plane logs are enabled | `run collect logs ... --case-dir <case> --target log_groups=/aws/eks/<cluster>/cluster --suffix <word>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Cluster C is <status>: ... health issues: ..." | the control plane is unhealthy, or a setting is wrong (`current`) | the issue code and message |
| "Nodegroup G is DEGRADED ... health issues: ..." | nodes cannot join or launch; the issue code names why | `autoscaling` and `ec2` for the nodes |
| "Add-on A is DEGRADED" or `CREATE_FAILED` | a core add-on (networking, DNS, storage) is broken; only non-active add-ons are listed | the issue message; `access.md` for its role |
| "Update U (type) is Failed; errors: ..." | a cluster upgrade created inside the window that stopped | the error code; the add-on and nodegroup facts |
| "Nodegroup G update U (ConfigUpdate or VersionUpdate) is Successful, created <time>, N minutes before the window start" | a node rollout (AMI or version); the time is its creation, there is no end time, so it may have finished later; updates up to a day before the window are listed | node health and pod restarts after that time |
| "Pod P is Pending and not ready ... condition PodScheduled false" | nothing could place it: capacity, taints, or requests too large | the excerpt (scheduler message) and the warning events |
| "container X waiting CrashLoopBackOff", restarts counted | the process starts and dies | the log fact of the previous instance |
| "container X last terminated OOMKilled exit code 137 ... resources: container X: memory limit 256Mi, request 128Mi; cpu limit ..." | memory limit reached; the limit and request that the pod runs with are in the same fact ("none" means unset) | the workload fact's limits, and the ReplicaSet lead for the previous ones |
| "waiting ImagePullBackOff" or `ErrImagePull` | image missing, tag moved, or no registry access | `ecr`; the pull message in the excerpt |
| "Warning event FailedScheduling ... N times" | capacity or constraint problem; the count shows persistence | the message: insufficient cpu or memory, untolerated taint, volume zone |
| "Workload W: desired N, ready fewer, updated M; ... resources: container X: memory limit ..., request ..." | a rollout is stuck or pods are failing; the resources are those of the template now (`current`) | rollout history, the pod facts, and the ReplicaSet lead |
| "Log lines of container ... first strong error-looking line: ..." | the lines are in the fact's `data["lines"]`: first 20 and the distinct errors, repeats once | read them in order for the first failure |
| "No log line ... falls inside the incident window" | the process was silent, or logs are not written to stdout | the pod state and previous instance |

Cluster, nodegroup, add-on, pod, and workload lines are `current`. Update, warning
event, and log facts carry times. At most three unhealthy pods get their logs read.
The `data` of AWS facts holds the resource ARN; a workload fact holds its kind, name,
and namespace, and the containers' limits and requests. A work order names those.

Changes made inside the cluster (`kubectl set resources`, an edited ConfigMap, a
scale) are not in CloudTrail, so `changes` shows nothing for them. Look at the
ReplicaSet creation times and the `kubernetes.io/change-cause` annotation (lead
below), and, when control-plane logging is on, the audit log: `run collect logs ... --case-dir <case>
--target log_groups=/aws/eks/<cluster>/cluster --target pattern=<resource name> --suffix <word>`.

## Common causes

1. **A new image or setting breaks the pods.** Evidence: a rollout newer than the
   incident start, pods of the new revision crash, the log's first error names a
   setting or a dependency, the old pods are fine. Work order: workload, both image
   tags, the changed value; mitigation is a rollback to the previous revision;
   permanent fix is the corrected setting in the source manifest.
2. **Memory limit too low.** Evidence: `OOMKilled`, restarts that match the load
   peak. Work order: the memory limit now and the observed use; a higher limit or a
   leak fix, stated separately.
3. **No capacity to schedule.** Evidence: `FailedScheduling` events, Pending pods,
   a nodegroup at its maximum or with health issues. Work order: the nodegroup, its
   min, max, and desired, and the resource that is short.
4. **Image cannot be pulled.** Evidence: `ImagePullBackOff` and a missing tag or a
   denied pull in the excerpt. Work order: image reference, the tag that exists, the
   node role; read `ecr.md`.
5. **A failed upgrade or add-on.** Evidence: an update with errors, a degraded
   add-on, nodes on different versions. Work order: update id, error code, and the
   add-on version; permanent fix is the upgrade order that was skipped.
6. **A dependency fails and the pods report it.** Evidence: errors naming a
   database or API in the logs, healthy until the incident start. The cause is in
   that service's playbook.

## Compare with

Pods of the same workload that are healthy, the previous revision, and the same
workload in another environment. The previous revision's limits and the time it was
applied are read from the workload's ReplicaSets (first lead below): each one's
creation time, revision number, and container resources.

## Follow a lead

```bash
kubectl --kubeconfig "$HOME/.claude/skills/ai-triage/config/kubeconfig" --context <triage context> -n <namespace> get replicasets -l '<label>=<value>' -o json | jq -c '.items[] | {created:.metadata.creationTimestamp,revision:.metadata.annotations["deployment.kubernetes.io/revision"],cause:.metadata.annotations["kubernetes.io/change-cause"],replicas:.spec.replicas,containers:[.spec.template.spec.containers[] | {name:.name,resources:.resources}]}'
kubectl --kubeconfig "$HOME/.claude/skills/ai-triage/config/kubeconfig" --context <triage context> -n <namespace> describe pod <pod>
kubectl --kubeconfig "$HOME/.claude/skills/ai-triage/config/kubeconfig" --context <triage context> -n <namespace> logs <pod> --previous --tail 100
kubectl --kubeconfig "$HOME/.claude/skills/ai-triage/config/kubeconfig" --context <triage context> -n <namespace> get events --sort-by .lastTimestamp
aws eks describe-nodegroup --cluster-name <cluster> --nodegroup-name <nodegroup> --profile <triage profile> --region <region> --query 'nodegroup.{status:status,issues:health.issues,scaling:scalingConfig,ami:amiType,version:version}'
```
