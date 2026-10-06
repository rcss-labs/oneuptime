# EFS playbook

## When to open

The target has an `efs` resource, or evidence names an EFS file system or a mount:
a task or pod that cannot mount, slow file operations, or a stalled mount.

## Collect

The plan already runs `efs` for the mapped file system. It lists mount targets (up to
20), whether their security groups allow NFS, access points that are not available,
and five metrics. Add these when they apply. Take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| A mount target's security groups need reading in full | `run collect vpc ... --case-dir <case> --target security_group_ids=<groups of the mount target> --suffix <word>` |
| The client is in a subnet with no mount target, or routes are suspected | `run collect vpc ... --case-dir <case> --target subnet_ids=<client subnets and mount target subnets> --suffix <word>` |
| The client is a task, instance, or pod | `run collect ecs ... --case-dir <case> --target cluster=<c> --target service=<s> --suffix <word>` (or `ec2` with `instance_ids=<ids>`, `eks` with `cluster=<name>`); read `ecs.md`, `ec2.md`, or `eks.md` |
| The file system is encrypted and the mount fails | `run collect access ... --case-dir <case> --target kms_key=<key id> --suffix <word>` |
| A throughput mode or mount target change is suspected | `run collect changes ... --case-dir <case> --target resource_names=<name> --suffix <word>` and read `cloudtrail.md` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "File system X is available: performance mode generalPurpose, throughput mode bursting, size N GiB" (`current`) | the mode that sets the limits; with `provisioned` it adds "(provisioned N MiB/s)" | the metric facts for that mode |
| "Mount target M in AZ, subnet S, state available, address IP" (`current`) | one entry point per AZ | the client's AZ against this list |
| "File system X has no mount targets" | nothing can mount it | the work order is to create a mount target in each client AZ |
| "Mount targets not available: M (creating)" | a mount target is not usable | its state and the change evidence |
| "Mount target M in AZ allows NFS from SRC" | an inbound rule for TCP 2049 exists on its security groups, from that address range or group | whether the client is inside SRC; the client's own outbound rules, network ACLs, and routes are not checked |
| "Mount target M: nothing allows TCP 2049 in its security groups (...)" | NFS is blocked at the mount target | the groups named; the rule to add, stated in the work order |
| "Mount target M: whether it allows NFS ... could not be determined" | no verdict | say so; read the groups with `vpc` |
| "Access point A (name) is creating, deleting, or error" | clients using that access point fail | the access point's state and the change evidence |
| "BurstCreditBalance (Minimum): lowest A at T, highest B at T ...; fell below the range of one week earlier at T1" (bytes) | burst credits left; only meaningful in `bursting` mode | the lowest value A near zero with a drop in `PermittedThroughput` means exhaustion |
| "PermittedThroughput (Minimum)", "MeteredIOBytes (Sum)" | the allowed rate and the bytes counted against it | metered I/O at or above the permitted rate means a throughput limit |
| "PercentIOLimit (Maximum): lowest A at T, highest B at T ..." | I/O against the general purpose limit | a highest value B near 100 means the I/O limit, which more throughput does not raise |
| "ClientConnections (Sum)" | connected clients | a fall to zero at the incident start means clients lost the mount |

A `current` fact is the state now. A metric fact carries the time the series first left last week's range, else the time of its extreme.

## Common causes

1. **Burst credits exhausted.** Evidence: bursting mode, `BurstCreditBalance` falling
   to near zero, `PermittedThroughput` dropping to the baseline, slow file operations.
   Rule out: another throughput mode, or a balance that stayed high. Work order: the
   mode, size, minimum balance and the time it ran out; mitigation is switching to
   elastic or provisioned throughput (a mode change has a cooldown before the next);
   permanent fix is the mode and size chosen from the workload's real rate.
2. **A throughput or I/O limit.** Evidence: `MeteredIOBytes` at `PermittedThroughput`
   in provisioned mode, or `PercentIOLimit` near 100 in general purpose. Work order: the
   mode, the limit, the highest value; name which limit, since the fixes differ.
3. **A security group blocks NFS.** Evidence: "nothing allows TCP 2049" for a mount
   target, mount timeouts on clients in that AZ. Rule out: every mount target allows
   NFS from the client's range. Work order: the mount target, its groups, and the missing
   rule (TCP 2049 from the client's group or range); the permanent fix is the rule
   in the source that defines the groups.
4. **No mount target where the client is.** Evidence: the client's AZ or subnet is
   not among the mount target AZs, or "has no mount targets". Work order: the client AZ
   and the AZs that have a mount target.
5. **A mount target or access point not available.** Evidence: a state other than
   `available` in the facts. Work order: the identifier and state; the cause
   is in the change evidence.
6. **The client side, not EFS.** Evidence: mount targets available, NFS allowed from
   the client's range, metrics normal. Then the cause is the client's security group
   outbound rules, network ACLs, routes, or an IAM or key denial; read `vpc.md` and
   `access.md`.

## Compare with

A file system of the same size in another environment, a client in an AZ that mounts
fine against one that does not, and the metric facts against one week earlier.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws efs describe-file-systems --file-system-id <file system> --profile <triage profile> --region <region> --query 'FileSystems[0].{mode:ThroughputMode,provisioned:ProvisionedThroughputInMibps,performance:PerformanceMode,encrypted:Encrypted,state:LifeCycleState}'
aws efs describe-mount-targets --file-system-id <file system> --profile <triage profile> --region <region> --max-items 20 --query 'MountTargets[].{id:MountTargetId,az:AvailabilityZoneName,subnet:SubnetId,state:LifeCycleState}'
aws efs describe-file-system-policy --file-system-id <file system> --profile <triage profile> --region <region> --query 'Policy' | jq -r '.'
```
