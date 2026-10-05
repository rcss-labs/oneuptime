# RDS playbook

## When to open

The target has an `rds` resource, or evidence names a database instance or cluster:
connection errors, timeouts, slow queries, a failover, or a full disk.

## Collect

The plan already runs `rds` for the mapped database (an instance, or a cluster whose
member instances it then describes). Pass `incident_start` so the error log lines are
chosen around it. Add these when they apply.

| When | Command |
|---|---|
| A reader or replica is involved, or lag is reported | `run collect rds ... --suffix reader --target db=<reader instance id>` |
| The state is `inaccessible-encryption-credentials`, or the storage is encrypted | `run collect access ... --target kms_key=<key id of the instance>` |
| The application times out (not "refused") | `run collect vpc ... --target security_group_ids=<groups of the database and of the client>` |
| A parameter, class, or version change is suspected | `run collect changes ...` and read `cloudtrail.md` |
| The application's own errors are needed | `run collect logs ... --target log_groups=<application log group>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Instance X is available: class, engine, multi-AZ, storage N GiB, pending modified values ..., parameter group P pending-reboot" (`current`) | state now; `pending-reboot` means a parameter value is set but not applied | the events and the change evidence for who set it |
| state `storage-full`, `failed`, `incompatible-parameters`, `inaccessible-encryption-credentials` | the instance cannot serve | storage metric; parameter group; `access.md` for the key |
| "Instance event on X: ..." (times) such as a Multi-AZ failover started or completed, restarted, modified, maintenance applied | the instance itself changed at that time | the other facts after that time; the application's connection errors |
| "Instance X endpoint is HOST port N" or "Cluster X writer endpoint is HOST, reader endpoint ..." (`current`) | where the database really is | compare HOST with the host the application's logs or configuration name; a different one means the application points elsewhere (an old instance, a reader, a restored copy) |
| "DatabaseConnections (Maximum): peak N ..." | connections in use | the `max_connections` parameter (Follow a lead); a peak at the limit means exhaustion |
| "FreeStorageSpace (Minimum): peak N" (the number is the lowest point, in bytes) | storage left | near zero means the disk filled; check the allocated size in the state fact |
| "CPUUtilization", "ReadLatency", "WriteLatency", "FreeableMemory", "ReplicaLag" with peak time and one-week comparison | load or lag against normal | "times higher" with a peak at the incident start is a lead; "about the same" rules it out |
| "Top wait events by average database load in the window: A 1.20, B 0.40" | where sessions spend time (CPU, IO, locks, client) | the error lines; compare the load with the instance's vCPU count. Absent when Performance Insights is off, which is not a clean result |
| "N error lines found in the lines read, K kept ..." with `data["lines"]` (times) | errors the engine logged | see below |
| "No error line inside the window was found in the last 1,000 lines read" | nothing in the tail of those files | earlier lines were not read; this does not prove there were no errors |

Error lines are masked. What survives: the timestamp, process id, database name,
application name and client address in the prefix; the error class (`ERROR`, `FATAL`,
`PANIC`, `deadlock`); a relation, table, column, constraint, index or key name that
directly follows that word; engine codes (SQLSTATE, `MY-` codes, `ORA-` codes, SQL
Server error, severity, state, MySQL `ERROR 1040 (HY000)`); and a few numbers (error
number, errno, `at character`, `line`, a type length). Users, roles and accounts are
never shown; other numbers show as `<n>`; from any other quote to the end of the line
the text is `<rest masked>`. A line therefore tells you the class and where, not who
or which value. Do not guess a statement from it.

## Common causes

1. **Failover or restart.** Evidence: failover, restart, or "recovery completed" events
   at the incident start; connection errors in the application for a minute or two,
   then recovery; the endpoint unchanged. Rule out: no event in the window. Work
   order: name the event and its time; mitigation is none beyond waiting (state when
   the last error was); permanent fix is reconnect and retry in the client, short
   DNS caching of the endpoint, and finding the failover's cause if the event gives one.
2. **Connection exhaustion.** Evidence: `DatabaseConnections` peak at the
   `max_connections` value, error lines with "too many connections" or "remaining
   connection slots" (`ERROR 1040`, SQLSTATE `53300`), a recent scale-out of clients. Rule out: peak far
   below the limit. Work order: the limit, the peak, the clients times their pool
   size; mitigation is fewer client connections (name the service); permanent fix is
   pool sizing or a proxy, and the limit only if memory allows.
3. **Storage full.** Evidence: `storage-full`, `FreeStorageSpace` near zero, write
   errors. Rule out: a gigabyte or more free at the incident start. Work order:
   allocated storage and what grew; mitigation is more allocated storage (a pending
   modification shows in the state fact; storage changes have a cooldown); permanent
   fix is storage autoscaling with a maximum, and removing the growth.
4. **Slow queries or lock contention.** Evidence: CPU or latency up with a peak at the
   incident start, wait events dominated by one type (lock, IO, CPU), `deadlock` lines
   naming a relation. Rule out: wait load low. Work order: the wait event, relation,
   and times; the statement is not in the evidence, so name the owner to ask; the fix
   is an index or query change.
5. **A parameter or configuration change.** Evidence: `pending-reboot` or
   `incompatible-parameters` in the parameter group status, a modify or parameter
   group event at the incident start, a change in the change evidence. Work order:
   the parameter group, parameter, old and new value; mitigation is the old value.
6. **Maintenance or an engine upgrade.** Evidence: events naming maintenance, an
   upgrade or patch, state `upgrading` or `modifying`, pending maintenance (Follow a
   lead). Work order: the action and its window; the permanent fix is moving it to a
   quiet window.

## Compare with

A reader of the same cluster (the `--suffix reader` run), the same database in
another environment, and the metric facts against one week earlier.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws rds describe-db-parameters --db-parameter-group-name <group> --source user --profile <triage profile> --region <region> --max-items 100 --query 'Parameters[].{name:ParameterName,value:ParameterValue,apply:ApplyMethod}' 2>/dev/null
aws rds describe-pending-maintenance-actions --filters Name=db-instance-id,Values=<instance> --profile <triage profile> --region <region> --query 'PendingMaintenanceActions[].PendingMaintenanceActionDetails[].{action:Action,due:AutoAppliedAfterDate,current:CurrentApplyDate}' 2>/dev/null
aws rds describe-events --source-identifier <instance> --source-type db-instance --duration 1440 --profile <triage profile> --region <region> --max-items 50 --query 'Events[].{at:Date,message:Message}' 2>/dev/null
```
