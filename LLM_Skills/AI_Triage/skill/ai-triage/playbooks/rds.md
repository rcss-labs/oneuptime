# RDS playbook

## When to open

The target has an `rds` resource, or evidence names a database instance or cluster:
connection errors, timeouts, slow queries, a failover, or a full disk.

## Collect

The plan already runs `rds` for the mapped database (an instance, or a cluster whose
member instances it then describes). Pass `incident_start` (an ISO time with a timezone) so the collector
reads the log file that covers it and keeps the lines around it (up to 6 files). Add these when they apply. Take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| A reader or replica is involved, or lag is reported | `run collect rds ... --case-dir <case> --suffix reader --target db=<reader instance id>` |
| The state is `inaccessible-encryption-credentials`, or the storage is encrypted | `run collect access ... --case-dir <case> --target kms_key=<key id of the instance> --suffix <word>` |
| The application times out (not "refused") | `run collect vpc ... --case-dir <case> --target security_group_ids=<groups of the database and of the client> --suffix <word>` |
| A parameter, class, or version change is suspected | `run collect changes ... --case-dir <case> --target resource_names=<name> --suffix <word>` and read `cloudtrail.md` |
| The application's own errors are needed | `run collect logs ... --case-dir <case> --target log_groups=<application log group> --suffix <word>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Instance X is available: class, engine, multi-AZ, storage N GiB, pending modified values ..., parameter group P pending-reboot" (`current`) | state now; `pending-reboot` means a parameter value is set but not applied | the events and the change evidence for who set it |
| state `storage-full`, `failed`, `incompatible-parameters`, `inaccessible-encryption-credentials` | the instance cannot serve | storage metric; parameter group; `access.md` for the key |
| "Instance event on X: ..." (times) such as a Multi-AZ failover started or completed, restarted, modified, maintenance applied | the instance itself changed at that time | the other facts after that time; the application's connection errors |
| "Instance X endpoint is HOST port N" or "Cluster X writer endpoint is HOST, reader endpoint ..." (`current`) | where the database really is | compare HOST with the host the application's logs or configuration name; a different one means the application points elsewhere (an old instance, a reader, a restored copy) |
| "DatabaseConnections (Maximum): lowest A at T, highest B at T ..." | connections in use | the `max_connections` parameter (Follow a lead); a highest value at the limit means exhaustion |
| "FreeStorageSpace (Minimum): lowest A at T, highest B at T ...; fell below the range of one week earlier at T1" (bytes) | storage left; the lowest value A is the low point | A near zero means the disk filled; check the allocated size in the state fact |
| "CPUUtilization", "ReadLatency", "WriteLatency", "FreeableMemory", "ReplicaLag" with the time the series left last week's range | load or lag against normal | "rose above the range of one week earlier" at a time near the incident start is a lead; "about the same as one week earlier" (neither the incident-part average nor an extreme left last week's range) rules it out |
| "Top wait events by average database load in the window: A 1.20, B 0.40" | where sessions spend time (CPU, IO, locks, client) | the error lines; compare the load with the instance's vCPU count. Absent when Performance Insights is off, which is not a clean result |
| "N error lines found in the lines read, K kept, M not kept ..." with `data["lines"]` (time of the first kept line from the incident start) | errors the engine logged; K is at most 40: up to 5 just before the incident start, the first 15 from it, and the newest 20 | see below; M not kept means more lines exist than shown |
| "No error log file overlapping the window was found", "Error log files overlapping the window that were not read: ...", "The listing was cut after 5 pages ..." | the log evidence is incomplete | the files named; do not read it as no errors |
| "No error line inside the window was found in the last 1,000 lines read" | nothing in the tail of those files | earlier lines were not read; this does not prove there were no errors |

Error lines are masked. What survives: the timestamp, process id, database name,
application name and client address in the prefix; the error class (`ERROR`, `FATAL`,
`PANIC`, `deadlock`); a relation, table, column, constraint, index or key name that
directly follows that word; engine codes (SQLSTATE, `MY-` codes, `ORA-` codes, SQL
Server error, severity, state, MySQL `ERROR 1040 (HY000)`); and a few numbers (error
number, errno, `at character`, `line`, a type length). Users, roles and accounts are
never shown; other numbers show as `<n>`; from any other quote to the end of the line
the text is `<rest masked>`, followed only by the strict engine codes found in that part. A line therefore tells you the class and where, not who
or which value. Do not guess a statement from it.

## Common causes

1. **Failover or restart.** Evidence: failover, restart, or "recovery completed" events
   at the incident start; connection errors in the application for a minute or two,
   then recovery; the endpoint unchanged. Rule out: no event in the window. Work
   order: name the event and its time; mitigation is none beyond waiting (state when
   the last error was); permanent fix is reconnect and retry in the client, short
   DNS caching of the endpoint, and finding the failover's cause if the event gives one.
2. **Connection exhaustion.** Evidence: `DatabaseConnections` highest value at the
   `max_connections` value, error lines with "too many connections" or "remaining
   connection slots" (`ERROR 1040`, SQLSTATE `53300`), a recent scale-out of clients. Rule out: highest value far
   below the limit. Work order: the limit, the highest value, the clients times their pool
   size; mitigation is fewer client connections (name the service); permanent fix is
   pool sizing or a proxy, and the limit only if memory allows.
3. **Storage full.** Evidence: `storage-full`, `FreeStorageSpace` near zero, write
   errors. Rule out: a gigabyte or more free at the incident start. Work order:
   allocated storage and what grew; mitigation is more allocated storage (a pending
   modification shows in the state fact; storage changes have a cooldown); permanent
   fix is storage autoscaling with a maximum, and removing the growth.
4. **Slow queries or lock contention.** Evidence: CPU or latency that rose at the
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
aws rds describe-db-parameters --db-parameter-group-name <group> --source user --profile <triage profile> --region <region> --max-items 100 --query 'Parameters[].{name:ParameterName,value:ParameterValue,apply:ApplyMethod}'
aws rds describe-pending-maintenance-actions --filters Name=db-instance-id,Values=<instance> --profile <triage profile> --region <region> --query 'PendingMaintenanceActions[].PendingMaintenanceActionDetails[].{action:Action,due:AutoAppliedAfterDate,current:CurrentApplyDate}'
aws rds describe-events --source-identifier <instance> --source-type db-instance --duration 1440 --profile <triage profile> --region <region> --max-items 50 --query 'Events[].{at:Date,message:Message}'
```
