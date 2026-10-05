# CloudWatch playbook

## When to open

The target has an alarm or a log group, an alarm is named in the report, or you must
read a metric comparison that any collector wrote (CPU, errors, latency, depth).

## Collect

The plan runs `alarms` for the mapped alarms and `logs` for the mapped log groups. The
metric facts come with every service collector. Add these when they apply.

| When | Command |
|---|---|
| Alarm names are known | `run collect alarms ... --target alarm_names=<name1>,<name2>` |
| An alarm family shares a prefix | `run collect alarms ... --target name_prefix=<prefix>` |
| Log lines should show when the problem began | `run collect logs ... --target log_groups=<group1>,<group2>` |
| The default pattern is too broad or too narrow | `run collect logs ... --target log_groups=<group> --target pattern=<regular expression> --suffix <word>` |
| The first alarm points at a service | the playbook of that service; its collector writes the metric facts |

`logs` matches case-insensitively on error, exception, fatal, panic, time out,
refused, denied, oom, and killed unless you give `pattern`. It cuts at the group limit
in the config and says which groups it skipped.

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Alarm A is ALARM: metric M, threshold GreaterThanThreshold T" | the alarm is firing now (`current`); the excerpt is the state reason | the state history of the same alarm |
| "Alarm A is INSUFFICIENT_DATA" | the metric stopped reporting: the source is down, or nothing is sent | the source's own state |
| "Alarm A changed from OK to ALARM" with a time | the evaluation that crossed the threshold | that time minus the alarm's period times evaluation periods is the onset |
| "The first alarm to go into ALARM in the window was A at T" | the earliest metric alarm, named only when every alarm's history was read to its end; a composite is named apart | what A watches; not necessarily the cause |
| "Which alarm went into ALARM first cannot be named: the history was cut or not read for ..." | earlier changes may exist for the alarms listed | say so; do not name a first alarm |
| "Alarm A: read P pages of state changes, N in the window; showing the newest 20 and the earliest change into ALARM" | a busy alarm; newest changes first, up to 5 pages, then the earliest change into ALARM is kept | the "cut after 5 pages and older changes exist" part means the onset may be older |
| "The composite alarm C changed to ALARM at the same time or earlier" | C summarizes others and fires from them | its rule, to find its children |
| "State change history was read for 20 of N alarms" | alarms were left out, metric alarms first | rerun with the names that matter |
| "N matching log lines in the 5 minutes starting T" | the count per 5-minute bucket | the first and the peak bucket |
| "Peak bucket starts T with N ...; the first bucket with matches starts T0" | T0 is when matching lines began, T the worst moment | T0 against the incident start and the change times |
| "Message pattern seen N times" with a pattern excerpt | a repeated message shape; `<*>` stands for a varying part | the most frequent shape first |
| "Matching log line in stream S" | the earliest matching lines of the window, oldest first | the very first line |
| "No log lines matched the pattern in the window" | none, or the pattern or group is wrong | the group name, the pattern, a wider one |
| "CPUUtilization (Average): peak X at T; window average Y against Z one week earlier (N times higher)" | the comparison reads as load against its normal | the ratio and the peak time |
| "... (about the same)" | within 0.8 to 1.25 of last week; this is usual, not the cause | look elsewhere |
| "... no comparable baseline" | nothing one week earlier: a new resource, or an idle week | do not call it normal or abnormal |
| "... no data was returned for the window" | nothing recorded; for counts this can mean none | the invocation or request metric |
| "... the metric could not be read (see errors)" | the read failed | the collector's errors; permission |

Alarm and log facts with times are incident-time facts; the "Alarm A is ..." line is
`current`. The peak is of 5-minute values, so its time is the start of that period.
For an average statistic it is the highest average, not the highest instant.

## Common causes

Here the cause is usually a misreading of the facts. Most frequent first.

1. **The alarm time taken as the onset.** An alarm fires after its evaluation
   periods, so the real start is earlier. Evidence: the first matching log bucket or
   the metric's first rise comes before the state change. Work order: both times, and
   the alarm's period and evaluation count (lead command).
2. **The first alarm taken as the cause.** It is the most sensitive one, not the
   origin. Rule out by reading the playbook of the service it watches. Work order: the
   alarm, the service, and the facts that confirm or refute a cause there.
3. **Matching lines that began before the window.** A first bucket that already holds
   many lines means the problem started earlier. Work order: say the onset is
   unknown and ask for a wider window.
4. **A noisy pattern.** A steady count equal to last week's is background noise.
   Rerun with a narrower `pattern` before using it; the work order names the pattern.
5. **A cut alarm history.** Evidence: the derived fact says the history was cut after
   5 pages. The earliest change in the window is then unknown. Work order: say that,
   and that no first alarm can be named.

## Compare with

The same metric one week earlier (the fact states it), the alarm's threshold against
the peak, and the log count before the first bucket with matches.

## Follow a lead

```bash
aws cloudwatch describe-alarm-history --alarm-name <alarm> --history-item-type StateUpdate --max-records 50 --profile <triage profile> --region <region> --query 'AlarmHistoryItems[].{t:Timestamp,summary:HistorySummary}' 2>/dev/null
aws cloudwatch describe-alarms --alarm-names <alarm> --profile <triage profile> --region <region> --query 'MetricAlarms[].{period:Period,evaluations:EvaluationPeriods,datapoints:DatapointsToAlarm,missing:TreatMissingData}' 2>/dev/null
aws logs describe-log-streams --log-group-name <log group> --order-by LastEventTime --descending --limit 5 --profile <triage profile> --region <region> --query 'logStreams[].{name:logStreamName,last:lastEventTimestamp}' 2>/dev/null
aws logs describe-log-groups --log-group-name-prefix <log group> --profile <triage profile> --region <region> --query 'logGroups[].{name:logGroupName,retention:retentionInDays}' 2>/dev/null
```
