# Edge playbook

## When to open

The target has a load balancer (`load_balancer`), or evidence names a load balancer,
target group, listener, certificate, or a host name served through one.

## Collect

The plan already runs `edge` for the mapped load balancer. Add these when they apply;
take the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| You know the public host name and need to know whether DNS points at this balancer | `run collect edge ... --case-dir <case> --target load_balancer=<name> --target hostname=<host name> --suffix <word>` |
| Targets are ECS tasks that fail health checks | `run collect ecs ... --case-dir <case> --target cluster=<cluster> --target service=<service> --suffix <word>` |
| Targets are instances that are unhealthy or were replaced | `run collect ec2 ... --case-dir <case> --target instance_ids=<target ids> --suffix <word>` |
| Targets cannot be reached on the health check port | `run collect vpc ... --case-dir <case> --target security_group_ids=<balancer and target groups> --suffix <word>` |
| The balancer sits behind CloudFront or a web ACL | `run collect cloudfront_waf ... --case-dir <case> --target resource_arn=<load balancer ARN> --suffix <word>` |
| A listener, rule, or certificate may have been changed | `run collect changes ... --case-dir <case> --target resource_names=<load balancer name> --suffix <word>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Load balancer X was not found" | wrong name or region, or it was deleted | the name in the plan; `cloudtrail.md` for a delete |
| "Load balancer X is active/provisioning/failed: ... zones ..." | `current` state; fewer zones than expected means a subnet was dropped | the zones against the targets' zones |
| "Listener HTTPS 443, certificate <id>" or "certificate none" | `current`; a secure listener without a certificate cannot serve | the certificate facts |
| "Listener ... has N rules forwarding to <groups>" | which target groups take traffic | a group that is missing here gets no traffic |
| "Target group X health check path ..., on port ..., every N seconds, healthy threshold ..." | `current` health check settings | compare path and port with what the application serves |
| "Target group X has 2 healthy, 3 unhealthy targets" | `current` counts; the data holds the states | the per-target facts below |
| "Target T:port in target group X is unhealthy (Target.Timeout): ..." | the target does not answer in time: security group, wrong port, or an overloaded application | `vpc` for the group; the compute playbook |
| reason `Target.ResponseCodeMismatch` | the application answers, with a code the check does not accept | the check path against the application's route |
| reason `Target.FailedHealthChecks` or `Target.NotRegistered`, state `draining`, `unused` | check failing, nothing registered, or deregistration in progress | the deployment or scaling facts of the compute service |
| "N targets are unhealthy in total; only the first 20 are listed" | many failing at once, usually one shared cause | do not read each target; find what they share |
| "Certificate C (domain) is ISSUED, valid until T" | `current`; the time is the expiry | the expiry fact if present |
| "Certificate C expired at T, inside the incident window, N minutes before the window start" | incident-time event, with a time: expiry is the leading cause of TLS failures | whether renewal was possible: `describe-certificate` below |
| "Certificate C expires at T" (within 30 days after the window) | not the cause; report it as a risk | name the date in the report |
| "<host> does not point at this load balancer; its records point at: ..." | traffic goes elsewhere (or the host is served by another balancer) | the record's target; `cloudtrail.md` for a record change |
| "No A, AAAA, or CNAME record named <host> ..." | missing record, or a wildcard applies | the zone in the evidence |
| `HTTPCode_ELB_5XX_Count` peak, `HTTPCode_Target_5XX_Count` zero | the balancer itself failed: no healthy target (503), or timeout (504) | the target counts and `TargetResponseTime` |
| `HTTPCode_Target_5XX_Count` peak | the application returned the 5xx | the compute playbook and the logs |
| `TargetConnectionErrorCount` or `RejectedConnectionCount` peak | targets refuse or cannot be reached; rejected means the balancer hit its connection limit | `vpc`, then the targets |
| "no data was returned for the window" on a metric | no requests, or the wrong balancer dimension | `RequestCount` first |

Network and gateway balancers get no balancer metrics from the collector; only the
per-target-group host counts. Time-bearing facts are the certificate expiry and the
metric peaks; the rest is `current`.

## Common causes

1. **Targets are unhealthy.** Evidence: unhealthy count above zero with a reason,
   `UnHealthyHostCount` up and `HealthyHostCount` down inside the window, balancer 5xx up,
   target 5xx flat. Rule out: all targets healthy for the whole window. Work order: the
   target group, the reason code, the health check path, port, and thresholds; the
   mitigation is on the compute service (restore the last good revision), the permanent
   fix is the check or the application route.
2. **The certificate expired or was replaced.** Evidence: an expiry fact inside the window
   or before it, client TLS errors, healthy targets. Rule out: expiry after the window.
   Work order: the certificate id, domain, the listener that uses it, and whether
   it is ACM-managed with a validation record that no longer exists; mitigation is to
   attach a valid certificate to the listener, the permanent fix is working renewal.
3. **A listener rule or forwarding change.** Evidence: a change event on the balancer
   shortly before the start, a rule forwarding to a group with no targets. Rule out:
   no change event. Work order: the rule, its priority, old and new target group.
4. **Security group or health check mismatch.** Evidence: `Target.Timeout`, nothing in
   the application's logs for the check, a recent security group change. Work order:
   the balancer's group, the target's group, the port.
5. **DNS points elsewhere.** Evidence: the DNS fact above, requests dropping on this
   balancer without errors. Work order: the record name, zone, old and new value.
6. **Targets are overloaded.** Evidence: `TargetResponseTime` peak, target 5xx or 504s,
   CPU or memory at the limit in the compute evidence. Work order: capacity now and the peak.

## Compare with

The same balancer one week earlier (the metric facts state it), another target group
of the same balancer that is healthy, and the same host in another environment.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws elbv2 describe-target-health --target-group-arn <target group ARN> --profile <triage profile> --region <region> --query 'TargetHealthDescriptions[?TargetHealth.State!=`healthy`].{target:Target.Id,port:Target.Port,state:TargetHealth.State,reason:TargetHealth.Reason}'
aws elbv2 describe-rules --listener-arn <listener ARN> --profile <triage profile> --region <region> --query 'Rules[].{priority:Priority,conditions:Conditions[].Field,actions:Actions[].Type}'
aws acm describe-certificate --certificate-arn <certificate ARN> --profile <triage profile> --region <region> --query 'Certificate.{status:Status,notAfter:NotAfter,renewal:RenewalEligibility,inUse:InUseBy}'
```
