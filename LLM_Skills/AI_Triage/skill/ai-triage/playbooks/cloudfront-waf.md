# CloudFront and WAF playbook

## When to open

The target has a CloudFront distribution or a web ACL, or evidence shows 403, 502,
503, or 504 responses at the edge, a CDN host name, or WAF blocks.

## Collect

The plan already runs `cloudfront_waf` for the mapped distribution or web ACL. Add
these when they apply; take the account, region, and window from the
plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| The web ACL is known but not the distribution | `run collect cloudfront_waf ... --case-dir <case> --target web_acl_arn=<web ACL ARN> --suffix <word>` |
| The web ACL guards a load balancer or API stage | `run collect cloudfront_waf ... --case-dir <case> --target resource_arn=<load balancer ARN or stage ARN> --suffix <word>` |
| The origin is a load balancer | `run collect edge ... --case-dir <case> --target load_balancer=<name> --suffix <word>` |
| The origin is an API | `run collect apigateway ... --case-dir <case> --target api_id=<api id> --suffix <word>` |
| A distribution or rule change is suspected | `run collect changes ... --case-dir <case> --target resource_names=<distribution id or web ACL name> --suffix <word>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Distribution D was not found" | wrong id | the id in the plan |
| "Distribution D is Deployed, last modified T and was modified inside the window; domain names ...; origins ...; default cache behavior sends requests to origin O" | incident-time: its configuration changed in the window | the change events: `cloudtrail.md`, `changes` |
| "Distribution D is InProgress" | a change is still rolling out to edges | the modified time |
| "Distribution D is Deployed, last modified T; ..." | `current`, with its modification time; outside the window | rule a change out with that time |
| `5xxErrorRate` peak, `OriginLatency` peak | the origin fails or is slow | the origin's own evidence (`edge.md`, `apigateway.md`) |
| `5xxErrorRate` peak with `OriginLatency` flat | CloudFront could not reach the origin, or the origin name is wrong | the origins in the distribution fact |
| `4xxErrorRate` peak | 403 from a web ACL or an origin access rule, or 404 from a path change | the WAF facts, then the origin |
| `Requests` drop to near zero | clients do not reach the edge | DNS for the host name |
| "Web ACL N (CLOUDFRONT) default action allow, K rules" | `current`; a regional ACL says (REGIONAL) | the rule facts |
| "Rule R priority 10 action block" | the rule blocks outright | the sampled requests for it |
| "Rule G priority 20 override action none (rule group)" | the group applies its own actions, so it can block | the sampled requests for the group |
| "Rule G ... override action count" | the group only counts | rule it out as a blocker |
| "Nothing in web ACL N blocks ..." | WAF is ruled out | the origin |
| "No rule in web ACL N blocks outright, but CAPTCHA or Challenge rules exist" | API clients may be stopped by a challenge they cannot answer | the rule and the client type |
| "Request blocked by rule R: /path from country XX" | incident-time sample, with a time | whether the path is one real users call |
| "Sampling for R covered A to B and saw N requests; WAF samples only the first 5,000" | how much the sample covers; N high and samples few means they are not the whole picture | do not infer a rate from the sample |
| "Blocked requests of web ACL N were not sampled: WAF keeps sampled requests for only the last three hours" | the window is too old for samples | the WAF logs if enabled, or `cloudwatch.md` |
| "K more blocking rules ... were not sampled" | only the first five by priority were sampled | the rule list |

The collector deliberately copies only the path and country of a sampled request:
no headers, no client address, no body. Do not ask for them in a work order; ask the
owner to look in the WAF logs. Only distribution and sample facts carry times.

## Common causes

1. **A WAF rule or managed rule group blocks real traffic.** Evidence: blocked
   samples on paths real clients call, 403s, a rule or group change before the
   start. Rule out: samples only on scanner-like paths, or no block samples. Work
   order: the web ACL, the rule or group name, its priority, and the path
   it blocks; mitigation is to set that rule to count, permanent fix is a narrower
   rule or an exception for the path.
2. **The origin fails.** Evidence: `5xxErrorRate` up with `OriginLatency`, and origin
   evidence of errors. Work order: the origin id and domain, and the origin's cause.
3. **The distribution was changed.** Evidence: modified inside the window, origin or
   behavior or alias differs from the previous configuration. Work order: the
   distribution id, what changed, and the previous value from CloudTrail.
4. **The origin is unreachable from CloudFront.** Evidence: 502 or 504 with flat
   `OriginLatency`, an origin domain that does not resolve, or an origin security
   group that excludes CloudFront. Work order: the origin domain and the rule at the origin.
5. **A rule is in the wrong mode after a change.** Evidence: a rule that changed from
   count to block near the start. Work order: the rule, its old and new action.

## Compare with

The same distribution one week earlier, a second distribution with the same origin, and
the web ACL's blocked share for paths the same clients called before the incident.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws cloudfront get-distribution-config --id <distribution id> --profile <triage profile> --region us-east-1 --query 'DistributionConfig.Origins.Items[].{id:Id,domain:DomainName,readTimeout:CustomOriginConfig.OriginReadTimeout,protocol:CustomOriginConfig.OriginProtocolPolicy}'
aws cloudfront get-distribution-config --id <distribution id> --profile <triage profile> --region us-east-1 --query 'DistributionConfig.WebACLId'
# the web ACL name and id are the last two parts of the WebACLId above (.../webacl/<name>/<id>)
aws wafv2 get-web-acl --name <web ACL name> --scope CLOUDFRONT --id <web ACL id> --profile <triage profile> --region us-east-1 --query 'WebACL.Rules[].{name:Name,priority:Priority,group:Statement.ManagedRuleGroupStatement.Name,overrides:Statement.ManagedRuleGroupStatement.RuleActionOverrides[].Name}'
```
