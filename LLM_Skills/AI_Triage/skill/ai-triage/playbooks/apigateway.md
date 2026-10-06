# API Gateway playbook

## When to open

The target has an `api_gateway`, or evidence names an API Gateway REST or HTTP API, a
stage, or 429, 502, 503, or 504 responses from an API URL.

## Collect

The plan already runs `apigateway` for the mapped API. Add these when they apply; take
the account, region, and window from the plan's own lines; `<case>` is the case folder. `<word>` is a
short `--suffix` of your choice: a run without one stops when that collector already
wrote its file for the account and region, as every planned run has.

| When | Command |
|---|---|
| The API is an HTTP API | `run collect apigateway ... --case-dir <case> --target api_id=<api id> --target kind=http --suffix <word>` (REST is the default) |
| Only one stage matters | `run collect apigateway ... --case-dir <case> --target api_id=<api id> --target stage=<stage name> --suffix <word>` |
| The integration is a Lambda function | `run collect lambda ... --case-dir <case> --target function=<function name> --suffix <word>` |
| The integration is a load balancer or service behind a VPC link | `run collect edge ... --case-dir <case> --target load_balancer=<name> --suffix <word>` |
| The API sits behind CloudFront or a web ACL | `run collect cloudfront_waf ... --case-dir <case> --target resource_arn=<stage ARN or distribution ARN> --suffix <word>` |
| A stage or route changed outside a deployment | `run collect changes ... --case-dir <case> --target resource_names=<api id> --suffix <word>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "API X was not found" | wrong id, wrong region, or wrong `kind` | the kind (REST or HTTP) and region |
| "Stage S runs deployment D, last updated T and was updated inside the window; throttling ...; cache ..." | incident-time: the stage changed in the window (a deployment, a setting, or a variable) | the deployment facts and `changes` |
| "Stage S runs deployment D, last updated T; ..." | `current`, with the update time; outside the window | rule the stage change out with that time |
| "throttling rate 100 burst 50" (REST: a method key such as `*/*`; HTTP: `default`) | the stage limit; requests above it get 429 | the Count peak against the rate |
| "no throttling settings" | only the account-level limits apply | the account limit, `platform.md` |
| "Deployment D was created" (with its description) | incident-time: a deployment inside the window | its gap to the incident start; the description names what shipped |
| `5XXError` or `5xx` peak | gateway or integration failed | `IntegrationLatency` against `Latency` |
| `4XXError` or `4xx` peak with `Count` flat or up | 429 from throttling, or 403 from a web ACL or authorizer | stage throttling; `cloudfront_waf` |
| `IntegrationLatency` peak near the integration timeout | backend slow; the gateway returns 504 | the backend's own evidence |
| `Latency` peak far above `IntegrationLatency` | time spent in the gateway (authorizer, mapping) | the authorizer and cache settings |
| `Count` drop to near zero | clients do not reach the API at all | DNS and `edge.md` or CloudFront evidence |
| "no data was returned for the window" | no traffic, or wrong stage or API name | the `Count` metric first |

REST metrics use the API name and the names `5XXError` and `4XXError`; HTTP metrics use
the API id and `5xx` and `4xx`. The collector shows only the newest five deployments
inside the window. Metric peaks and deployments carry times; the stage fact is
`current` unless it was updated in the window.

## Common causes

1. **A deployment or stage change shipped a bad setting.** Evidence: a deployment or
   stage update minutes before the start, errors starting then, integration unchanged.
   Rule out: errors already present before it. Work order: the stage, the old and new
   deployment ids, the changed route, integration, or stage variable; mitigation is
   to point the stage at the previous deployment, permanent fix is in the API definition.
2. **Throttling.** Evidence: 4xx peak with `Count` at or above the stage rate, a 429 in
   the logs, no integration error. Work order: the stage rate and burst now, the
   request peak observed, and whether it is one client; the change is a higher limit
   or a usage plan per client, not both as one.
3. **The integration timed out.** Evidence: `IntegrationLatency` at the integration
   timeout, 504 responses, a slow backend. Work order: the integration's timeout,
   the backend's latency peak; the fix is on the backend (its playbook) first.
4. **The integration target is gone or unreachable.** Evidence: 5xx with low
   `IntegrationLatency`, a deleted function or load balancer, a VPC link or security
   group change. Work order: the integration URI or function name and what happened to it.
5. **A web ACL or authorizer rejects real clients.** Evidence: 403s, a blocking rule
   in the WAF evidence, or an authorizer failing. Work order: the rule or authorizer
   name and the request path it blocks.

## Compare with

The same API's other stages, the same stage one week earlier (the metric facts state
it), and the previous deployment.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws apigateway get-stage --rest-api-id <api id> --stage-name <stage> --profile <triage profile> --region <region> --query '{deployment:deploymentId,updated:lastUpdatedDate,throttling:methodSettings,variableNames:keys(variables)}'
aws apigatewayv2 get-integrations --api-id <api id> --profile <triage profile> --region <region> --max-items 20 --query 'Items[].{id:IntegrationId,type:IntegrationType,uri:IntegrationUri,timeoutMs:TimeoutInMillis}'
```

Stage variables can hold secrets: print their names only, as above.
