# AI Triage: access and permissions

This document lists every permission the AI Triage skill needs, why it needs it,
and how to set it up. The skill only reads. It never changes anything in AWS,
Kubernetes, OpenSearch, or OneUptime.

## How read-only is guaranteed

| System | What enforces read-only | Strength |
|---|---|---|
| AWS | The `ai-triage-read-only` permission set. It grants read actions only and explicitly denies secret values and interactive access. | Enforced by AWS |
| Kubernetes (EKS) | An access entry tied to the AWS access policy `AmazonEKSViewPolicy`. | Enforced by the cluster |
| OpenSearch | The skill's query tool allows only a fixed list of read operations, and the guard blocks every other route to the cluster. | Convention only: the cluster has no login |
| OneUptime | The MCP connection is authorised as read only. | Enforced by OneUptime |

On the engineer's machine, a guard hook makes sure these identities are the ones
in use. It blocks any AWS command that does not use a triage profile, and any
`kubectl` command that does not use the skill's own kubeconfig.

## 1. AWS permission set

### Create it

Do this once, in IAM Identity Center, from the management or delegated
administrator account.

1. Create a permission set named `ai-triage-read-only`. A session duration of two
   hours suits a triage run.
2. Attach the AWS managed policy `ViewOnlyAccess`
   (`arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`).
3. Add the contents of [`iam/ai-triage-inline-policy.json`](../iam/ai-triage-inline-policy.json)
   as the inline policy.
4. Assign the permission set to your on-call group in every account the skill
   should cover.

If you use a different name, set `permission_set` in `triage-config.yaml` to match.
The skill refuses to run with a profile that uses any other permission set.

### Why this composition

The AWS managed `ViewOnlyAccess` policy covers most describe and list calls but
leaves out content such as log events. `ReadOnlyAccess` goes too far the other
way: it allows reading S3 objects, DynamoDB items, queue messages, and source
code. The permission set therefore starts from `ViewOnlyAccess` and adds a short,
explicit list. A missing permission shows up as an access-denied error, which the
skill records in the report's coverage notes.

Checked on 2026-10-04 against `ViewOnlyAccess` version 46 and `ReadOnlyAccess`
version 190. AWS changes these policies over time. Re-run
`tools/check_policy_actions.py` and `run.py verify_access` after AWS updates them.

### What `ViewOnlyAccess` already provides

**This list is unverified until your first `run.py verify_access` run.** The contents of
`ViewOnlyAccess` were not read when this document was written. Every read that rests on it
(SQS queue attributes, the EKS describes, `acm:ListCertificates`, `cloudwatch:GetMetricData`,
the VPC describes, and the rest) is asked of the IAM policy simulator by `run.py verify_access`,
which reports any that are not granted, grouped by the collector that needs them.

ECS describe and list, EC2 describe, EKS describe and list, RDS describe including
events, ElastiCache describe, load balancer basics and target health, CloudWatch
metrics, CloudTrail event lookup, Route 53, EC2 Auto Scaling, VPC networking
describes, SQS queue attributes, DynamoDB table metadata, and API Gateway `GET` on
the common resource paths.

### What the inline policy adds

| Area | Actions | Why triage needs it | Sensitivity |
|---|---|---|---|
| CloudWatch Logs | `logs:GetLogEvents`, `FilterLogEvents`, `StartQuery`, `StopQuery`, `GetQueryResults` | Application and platform errors | High: log content |
| CloudWatch alarms | `cloudwatch:DescribeAlarms`, `DescribeAlarmHistory` | What fired and when | Low |
| AWS Health | `health:DescribeEvents`, `DescribeEventDetails` | AWS-side incidents | Low |
| Tagging | `tag:GetResources` | Finding resources by tag | Low |
| Service Quotas | `servicequotas:ListServiceQuotas` | Limit exhaustion | Low |
| ECR | `ecr:DescribeImages`, `DescribeImageScanFindings` | Which image is deployed and when it was pushed | Low |
| EC2 | `ec2:GetConsoleOutput` | Boot failures | Medium |
| Application Auto Scaling | `application-autoscaling:DescribeScalableTargets`, `DescribeScalingActivities`, `DescribeScalingPolicies` | Service scaling history | Low |
| Lambda | `lambda:GetFunctionConfiguration`, `GetFunctionConcurrency`, `GetFunctionEventInvokeConfig`, `GetEventSourceMapping`, `GetFunctionUrlConfig`, `GetAlias`, `GetAccountSettings` | Settings, limits, event sources | Medium: environment values |
| RDS | `rds:DownloadDBLogFilePortion` | Database error and slow query logs | High: logs may hold query text |
| Performance Insights | `pi:GetResourceMetrics`, `GetResourceMetadata`, `ListAvailableResourceDimensions`, `ListAvailableResourceMetrics` | Database load and top queries | Medium: query text |
| OpenSearch domains | `es:DescribeDomain`, `DescribeDomains`, `DescribeDomainConfig`, `DescribeDomainHealth`, `DescribeDomainNodes`, `DescribeDomainChangeProgress`, `ListTags` | Domain state and configuration changes | Low |
| EFS | `elasticfilesystem:DescribeMountTargets`, `DescribeMountTargetSecurityGroups`, `DescribeAccessPoints`, `DescribeFileSystemPolicy`, `DescribeLifecycleConfiguration` | Mount and access failures | Low |
| SNS | `sns:GetTopicAttributes` | Delivery policy and failures | Low |
| Load balancing | `elasticloadbalancing:DescribeRules`, `DescribeTargetGroupAttributes`, `DescribeListenerCertificates`, `DescribeTags` | Routing and health check settings | Low |
| ACM | `acm:DescribeCertificate` | Certificate expiry | Low |
| CloudFront | `cloudfront:GetDistribution`, `GetDistributionConfig` | Origins and behaviors | Medium: custom origin headers |
| WAF | `wafv2:GetWebACL`, `GetWebACLForResource`, `GetSampledRequests` | Which rule blocked traffic | High: sampled requests |
| API Gateway | `apigateway:GET` on REST and HTTP APIs, account settings, domain names | Stages, integrations, throttling | Low |
| CloudFormation | `cloudformation:DescribeStackEvents` | What a stack update changed | Low |
| CodePipeline | `codepipeline:GetPipelineState`, `ListPipelineExecutions` | Correlate releases with the incident | Low |
| AWS Config | `config:GetResourceConfigHistory` | What changed on one resource, and when | Medium: configuration values |
| Parameter Store | `ssm:DescribeParameters` | Which parameters exist (names and metadata only) | Low |
| IAM | `iam:GetRole`, `GetRolePolicy`, `GetPolicy`, `GetPolicyVersion`, `SimulatePrincipalPolicy` | Diagnose access-denied incidents; power the verify script | Low |
| KMS | `kms:DescribeKey`, `GetKeyPolicy` | Key state and key access | Low |
| Secrets Manager | `secretsmanager:DescribeSecret`, `ListSecrets` | Rotation status only | Low |

Actions that no collector or playbook uses are deliberately not granted (Parameter Store values,
CodeBuild builds, Performance Insights dimension keys, `logs:GetLogRecord`, and similar). Add one together
with the code that needs it.

### Sensitive data decisions

- **API Gateway** usage plans and API keys are not readable, because they expose key values.
- **CloudFront** custom origin headers are readable; collectors do not store those values. CodeBuild is not granted.
- **Log content** is readable for every log group. Triage is not possible without it.
- **Parameter Store** parameter values are not readable, only names and metadata.
- **Secrets Manager** exposes metadata only. Secret values are explicitly denied.
- **ECS task definitions and Lambda configuration** may contain plaintext
  environment values. The skill's collectors redact secret-looking values before
  they reach the model or any report.
- **WAF sampled requests** are readable. Client addresses and headers are redacted.
- **DynamoDB** exposes table metadata and metrics only. Items cannot be read.
- **S3 objects** cannot be read. See the optional exception below.
- **Lambda code** cannot be downloaded.

### Explicit denies

These are denied outright, so they stay blocked even if someone later attaches a
broader policy to the permission set:

`secretsmanager:GetSecretValue`, `secretsmanager:BatchGetSecretValue`,
`kms:Decrypt`, `ssm:StartSession`, `ssm:SendCommand`, `ecs:ExecuteCommand`,
`ec2:GetPasswordData`, `ec2-instance-connect:*`, `rds-data:*`, `rds-db:connect`.

### Optional: load balancer access logs in S3

Off by default. To let triage read load balancer access logs, add this statement
to the inline policy of your permission set, naming only the log buckets. Keep it
out of the copy in this repository.

```json
{
  "Sid": "TriageLoadBalancerAccessLogs",
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::<your-load-balancer-log-bucket>/*"]
}
```

### Cost

Read-only is not free. CloudWatch Logs Insights bills by the volume of data
scanned. The skill always bounds the time window and the number of log groups,
using `limits` in `triage-config.yaml`.

## 2. AWS CLI profiles

Each engineer adds one profile per account to `~/.aws/config`. The name must start
with `triage-` and match the `profile` value for that account in
`triage-config.yaml`.

```ini
[profile triage-prod-main]
sso_session = <your sso session name>
sso_account_id = <account id>
sso_role_name = ai-triage-read-only
region = eu-west-1
```

Sign in with `aws sso login --profile triage-prod-main`. The skill never signs in
for you. When a session expires, it stops and prints this command.

## 3. Kubernetes access for EKS

The AWS API sees a cluster only from outside. To see pods, events, and logs, the
triage role needs read access to the Kubernetes API. An administrator sets this up
once per cluster. The cluster's authentication mode must be `API` or
`API_AND_CONFIG_MAP`.

Find the role that the permission set created in the cluster's account:

```bash
aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/ \
  --query "Roles[?starts_with(RoleName, 'AWSReservedSSO_ai-triage-read-only_')].Arn" \
  --output text --profile <admin profile> --region <region>
```

Create the access entry and attach the view policy. Use the role ARN exactly as
printed, including its path.

```bash
aws eks create-access-entry --cluster-name <cluster> --principal-arn <role arn> \
  --type STANDARD --profile <admin profile> --region <region>

aws eks associate-access-policy --cluster-name <cluster> --principal-arn <role arn> \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy \
  --access-scope type=cluster --profile <admin profile> --region <region>
```

These two commands change the cluster's access configuration. An administrator
runs them. The skill never does.

### What the view policy allows

Checked on 2026-10-04. `get`, `list`, and `watch` on pods, pod logs, events,
deployments, replica sets, stateful sets, daemon sets, jobs, cron jobs, services,
endpoints, ingresses, network policies, config maps, persistent volume claims,
autoscalers, disruption budgets, quotas, and namespaces.

It does not include secrets. It also does not include nodes or the metrics API.
Without the optional role below, node health comes from the AWS side: node group
health, EC2 instance status, and Container Insights.

### Optional: nodes and metrics

To let triage read node state and resource usage from inside the cluster, apply
this manifest and add the group to the access entry.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ai-triage-nodes-read
  labels:
    app: ai-triage
    owner: platform
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["metrics.k8s.io"]
    resources: ["nodes", "pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ai-triage-nodes-read
  labels:
    app: ai-triage
    owner: platform
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ai-triage-nodes-read
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: ai-triage-nodes
```

```bash
aws eks update-access-entry --cluster-name <cluster> --principal-arn <role arn> \
  --kubernetes-groups ai-triage-nodes --profile <admin profile> --region <region>
```

### The skill's own kubeconfig

The skill uses a separate kubeconfig that holds only triage contexts. It never
reads `~/.kube/config`, so your everyday cluster access is not reachable from a
triage run. Each engineer creates the contexts once:

```bash
aws eks update-kubeconfig --name <cluster> --alias triage-<cluster> \
  --kubeconfig ~/.claude/skills/ai-triage/config/kubeconfig \
  --profile triage-<account-alias> --region <region>
```

The alias must match the `context` value for that cluster in `triage-config.yaml`.

During a run, only these `kubectl` verbs are allowed: `get`, `describe`, `logs`,
`events`, `top`, `rollout status`, `rollout history`, `auth can-i`,
`api-resources`, `api-versions`, `explain`, and `version`. Reading secrets,
following logs without a bound, and every changing verb are blocked.

## 4. OpenSearch

The cluster is reachable on the network without a login. Nothing on the server
side stops a write. Read-only therefore rests on two things on the engineer's
machine:

- **The query tool** allows a fixed list of read operations: search, count,
  mappings, settings, and the health and statistics endpoints. Everything else is
  refused.
- **The guard** blocks any command that addresses a configured cluster without
  going through the tool. It matches the cluster's hostname. A cluster reached by
  IP address is not recognised, so always configure and use the hostname.

This is a strong convention, not a hard boundary. Turning on fine-grained access
control and giving the skill a read-only user would close the gap.

Every query has a mandatory time range, a result cap, and a timeout, because a
heavy query against a struggling cluster can make an incident worse.

## 5. OneUptime

Connect the OneUptime MCP server by signing in, and choose **read only** when
authorising. The skill uses only the `get_`, `list_`, and `count_` tools.

## 6. Verify your setup

```bash
~/.claude/skills/ai-triage/.venv/bin/python ~/.claude/skills/ai-triage/scripts/run.py verify_access
```

For every configured account this checks four things:

1. **Identity.** The profile signs in to the expected account with the triage
   permission set.
2. **Reads.** One harmless list or describe call per permission area succeeds.
3. **Reads are granted.** The IAM policy simulator is asked about every read the collectors
   and playbooks use, including those that rest on `ViewOnlyAccess`. A missing grant is
   listed as `Missing grants: <collector>`.
4. **Writes are denied.** The IAM policy simulator is asked about a sample of
   write actions. Nothing is attempted against your resources.

The simulator evaluates the role's own policies. It does not evaluate service
control policies or resource policies, so treat it as a check on the permission
set and not as a full audit.

AWS Health needs a Business or Enterprise support plan. Without one, that check is
reported as skipped.
