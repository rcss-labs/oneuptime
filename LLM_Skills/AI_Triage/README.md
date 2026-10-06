# AI Triage

AI Triage is a skill for Claude Code. You point Claude at a OneUptime incident, and it looks for the cause in read-only evidence from AWS, Kubernetes (EKS) and OpenSearch. It maps the incident to a service, collects evidence with scripts, and has analyst subagents read it. Claude then tests hypotheses, and every claim in the report must cite a checked fact. TypeSafe, an independent scoring service, decides how strongly each cause may be labelled (confirmed, probable or candidate), so the confidence comes from judgments and not from Claude's own estimate. The result is a report and a work order that another engineer or agent can act on.

It changes nothing in AWS, Kubernetes, OpenSearch or OneUptime. It describes fixes and does not apply them. Its outputs are files on your machine, a Confluence page and, if you say yes, a Slack message. To score its claims it also sends redacted text to the TypeSafe scoring service (see "What is sent to the scoring service" below).

## What you get from a run

Each run writes a case folder, `<cases_dir>/<incident number>/<timestamp>/`. By default `cases_dir` is `~/.ai-triage/cases`, outside the skill folder, so an upgrade never touches it.

| In the case folder | What it is |
|---|---|
| `report.md` | The report, with nine sections: summary, incident and window, timeline, findings, ranked causes, remediation work order, coverage notes, proposed service map changes, run details. |
| `work-order.json` | The same fixes as data. Each action names the exact resource, its current state, the required state, the change, how to verify it and how to roll it back. |
| `evidence/` | What the collectors read, as numbered facts, with secrets already removed. |
| `findings/` | The analysts' findings, each citing facts, and `checked.json`, the result of checking those citations. |
| `judgments/` | What TypeSafe was asked and answered, and `summary.json`, which holds the labels. |
| `timeline.json` | Incident times and every dated fact, merged and ordered. Facts dated before the window are grouped under their own heading in the report. |
| `case.md`, `case.json`, `incident.json`, `render.json`, `audit.json`, `slack-message.md` | Files that scripts write: the case, the render marker, the publish audit and the proposed Slack text. A case made from recordings is marked as a replay in `case.json`, in every evidence file and on the first line of the report, and it cannot be published. |

Besides the folder you get:

- **A Confluence page**, one per incident under the parent page in your config. The page body is exactly the audited `report.md`.
- **A Slack question.** Claude shows the proposed message and asks whether and where to post it. It posts only when you say yes.
- **A proposed service-map entry**, when the incident matched no service and the target came from discovery. Claude shows the entry and writes it only when you say yes.

## Requirements

### Prerequisites on your machine

- Claude Code.
- Python 3.10 or newer.
- AWS CLI version 2.
- `kubectl`, only if you configure EKS clusters.
- `jq`. The skill's AWS commands pipe their output through it.
- `zsh`. The guard's command scanner is written and tested against zsh. Preflight checks neither `jq` nor `zsh`.

### Accounts and connectors

- **AWS.** An IAM Identity Center permission set named `ai-triage-read-only`, assigned to you in each account. [docs/aws-permissions.md](docs/aws-permissions.md) gives the policy, the profile settings and the Kubernetes access for EKS. An administrator creates the permission set once.
- **OneUptime MCP server, read-only scope.** Connect it with:

  ```bash
  claude mcp add --transport http oneuptime <your OneUptime URL>/mcp
  ```

  Authorise the connection as read only. Claude reads the incident, its monitors, alerts, timeline, labels and notes through it.
- **Confluence and Slack connectors** in Claude Code, for the page and the message.
- **A TypeSafe API key** in the environment variable `TYPESAFE_API_KEY`, set in your shell profile. Without it the skill still runs, but no cause can be labelled above probable, and the report says so. Preflight prints a warning.

## Install, configure, verify

### Install

```bash
cd LLM_Skills/AI_Triage
./install.sh --dry-run   # prints every step, changes nothing
./install.sh
```

The installer checks for the AWS CLI version 2 and Python 3.10, copies the skill to `~/.claude/skills/ai-triage/`, creates a Python environment there, and creates `config/triage-config.yaml` and `config/service-map.yaml` from the examples if they are missing. It does not edit your AWS config or your Claude Code settings. It prints the remaining steps.

The installer refuses to install when the destination, or its nearest existing parent, is the source folder or lies inside it, also through a symbolic link.

### Upgrade

Pull the repository and run `./install.sh` again. It replaces the skill's code and keeps your config, service map and kubeconfig. It copies them to `~/.ai-triage/backups/<timestamp>/` first.

### Uninstall

Remove `~/.claude/skills/ai-triage/` and the `triage-*` profiles in `~/.aws/config`. Case files and backups stay under `~/.ai-triage/`.

### Configure

Your settings live in `~/.claude/skills/ai-triage/config/`, on your machine only.

1. **`triage-config.yaml`.** Your OneUptime address, AWS accounts (alias, account id, profile, regions), OpenSearch clusters, EKS clusters, Confluence space and parent page, Slack channel, `cases_dir` and limits. It holds no secrets. [`triage-config.example.yaml`](skill/ai-triage/config/triage-config.example.yaml) shows every key.
2. **`service-map.yaml`.** Which OneUptime monitors, labels and host names belong to which service, and where each environment of that service runs. An environment may list `depends_on` services. The collection plan then runs a light set (changes, and alarms when mapped) for each direct dependency, one level deep. See [`service-map.example.yaml`](skill/ai-triage/config/service-map.example.yaml). The resources of an environment use these keys, and the file is checked against them:

   Resource keys: `ecs_service`, `ec2_instances`, `auto_scaling_group`, `lambda_functions`, `eks`, `load_balancer`, `api_gateway`, `cloudfront_distribution`, `rds`, `elasticache`, `dynamodb_tables`, `efs`, `sqs_queues`, `sns_topics`, `log_groups`, `opensearch`, `alarms`, `ecr_repository`, `opensearch_domain`.
3. **AWS profiles.** One profile per account in `~/.aws/config`, named as in `triage-config.yaml` (for example `triage-prod-main`), with `sso_role_name = ai-triage-read-only`.
4. **Kubeconfig for EKS.** One context per cluster in the skill's own file, `config/kubeconfig`:

   ```bash
   aws eks update-kubeconfig --name <cluster> --alias triage-<cluster> \
     --kubeconfig ~/.claude/skills/ai-triage/config/kubeconfig \
     --profile triage-<account-alias> --region <region>
   ```

5. **Connectors and TypeSafe.** As under Requirements. The installer also prints the plugin commands for TypeSafe (`claude plugin marketplace add typesafe-ai/skills`, then `claude plugin install typesafe@typesafe-ai`).

Never commit any of these files, or a case folder, to a repository. The config and the service map contain your account ids, host names and internal structure, and the kubeconfig contains cluster addresses. This repository is public, and its examples use only placeholder values.

### Verify

```bash
cd ~/.claude/skills/ai-triage
.venv/bin/python scripts/run.py validate_map    # config and service map are well formed
.venv/bin/python scripts/run.py preflight       # config, sign-in, tools, shell, folders, TypeSafe key
.venv/bin/python scripts/run.py verify_access   # reads work, writes are denied
```

Preflight checks that the config and map load, that the AWS CLI is present, that each account is signed in, that `kubectl` and the kubeconfig exist when EKS clusters are configured, that the cases folder is writable, and whether `TYPESAFE_API_KEY` is set. It also fails when `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` or `AWS_SESSION_TOKEN` is exported (kubectl would use it instead of the triage profile), warns when `~/.aws/cli/alias` defines CLI aliases (top-level and `[command <service>]` sub-command aliases) and when `AWS_CONFIG_FILE` or `AWS_SHARED_CREDENTIALS_FILE` moves where the triage profile is read from, and fails when the session is in replay mode unless you pass `--allow-replay`. It reads Claude Code's newest shell snapshot and fails when a function, alias or shell option would change what an approved command runs. `run.py verify_access` signs in with each profile, makes one harmless read per permission area, simulates every read that the collectors and playbooks use and that rests on `ViewOnlyAccess` (a missing grant is reported by name), and asks the IAM policy simulator about sample writes. Nothing is attempted against your resources.

| Script | Exit 0 | Exit 1 | Exit 2 | Exit 3 |
|---|---|---|---|---|
| `run.py validate_map` | valid | invalid | usage error | |
| `run.py preflight` | ready | a check failed | usage error | only a sign-in is needed |
| `run.py verify_access` | all passed | a check failed | usage or config error | a sign-in expired |

## Permissions in Claude Code

The skill's guard approves the skill's own commands, read-only AWS and kubectl commands and OneUptime read tools without a prompt. File writes are different. The agent writes the intake files (`~/.ai-triage/intake/`), `findings/<name>.json` and `report.json` with Claude Code's Write and Edit tools, and those go through Claude Code's normal permission prompts. For an unattended run, add allow rules to your Claude Code settings:

```json
{ "permissions": { "allow": [
  "Write(~/.ai-triage/intake/**)", "Edit(~/.ai-triage/intake/**)",
  "Write(~/.ai-triage/cases/*/*/findings/*.json)", "Write(~/.ai-triage/cases/*/*/report.json)",
  "Edit(~/.ai-triage/cases/*/*/findings/*.json)", "Edit(~/.ai-triage/cases/*/*/report.json)"
] } }
```

These rules name only the files that the agent writes. They do not let the file tools write a case folder as a whole: do not use `~/.ai-triage/**` or `~/.ai-triage/cases/**`. If you changed `cases_dir`, change the paths. An unattended run needs more than these rules, and the rest is unverified until a live session: reads of `~/.ai-triage/` and of the skill folder (the agent reads case files and playbooks), the Confluence and Slack read tools, and the Confluence write tool, which the guard allows only for the audited body but which Claude Code may still prompt for. The glob forms of the rules above are also unverified. The guard refuses file-tool writes to the files that scripts own: the installed skill folder, and in a case folder `evidence/`, `judgments/`, `findings/checked.json`, `case.json`, `case.md`, `incident.json`, `report.md`, `work-order.json`, `render.json`, `audit.json`, `slack-message.md`, `timeline.json` and any `.stale` file. An allow rule does not override that. The analyst subagents are told to read the case folder and write one findings file there, and nothing else. Whether skill hooks also fire inside subagents is not verified.

## Use

Start a triage in Claude Code by asking, for example, "triage incident 1234" or "find the cause of this incident: https://oneuptime.example.com/...". Or use the slash command with an incident number or URL:

```
/ai-triage 1234
```

The skill then does the following, in order:

1. Runs preflight. An expired sign-in stops the run with the `aws sso login` line to use.
2. Reads the incident from OneUptime (the order is in `reference/intake.md`, which has not yet been run against a live OneUptime), saves it as an intake file and creates the case folder.
3. Matches the incident to a service in the map and chooses the target. With several matches, a TypeSafe question chooses or tells Claude to ask you. With none, `run.py discover --save` looks for the resources behind the host name. If the incident has no host name or discovery finds nothing, Claude asks you.
4. Runs the whole collection plan with `run.py case collect`, then the further collectors that each service playbook names.
5. Dispatches analyst subagents on Sonnet in parallel (changes and logs always; compute, data and edge when there is evidence in their domain). They write findings.
6. Checks every finding against the evidence it cites, and builds `timeline.json`.
7. Forms hypotheses: changes first, then the request path hop by hop, then a comparison with something that works. Each one is tested with a read that could disprove it.
8. Writes `report.json`: symptoms, causes, every hypothesis and the actions. Free text never states a label.
9. Runs judging. TypeSafe scores the claims, and the labels come from its summary.
10. Validates and renders `report.md` and `work-order.json`.
11. Audits the report for secrets, has a subagent read it, publishes it to Confluence, reads the page back and compares it with `run.py publish verify-confluence`, then shows you the Slack message and asks.
12. Proposes a service-map entry when the target came from discovery.
13. Hands over: status, top cause and label, actions, what was not checked and where the case folder is.

Claude stops and asks you when several services match and the judging step cannot choose, when the incident has no host name or discovery finds nothing, when a script prints `REPLAY`, when a sign-in has expired, when a denied permission blocks the main line of investigation, after three rejected hypotheses, when the audit finds something it cannot remove at its source, before posting to Slack, and before changing the service map.

Loading the skill turns on the guard for the rest of that Claude Code session. It stays on. To use your everyday AWS profiles again, start a new session.

## The guard

The guard is a Claude Code hook that evaluates every shell command, every Write and Edit call, and every OneUptime, Slack and Confluence tool call in the session. For AWS and kubectl it approves only what it fully understands. Anything else is not approved, and Claude Code applies your normal permission settings.

- **Allows without a prompt:** AWS commands that use a triage profile, set a region and name a known read operation; kubectl reads (`get`, `describe`, `logs`, `top`, `events` and similar) with the skill's kubeconfig, a triage context and a namespace; the skill's own scripts, with case folders only of the form `<cases_dir>/<incident>/<run>`; the output filters `jq`, `head`, `tail`, `sort`, `uniq`, `wc`, `cut`, `tr` and `column`; and OneUptime read tools.
- **Denies:** AWS commands with another profile or no profile, with a write operation, or with an operation that returns secrets (including EC2 user data from instance attributes, launch template data and spot requests, and VPN pre-shared keys) or writes a local file (including `--cli-input-json`); kubectl write verbs, secret reads and other kubeconfigs; direct requests to a configured OpenSearch cluster (use `run.py opensearch_query`); OneUptime write tools; and file-tool writes to the script-owned files listed above.
- **Asks you** for a Slack tool that sends or changes anything; for a Confluence write whose body is not the report that was audited in the last 30 minutes (the exact audited body is allowed only with the recorded title and, for an update, the page recorded for the incident); for AWS reads that return user data, launch templates or build environments; for `run.py map_suggest apply` and `run.py publish --accept-hits`; for path-like option values outside the CloudWatch Logs name options; and for any command it cannot check (see below).
- **Leaves alone** everything unrelated. Tool names of other connectors, and unusual connector names, fall through to your normal prompt. The guard cannot catch other tools that change infrastructure with your everyday credentials (terraform, `psql`, `curl` to an IP address). Commands that use `aws` indirectly (`env aws`, a full path, `xargs aws`) are asked about.
- **Redirects.** Output redirects to `/dev/null` and copies of one output descriptor to another (`>/dev/null`, `2>/dev/null`, `&>/dev/null`, `2>&1`) are accepted. A redirect to any other file is not approved.
- **Replay.** A case made from recordings is marked as a replay, and the publish commands refuse to publish it. There is no option to override this; the tests reach the publish step through the command's `main` function. `run.py collect` and `run.py opensearch_query` also refuse to write recorded evidence into a live case, or live evidence into a replay case.
- **If the guard breaks** (missing Python environment, crash), the wrapper script falls back to a text check. It denies commands that mention `aws` or `kubectl`, writes to a run's judgments, edits of the skill config, calls to the OpenSearch tool or host, and any connector call to OneUptime, Slack or Confluence. It says what it still cannot cover.

Refused by design, with the reason:

- **A pipe into `grep`.** Claude Code's shell snapshot can define `grep` as a shell function, so the guard cannot know what would run. Use `--query` and `jq`.
- **`~`.** zsh expands it, and the guard cannot see the result. Write `"$HOME/..."` in double quotes.
- **Shell variables and command substitution.** The guard sees the text, not the value that the shell would put in.
- **Input redirects (`<`).** zsh reads forms such as numeric globs as redirects, so what the guard checks would differ from what runs.

Two options are yours alone. `run.py map_suggest apply` writes into your service map. `run.py publish --accept-hits=<digest>` publishes although the audit found something. The skill's instructions forbid the agent to use the second one, and the guard always asks you for a command that carries it.

## What is published, and the residual risk

### What is sent to the scoring service

Every judged run sends redacted text to the TypeSafe scoring service: finding claims, the evidence summaries and quoted passages they cite, what was asked, cause statements, symptoms, scope, and action titles, targets and changes. For `run.py judge locate` it sends the incident title, description, monitors, labels, host names, and each candidate's account alias, region and resource names. The text is redacted first, and account ids become aliases. The redaction limits below apply to this text too.

### What is published

Before anything is published, two automated checks and a reading pass run. The first check applies the redaction rules to the files. The second is an independent detector, written separately and not sharing those rules. Then a subagent reads `report.md`. Evidence is also cleaned when it is collected, so secrets rarely reach Claude at all. Both checks must be clean. Any 12-digit number that is not one of your configured account ids is a hit, and the Slack message and the page title may contain no account id.

Measured on three test sets, the two checks together missed between 1 and 7 percent of planted secrets. The misses were passwords in unusual command forms, phone numbers in some formats, passphrase-like values and short random strings. A false alarm leaks nothing but stops publishing until you approve the exact files with `--accept-hits`. In the build measurements, between 4 and 12 percent of harmless test lines raised a false alarm.

After the final review, a value that follows a secret word is masked whatever its shape, and the second detector flags any value of 16 or more characters after a secret word. What still stays readable after a secret word: values under 8 characters, a single word of up to 15 letters, numbers of up to 14 digits, letter-only names, ARNs and passphrases written as words joined by dashes. A resource whose name follows "key" or "secret" (a UUID key id, for example) may be masked or may prompt at publish time.

This was judged acceptable for an internal, access-controlled Confluence space. It is not acceptable for an external or broad audience. Do not point `confluence.space_key` at such a space.

Stated limits, from the build records:

- Redaction cannot match a key and its value on separate lines, short passwords with no name, or key names written with look-alike letters.
- A secret stored under a misleading setting name is shown: a word under an address name, a short value under an identifier name, a word inside a path, 40 hex characters under a version name. Placeholders for the same value can differ between files.
- Public IPv4 addresses are masked as `<IP-n>`, and the numbering restarts in each evidence file, so two different public addresses in two files can both read `<IP-1>`. Private addresses stay readable. Phone numbers that start with `+` are masked. IPv6 addresses are not.
- RDS log text that an application raises inside the database is shown apart from numbers, and an identifier-shaped value after a keyword is kept. The slow-query log is not read.
- A long host name label (an EKS endpoint, for example) is hidden in environment values.
- The citation check cannot judge meaning: collector wording of 12 or more characters around an asked name counts as found text. The judging step has to catch a quote that does not support its claim.
- Random lower-case tokens shorter than about 40 characters are partly missed by the second detector (in a measurement taken during the build it caught 71 percent at 20 characters and 98 percent at 40).
- CloudTrail lookups read from the window start to five minutes after the incident start, so changes made during the incident are not visible. Global-service events are read in `us-east-1`, except STS and route53domains.
- EKS pod logs start at the window start and are cut by size, so the end of a long window on a busy pod can be missing. The evidence says so.
- A hard link made beforehand to a protected file is not detected. Writes through `env`, `command`, `sudo`, `xargs`, `find -delete`, `git` or `python -c` get Claude Code's normal prompt and are never approved by the guard.
- The report strips only one spelling of the case folder path (`/private/tmp` against `/tmp`).
- An old `slack-message.md` and `audit.json` stay in the folder after outputs go stale. Nothing is posted from them.
- More than 10 cited facts for one finding is refused. TypeSafe thresholds are uncalibrated starting values.
- OpenSearch is read-only by convention only: the cluster has no login, so the query tool and the guard are the barrier.

## Service playbooks

One file per service in `skill/ai-triage/playbooks/`. The agent opens the one that matches the target.

| File | For |
|---|---|
| `access.md` | IAM roles, KMS keys, secrets, and `AccessDenied` errors |
| `apigateway.md` | API Gateway APIs and stages, 429 and 5xx from an API URL |
| `autoscaling.md` | Auto Scaling groups, instance refreshes, scaling that keeps replacing instances |
| `cloudfront-waf.md` | CloudFront distributions and WAF web ACLs, edge 403 and 5xx |
| `cloudtrail.md` | Who changed what, in the window |
| `cloudwatch.md` | Alarms, log groups and metric comparisons |
| `deployments.md` | What changed before the incident: stacks, pipelines, AWS Config |
| `dynamodb.md` | Throttling, slow reads and writes, capacity |
| `ec2.md` | Instances, status checks and scheduled events |
| `ecr.md` | Image pulls, tags and digests |
| `ecs.md` | ECS clusters, services, tasks and task definition revisions |
| `edge.md` | Load balancers, target groups, listeners and certificates |
| `efs.md` | File systems and mounts |
| `eks.md` | Clusters, nodes, namespaces, pods and workloads |
| `elasticache.md` | Redis or Valkey replication groups: timeouts, evictions, failover |
| `lambda.md` | Functions, invocation errors, timeouts and throttling |
| `messaging.md` | SQS queues and SNS topics: backlog, dead letters |
| `opensearch.md` | OpenSearch domains and clusters: status, rejections, disk |
| `platform.md` | AWS Health events and quotas, when several services fail together |
| `rds.md` | Database instances and clusters: connections, failover, disk |
| `vpc.md` | Security groups, subnets and network reachability |

## Troubleshooting

| Symptom | What to do |
|---|---|
| Preflight exits 3 or says the sign-in session has expired | Run the `aws sso login --profile <name>` line it prints, then run preflight again. The skill stops and gives you that line. |
| A command stops with a permission prompt | Read the reason on the prompt. Most often the command uses `~`, a variable, a redirect or `grep`. Write it in the forms in `skill/ai-triage/reference/reading.md`, or approve it yourself if you understand it. |
| The audit reports a hit | Do not edit `report.md`. If the hit is in words Claude wrote in `report.json`, Claude rewrites them there, then judges and renders again. Otherwise read the positions the audit printed. If it is a false alarm, you may publish with `--accept-hits=<digest>`, using the digest the refusal printed. It is valid only for the files exactly as audited, so publish to Confluence before writing the Slack message, or audit again. |
| "the report must be validated and rendered again before anything is published" | `report.json`, the judging summary or `checked.json` changed after the last render. Run `run.py report validate`, then `run.py report render`. If you changed a cause or action after judging, run `run.py judge run` again first. |
| A judging run failed ("failed: ...; judging must be run again") | The TypeSafe call failed or answered in a form the client refused. Every label is candidate. Check `TYPESAFE_API_KEY` and run `run.py judge run` again. If the service is only unavailable, the report is capped at probable and says so. |
| "<file> already exists; pass another --suffix to keep both" | A collector never overwrites evidence. Run it again with a different `--suffix`, or leave the existing file. |
| "the triage guard has no valid config" | `triage-config.yaml` is missing or invalid. Run `run.py validate_map` and fix what it lists. |
| "the skill is not installed correctly" | The Python environment is missing. Run `./install.sh` again. |
| `run.py verify_access` says the profile does not use the `ai-triage-read-only` permission set | The profile's `sso_role_name` points at another permission set. |

## Develop

```bash
cd LLM_Skills/AI_Triage
./run-tests.sh tests/test_guard.py -k kubectl   # chosen test files
./run-tests.sh                                  # this project's whole suite
python3 tools/check_policy_actions.py           # needs network; run after editing the policy
```

Run `./run-tests.sh` with the test files you changed. Do not run the lint of the surrounding OneUptime repository over this folder. The tests never call AWS. `run.py verify_access` is the only command that does, and you run it yourself.

- **Replay scenarios.** `tests/replay/` holds three recorded incidents (`ecs-bad-deploy`, `cert-expired`, `eks-oom-discovered`) with canned AWS and OpenSearch answers. `tests/test_replay_pipeline.py` runs the whole pipeline on them with no credentials. See [tests/replay/README.md](tests/replay/README.md).
- **The instruction files are tested.** `tests/test_skill_text.py`, `tests/test_playbooks.py` and `tests/test_reference_formats.py` check `SKILL.md`, the playbooks, the prompts and `reference/formats.md` against the code: collector names and target keys, that every aws and kubectl command in the text is approved by the real guard, and that the examples in `reference/formats.md` run through the real commands. `tests/test_docs.py` checks the permission document and this README against the code.
- **Design and decisions.** [docs/specs/2026-10-04-ai-triage-design.md](docs/specs/2026-10-04-ai-triage-design.md) is the design before the build, with section 18 on what changed. [docs/decisions.md](docs/decisions.md) records the decisions taken during the build, why, and what each costs if wrong. [docs/aws-permissions.md](docs/aws-permissions.md) explains the permission set.
