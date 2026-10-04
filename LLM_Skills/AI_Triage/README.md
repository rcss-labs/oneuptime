# AI Triage

A Claude Code skill that triages a OneUptime incident. You point Claude at an
incident, and it investigates on its own using read-only access to AWS, EKS, and
OpenSearch. It finds the likely root cause and writes a detailed remediation work
order. It never changes anything.

## Status

This is the **foundation build**. It installs the safety layer and the setup
checks:

- the config file and service map, with validation
- the guard that keeps every AWS and Kubernetes command read-only
- the AWS permission policy and the script that verifies your access
- the preflight check and the installer

The triage method, the evidence collectors, the confidence checks, and publishing
to Confluence and Slack arrive in later builds. See
[the design](docs/specs/2026-10-04-ai-triage-design.md).

## Prerequisites

- Claude Code
- AWS CLI version 2
- Python 3.10 or newer
- `kubectl`, only if you configure EKS clusters
- The `ai-triage-read-only` permission set assigned to you in each account. See
  [docs/aws-permissions.md](docs/aws-permissions.md).

## Install

```bash
cd LLM_Skills/AI_Triage
./install.sh --dry-run   # shows every step, changes nothing
./install.sh
```

The skill is copied to `~/.claude/skills/ai-triage/`. The installer does not edit
your AWS config or your Claude Code settings.

## Configure

All of your settings live in `~/.claude/skills/ai-triage/config/`. This folder is
on your machine only. Never copy these files into this repository, which is public.

1. **`triage-config.yaml`.** Your OneUptime address, AWS accounts, OpenSearch
   clusters, EKS clusters, Confluence target, and Slack channel. It holds no
   secrets.
2. **`service-map.yaml`.** Which OneUptime monitors, labels, and hostnames belong
   to which service, and where each environment of that service runs.
3. **AWS profiles.** One profile per account in `~/.aws/config`, named
   `triage-<account-alias>`. See [docs/aws-permissions.md](docs/aws-permissions.md).
4. **Kubeconfig.** One context per EKS cluster in the skill's own kubeconfig. The
   command is in [docs/aws-permissions.md](docs/aws-permissions.md).
5. **Connectors.** Connect OneUptime as read only, then Confluence and Slack:

   ```bash
   claude mcp add --transport http oneuptime <your OneUptime URL>/mcp
   ```

6. **TypeSafe.** Install the plugin and set `TYPESAFE_API_KEY` in your shell
   profile. Without the key the skill still runs, but it cannot label a cause
   higher than "probable".

   ```bash
   claude plugin marketplace add typesafe-ai/skills
   claude plugin install typesafe@typesafe-ai
   ```

## Verify

```bash
cd ~/.claude/skills/ai-triage
.venv/bin/python scripts/validate_map.py    # config and service map are well formed
.venv/bin/python scripts/preflight.py       # sign-in, tools, folders
.venv/bin/python scripts/verify_access.py   # reads work, writes are denied
```

| Script | Exit 0 | Exit 1 | Exit 2 | Exit 3 |
|---|---|---|---|---|
| `validate_map.py` | valid | invalid | usage error | |
| `preflight.py` | ready | a check failed | usage error | only a sign-in is needed |
| `verify_access.py` | all passed | a check failed | usage or config error | a sign-in expired |

When a sign-in has expired, run the `aws sso login --profile <name>` command that
the script prints.

## Use

In Claude Code:

```
/ai-triage
```

In this build the skill runs the preflight check and turns on the guard.

## The guard

Invoking the skill turns on a guard for the rest of that Claude Code session.

- **Approved without a prompt:** read-only AWS commands that use a triage profile
  and set a region, read-only `kubectl` commands that use the skill's kubeconfig
  with a triage context and a namespace, and the skill's own scripts.
- **Blocked:** every other AWS or `kubectl` command, including reads with your
  everyday profiles, and any direct call to a configured OpenSearch cluster.
- **Asked about:** commands the guard cannot check, such as `bash -c "aws ..."`.
- **Left alone:** everything unrelated. Your normal permission settings apply.

To work with your everyday AWS profiles again, start a new session.

## Upgrade

Pull the repository and run `./install.sh` again. Your config, service map, and
kubeconfig are kept, and a copy is saved under `~/.ai-triage/backups/` first.

## Uninstall

Remove `~/.claude/skills/ai-triage/` and the `triage-*` profiles in
`~/.aws/config`. Case files and backups live under `~/.ai-triage/`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| "the triage guard has no valid config" | `triage-config.yaml` is missing or invalid. Run `validate_map.py` and fix what it lists. |
| "profile 'x' is not a triage profile" | The command used a profile that is not in `triage-config.yaml`. Triage commands must use a `triage-` profile. |
| "the skill is not installed correctly" | The Python environment is missing. Run `./install.sh` again. |
| `verify_access.py` reports "does not use the ai-triage-read-only permission set" | The profile's `sso_role_name` points at another permission set. |
| A read check fails with `AccessDeniedException` | The inline policy is missing or out of date in that account. |

## Develop

```bash
cd LLM_Skills/AI_Triage
./run-tests.sh                 # whole suite
./run-tests.sh tests/test_guard.py -k kubectl
python3 tools/check_policy_actions.py   # needs network; run after editing the policy
```

The tests never call AWS. `verify_access.py` is the only thing that does, and you
run it yourself.
