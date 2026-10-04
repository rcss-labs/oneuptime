---
name: ai-triage
description: Triage a OneUptime incident against AWS, EKS, and OpenSearch using read-only access. This build contains the foundation only (config, guard, access checks); the triage method is not included yet.
argument-hint: "[incident number or URL]"
disable-model-invocation: true
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "\"$HOME/.claude/skills/ai-triage/scripts/guard_hook.sh\""
          timeout: 10
---

# AI Triage (foundation build)

This build installs the safety foundation. It cannot triage an incident yet.

Invoking this skill turns on the triage guard for the rest of the session. The
guard approves read-only AWS and Kubernetes commands that use a triage profile
or the triage kubeconfig, and blocks every other AWS or Kubernetes command.
Start a new session to work with your everyday profiles again.

## What to do when invoked

1. Run the preflight check and show its output:

   ```bash
   "$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/preflight.py"
   ```

2. If a sign-in session has expired, tell the engineer to run the
   `aws sso login --profile <name>` command that preflight printed. Do not try
   to sign in yourself.
3. Tell the engineer that the triage method is not part of this build.

## Rules that already apply

- Every AWS command sets `--profile` to a triage profile and sets `--region`.
- Every `kubectl` command sets `--kubeconfig` to the skill's kubeconfig,
  `--context` to a triage context, and a namespace.
- Never change anything in AWS, Kubernetes, OpenSearch, or OneUptime.
- Never print or store secret values.
