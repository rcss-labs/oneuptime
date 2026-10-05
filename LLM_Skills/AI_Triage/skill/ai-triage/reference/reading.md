# Your own read-only commands

The collectors gather most evidence. When a lead needs a read they do not make, you
may run it yourself. The guard approves a command only when it can see that it is a
read on a triage profile; anything it does not fully understand is not approved.
A command written differently from the forms below will stop and wait for the
engineer, so write it this way the first time.

## First choice: a collector

`run collect --list` shows every collector and its targets. A collector run writes an
evidence file that findings can cite. A raw command's output cannot be cited, so
after a raw read confirms a lead, collect the same thing with a collector when one
exists. Give a second run of the same collector in one case a different `--suffix`.

## AWS

```bash
aws <service> <operation> --profile <triage profile> --region <region> [options] --query '<JMESPath>' 2>/dev/null | jq -r '<filter>'
```

- The profile is the triage profile of the account, as `case.md` and the config
  name it. No other profile is approved.
- Always give `--region`.
- Only read operations: describe, get, list, lookup-events, filter-log-events,
  start-query and get-query-results, get-metric-data, and the like. Operations that
  write a local file or return secret material are refused.
- Put the `--query` expression in single quotes.
- No argument may be a local path, and never `file://`.
- To narrow output use `--query` and `jq`. The filters `head`, `tail`, `sort`, `uniq`,
  `wc`, `cut`, `tr`, and `column` are approved too. `grep` is not approved.
- The only redirect to use is `2>/dev/null`.
- Bound every read: a time range, `--max-items`, or `--limit`.

## Kubernetes

```bash
kubectl --kubeconfig "$HOME/.claude/skills/ai-triage/config/kubeconfig" --context <triage context> -n <namespace> get|describe|logs|top <...>
```

- Write `--kubeconfig` and its path as two words, with the path in double quotes
  starting at `$HOME`.
- Always give the context and a namespace (`-A` is accepted for `get`).
- `logs` needs a bound: `--since-time`, `--since`, `--tail` (at most 5000), or
  `--limit-bytes`.
- Quote a selector that contains `!`: `-l 'tier!=canary'`.
- Secrets cannot be read.

## OpenSearch

Only through `run opensearch_query <subcommand>` (`--help` lists the subcommands). It
sends search and read-only state requests and nothing else.

## Not approved, by design

Shell variables, `~`, command substitution, `;`, input redirects, writing to files,
`sudo`, and any AWS or kubectl verb that changes something. If you believe a write
is needed to learn something, it is not: put the question in the report's open
questions.
