# Replay scenarios

A scenario is a recorded incident in a folder. The skill's commands read the folder's canned answers in place of
AWS, Kubernetes, and OpenSearch, so the whole pipeline can run with no credentials and no network. Everything in
here is invented: the account ids are the placeholders `111111111111` and `222222222222`, the hostnames end in
`example.com`, and `fixture-db-password-do-not-leak` is a deliberate fake secret that must never reach an output.

## What a scenario folder holds

| File | What it is |
| --- | --- |
| `incident.json` | The incident as OneUptime reports it. `observed_at` is the time the recording was taken; replay passes it as `--now`. |
| `aws.json` | Canned `aws` answers, read by `AI_TRIAGE_FIXTURES`. Each entry has `match` (service and operation), optional `contains` (words that must appear in the arguments), and a `result` or an `error`. The first entry that fits wins. |
| `opensearch.json` | Canned OpenSearch answers (only `ecs-bad-deploy`). Each entry has `path_contains` and a `body`. One body serves every query on that index, so it holds hits and both aggregations. |
| `kubectl.json` | Canned `kubectl` answers (only `eks-oom-discovered`). Each entry has `match` (the verb and first argument, for example `get pods` or `logs <pod>`), optional `contains`, and a `stdout` or an `error`. |
| `engineer-additions.json` | Only for a discovered service: what the engineer adds by hand to what `run.py discover` found (see below). |
| `triage-config.yaml` | The config of the recorded world. `cases_dir` is overridden by the test. |
| `service-map.yaml` | The service map of the recorded world. |
| `findings/` | The canned analyst findings, in the stage 3 format. Each cites facts the collectors really produce from these answers. |
| `report.json` | A canned report draft that names the expected cause with one mitigation and one permanent fix. |
| `expected.json` | What a correct run finds: `cause_keywords`, `not_the_cause`, `mitigation_keywords`, and `must_not_contain`. |

The scenarios:

- `ecs-bad-deploy`: the checkout API is down because task definition revision 42 changed `DB_HOST` to a name that
  does not resolve. Distractors: an RDS CPU spike and a backup before the impact.
- `cert-expired`: the checkout API certificate on the load balancer expired at 12:00:00. Distractor: a routine
  deployment of `checkout-api:41` at 10:05.

- `eks-oom-discovered`: the orders API, which is not in the service map, returns 503 because the containers of its
  EKS deployment are OOMKilled at a 256Mi limit after traffic doubles. The first suspects are wrong: a node group
  update that finished at 13:55 (the platform team's note in the incident) and a database whose connections drop
  because its only client crash-loops. The node group update is in the evidence both as an EKS update and as a
  CloudTrail event. One optional read (`eks describe-addon` for coredns) is access denied, so the
  eks evidence file holds one error. Pod logs hold the fake secret and an invented customer email address.

For a service that is not in the map, `run_pipeline` takes the discovery path: `run.py case init` finds no match,
`run.py discover --hostname` runs against the recording, its output (plus `engineer-additions.json`) goes to
`run.py case target --discovery`, and after publishing `run.py map_suggest propose` prints the entry. discovery follows the IP targets of the load balancer to the pods of the configured EKS cluster and finds the cluster,
namespace, and workload; it cannot find the database of a pod, so the engineer's additions hold the database only.

## Run the pipeline in a test

```python
from replay_support import REPLAY_DIR, favourable_judge, run_pipeline

scenario = REPLAY_DIR / "ecs-bad-deploy"
case_dir = run_pipeline(scenario, tmp_path, favourable_judge(scenario))
```

`run_pipeline` builds a skill folder under `tmp_path`, runs `run.py case init`, `target`, and `plan`, every planned
collector, `run.py findings check`, `run.py timeline`, judging (in this process, with the judge you pass), `run.py report render`,
`run.py publish audit`, `run.py publish confluence`, and `run.py publish slack-message`, and returns the case folder. The commands it
ran are listed by `replay_support.load_log(tmp_path)`. The tests are in `tests/test_replay_pipeline.py`:

```
./run-tests.sh tests/test_replay_pipeline.py
```

## Run a scenario by hand

Work in a scratch copy of the skill folder under a temporary `HOME`. Never use your installed skill folder or its
config: the scenario's config and service map would replace yours. Point the commands at the scenario folder with
`AI_TRIAGE_FIXTURES`; every command that would call a real tool prints `REPLAY MODE` and answers from the folder instead.
A call with no recorded answer is an error in the evidence file. Set `AI_TRIAGE_FIXTURE_LOG` to a file to get one line per
call, with the recorded entry that answered it.

```
SCENARIO="$PWD/tests/replay/ecs-bad-deploy"
export HOME="$(mktemp -d)"                      # this shell only; a scratch home
S="$HOME/.claude/skills/ai-triage"
mkdir -p "$S/config"
cp -R skill/ai-triage/scripts skill/ai-triage/judgments skill/ai-triage/templates skill/ai-triage/VERSION "$S/"
cp "$SCENARIO/triage-config.yaml" "$SCENARIO/service-map.yaml" "$S/config/"
# edit cases_dir in "$S/config/triage-config.yaml" to a folder under $HOME, for example $HOME/cases
export AI_TRIAGE_FIXTURES="$SCENARIO"
python3 "$S/scripts/run.py" case init --incident "$SCENARIO/incident.json" --now 2026-10-04T11:10:00Z
python3 "$S/scripts/run.py" case target --case-dir <the case_dir printed above> --service checkout-api --environment prod
python3 "$S/scripts/run.py" case plan --case-dir <the case_dir>
```

Run each planned command (with `python3` in place of the skill's venv python), copy `findings/` into the case folder, and
carry on with `run.py findings check`, `run.py timeline`, `run.py judge run` (this one needs TypeSafe, or use the test),
`run.py report render`, and `run.py publish audit`. `run.py verify_access` refuses to run in replay mode, and preflight skips the
kubeconfig and shell checks there.

## What the tests check beyond the happy path

- Every call the collectors make is recorded: no call is missed and every recorded answer is used (the call log).
- Every collector writes a fact, or is listed in `expected.json` under `no_facts_expected` with the reason.
- Metric points and ECS service events are recorded in the order the real service returns them (newest first).
- `fixture-db-password-do-not-leak` also sits in one application log line and the reason of one stopped ECS container, where only the
  redactor can stop it.
- The fake judge reads `expected.json`: it favours a cause only when its statement holds the cause keywords and none of
  the `not_the_cause` words, so a draft that blames the distractor is not confirmed.
