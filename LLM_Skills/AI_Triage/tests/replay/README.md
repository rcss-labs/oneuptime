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

## Run the pipeline in a test

```python
from replay_support import REPLAY_DIR, favourable_judge, run_pipeline

scenario = REPLAY_DIR / "ecs-bad-deploy"
case_dir = run_pipeline(scenario, tmp_path, favourable_judge(scenario))
```

`run_pipeline` builds a skill folder under `tmp_path`, runs `case.py init`, `target`, and `plan`, every planned
collector, `findings.py check`, `timeline.py`, judging (in this process, with the judge you pass), `report.py render`,
`publish.py audit`, `publish.py confluence`, and `publish.py slack-message`, and returns the case folder. The commands it
ran are listed by `replay_support.load_log(tmp_path)`. The tests are in `tests/test_replay_pipeline.py`:

```
./run-tests.sh tests/test_replay_pipeline.py
```

## Run a scenario by hand

Point the commands at the scenario folder with `AI_TRIAGE_FIXTURES`; every command that would call a real tool prints
`REPLAY MODE` and answers from the folder instead. Use a skill folder whose `config/` holds the scenario's
`triage-config.yaml` and `service-map.yaml` (set `cases_dir` to a folder you can write to):

```
export AI_TRIAGE_FIXTURES="$PWD/tests/replay/ecs-bad-deploy"
S="$HOME/.claude/skills/ai-triage"
"$S/.venv/bin/python" "$S/scripts/case.py" init --incident "$AI_TRIAGE_FIXTURES/incident.json" --now 2026-10-04T11:10:00Z
"$S/.venv/bin/python" "$S/scripts/case.py" target --case-dir <the case_dir printed above> --service checkout-api --environment prod
"$S/.venv/bin/python" "$S/scripts/case.py" plan --case-dir <the case_dir>
```

Run each planned command, copy `findings/` into the case folder, and carry on with `findings.py check`,
`timeline.py`, `judge.py run` (this one needs TypeSafe, or use the test), `report.py render`, and `publish.py audit`.
`verify_access.py` refuses to run in replay mode, and preflight skips the kubeconfig and shell checks there.
