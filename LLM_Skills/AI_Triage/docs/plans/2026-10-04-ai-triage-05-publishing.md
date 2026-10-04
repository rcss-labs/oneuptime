# AI Triage Publishing and Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the last code of the AI Triage skill: the redaction audit and publishing helpers, service map suggestions, and recorded incidents that replay the whole pipeline without AWS.

**Architecture:** Claude publishes through the Confluence and Slack connectors. Code prepares exactly what is published, checks it for leaks first, and records what was done so a rerun updates the same page. Replay scenarios are folders of canned answers that the collectors read in place of AWS.

**Tech Stack:** Python 3.10+ (standard library plus PyYAML 6.0.3), pytest 9.1.1.

**Spec:** `LLM_Skills/AI_Triage/docs/specs/2026-10-04-ai-triage-design.md`, sections 4 (map suggestions), 9 (redaction), 11 (publishing), and 13 (replay tests). This is build stage 5, code part. The skill text, playbooks, and prompts are written by the controller after this plan, test-first, using the replay scenarios from Task 3.

This plan specifies interfaces, behaviour, and required tests. Each task is implemented test-first.

## Global Constraints

- All paths are relative to `LLM_Skills/AI_Triage/`. Run tests with `./run-tests.sh tests/<file>` from that folder.
- Branch `claude-skill`. Never commit to `master`. Never push.
- The repository is a public fork. Use only placeholder account IDs (`111111111111`, `222222222222`), `example.com` hostnames, and invented resource names. Build secret-looking test values at runtime by joining pieces.
- No code in this plan posts to Confluence or Slack, and none calls AWS. Tests make no network call.
- Nothing is prepared for publishing before the audit is clean.
- The service map is changed only by `map_suggest.py apply`, only after a backup, and the result must pass `load_map` or the backup is restored.
- Every command script: `--help` usage, a hidden `--skill-dir` option for tests, exit code 0 on success and 2 for a usage or config error. Other codes are named per task.
- Python 3.10+. Type hints on public functions. No new dependencies. Test-first, with pristine test output. Conventional commits with a body that says why.
- Use `ts_check.py` for the red-phase check and the done check, as the implementer rules describe.

## Interfaces from earlier stages

- `triage.case`: `load_case`, `save_case`, `CaseError`.
- `triage.config`: `TriageConfig` (`confluence_space_key`, `confluence_parent_page_id`, `slack_default_channel`, `cases_dir`), `load_config`, `default_config_path`.
- `triage.service_map`: `load_map`, `parse_map`, `default_map_path`, `MapError`.
- `triage.redact`: `Redactor`, `audit_text`, `AuditHit(category, line, column)`.
- `triage.report`: the `report.json` contract; `report.md` and `work-order.json` in the case folder.
- `triage.fixtures`: `FIXTURE_ENV`, replay mode in `collect.py`, `discover.py`, `opensearch_query.py`, `preflight.py`.
- `triage.collection_plan.plan_collection`; `triage.findings.check_findings`; `triage.timeline.build_timeline`; `triage.judge.run_judgments`; `tests/fakes.py`: `FakeJudge`.

---

### Task 1: Audit and publishing helpers

**Files:**
- Create: `skill/ai-triage/scripts/triage/publish.py`
- Create: `skill/ai-triage/scripts/publish.py`
- Test: `tests/test_publish.py`, `tests/test_publish_cli.py`

**Interfaces:**
- Produces:
  - `triage/publish.py`: `PUBLISHED_FILES = ("report.md", "work-order.json", "slack-message.md")`; `audit_case(case_dir: Path) -> dict`; `page_title(case: dict) -> str`; `confluence_request(case_dir: Path, config: TriageConfig) -> dict`; `previous_page(case_dir: Path) -> dict | None`; `slack_message(case_dir: Path, confluence_url: str | None) -> str`; `record_confluence(case_dir: Path, page_id: str, url: str, now: datetime) -> None`; `record_slack(case_dir: Path, destination: str, now: datetime) -> None`; `PublishError(Exception)`.
  - Command `publish.py` with subcommands `audit`, `confluence`, `slack-message`, `record-confluence`, `record-slack`. Exit codes: 0 done, 1 the audit found something or a precondition failed, 2 usage or config error.

**Behaviour**

- `audit_case` runs `audit_text` over each file in `PUBLISHED_FILES` that exists and writes `audit.json`: `{"clean": bool, "checked": [file names], "hits": [{"file", "line", "column", "category"}]}`. It never stores or prints the matched value. `report.md` must exist; otherwise it raises `PublishError`.
- `page_title` is `<incident number> Triage: <incident title>`, cut to 200 characters.
- `confluence_request` requires `audit.json` to exist with `clean` true, and to be newer than `report.md` (by modification time); otherwise it raises `PublishError("run the audit again")`. It returns `{"space_key", "parent_page_id", "title", "body_file": <absolute path of report.md>, "existing_page": <previous_page result or null>}`.
- `previous_page` looks for a recorded page so that a rerun updates it: first in this case's `case.json` under `publish.confluence`, then in the `case.json` of every sibling run folder of the same incident, newest first. It returns `{"page_id", "url"}` or `None`.
- `slack_message` builds the text from `report.json` and `case.json`: a first line with the incident number and title; the status; the top cause and its label, or that no cause was established; up to three action titles with their labels; the Confluence link when given, otherwise the line `Full report: not published to Confluence`. It is redacted, at most 1500 characters, and is also written to `slack-message.md`.
- `record_confluence` and `record_slack` store what was published in `case.json` under `publish`: `{"confluence": {"page_id", "url", "at"}, "slack": [{"destination", "at"}]}`. Slack entries accumulate.

Command:

- `publish.py audit --case-dir D` prints `clean` or one line per hit as `<file>:<line>:<column> <category>`, and exits 0 or 1.
- `publish.py confluence --case-dir D` prints the request as JSON. A failed precondition exits 1 with the reason.
- `publish.py slack-message --case-dir D [--confluence-url URL]` prints the message, then runs the audit again because it wrote a new published file, and exits 1 if the audit is no longer clean.
- `publish.py record-confluence --case-dir D --page-id ID --url URL` and `publish.py record-slack --case-dir D --destination TEXT`.

**Required tests**

- [ ] Audit: clean files; a hit in each file; a hit never includes the value; missing `report.md`; `audit.json` content.
- [ ] `page_title` cut at 200 characters.
- [ ] `confluence_request`: without an audit, with a dirty audit, with an audit older than the report, and clean and fresh.
- [ ] `previous_page`: none; in this run; in an older sibling run; the newest sibling wins.
- [ ] `slack_message`: a found cause; unresolved; with and without a link; three-action cap; the 1500-character cap; redaction; the file is written.
- [ ] Recording: Confluence overwrites, Slack accumulates, `case.md` is rewritten through `save_case`.
- [ ] Command: every subcommand and exit code.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): audit and prepare what is published`.

### Task 2: Service map suggestions

**Files:**
- Create: `skill/ai-triage/scripts/triage/map_suggest.py`
- Create: `skill/ai-triage/scripts/map_suggest.py`
- Test: `tests/test_map_suggest.py`, `tests/test_map_suggest_cli.py`

**Interfaces:**
- Produces:
  - `triage/map_suggest.py`: `SuggestError(Exception)`; `proposed_entry(case: dict, service_name: str, environment: str, today: date) -> dict`; `entry_yaml(service_name: str, entry: dict) -> str`; `propose(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str, environment: str, today: date) -> dict`; `apply(case_dir: Path, config: TriageConfig, map_path: Path, service_name: str, environment: str, today: date, now: datetime) -> Path`.
  - Command `map_suggest.py propose|apply --case-dir D --service-name NAME [--environment ENV]`. Exit codes: 0 done, 1 the suggestion cannot be made or applied, 2 usage or config error.

**Behaviour**

- A suggestion is made only from a case whose target has `source: "discovered"`. Any other case raises `SuggestError("this run used the service map; there is nothing to add")`.
- `proposed_entry` returns `{"match": {...}, "environments": {<environment>: {"account", "region", "resources", "depends_on"?}}, "source": "discovered", "last_verified": <today as ISO date>}`. The match block holds the incident's monitor names and hostnames. `environment` defaults to `prod`.
- `entry_yaml` renders the entry as a YAML block for one service, indented two spaces under `services:`, with keys in the order `match`, `environments`, `source`, `last_verified`.
- `propose` refuses a `service_name` that already exists in the map (`SuggestError` naming the service and telling the engineer to edit the entry by hand), validates the merged result with `parse_map`, and returns `{"service_name", "yaml": <the block>, "valid": true}`. An invalid result raises `SuggestError` with the map errors.
- `apply` does everything `propose` does, then:
  1. copies the map file to `<map file>.bak-<YYYYMMDD-HHMMSS>` and keeps that path;
  2. writes the new content: when the map has no services (the file is empty, has only comments, or holds `services: {}`), the content is any leading comment lines, then `services:` and the block; otherwise the existing text, a newline if needed, and the block appended;
  3. loads the new file with `load_map`. On any `MapError`, it restores the backup byte for byte and raises `SuggestError("the service map could not be updated automatically; add the entry by hand")`.
  4. records `map_change: {"service_name", "backup", "at"}` in `case.json` and returns the backup path.
- Appending text, rather than rewriting the file from parsed data, keeps the engineer's comments and layout.

**Required tests**

- [ ] `proposed_entry` and `entry_yaml` for a full discovered target; the YAML parses back to the same entry.
- [ ] `propose`: a map-sourced case; an existing service name; an invalid merged map; a valid proposal.
- [ ] `apply` on: a populated map with comments (comments and existing entries are unchanged byte for byte before the appended block); an empty file; a comments-only file; a file holding `services: {}`; a file without a trailing newline.
- [ ] `apply` when the appended result does not load: the original file is restored byte for byte and the error is raised. Force this with a map whose last top-level key is not `services`.
- [ ] The backup exists and equals the original. `case.json` records the change.
- [ ] Command: both subcommands and each exit code; `propose` prints the YAML block and changes nothing.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): propose and apply service map entries`.

### Task 3: Replay scenarios and the end-to-end pipeline test

**Files:**
- Create: `tests/replay/README.md`
- Create: `tests/replay/ecs-bad-deploy/` with `incident.json`, `aws.json`, `opensearch.json`, `triage-config.yaml`, `service-map.yaml`, `findings/` (canned analyst findings), `report.json` (a canned report draft), `expected.json`
- Create: `tests/replay/cert-expired/` with the same set of files, without `opensearch.json`
- Create: `tests/replay_support.py`
- Test: `tests/test_replay_pipeline.py`

**Interfaces:**
- Consumes: every command from stages 2 to 5.
- Produces: two recorded incidents and `replay_support.run_pipeline(scenario: Path, tmp_path: Path, judge) -> Path`, which runs the whole code path and returns the case directory. The scenario folders are also the fixtures the controller uses to test the skill text.

**The scenarios**

Both use the invented service `checkout-api` in account alias `prod-main` (`111111111111`), region `eu-west-1`, ECS cluster `checkout`, load balancer `checkout-prod`, database `checkout-prod-db`, cache `checkout-prod-redis`, log group `/ecs/checkout-api`, hostname `checkout.example.com`. The scenario's `triage-config.yaml` and `service-map.yaml` are complete, valid files for that world, with `cases_dir` left for the test to override.

**`ecs-bad-deploy`.** The incident: "Checkout API is down", impact from 10:42 UTC, declared at 10:45, still open at 11:10 on 2026-10-04. What the fixtures must show:

- CloudTrail: `RegisterTaskDefinition` at 10:36 and `UpdateService` at 10:37 by user `deployer`.
- ECS: a deployment of `checkout-api:42` in progress since 10:37, with `checkout-api:41` still listed; service events from 10:39 saying tasks failed container health checks and were stopped; several stopped tasks with `stoppedReason` "Essential container in task exited" and exit code 1.
- Task definitions: revision 42 differs from 41 only in the environment variable `DB_HOST`, which changed from `checkout-prod-db.cluster-abc.eu-west-1.rds.example.com` to `checkout-db.internal.example.com`. The image is the same in both.
- Logs (CloudWatch Logs Insights answers): from 10:38, many lines `getaddrinfo ENOTFOUND checkout-db.internal.example.com`, and a pattern summary dominated by that message.
- Load balancer: target group with no healthy targets since 10:41; `HTTPCode_ELB_5XX_Count` rising from 10:41.
- RDS: `checkout-prod-db` is `available`; its endpoint address is `checkout-prod-db.cluster-abc.eu-west-1.rds.example.com`; connections dropped at 10:40.
- A distractor: an RDS CPU spike to 85 percent between 09:50 and 10:00 that recovered fully, and an RDS event "Backup completed" at 09:55.
- OpenSearch: the same `ENOTFOUND` messages in index `app-logs-checkout-2026.10.04`.
- A secret to prove redaction end to end: both task definitions carry an environment variable `DB_PASSWORD` whose value is built so that it must never appear in any output. Because fixture files are static JSON, use the fixed value `fixture-db-password-do-not-leak` and assert on that string.

Expected (in `expected.json`): `{"cause_keywords": ["DB_HOST", "checkout-db.internal.example.com", "42"], "not_the_cause": ["CPU", "backup"], "mitigation_keywords": ["41"], "must_not_contain": ["fixture-db-password-do-not-leak"]}`.

**`cert-expired`.** The incident: "Checkout API certificate errors", impact from 12:00:05 UTC, declared at 12:03, still open at 12:30 on 2026-10-04. What the fixtures must show:

- Load balancer `checkout-prod` with an HTTPS listener using an ACM certificate whose `NotAfter` is 2026-10-04T12:00:00Z and whose status is `EXPIRED`.
- Targets all healthy. ECS service steady with no deployment in the window. Load balancer 5xx counts flat.
- Logs: no error lines from the application; the Logs Insights answers are empty.
- A distractor: a routine deployment of `checkout-api:41` at 10:05 that completed normally at 10:09, with CloudTrail `UpdateService` at 10:05.
- Route 53: `checkout.example.com` is an alias to the load balancer.

Expected: `{"cause_keywords": ["certificate", "expired"], "not_the_cause": ["deployment", "checkout-api:41"], "mitigation_keywords": ["certificate"], "must_not_contain": []}`.

**Canned analyst output.** Each scenario's `findings/` holds one or two finding files in the stage 3 format, citing fact ids that the collectors really produce from these fixtures, and `report.json` holds a valid draft that names the expected cause with one mitigation and one permanent fix. Run the collectors once against the fixtures to learn the fact ids, then write these files. The pipeline test fails if a cited fact id does not exist, which keeps the canned files honest.

**Behaviour: `run_pipeline`**

1. Build a temporary skill directory: `config/triage-config.yaml` (the scenario's, with `cases_dir` set under `tmp_path`) and `config/service-map.yaml`.
2. Set `AI_TRIAGE_FIXTURES` to the scenario folder for every command.
3. `case.py init` with the scenario's `incident.json` and `--now` set to the scenario's end time; then `case.py target` with the single matched candidate.
4. `case.py plan`, then run every planned command as a subprocess.
5. Copy the scenario's `findings/` into the case; run `findings.py check`; run `timeline.py`.
6. Copy the scenario's `report.json`; run the judgments in-process with the given `judge`; run `report.py render`.
7. Run `publish.py audit` and `publish.py slack-message`.
8. Return the case directory.

**Required tests**

- [ ] For each scenario, with a `FakeJudge` that answers every question in favour of the canned cause: every planned command exits 0; no evidence file has an error other than ones the scenario intends; every canned finding is valid; the report renders; the audit is clean; the rendered report contains every cause keyword and none of `must_not_contain`; `work-order.json` validates.
- [ ] The secret in `ecs-bad-deploy` appears in no file of the case folder.
- [ ] The timeline of `ecs-bad-deploy` places the `UpdateService` event before the incident start and words the gap as minutes before.
- [ ] With a `FakeJudge` that is unavailable: the report still renders, states that TypeSafe was unavailable, and no cause is labelled `confirmed`.
- [ ] With a `FakeJudge` whose `evidence_relation` answer is `contradicts`: rendering fails validation, because the canned report labels the cause `confirmed`.
- [ ] Replay made no real call: run with `PATH` stripped of `aws` and `kubectl` (prepend a directory holding stub scripts named `aws` and `kubectl` that exit 99 and write to a marker file), and assert the marker file was never created.
- [ ] `tests/replay/README.md` explains what a scenario folder holds and how to run one by hand.

- [ ] **Step 1: Write the failing test** for `ecs-bad-deploy` with the fixture files still missing.
- [ ] **Step 2: Run it** and confirm it fails because the scenario does not exist.
- [ ] **Step 3: Write the fixtures and `replay_support.py`**, running the collectors against the fixtures as you go to see what they produce. Check response shapes with `aws <service> <operation> --generate-cli-skeleton output`.
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `test(ai-triage): replay a failed deployment end to end`.
- [ ] **Step 6: Repeat steps 1 to 4 for `cert-expired`**, then commit as `test(ai-triage): replay an expired certificate end to end`.
