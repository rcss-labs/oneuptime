# AI Triage Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the evidence layer of the AI Triage skill: time window arithmetic, redaction at the source, the evidence format, read-only collectors for every playbook, the OpenSearch query tool, and discovery.

**Architecture:** Collectors are small Python modules that call the AWS CLI or `kubectl` through one context object, turn the answers into bounded, redacted facts, and print one evidence JSON document. A registry finds collectors by module, so adding one never edits a shared file. The OpenSearch tool sends only requests that pass a fixed read policy.

**Tech Stack:** Python 3.10+ (standard library plus PyYAML 6.0.3), pytest 9.1.1, AWS CLI v2, `kubectl`.

**Spec:** `LLM_Skills/AI_Triage/docs/specs/2026-10-04-ai-triage-design.md`, sections 3, 5.2, 5.3, 7 (playbook table), 9, and build stage 2 of section 14. Stage 1 is complete; read `docs/plans/2026-10-04-ai-triage-01-foundation.md` only for the interfaces named below.

> **Superseded:** the interfaces and requirements in this plan were changed by later fix rounds and the final review. The repository, not this plan, is the reference. Decisions are in `docs/decisions.md`.

This plan specifies interfaces, behaviour, and required tests. It does not carry complete code. Each task is implemented test-first by its implementer.

## Global Constraints

- All paths are relative to `LLM_Skills/AI_Triage/`. Run tests with `./run-tests.sh tests/<file>` from that folder.
- Branch `claude-skill`. Never commit to `master`. Never push.
- The repository is a public fork. Use only placeholder account IDs (`111111111111`, `222222222222`), `example.com` hostnames, and invented resource names. Build any secret-looking test value at runtime by joining pieces (for example `"AKIA" + "A" * 16`), so that no scanner-matching literal is committed.
- **Read-only.** A collector may only issue AWS CLI operations that `triage.guard_aws.check_aws` allows, and `kubectl` calls that `triage.guard_kubectl.check_kubectl` allows. Every collector test file must assert this with the helpers from Task 5.
- **No live calls in tests.** Tests never call AWS, a cluster, or OpenSearch. They use `tests/fakes.py`. The only `aws` commands an implementer may run by hand are `aws <service> <operation> --generate-cli-skeleton output` (prints the response shape) and `... --generate-cli-skeleton` (checks that options parse). Both are local and make no AWS call.
- Every AWS call goes through `CollectContext.aws`, which uses `triage.awscli.run_aws`. Profile and region are always explicit.
- **Bounded output.** An excerpt is at most 500 characters. A collector emits at most 200 facts. List calls pass `--max-items`. Raw log lines never leave a collector unbounded.
- **Redaction at the source.** Every string that enters a fact passes through the `Redactor`. A collector never bypasses `Evidence.add`.
- **Time and numbers in code.** Collectors compute ordering, durations, and ratios and state them in the fact summary. All times are UTC, formatted `YYYY-MM-DDTHH:MM:SSZ`.
- **Provenance.** Each fact has `kind`: `incident_time` (an event, log line, metric, or audit record with its own timestamp), `current` (state read now), or `derived` (computed from other facts).
- A failed call is recorded as an evidence error and the collector continues. An expired sign-in raises `SignInExpired` and stops the run.
- Python 3.10+. Type hints on public functions. No new dependencies.
- Test-first. Write the failing test, see it fail for the expected reason, then write the code. Keep test output pristine.
- Conventional commits with a body that says why, ending with the attribution lines given in the implementer rules.
- Use the `typesafe-ai` skill for the red-phase check and the done check, as the user's rules require. If it is unavailable, say so in the report and proceed.

## Shared Contracts

These are fixed. Later tasks and later stages depend on the exact names.

### Evidence document

```json
{
  "collector": "ecs",
  "account": "prod-main",
  "region": "eu-west-1",
  "window": {"start": "2026-10-04T10:00:00Z", "end": "2026-10-04T12:00:00Z"},
  "facts": [
    {
      "id": "ecs-0001",
      "kind": "incident_time",
      "time": "2026-10-04T10:42:10Z",
      "resource": "service/checkout/checkout-api",
      "summary": "Deployment of task definition checkout-api:42 started",
      "data": {"task_definition": "checkout-api:42"},
      "command": "aws ecs describe-services --cluster checkout --services checkout-api --profile triage-prod-main --region eu-west-1",
      "excerpt": "(service checkout-api) has started 2 tasks"
    }
  ],
  "errors": [
    {"command": "aws ecs list-tasks ...", "code": "AccessDeniedException", "message": "..."}
  ],
  "truncated": false
}
```

`time` is `null` for `current` and `derived` facts that have no timestamp of their own.

### Stage 1 interfaces this plan uses

- `triage.config`: `TriageConfig`, `Account(alias, account_id, profile, regions)`, `OpenSearchCluster`, `EksCluster`, `load_config`, `default_config_path`, `ConfigError`.
- `triage.awscli`: `run_aws(service, operation, args=(), *, profile, region, runner=subprocess_runner, timeout=60) -> AwsResult(ok, data, error_code, error_message, argv)`, `Runner`, `subprocess_runner`, `SSO_EXPIRED`.
- `triage.guard_aws.check_aws(argv, env, profiles) -> Verdict`; `triage.guard_kubectl.check_kubectl(argv, env, kubeconfig, contexts) -> Verdict`; `triage.verdict.ALLOW`.
- `triage.guard.KUBECONFIG_NAME`.
- `tests/fakes.py`: `FakeAws(answers, default=None)`, `access_denied(action)`, `SSO_EXPIRED_ERROR`. `tests/conftest.py`: `config_data`, `ROOT`, `SKILL_SRC`.

---

### Task 1: Time window and redaction

**Files:**
- Create: `skill/ai-triage/scripts/triage/window.py`
- Create: `skill/ai-triage/scripts/triage/redact.py`
- Test: `tests/test_window.py`
- Test: `tests/test_redact.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `window.py`: `WindowError(ValueError)`; `Window(start: datetime, end: datetime)` frozen dataclass with `duration() -> timedelta`, `shifted(delta: timedelta) -> Window`, `iso() -> dict[str, str]`, `epoch_seconds() -> tuple[int, int]`, `epoch_millis() -> tuple[int, int]`, `contains(moment: datetime) -> bool`; `parse_time(text: str) -> datetime`; `format_time(moment: datetime) -> str`; `make_window(start: str, end: str, max_hours: int) -> Window`; `window_around(incident_start: str, incident_end: str | None, now: datetime, max_hours: int, lead_minutes: int = 60, tail_minutes: int = 15) -> Window`; `describe_offset(event: datetime, reference: datetime) -> str`.
  - `redact.py`: `Redactor` with `text(value: str) -> str`, `value(obj: Any, key: str | None = None) -> Any`, `counts() -> dict[str, int]`; `AuditHit(category: str, line: int, column: int)`; `audit_text(text: str) -> list[AuditHit]`.

**Behaviour: window**

- `parse_time` accepts ISO 8601 with `Z` or a numeric offset and returns an aware UTC `datetime`. A value without a zone raises `WindowError("time must include a timezone: <text>")`. Anything unparseable raises `WindowError`.
- `format_time` returns `YYYY-MM-DDTHH:MM:SSZ`, dropping sub-second precision.
- `make_window` raises `WindowError` when `end` is not after `start`, and when the window is longer than `max_hours`.
- `window_around` starts `lead_minutes` before the incident start. It ends `tail_minutes` after the incident end, or at `now` when the incident is still open, and never after `now`. If the result is longer than `max_hours`, it keeps the start and cuts the end.
- `describe_offset` returns plain words for a model that cannot do time arithmetic: `"at the same time as"` when the gap is under 30 seconds, otherwise `"<N> minutes before"`, `"<N> seconds after"`, `"<H> hours <M> minutes before"`, `"<D> days <H> hours after"`. Use singular units for 1 (`"1 minute before"`).

**Behaviour: redaction**

Placeholders are stable within one `Redactor`: the same original value always maps to the same placeholder, numbered in order of first appearance per category: `<SECRET-1>`, `<EMAIL-1>`, `<IP-1>`. The `Redactor` never exposes original values.

`text` replaces, in this order:

1. PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----` through the matching `END` line) with one secret placeholder.
2. Credentials inside URLs: `scheme://user:password@host` keeps scheme, user, and host and replaces only the password.
3. `Authorization: Bearer <token>` and `Authorization: Basic <token>` values, keeping the scheme word.
4. Key-value pairs whose key looks secret, in the forms `key=value`, `key: value`, `"key": "value"`, and URL query parameters. A key looks secret when, case-insensitively, it contains `password`, `passwd`, `secret`, `token`, `apikey`, `api_key`, `private_key`, `credential`, or `auth`, or ends with `_key` or `-key`. The key is kept and the value replaced.
5. AWS access key IDs (`AKIA` or `ASIA` followed by 16 uppercase letters or digits).
6. JSON Web Tokens (three base64url segments separated by dots, the first starting with `eyJ`).
7. Email addresses, with `<EMAIL-n>`.
8. Public IPv4 addresses, with `<IP-n>`. Addresses in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, and `100.64.0.0/10` are infrastructure and are kept.

`value` walks dicts, lists, and strings and returns a redacted copy without changing the input:

- A string value under a secret-looking dict key is replaced whole.
- A dict shaped like an environment entry, `{"name": N, "value": V}` (also `Name`/`Value`), has `V` replaced when `N` looks secret. This is how ECS and Lambda environment variables arrive.
- A dict entry named `valueFrom` is kept: it is a reference, not a secret.
- Every other string goes through `text`.
- Numbers, booleans, and `None` pass through.

`audit_text` scans finished output for anything rule 1 to 6 would still match and returns the location and category of each hit, never the value. An already redacted text returns `[]`.

**Required tests**

- [ ] Window: parse `Z`, offset, and fractional seconds; reject naive and garbage input; format round trip; `make_window` limits; `window_around` for a closed incident, an open incident, and one that needs cutting; `shifted`, `contains`, epoch conversions; every branch of `describe_offset` including singular units.
- [ ] Redaction, one test per rule above, each asserting the secret is gone and the surrounding text is kept. Build secret-looking inputs at runtime by joining pieces.
- [ ] Stable placeholders: the same value twice gives the same placeholder; two values give two numbers; `counts()` reports distinct values per category.
- [ ] `value`: ECS environment list, Lambda `Environment.Variables` dict, nested lists, `valueFrom` kept, input not mutated, non-string scalars untouched.
- [ ] Hostnames, ports, ARNs, private IPs, and resource names are kept.
- [ ] `audit_text` finds each category in unredacted text and returns `[]` for redacted text; hits carry line and column and no value.

- [ ] **Step 1: Write the failing tests** for both modules as listed.
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_window.py tests/test_redact.py` and confirm they fail because the modules do not exist.
- [ ] **Step 3: Implement** `window.py` and `redact.py`.
- [ ] **Step 4: Run the tests** and confirm they pass with pristine output.
- [ ] **Step 5: Commit** as `feat(ai-triage): add time window arithmetic and source redaction`.

### Task 2: kubectl wrapper and OpenSearch config fields

**Files:**
- Create: `skill/ai-triage/scripts/triage/kubectl.py`
- Modify: `skill/ai-triage/scripts/triage/config.py`
- Modify: `skill/ai-triage/config/triage-config.example.yaml`
- Test: `tests/test_kubectl.py`
- Modify: `tests/test_config.py`

**Interfaces:**
- Consumes: `triage.awscli.Runner`, `subprocess_runner`; `triage.config`.
- Produces:
  - `kubectl.py`: `KubectlResult(ok: bool, stdout: str, error_message: str | None, argv: tuple[str, ...])`; `run_kubectl(args: Sequence[str], *, kubeconfig: Path, context: str, namespace: str | None = None, all_namespaces: bool = False, runner: Runner = subprocess_runner, timeout: int = 60) -> KubectlResult`.
  - `config.py`: `OpenSearchCluster` gains `verify_tls: bool` (default `True`), `ca_bundle: str | None` (default `None`), `message_field: str` (default `"message"`), `level_field: str` (default `"level"`). Existing fields and their order are unchanged; new fields are added at the end with defaults.

**Behaviour**

- `run_kubectl` builds `["kubectl", "--kubeconfig", str(kubeconfig), "--context", context, <namespace part>, *args]`. The namespace part is `["-n", namespace]`, or `["-A"]` when `all_namespaces` is true, or nothing when both are unset (for cluster-scoped reads). Passing both a namespace and `all_namespaces=True` raises `ValueError`.
- Exit code 0 gives `ok=True` with stdout. A non-zero exit gives `ok=False` with stderr trimmed as the message. `FileNotFoundError` gives `ok=False` with `"the kubectl command was not found"`. A timeout gives `ok=False` with `"no answer within <n> seconds"`.
- Config: `verify_tls` must be a boolean; `ca_bundle`, `message_field`, `level_field` must be non-empty strings when present. Wrong types are reported in the same error list as every other config problem. Add `verify_tls: true` to the example file's cluster.

**Required tests**

- [ ] `run_kubectl` argv for a namespace, for all namespaces, and for neither; the `ValueError`; success, failure, missing binary, and timeout.
- [ ] Every argv built by `run_kubectl` for a read verb gets `ALLOW` from `check_kubectl` when the kubeconfig and context are the triage ones.
- [ ] Config defaults when the new keys are absent; each new key accepted; each wrong type rejected with a message naming the key. The existing config tests still pass unchanged.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_kubectl.py tests/test_config.py` and confirm the new ones fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): add the kubectl wrapper and OpenSearch connection settings`.

### Task 3: OpenSearch request policy and client

**Files:**
- Create: `skill/ai-triage/scripts/triage/opensearch/__init__.py`
- Create: `skill/ai-triage/scripts/triage/opensearch/policy.py`
- Create: `skill/ai-triage/scripts/triage/opensearch/client.py`
- Test: `tests/test_opensearch_policy.py`
- Test: `tests/test_opensearch_client.py`

**Interfaces:**
- Consumes: `OpenSearchCluster` (with the Task 2 fields; until Task 2 lands, read them with `getattr(cluster, "verify_tls", True)` style defaults), `Window` from Task 1 (`triage.window`). If Task 1 has not landed when you start, build against the interface listed in Task 1 and use a small local stand-in in tests.
- Produces:
  - `policy.py`: `Refused(Exception)`; `Request(method: str, path: str, params: dict[str, str] = {}, body: dict | None = None)` frozen dataclass; `check_request(request: Request, cluster: OpenSearchCluster, limits: dict[str, int]) -> None` (raises `Refused` with a reason); `search_body(cluster, window: Window, limits, *, query_string: str | None = None, filters: dict[str, str] | None = None, size: int = 0, aggs: dict | None = None, sort_order: str = "asc") -> dict`.
  - `client.py`: `OpenSearchError(Exception)` with `status: int | None`; `Transport = Callable[[str, str, bytes | None, int, bool, str | None], tuple[int, str]]` taking `(method, url, body, timeout_seconds, verify_tls, ca_bundle)`; `urllib_transport`; `OpenSearchClient(cluster, limits, transport=urllib_transport)` with `request(request: Request) -> Any` (parsed JSON, or text when the response is not JSON).

**Behaviour: policy**

`check_request` is the only gate between the skill and a cluster that has no login. It refuses anything not listed here.

- Methods: `GET` and `HEAD` for every allowed path. `POST` only for `<index>/_search`, `<index>/_count`, and `_cluster/allocation/explain`. Every other method is refused.
- The path has no leading slash requirement: normalise by stripping leading and trailing slashes. Refuse a path containing `..`, `%`, `?`, `#`, whitespace, or a backslash.
- Allowed cluster paths, exactly: `_cluster/health`, `_cluster/stats`, `_cluster/settings`, `_cluster/allocation/explain`, `_nodes`, `_nodes/stats`, `_nodes/stats/<metrics>` where `<metrics>` is a comma list of lowercase names, `_tasks`, and `_cat/<name>` where `<name>` is lowercase letters and underscores. `_cat/<name>/<index>` is allowed when `<index>` passes the index rule.
- Allowed index paths: `<index>/_mapping`, `<index>/_settings`, `<index>/_count`, `<index>/_search`.
- Index rule: one expression, no commas. It must not be `*` or `_all`, must not start with `_`, `-`, or `.`, and must match at least one of `cluster.allowed_index_patterns` using `fnmatch.fnmatchcase(expression, allowed)`.
- Parameters: only `format`, `h`, `s`, `v`, `bytes`, `level`, `filter_path`, `flat_settings`, `include_defaults`, `pretty`. Anything else is refused, including `q`, `scroll`, and `size`.
- A body is allowed only on `_search`, `_count`, and `_cluster/allocation/explain`.
- Search and count bodies:
  - Must be a dict. Anywhere in the body, at any depth, the keys `script`, `script_fields`, `scripted_metric`, `runtime_mappings`, `scroll`, and `pit` are refused.
  - The query must be a `bool` whose `filter` list contains a `range` on `cluster.time_field` with both `gte` and `lte` as `YYYY-MM-DDTHH:MM:SSZ` strings, `lte` after `gte`, and a span of at most `limits["max_window_hours"]`.
  - Search only: `size` must be present and at most `limits["opensearch_max_hits"]`; `timeout` must be present; `terminate_after` must be present and at most 100000; `track_total_hits`, when present, must be `false` or an integer of at most 10000.
- `search_body` builds the only shape the tool sends, so that it always passes `check_request`: a `bool` query with the time range filter, one `term` filter per entry of `filters`, an optional `query_string` clause in `must` with `allow_leading_wildcard: false` and `lenient: true`, `size`, `timeout` of `"<limits['opensearch_timeout_seconds']>s"`, `terminate_after: 100000`, `track_total_hits: 10000`, a sort on the time field, and `aggs` when given. A `size` above the limit is clamped to the limit.

**Behaviour: client**

- `request` calls `check_request` first, always. A refused request never reaches the transport.
- The URL is `cluster.endpoint` joined with the path and the encoded parameters. The body is JSON bytes with `Content-Type: application/json`.
- The timeout passed to the transport is `limits["opensearch_timeout_seconds"]` plus 5 seconds.
- A status of 400 or above raises `OpenSearchError` with the status and at most 300 characters of the response. A network failure raises `OpenSearchError` with `status=None`.
- `urllib_transport` uses only the standard library. With `verify_tls=False` it disables certificate checks; with `ca_bundle` it loads that file. It does not follow redirects to another host.

**Required tests**

- [ ] One parametrised table of allowed requests, covering every allowed path form and method.
- [ ] One parametrised table of refused requests, each with the expected reason fragment: `PUT`, `DELETE`, `PATCH`; `POST` to a `_cat` path; `_bulk`, `_delete_by_query`, `_update_by_query`, `_reindex`, `_snapshot`, `_scripts`, `<index>/_doc/1`, `<index>` alone; `_all/_search`, `*/_search`, an index outside the allowed patterns, a comma list, a leading-dot index; `..` and `%2e` in the path; the `q`, `scroll`, and `size` parameters; a body on a `GET _cat` path.
- [ ] Body rules: missing time range, range on another field, range longer than the limit, `lte` before `gte`, missing `size`, `size` over the limit, missing `timeout`, missing `terminate_after`, `track_total_hits: true`, and each forbidden key nested inside an aggregation.
- [ ] `search_body` output passes `check_request` for: no filters, filters, a query string, aggregations, and a clamped size.
- [ ] Client: a refused request never calls the transport; URL and body construction; JSON and text responses; HTTP error; network error; the timeout value; `verify_tls` and `ca_bundle` passed through.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_opensearch_policy.py tests/test_opensearch_client.py` and confirm they fail because the package does not exist.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): add the OpenSearch read policy and client`.

### Task 4: Evidence, collection context, and metrics

**Files:**
- Create: `skill/ai-triage/scripts/triage/evidence.py`
- Create: `skill/ai-triage/scripts/triage/context.py`
- Create: `skill/ai-triage/scripts/triage/metrics.py`
- Test: `tests/test_evidence.py`
- Test: `tests/test_context.py`
- Test: `tests/test_metrics.py`

**Interfaces:**
- Consumes: `Window`, `format_time`, `parse_time` (Task 1); `Redactor` (Task 1); `run_kubectl` (Task 2); `run_aws`, `Runner`, `SSO_EXPIRED` (Stage 1); `TriageConfig`, `Account` (Stage 1); `KUBECONFIG_NAME` (Stage 1).
- Produces:
  - `evidence.py`: constants `INCIDENT_TIME = "incident_time"`, `CURRENT = "current"`, `DERIVED = "derived"`, `MAX_EXCERPT = 500`, `MAX_FACTS = 200`; `Fact` dataclass with the fields of the evidence document; `Evidence(collector: str, account: str, region: str, window: Window, redactor: Redactor | None = None)` with `add(*, kind: str, resource: str, summary: str, time: datetime | str | None = None, data: dict | None = None, command: str = "", excerpt: str = "") -> Fact | None`, `add_error(command: str, code: str, message: str) -> None`, `facts: list[Fact]`, `errors: list[dict]`, `truncated: bool`, `to_dict() -> dict`, `to_json() -> str`, `write(case_dir: Path, suffix: str = "") -> Path`; `load_evidence(path: Path) -> dict`.
  - `context.py`: `SignInExpired(Exception)` with `profile: str`; `CollectContext(config: TriageConfig, account: Account, region: str, window: Window, evidence: Evidence, skill_dir: Path, runner: Runner = subprocess_runner, kube_runner: Runner = subprocess_runner)` with `aws(service: str, operation: str, args: Sequence[str] = (), *, region: str | None = None) -> Any | None`, `last_command: str`, `kubectl(cluster: str, args: Sequence[str], *, namespace: str | None = None, all_namespaces: bool = False) -> str | None`, `kubectl_json(...) -> Any | None`.
  - `metrics.py`: `MetricSpec(label: str, namespace: str, metric: str, dimensions: dict[str, str], stat: str = "Average")` frozen dataclass; `MetricSummary(label, stat, window_avg, window_max, window_min, peak_time, baseline_avg, baseline_max, change_ratio, datapoints)`; `fetch(ctx: CollectContext, specs: Sequence[MetricSpec], period: int = 300) -> list[MetricSummary]`; `add_metric_facts(ctx: CollectContext, resource: str, specs: Sequence[MetricSpec], period: int = 300) -> list[MetricSummary]`.

**Behaviour: evidence**

- Fact ids are `<collector>-<n:04d>`, starting at 1.
- `add` validates `kind` (a `ValueError` for anything else), formats a `datetime` with `format_time`, parses and re-formats a string time, redacts `summary`, `excerpt`, `resource`, and `data`, and cuts the excerpt to `MAX_EXCERPT` characters, ending with `…` when cut.
- After `MAX_FACTS` facts, `add` returns `None`, stores nothing, and sets `truncated`.
- `add_error` redacts the message and cuts it to 300 characters.
- `write` creates `<case_dir>/evidence/` and writes `<collector>-<account>-<region>.json`, or `<collector>-<account>-<region>-<suffix>.json` with a suffix. The suffix is reduced to letters, digits, and dashes. It returns the path.
- `to_dict` matches the evidence document exactly, including key names.

**Behaviour: context**

- `aws` calls `run_aws` with the account's profile and `region or self.region`. It stores the full command as one shell-quoted string in `last_command`. On success it returns `result.data` (which may be `None`). On failure it records `evidence.add_error(last_command, code, message)` and returns `None`. When the error code is `SSO_EXPIRED` it raises `SignInExpired(profile)` instead.
- `kubectl` looks the cluster up in `config.eks_clusters` (a `KeyError` with a clear message when unknown), uses `<skill_dir>/config/<KUBECONFIG_NAME>` and the cluster's context, sets `last_command`, records failures as evidence errors with code `KubectlError`, and returns stdout or `None`.
- `kubectl_json` appends `-o json`, parses the output, and records `UnreadableOutput` when it is not JSON.

**Behaviour: metrics**

- `fetch` makes two `cloudwatch get-metric-data` calls, one for the window and one for the same span seven days earlier, each with `--metric-data-queries` as a JSON string, `--start-time`, `--end-time`, and one query per spec with ids `m0`, `m1`, and so on. `period` is passed through.
- `MetricSummary` holds the average, maximum, and minimum of the window's datapoints, the time of the maximum, the baseline average and maximum, the count of datapoints, and `change_ratio = window_avg / baseline_avg`, or `None` when the baseline is missing or zero. With no datapoints, the numeric fields are `None` and `datapoints` is 0.
- `add_metric_facts` calls `fetch` and adds one `incident_time` fact per metric that has datapoints, timed at the peak. The summary states the numbers in words, for example: `CPUUtilization (Average): peak 96.2 at 2026-10-04T10:41:00Z; window average 71.0 against 23.5 one week earlier (3.0 times higher)`. Use `"about the same"` when the ratio is between 0.8 and 1.25, `"<x> times higher"` above, `"<x> times lower"` below, and `"no baseline data"` when the ratio is `None`. A metric with no datapoints adds one `derived` fact saying no data was returned. `data` carries the numeric fields.

**Required tests**

- [ ] Evidence: ids, kind validation, time formatting from `datetime` and string, excerpt cutting, redaction of each field (use an environment-style `data` value), the fact cap and `truncated`, error recording, `to_dict` key set, `write` path with and without suffix, `load_evidence` round trip.
- [ ] Context: success returns data and sets `last_command` with profile and region; a region override; failure records one error and returns `None`; sign-in expiry raises `SignInExpired` and records nothing else; `kubectl` argv uses the skill kubeconfig and cluster context; unknown cluster; kubectl failure; `kubectl_json` good and bad output.
- [ ] Metrics: two calls with the right time ranges; summaries for rising, flat, falling, and missing-baseline data; no datapoints; the wording of each summary variant; one fact per metric.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_evidence.py tests/test_context.py tests/test_metrics.py` and confirm they fail because the modules do not exist.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): add the evidence format, collection context, and metric comparison`.

### Task 5: Collector registry, command, test helpers, and the ECS collector

**Files:**
- Create: `skill/ai-triage/scripts/triage/collectors/__init__.py`
- Create: `skill/ai-triage/scripts/triage/collectors/ecs.py`
- Create: `skill/ai-triage/scripts/collect.py`
- Create: `tests/helpers.py`
- Test: `tests/test_collect_cli.py`
- Test: `tests/test_collector_ecs.py`

**Interfaces:**
- Consumes: everything from Task 4; `check_aws`, `check_kubectl`, `ALLOW` (Stage 1).
- Produces:
  - `collectors/__init__.py`: `Collector(name: str, description: str, required: tuple[str, ...], optional: tuple[str, ...], run: Callable[[CollectContext, dict[str, str]], None])` frozen dataclass; `all_collectors() -> dict[str, Collector]`, which imports every module in the package with `pkgutil.iter_modules` and returns each module's `COLLECTOR` by name. A new collector is a new file with a module-level `COLLECTOR`. Nothing else is edited.
  - `collect.py`: command `collect.py NAME --account ALIAS --start ISO --end ISO [--region R] [--target KEY=VALUE ...] [--case-dir DIR] [--suffix TEXT]`, and `collect.py --list`. Exit codes: 0 collected, 2 usage or config error, 3 sign-in expired, 4 unknown collector or missing target key.
  - `tests/helpers.py`: `make_context(config_data, tmp_path, answers, collector="test", account="prod-main", region="eu-west-1", kube_answers=None) -> tuple[CollectContext, FakeAws, FakeKubectl]`; `FakeKubectl(answers: dict[str, object])` keyed by the kubectl verb and first argument (for example `"get pods"`), with `.calls`; `assert_read_only(ctx, fake_aws, fake_kubectl=None)`, which asserts that every recorded AWS argv gets `ALLOW` from `check_aws` and every kubectl argv gets `ALLOW` from `check_kubectl`; `fact_summaries(ctx) -> list[str]`; `WINDOW_START = "2026-10-04T10:00:00Z"`, `WINDOW_END = "2026-10-04T12:00:00Z"`.

**Behaviour: command**

- `--list` prints one line per collector: name, required target keys, description.
- `--region` defaults to the account's first region. `--start` and `--end` go through `make_window` with `config.limits["max_window_hours"]`.
- Each `--target` is `KEY=VALUE`. A missing required key, or a key the collector does not declare, exits 4 with a message listing the collector's keys.
- Without `--case-dir` the evidence JSON is printed. With it, the evidence is written with `Evidence.write` and one line is printed: `<path> facts=<n> errors=<n> truncated=<bool>`.
- `SignInExpired` exits 3 after printing `Sign-in expired. Run: aws sso login --profile <profile>` to stderr.
- The config is loaded from the skill folder (the parent of the script's folder), with a hidden `--skill-dir` option for tests, as `preflight.py` does.

**Behaviour: ECS collector**

Targets: required `cluster`, `service`. This collector is the pattern the others follow: small private functions, each making one call and adding facts.

1. `ecs describe-services --cluster C --services S`. If the service is missing, add one `current` fact saying so and stop.
   - One `current` fact: status, desired, running, and pending counts, and the task definition in use.
   - One `incident_time` fact per deployment in `deployments`, timed at `createdAt`: rollout state, task definition, running and desired counts, and `rolloutStateReason` as the excerpt.
   - One `incident_time` fact per service event whose `createdAt` is inside the window, with the message as the excerpt. At most 30, newest first.
2. `ecs list-tasks --cluster C --service-name S --desired-status STOPPED --max-items 20`, then `ecs describe-tasks --cluster C --tasks <arns>` when any exist. One `incident_time` fact per stopped task, timed at `stoppedAt`: `stopCode`, `stoppedReason`, and each container's name, exit code, and reason.
3. `ecs describe-task-definition --task-definition <current>`. One `current` fact: image, CPU, memory, and the names of environment variables per container. Environment values go in `data` and are redacted by `Evidence`.
4. When the current revision is above 1, describe the previous revision and add one `derived` fact listing what changed between the two: image, CPU, memory, and environment variable names added, removed, or changed. A changed value is reported by name only.
5. `application-autoscaling describe-scaling-activities --service-namespace ecs --resource-id service/C/S --max-items 20`. One `incident_time` fact per activity inside the window.
6. Metrics through `add_metric_facts` for `AWS/ECS` `CPUUtilization` and `MemoryUtilization` with dimensions `ClusterName` and `ServiceName`.

**Required tests**

- [ ] Registry: `all_collectors()` contains `ecs`; a module without `COLLECTOR` is ignored; names are unique.
- [ ] Command: `--list`; a full run printing JSON; `--case-dir` writing a file; default region; unknown collector; missing and undeclared target keys; bad window; sign-in expiry exit code and message; bad config exits 2. Use a `FakeAws` injected through a module-level hook or by calling the command's `main(argv, runner=...)`.
- [ ] ECS: a healthy service; a failed deployment with stopped tasks; a service that does not exist; events outside the window are dropped; the task definition diff names changed variables without values; a secret-looking environment value never appears in `to_json()`; access denied on one call still yields the other facts plus one error; `assert_read_only` passes.
- [ ] Helpers: `assert_read_only` fails when a fake records a write operation.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_collect_cli.py tests/test_collector_ecs.py` and confirm they fail.
- [ ] **Step 3: Implement.** Check response field names with `aws ecs describe-services --generate-cli-skeleton output`.
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): add the collector registry, the collect command, and the ECS collector`.

### Task 6: OpenSearch query tool

**Files:**
- Create: `skill/ai-triage/scripts/opensearch_query.py`
- Create: `skill/ai-triage/scripts/triage/opensearch/queries.py`
- Test: `tests/test_opensearch_queries.py`
- Test: `tests/test_opensearch_query_cli.py`

**Interfaces:**
- Consumes: `OpenSearchClient`, `Request`, `Refused`, `OpenSearchError`, `search_body` (Task 3); `Evidence` and kinds (Task 4); `make_window` (Task 1); `load_config`.
- Produces: the command `opensearch_query.py SUBCOMMAND --cluster NAME [options] [--case-dir DIR] [--suffix TEXT]`. The file name is fixed: the guard recognises `opensearch_query.py` by name. Exit codes: 0 done, 2 usage or config error, 5 refused by the read policy, 6 cluster error or unreachable. Output is an evidence document with `collector` set to `opensearch`, `account` set to the cluster's account, and `region` set to the cluster name.

**Subcommands**

| Subcommand | Request | Facts |
|---|---|---|
| `health` | `GET _cluster/health` | One `current` fact: status, node count, active and unassigned shards, pending tasks |
| `nodes` | `GET _nodes/stats/jvm,fs,os,thread_pool` | One `current` fact per node: heap used percent, disk free percent, CPU percent, and any thread pool with rejections |
| `indices [--index PATTERN]` | `GET _cat/indices` or `_cat/indices/<pattern>` with `format=json` | One `current` fact per index that is not green, at most 50, and one summary fact with the counts by health |
| `shards` | `GET _cat/shards` with `format=json` | One `current` fact per shard that is not `STARTED`, at most 50 |
| `allocation-explain` | `GET _cluster/allocation/explain` | One `current` fact with the index, shard, and the explanation. A 400 answer means nothing is unassigned: add a fact saying so |
| `mapping --index PATTERN` | `GET <pattern>/_mapping` | One `current` fact listing field names and types, flattened, at most 200 fields |
| `count --index P --start ISO --end ISO [--query Q] [--filter K=V ...]` | `POST <pattern>/_count` | One `derived` fact with the count |
| `histogram ... [--interval 5m]` | `POST <pattern>/_search` with a `date_histogram` | One `incident_time` fact per non-empty bucket, at most 100, and one `derived` fact naming the peak bucket |
| `top-messages ... [--field NAME]` | `POST <pattern>/_search` | Up to 20 `derived` facts: message and count |
| `search ... [--size N]` | `POST <pattern>/_search` | One `incident_time` fact per hit, timed from the time field |

- `--interval` accepts `1m`, `5m`, `15m`, `1h`. `--field` defaults to the cluster's `message_field`. `--query` is a Lucene query string. `--size` is clamped to `limits["opensearch_max_hits"]`.
- `top-messages` first tries a `terms` aggregation on `<field>.keyword`. When the cluster answers with an error, it falls back to fetching the allowed number of hits and grouping them in code after replacing digit runs and hexadecimal ids of 8 or more characters with `#`.
- A `search` fact's excerpt is the message field. Its `data` holds the time field, the level field when present, and the filter fields. Other fields are dropped.
- Every body is built by `search_body`. The tool never accepts a raw body or a raw path from the command line.
- `Refused` exits 5 with the reason on stderr. `OpenSearchError` exits 6.

**Required tests**

- [ ] `queries.py` functions with a fake transport, one per subcommand: the request sent (method, path, parameters, body) and the facts produced.
- [ ] `top-messages` fallback grouping, including the normalisation of numbers and ids.
- [ ] Secret-looking text in a hit is redacted in the output.
- [ ] Caps: 50 indices, 50 shards, 100 buckets, the size clamp.
- [ ] Command: each exit code; an index outside the allowed patterns exits 5 and sends nothing; an unknown cluster exits 2; `--case-dir` writes a file.
- [ ] Every request any subcommand sends passes `check_request`.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_opensearch_queries.py tests/test_opensearch_query_cli.py` and confirm they fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): add the bounded OpenSearch query tool`.

### Task 7: Compute collectors

**Files:**
- Create: `skill/ai-triage/scripts/triage/collectors/ec2.py`, `ecr.py`, `lambda_function.py`, `autoscaling.py`, `eks.py`
- Test: `tests/test_collector_ec2.py`, `test_collector_ecr.py`, `test_collector_lambda.py`, `test_collector_autoscaling.py`, `test_collector_eks.py`

**Interfaces:**
- Consumes: `CollectContext`, `Evidence` kinds, `add_metric_facts`, `MetricSpec`, `Collector`; `tests/helpers.py`.
- Produces: collectors named `ec2`, `ecr`, `lambda`, `autoscaling`, `eks`, each a module with `COLLECTOR`.

Follow `collectors/ecs.py` as the pattern. Each collector adds a `current` fact saying the resource was not found, and stops, when its first call returns nothing.

| Collector | Targets | Calls and facts |
|---|---|---|
| `ec2` | `instance_ids` (comma list) | `ec2 describe-instances --instance-ids ...`: one `current` fact per instance with state, type, launch time, zone, and state reason. `ec2 describe-instance-status --instance-ids ... --include-all-instances`: one `current` fact per instance whose system or instance status is not `ok`, and one per scheduled event. `ec2 get-console-output --instance-id I --latest` for each instance that is not healthy: one `current` fact whose excerpt is the last 500 characters of the decoded output. Metrics `AWS/EC2` `CPUUtilization`, `StatusCheckFailed` (stat `Maximum`) per instance. At most 10 instances; say so in a `derived` fact when more were given. |
| `ecr` | `repository`; optional `image_tag`, `image_digest` | `ecr describe-images --repository-name R --image-ids imageTag=T` (or digest), else the 5 most recent with `--max-items 50` sorted in code by `imagePushedAt`: one `incident_time` fact per image timed at `imagePushedAt` with tags, digest, size. When a pushed time is inside the window, the summary says so. `ecr describe-image-scan-findings` for the targeted image: one `current` fact with the severity counts. A missing tag yields a `current` fact stating the image does not exist, which is a common cause of failed deployments. |
| `lambda` | `function` | `lambda get-function-configuration --function-name F`: one `current` fact with runtime, memory, timeout, state, last update status and reason, `LastModified`; environment variables go in `data`. If `LastModified` is inside the window the summary says so. `lambda get-function-concurrency`: reserved concurrency. `lambda list-event-source-mappings --function-name F --max-items 20`: one `current` fact per mapping with state and last processing result. `lambda get-account-settings`: one `current` fact with the account concurrency limit and unreserved amount. Metrics `AWS/Lambda` `Errors` (`Sum`), `Throttles` (`Sum`), `Duration` (`Maximum`), `ConcurrentExecutions` (`Maximum`), `Invocations` (`Sum`) with dimension `FunctionName`. |
| `autoscaling` | `group` (EC2 Auto Scaling group name); optional `ecs_cluster`, `ecs_service` | `autoscaling describe-auto-scaling-groups --auto-scaling-group-names G`: one `current` fact with min, max, desired, instance count, health check type and grace period. `autoscaling describe-scaling-activities --auto-scaling-group-name G --max-items 30`: one `incident_time` fact per activity inside the window, with status, cause as the excerpt; failed activities are marked in the summary. `autoscaling describe-instance-refreshes --auto-scaling-group-name G --max-items 5`: one fact per refresh that is in progress or ended inside the window. When the ECS targets are given, also `application-autoscaling describe-scalable-targets` and `describe-scaling-policies` for `service/<cluster>/<service>`. |
| `eks` | `cluster` (the name in `config.eks_clusters`); optional `namespace`, `workloads` (comma list such as `deployment/payments-api`) | AWS side: `eks describe-cluster --name <cluster>`: version, status, endpoint access, health issues. `eks list-nodegroups` then `describe-nodegroup` for at most 10: status, scaling numbers, health issues. `eks list-addons` then `describe-addon`: status and issues for any not `ACTIVE`. `eks list-updates --name` with `--max-items 5` then `describe-update`: one `incident_time` fact per update created inside the window. Kubernetes side, only when `namespace` is given: `kubectl get pods -o json`: one `current` fact per pod that is not Running and Ready, with phase, restart count, and each container's waiting or terminated reason and message, at most 30. `kubectl get events --sort-by=.lastTimestamp -o json`: one `incident_time` fact per Warning event inside the window, at most 40. For each workload: `kubectl get <workload> -o json` (desired, ready, and updated replicas, and conditions) and `kubectl rollout history <workload>`. For each unhealthy pod, at most 3: `kubectl logs <pod> --tail 50 --since <window minutes>m` and, when it has restarted, the same with `--previous`; the excerpt is the last 500 characters. |

The AWS cluster name for `eks` is the key in `config.eks_clusters`. Use the cluster's own `region` and `account` from the config; if the context's account differs from the cluster's account, add an error fact and stop.

**Required tests, for each collector**

- [ ] A healthy resource and an unhealthy one, asserting the summaries that matter for triage.
- [ ] The resource does not exist.
- [ ] One call denied: the other facts are still produced and one error is recorded.
- [ ] Secret-looking values never appear in `to_json()` (Lambda environment, console output, pod logs).
- [ ] Bounds: the instance cap, the pod and event caps, the log tail.
- [ ] `assert_read_only` passes, including the kubectl calls for `eks`.

- [ ] **Step 1: Write the failing tests** for one collector.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement** that collector, checking field names with `--generate-cli-skeleton output`.
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** that collector as `feat(ai-triage): add the <name> collector`, then repeat steps 1 to 5 for the next one.

### Task 8: Data and messaging collectors

**Files:**
- Create: `skill/ai-triage/scripts/triage/collectors/rds.py`, `elasticache.py`, `opensearch_domain.py`, `dynamodb.py`, `efs.py`, `messaging.py`
- Test: `tests/test_collector_rds.py`, `test_collector_elasticache.py`, `test_collector_opensearch_domain.py`, `test_collector_dynamodb.py`, `test_collector_efs.py`, `test_collector_messaging.py`

**Interfaces:**
- Consumes: as Task 7.
- Produces: collectors named `rds`, `elasticache`, `opensearch_domain`, `dynamodb`, `efs`, `messaging`.

| Collector | Targets | Calls and facts |
|---|---|---|
| `rds` | `db` (instance or cluster identifier) | `rds describe-db-instances --db-instance-identifier D`; when that is not found, `rds describe-db-clusters --db-cluster-identifier D` and its member instances. One `current` fact per instance: status, class, engine and version, multi-AZ, storage, pending modified values, parameter group status. `rds describe-events --source-identifier D --source-type db-instance --start-time --end-time`: one `incident_time` fact per event. `rds describe-db-log-files --db-instance-identifier D --file-last-written <window start in epoch milliseconds> --max-items 10`, then `rds download-db-log-file-portion --db-instance-identifier D --log-file-name F --number-of-lines 200` for the single most recently written file whose name contains `error`, or the most recently written file when none does: one `incident_time` fact per line that contains `ERROR`, `FATAL`, `PANIC`, or `deadlock`, at most 20, timed when the line carries a timestamp and `current` otherwise. Metrics `AWS/RDS`: `CPUUtilization`, `DatabaseConnections` (`Maximum`), `FreeStorageSpace` (`Minimum`), `FreeableMemory` (`Minimum`), `ReplicaLag` (`Maximum`), `ReadLatency`, `WriteLatency` with dimension `DBInstanceIdentifier`. When Performance Insights is enabled on the instance: `pi get-resource-metrics --service-type RDS --identifier <DbiResourceId> --metric-queries '[{"Metric":"db.load.avg","GroupBy":{"Group":"db.wait_event","Limit":5}}]' --start-time --end-time --period-in-seconds 300`: one `derived` fact naming the top wait events by average load. |
| `elasticache` | `replication_group` | `elasticache describe-replication-groups --replication-group-id G`: status, node groups, primary and replica endpoints, automatic failover, multi-AZ. `elasticache describe-cache-clusters --show-cache-node-info` filtered in code to the group's members: engine version, node type, node status. `elasticache describe-events --source-identifier <each member> --source-type cache-cluster --start-time --end-time`: one `incident_time` fact per event. Metrics `AWS/ElastiCache` per member with dimension `CacheClusterId`: `EngineCPUUtilization`, `DatabaseMemoryUsagePercentage` (`Maximum`), `Evictions` (`Sum`), `CurrConnections` (`Maximum`), `ReplicationLag` (`Maximum`), `SwapUsage` (`Maximum`). |
| `opensearch_domain` | `domain` | `opensearch describe-domain --domain-name D`: version, instance type and count, storage, processing flag, endpoint. `opensearch describe-domain-health --domain-name D`: cluster health, node counts, shard counts. `opensearch describe-domain-change-progress --domain-name D`: one `incident_time` fact when a change is in progress or finished inside the window. Metrics `AWS/ES` with dimensions `DomainName` and `ClientId` (the account id): `ClusterStatus.red` (`Maximum`), `ClusterStatus.yellow` (`Maximum`), `FreeStorageSpace` (`Minimum`), `JVMMemoryPressure` (`Maximum`), `CPUUtilization`, `ThreadpoolWriteRejected` (`Sum`), `ThreadpoolSearchRejected` (`Sum`), `5xx` (`Sum`). |
| `dynamodb` | `table` | `dynamodb describe-table --table-name T`: status, billing mode, provisioned read and write capacity, item count, global secondary indexes with their status. `application-autoscaling describe-scaling-activities --service-namespace dynamodb --resource-id table/T --max-items 20`: activities inside the window. Metrics `AWS/DynamoDB` with dimension `TableName`: `ReadThrottleEvents` (`Sum`), `WriteThrottleEvents` (`Sum`), `ThrottledRequests` (`Sum`), `ConsumedReadCapacityUnits` (`Sum`), `ConsumedWriteCapacityUnits` (`Sum`), `SystemErrors` (`Sum`), `SuccessfulRequestLatency` (`Maximum`). No item is ever read. |
| `efs` | `file_system` (id) | `efs describe-file-systems --file-system-id F`: life cycle state, performance and throughput mode, provisioned throughput, size. `efs describe-mount-targets --file-system-id F`: one `current` fact per mount target with zone, subnet, state, address; a `derived` fact when any is not `available`. For each mount target `efs describe-mount-target-security-groups`, then `ec2 describe-security-groups --group-ids ...`: one `derived` fact stating whether any group allows inbound TCP 2049. `efs describe-access-points --file-system-id F --max-items 20`: one `current` fact per access point not `available`. Metrics `AWS/EFS` with dimension `FileSystemId`: `BurstCreditBalance` (`Minimum`), `PercentIOLimit` (`Maximum`), `ClientConnections` (`Sum`), `PermittedThroughput` (`Minimum`), `MeteredIOBytes` (`Sum`). |
| `messaging` | optional `queues` (comma list of queue names), optional `topics` (comma list of topic ARNs); at least one is required | Per queue: `sqs get-queue-url --queue-name Q`, then `sqs get-queue-attributes --queue-url U --attribute-names All`: visible, in-flight, and delayed message counts, visibility timeout, retention, and the redrive policy's dead letter target. `sqs list-dead-letter-source-queues --queue-url U --max-items 10`. Metrics `AWS/SQS` with dimension `QueueName`: `ApproximateAgeOfOldestMessage` (`Maximum`), `ApproximateNumberOfMessagesVisible` (`Maximum`), `NumberOfMessagesSent` (`Sum`), `NumberOfMessagesDeleted` (`Sum`). When the queue has a dead letter target, repeat the attribute and metric calls for it and add a `derived` fact when it holds messages. Per topic: `sns get-topic-attributes --topic-arn A`: subscriptions confirmed and pending, delivery policy. Metrics `AWS/SNS` with dimension `TopicName`: `NumberOfNotificationsFailed` (`Sum`), `NumberOfMessagesPublished` (`Sum`). No message is ever received. |

**Required tests, for each collector:** the same six kinds as Task 7. For `messaging`, also assert that no `receive-message` call is ever made and that giving neither target exits through the collector's own validation with a clear message.

- [ ] **Step 1: Write the failing tests** for one collector.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement** that collector.
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** that collector, then repeat for the next one.

### Task 9: Edge and network collectors

**Files:**
- Create: `skill/ai-triage/scripts/triage/collectors/edge.py`, `vpc.py`, `apigateway.py`, `cloudfront_waf.py`
- Test: `tests/test_collector_edge.py`, `test_collector_vpc.py`, `test_collector_apigateway.py`, `test_collector_cloudfront_waf.py`

**Interfaces:**
- Consumes: as Task 7.
- Produces: collectors named `edge`, `vpc`, `apigateway`, `cloudfront_waf`.

| Collector | Targets | Calls and facts |
|---|---|---|
| `edge` | `load_balancer` (name); optional `hostname` | `elbv2 describe-load-balancers --names L`: state, scheme, type, zones, DNS name. `elbv2 describe-listeners --load-balancer-arn`: one `current` fact per listener with port, protocol, and certificate. `elbv2 describe-rules --listener-arn` for each listener, at most 5 listeners: one `current` fact per listener summarising rule count and the target groups it forwards to. `elbv2 describe-target-groups --load-balancer-arn`: health check path, port, interval, thresholds. `elbv2 describe-target-health --target-group-arn` for each, at most 10: one `current` fact per target group with the count by state, and one per unhealthy target with its reason and description. `elbv2 describe-target-group-attributes` for each: deregistration delay and slow start. For each listener certificate: `acm describe-certificate --certificate-arn`: one `current` fact with status and `NotAfter`; a `derived` fact when it expires within 30 days of the window end or has expired, stating the gap with `describe_offset`. When `hostname` is given: `route53 list-hosted-zones --max-items 100`, pick the zone with the longest matching suffix, then `route53 list-resource-record-sets --hosted-zone-id Z --start-record-name H --max-items 5`: one `current` fact with the record type and where it points, and a `derived` fact when it does not point at this load balancer's DNS name. Metrics `AWS/ApplicationELB` with dimension `LoadBalancer` (the ARN suffix after `loadbalancer/`): `HTTPCode_ELB_5XX_Count` (`Sum`), `HTTPCode_Target_5XX_Count` (`Sum`), `TargetResponseTime` (`Maximum`), `RequestCount` (`Sum`), `RejectedConnectionCount` (`Sum`), `TargetConnectionErrorCount` (`Sum`); and per target group `UnHealthyHostCount` (`Maximum`) and `HealthyHostCount` (`Minimum`) with dimensions `TargetGroup` and `LoadBalancer`. For a network load balancer use namespace `AWS/NetworkELB` and only the host count metrics. |
| `vpc` | optional `security_group_ids` (comma list), optional `subnet_ids` (comma list), optional `vpc_id`; at least one is required | `ec2 describe-security-groups --group-ids ...`: one `current` fact per group with the count of inbound and outbound rules and the list of inbound port ranges with their sources. `ec2 describe-subnets --subnet-ids ...`: zone, available address count, and a `derived` fact for any subnet with fewer than 10 free addresses. `ec2 describe-route-tables --filters Name=association.subnet-id,Values=...`: one `current` fact per table with its default route target and any route in the `blackhole` state. `ec2 describe-network-acls --filters Name=association.subnet-id,Values=...`: one `current` fact per ACL listing deny entries. `ec2 describe-nat-gateways --filter Name=vpc-id,Values=V` when `vpc_id` is given or can be read from a subnet: state and failure message for each. `ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=V`: one fact per endpoint not `available`. Metrics `AWS/NATGateway` with dimension `NatGatewayId`: `ErrorPortAllocation` (`Sum`), `PacketsDropCount` (`Sum`), `ActiveConnectionCount` (`Maximum`). |
| `apigateway` | `api_id`; optional `stage`, optional `kind` (`rest` default, or `http`) | REST: `apigateway get-rest-api --rest-api-id A`, `apigateway get-stages --rest-api-id A`: one `current` fact per stage with deployment id, last updated time, throttling settings, and cache status; the summary says when a stage was updated inside the window. `apigateway get-deployments --rest-api-id A --max-items 5`: one `incident_time` fact per deployment created inside the window. HTTP: `apigatewayv2 get-api --api-id A`, `apigatewayv2 get-stages --api-id A`, `apigatewayv2 get-deployments --api-id A --max-items 5`. Metrics `AWS/ApiGateway`: REST uses dimensions `ApiName` and `Stage`, HTTP uses `ApiId` and `Stage`: `5XXError` (`Sum`) and `4XXError` (`Sum`) for REST, `5xx` and `4xx` for HTTP, plus `Latency` (`Maximum`), `IntegrationLatency` (`Maximum`), `Count` (`Sum`). |
| `cloudfront_waf` | optional `distribution_id`, optional `web_acl_arn`, optional `resource_arn`; at least one is required | `cloudfront get-distribution --id D` (region `us-east-1`): status, last modified time, domain names, origins with their domain names, and the default cache behaviour's target origin; the summary says when it was modified inside the window. Metrics `AWS/CloudFront` in `us-east-1` with dimensions `DistributionId` and `Region=Global`: `5xxErrorRate`, `4xxErrorRate`, `Requests` (`Sum`), `OriginLatency` (`Maximum`). WAF: when `resource_arn` is given, `wafv2 get-web-acl-for-resource --resource-arn R` to find the ACL; `wafv2 get-web-acl --name N --scope S --id I`: default action and one `current` fact per rule with its action and priority. `wafv2 get-sampled-requests --web-acl-arn W --rule-metric-name <metric> --scope S --time-window StartTime=...,EndTime=... --max-items 20` for the ACL's default metric: one `incident_time` fact per sampled request whose action is `BLOCK`, with the rule that matched, the URI path, and the country. Headers and the client address are not stored. Scope is `CLOUDFRONT` (region `us-east-1`) when the ACL ARN contains `:global/`, else `REGIONAL`. |

**Required tests, for each collector:** the same six kinds as Task 7. For `edge`, also: a certificate that expired before the window, one that expires in 10 days, one valid for a year; a hostname pointing elsewhere. For `cloudfront_waf`, also: the CloudFront calls use region `us-east-1`, and no header or client address appears in `to_json()`.

- [ ] **Step 1: Write the failing tests** for one collector.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement** that collector.
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** that collector, then repeat for the next one.

### Task 10: Change, access, and platform collectors

**Files:**
- Create: `skill/ai-triage/scripts/triage/collectors/changes.py`, `access.py`, `platform.py`
- Test: `tests/test_collector_changes.py`, `test_collector_access.py`, `test_collector_platform.py`

**Interfaces:**
- Consumes: as Task 7; `describe_offset` (Task 1).
- Produces: collectors named `changes`, `access`, `platform`.

| Collector | Targets | Calls and facts |
|---|---|---|
| `changes` | optional `resource_names` (comma list, at most 10), optional `stack` (CloudFormation stack name), optional `pipeline` (CodePipeline name), optional `config_resource` (`<resource type>/<resource id>`, for example `AWS::EC2::SecurityGroup/sg-0abc`), optional `incident_start` (ISO time) | For each resource name: `cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=N --start-time --end-time --max-items 50`. Keep only events whose `ReadOnly` field is `"false"`. One `incident_time` fact per event: event name, source, user name with any email redacted, and the resource; at most 40 per name. With no resource names: one call with `AttributeKey=ReadOnly,AttributeValue=false` and `--max-items 50`. When `incident_start` is given, each summary ends with the gap from `describe_offset`, for example `4 minutes before the incident started`. `stack`: `cloudformation describe-stack-events --stack-name S --max-items 50`: one `incident_time` fact per event inside the window whose status ends in `FAILED` or `ROLLBACK_IN_PROGRESS`, or that starts or completes an update on the stack itself. `pipeline`: `codepipeline list-pipeline-executions --pipeline-name P --max-items 10`: one `incident_time` fact per execution that started or ended inside the window, with status and trigger; `codepipeline get-pipeline-state --name P`: one `current` fact per stage that is not `Succeeded`. `config_resource`: `configservice get-resource-config-history --resource-type T --resource-id I --earlier-time <window start> --later-time <window end> --limit 10`: one `incident_time` fact per configuration item timed at `configurationItemCaptureTime`, with its status; the excerpt is the related change summary when present. A `ResourceNotDiscoveredException` becomes a `derived` fact saying AWS Config does not record this resource. |
| `access` | optional `role` (role name), optional `action` (for example `s3:GetObject`), optional `resource_arn`, optional `kms_key` (key id or ARN), optional `secret` (secret name or ARN); at least one is required | `role`: `iam get-role --role-name R`: creation date, last used date and region, and the trusted principals from the assume role policy. `iam list-attached-role-policies --role-name R --max-items 20` and `iam list-role-policies --role-name R --max-items 20`: one `current` fact listing the policy names. When `action` is also given: `iam simulate-principal-policy --policy-source-arn <role arn> --action-names A` plus `--resource-arns X` when `resource_arn` is given: one `derived` fact with the decision and, when denied, the matched statements. `kms_key`: `kms describe-key --key-id K`: state, enabled flag, deletion date, origin; a `derived` fact when the key is disabled or pending deletion. `secret`: `secretsmanager describe-secret --secret-id S`: rotation enabled, last rotated, last changed, next rotation; a `derived` fact when rotation is enabled and the last rotation is older than the rotation interval, or when the secret changed inside the window. The secret value is never requested. |
| `platform` | optional `service_codes` (comma list of Service Quotas service codes, default `ecs,lambda,ec2,rds,elasticloadbalancing`) | `health describe-events --filter eventStatusCodes=open,closed,upcoming --max-items 30` in region `us-east-1`: one `incident_time` fact per event whose start time is inside the window or that is still open, with service, region, category, and status. A `SubscriptionRequiredException` becomes one `derived` fact saying AWS Health needs a Business or Enterprise support plan, not an error. For each service code: `service-quotas list-service-quotas --service-code C --max-items 50`: no fact per quota; instead one `current` fact per service listing at most 10 quotas whose `UsageMetric` is present, by name and value, so the analyst knows which limits exist. |

**Required tests, for each collector:** the same six kinds as Task 7 where they apply. For `changes`, also: read-only CloudTrail events are dropped; the gap wording; the caps; a stack with a failed update; AWS Config not recording the resource. For `access`, also: an allowed and a denied simulation; a disabled key; an overdue rotation; `to_json()` never contains a call to `get-secret-value`. For `platform`, also: the support plan case, and the Health call uses region `us-east-1`.

- [ ] **Step 1: Write the failing tests** for one collector.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement** that collector.
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** that collector, then repeat for the next one.

### Task 11: CloudWatch logs and alarms collectors

**Files:**
- Create: `skill/ai-triage/scripts/triage/collectors/logs.py`, `alarms.py`
- Test: `tests/test_collector_logs.py`, `test_collector_alarms.py`

**Interfaces:**
- Consumes: as Task 7; `config.limits["logs_insights_max_log_groups"]`.
- Produces: collectors named `logs` and `alarms`. `logs.py` also exposes `run_query(ctx, log_groups: Sequence[str], query: str, *, sleep: Callable[[float], None] = time.sleep, max_wait_seconds: int = 60) -> list[dict[str, str]] | None`.

**Behaviour: logs**

Targets: required `log_groups` (comma list); optional `pattern` (a regular expression, default `(?i)(error|exception|fatal|panic|timed? ?out|refused|denied|oom|killed)`).

- More log groups than `logs_insights_max_log_groups` is refused with a `derived` fact naming the limit; the collector uses the first allowed number and says which were skipped.
- `run_query` calls `logs start-query --log-group-names ... --start-time <epoch s> --end-time <epoch s> --query-string Q`, then polls `logs get-query-results --query-id I` with the injected `sleep`, waiting 1 second between polls, until the status is `Complete`. On `Failed`, `Cancelled`, or `Timeout`, or after `max_wait_seconds`, it calls `logs stop-query --query-id I` when the query may still be running, records an evidence error, and returns `None`. Results are returned as a list of dicts from field name to value, without the `@ptr` field.
- Three queries, each a pipeline that starts with `filter @message like /<pattern>/`:
  1. `| stats count(*) as matches by bin(5m)`: one `incident_time` fact per bucket, and one `derived` fact naming the peak bucket and the first non-empty bucket.
  2. `| pattern @message | sort @sampleCount desc | limit 15`: one `derived` fact per pattern with its sample count, the pattern text as the excerpt.
  3. `| fields @timestamp, @logStream, @message | sort @timestamp asc | limit 20`: one `incident_time` fact per line, timed from `@timestamp`, the message as the excerpt.
- A pattern containing `/` is escaped before it is placed in the query.

**Behaviour: alarms**

Targets: optional `alarm_names` (comma list), optional `name_prefix`; at least one is required.

- `cloudwatch describe-alarms --alarm-names ...` or `--alarm-name-prefix P --max-items 50`: one `current` fact per alarm with state, state reason, metric, threshold, and comparison.
- `cloudwatch describe-alarm-history --alarm-name N --history-item-type StateUpdate --start-date --end-date --max-items 20` for each alarm, at most 20 alarms: one `incident_time` fact per state change inside the window, with the old and new state.
- One `derived` fact naming the first alarm that went into `ALARM` inside the window and its time.

**Required tests**

- [ ] `run_query`: completes after polling; failed status; timeout calls `stop-query`; `@ptr` dropped; the injected sleep is used and no real time passes.
- [ ] Logs: the three queries are sent with the pattern; the log group limit; the peak and first bucket facts; an empty result; a slash in the pattern; secret-looking log text is redacted; `assert_read_only` passes.
- [ ] Alarms: names and prefix; history inside and outside the window; the first-alarm fact; no alarms found; `assert_read_only` passes.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_collector_logs.py tests/test_collector_alarms.py` and confirm they fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): add the logs and alarms collectors`.

### Task 12: Discovery

**Files:**
- Create: `skill/ai-triage/scripts/triage/discover.py`
- Create: `skill/ai-triage/scripts/discover.py`
- Test: `tests/test_discover.py`
- Test: `tests/test_discover_cli.py`

**Interfaces:**
- Consumes: `TriageConfig`, `Account`, `run_aws`, `Runner`, `SSO_EXPIRED`, `Redactor`, `SignInExpired` (Task 4).
- Produces:
  - `triage/discover.py`: `Step(account: str, region: str, command: str, found: str)`; `Discovery(hostname: str, steps: list[Step], account: str | None, region: str | None, resources: dict[str, Any], notes: list[str])` with `to_dict()` and `proposed_entry(service_name: str, monitors: Sequence[str] = ()) -> dict`; `discover_hostname(hostname: str, config: TriageConfig, runner: Runner = subprocess_runner, accounts: Sequence[str] = ()) -> Discovery`.
  - `discover.py`: command `discover.py --hostname H [--account ALIAS ...] [--service-name NAME] [--monitor NAME ...]`, printing JSON `{"discovery": ..., "proposed_entry": ...}`. Exit codes: 0 something was found, 1 nothing was found, 2 usage or config error, 3 sign-in expired.

**Behaviour**

Discovery walks from a hostname to the resources behind it. Every step is recorded with the command that produced it, so the report can show how each resource was found. It searches the named accounts, or all configured accounts in order, and each account's regions in order, and stops at the first account and region where a load balancer is found.

1. **DNS.** In each account: `route53 list-hosted-zones --max-items 100`; choose the zone whose name is the longest suffix of the hostname; `route53 list-resource-record-sets --hosted-zone-id Z --start-record-name <hostname> --max-items 5`; take the record whose name equals the hostname. An alias target or a `CNAME` value gives the next DNS name. When no zone matches in any account, add a note and continue with the hostname itself as the DNS name.
2. **Load balancer.** In each region: `elbv2 describe-load-balancers --max-items 100`; match `DNSName` case-insensitively against the DNS name, ignoring a leading `dualstack.` and a trailing dot. A match sets `resources["load_balancer"]` to the load balancer name, and the account and region.
3. **Targets.** `elbv2 describe-target-groups --load-balancer-arn A`. For each target group, at most 10, record its ARN internally.
4. **ECS service.** `ecs list-clusters --max-items 50`; for each cluster, at most 10: `ecs list-services --cluster C --max-items 100`, then `ecs describe-services --cluster C --services ...` in batches of 10. A service whose `loadBalancers[].targetGroupArn` is one of the target groups sets `resources["ecs_service"]` to `<cluster>/<service>`.
5. **Auto Scaling group.** When no ECS service matched: `autoscaling describe-auto-scaling-groups --max-items 50`; a group whose `TargetGroupARNs` contains one of the target groups sets `resources["auto_scaling_group"]`.
6. **Dependencies from the task definition.** When an ECS service was found: `ecs describe-task-definition --task-definition <its task definition>`. Collect log groups from each container's `awslogs-group` option into `resources["log_groups"]`. Collect hostnames that appear in environment values, using a `Redactor` so no value is kept beyond the hostname itself. Then, in the same region:
   - `rds describe-db-instances --max-items 100` and `rds describe-db-clusters --max-items 100`: an endpoint address equal to a collected hostname sets `resources["rds"]`.
   - `elasticache describe-replication-groups --max-items 100`: a primary or configuration endpoint equal to a collected hostname sets `resources["elasticache"]`.
   - Each cluster in `config.opensearch_clusters` whose `host` equals a collected hostname sets `resources["opensearch"] = {"cluster": <name>}` and adds a note that the index pattern must be filled in by hand.
7. A failed call is added to `notes` with its error code and the walk continues. An expired sign-in raises `SignInExpired`.

`proposed_entry` returns a service map entry in the shape `parse_map` accepts: `{"match": {"hostnames": [hostname], "monitors": [...]}, "environments": {"discovered": {"account": ..., "region": ..., "resources": {...}}}, "source": "discovered", "last_verified": <today>}`. It returns an entry only when an account and region were found; otherwise it raises `ValueError`.

**Required tests**

- [ ] The full walk: hostname to alias, to load balancer, to ECS service, to log groups, database, cache, and a configured OpenSearch cluster. Assert `resources`, the account and region, and that each step names its command.
- [ ] The load balancer is in the second account, or in the second region.
- [ ] No hosted zone matches: the hostname is used directly and a note says so.
- [ ] An Auto Scaling group behind the load balancer instead of ECS.
- [ ] Nothing found: `resources` is empty and the command exits 1.
- [ ] One call denied: a note is added and later steps still run.
- [ ] Environment values with credentials never appear in the output.
- [ ] `proposed_entry` output is accepted by `parse_map` after the environment name is kept as `discovered`; it raises without an account.
- [ ] Every AWS argv gets `ALLOW` from `check_aws`.
- [ ] Command: the JSON shape and each exit code.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_discover.py tests/test_discover_cli.py` and confirm they fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): discover the resources behind a hostname`.
