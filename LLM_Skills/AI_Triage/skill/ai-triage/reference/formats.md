# File formats

Open this file when you have to write one of the files below. Every rule here is taken from the code that reads the file.
Messages are quoted as the commands print them; `<name>` stands for a value the command fills in.
Complete examples: `templates/findings.example.json` and `templates/report.example.json`.

You write three kinds of file: the incident file, `findings/<analyst>.json`, and `report.json`, plus an ad hoc question file when you need one.
The scripts write every other file in a case folder (the evidence files, `findings/checked.json`, `judgments/summary.json`,
`report.md`, `work-order.json`, `audit.json`, `render.json`, `case.json`, `case.md`, the timeline files). Never edit them.

## 1. The incident file for case.py init

`case.py init --incident <file>` reads one JSON object. A key it does not know is dropped (`observed_at` in the replay files is one).

| Field | Required | Allowed values |
| --- | --- | --- |
| `number` | yes | Text or a number (kept as text). 1 to 64 characters: a letter or digit first, then letters, digits, `.`, `_`, `-`. It names the case folder. |
| `title` | yes | Non-empty text |
| `declared_at` | yes | A time (see below) |
| `impact_started_at` | no | A time. When set it is the incident start; otherwise `declared_at` is. |
| `resolved_at` | no | A time, not before the incident start. The window ends 15 minutes after it, or now. |
| `url`, `description`, `severity`, `state` | no | Text |
| `monitors` | no | List of objects. `name` (text) and `target` (a URL or a host name) are matched against the service map; other keys are kept. |
| `labels`, `hostnames` | no | List of text |
| `timeline`, `notes` | no | List of objects. An entry with a `time` and a `text` becomes a row of the timeline. |

A time is ISO 8601: `YYYY-MM-DD`, `T` or a space, `hh:mm`, optional `:ss` and a fraction, then a zone: `Z` or `+hh:mm` or `-hh:mm`. A time without a zone is refused.
The window starts 60 minutes before the incident start.

| Refusal | Message |
| --- | --- |
| The file is not an object | `incident: must be a JSON object` |
| A required field is absent | `<field>: missing` |
| Wrong type | `<field>: must be text`, `<field>: must be a list of strings`, `<field>: must be a list of objects` |
| A time has no zone | `time must include a timezone: <value>` |
| A time cannot be read | `cannot parse time: <value>` |
| Bad number | `number: must start with a letter or digit and use only letters, digits, '.', '_' and '-', at most 64 characters` |
| End before start (printed after `window: `) | `incident end is before its start` |

## 2. Reading an evidence file

A collector writes `evidence/<collector>-<account>-<region>[-<suffix>].json`. Its stem (the name without `.json`) is the first half of every citation.

| Key | Holds |
| --- | --- |
| `collector`, `account`, `region` | Who collected, for which account alias and region |
| `window` | `start` and `end`, UTC |
| `facts` | List of facts, at most 200. When more existed, `truncated` is `true` and the later facts are missing. |
| `errors` | List of `command`, `code`, `message` (message at most 300 characters): what could not be read |
| `asked` | What the collector asked: `targets`, `target_items`, `window` (see "The asked objects") |

A fact:

| Field | Holds |
| --- | --- |
| `id` | `<collector>-<four digits>`, for example `ecs-0014`. Numbered per file, so it is unique only inside its file. |
| `kind` | `incident_time`, `current`, or `derived` (below) |
| `time` | UTC time of the event, or `null` |
| `resource` | The resource the fact is about |
| `summary` | One sentence, at most 500 characters; a cut one ends with `… [summary cut]` |
| `data` | Object with the detail (below) |
| `command` | The command that produced it |
| `excerpt` | A quoted line, at most 500 characters, or empty |

The three kinds:

| Kind | Meaning | What a finding may claim from it |
| --- | --- | --- |
| `incident_time` | An event or measurement from the incident period, with its own time | Provenance `incident_time` or `inferred` |
| `current` | The state at the moment of collection. It shows now, not then. | Provenance `current` or `inferred` |
| `derived` | The collector computed it from other data (a comparison, a count, an absence) | Provenance `inferred` only |

Where long lists live: in `data`, never in `summary`. Inside `data`: at most 50 keys (the number dropped is in `keys_omitted`),
a key at most 100 characters, a string at most 500, a list or object at most 200 entries. When a list or object was cut,
the count of dropped entries sits beside it as `<key>_omitted`. A list inside a list ends with the entry `<n> more entries omitted`.
Read `data` and the `_omitted` counts before you say that something was absent.

The asked objects. What a collector or a search was asked is kept under the key `asked`: at the top of the file
(`targets`, `target_items`, `window`) and inside a fact as `data.asked` (a query, an index, filters). Text under any `asked` key
at any depth is not evidence, because a search for a phrase would otherwise prove the phrase. A finding cannot quote it,
and a finding whose excerpt only repeats it is refused (rules in section 3). Dictionary keys and numbers in `data` cannot be quoted either.

## 3. The findings file an analyst writes

Write `findings/<analyst>.json`. The file name without `.json` is the analyst name. `findings.py check` reads every file there except `checked.json`.

| Field | Required | Allowed values |
| --- | --- | --- |
| `analyst` | no | Text. When present it must equal the file name stem. |
| `findings` | yes | List of finding objects |
| `findings[].id` | yes | Non-empty text starting with `<analyst>-`, for example `compute-1`. Unique across all files of the case. |
| `findings[].claim` | yes | Non-empty text: what the evidence shows |
| `findings[].fact_ids` | yes | Non-empty list of citations (below) |
| `findings[].excerpt` | yes | Text that appears in a cited fact (rules below) |
| `findings[].provenance` | yes | `incident_time`, `current`, or `inferred` (use `inferred` for a fact of kind `derived`) |
| `findings[].confidence` | yes | `high`, `medium`, or `low` |
| `findings[].time` | no | When the event happened, as a time with a zone. Judging needs it on a supporting finding to pass the timing gate. |
| `checked` | no | List of text: what was looked at, kept for the report. Items that are not text are dropped. |
| `requests` | no | List of objects asking for more evidence. No key is checked; each is copied to `requests` of `checked.json` with `analyst` added. A non-object item is ignored. |

Citation form: `<evidence file stem>:<fact id>`, for example `ecs-prod-main-eu-west-1:ecs-0014`. A bare fact id is accepted only when exactly one evidence file has it.
The check rewrites `fact_ids` to the qualified form in `checked.json`.

The check never stops at the first problem: a refused finding lists every reason. The command prints
`valid=<n> rejected=<n> unreadable=<n> requests=<n>` and exits 0 whatever it refused, so read `findings/checked.json`. A refused finding is not evidence and cannot be cited.

Excerpt rules, as enforced. Before any comparison the excerpt is trimmed and each run of whitespace becomes one space; comparison is case-sensitive.
The text a finding may quote, from one cited fact, is its `summary`, its `excerpt`, and every string in `data`, except strings under `asked`. The judge is shown what a finding quotes, so quote the words that prove the claim, not a nearby heading.

| Rule | Message | What to do |
| --- | --- | --- |
| Not empty | `excerpt is empty` | Copy the words that show the claim. |
| At most 300 characters | `excerpt is longer than 300 characters; quote the part that shows the claim` | Quote the shortest span that shows it. |
| More than redaction placeholders (`<SECRET-1>`, `<EMAIL-2>`) | `excerpt is only redaction placeholders, which carry no evidence` | Quote the words around the placeholder. |
| 12 characters or more: it must be a part of one string of one cited fact | `excerpt was not found in the summary, excerpt, or data of any cited fact` | Copy it from the fact, not from memory. Cite the fact that holds it. |
| 3 to 11 characters: it must equal a whole string of a cited fact; fewer than 3 characters never matches | `excerpt is shorter than 12 characters and is not a whole value (at least 3 characters) of a cited fact` | Quote a longer span, or a whole value such as `available`. |
| It must say what was found, not what was asked: it is refused when it lies inside an asked string, or when cutting the file's asked values (`targets`, `target_items`, `window`; each at least 3 characters) out of it leaves fewer than 12 non-space characters | `excerpt only repeats what was asked (the request, a query, or a target), not what was found; quote a longer span of what was found` | Quote a span that holds the result, such as the log line or the metric value. |

Other reasons a finding is refused:

| Rule | Message | What to do |
| --- | --- | --- |
| Every field present and of the right type | `<field> is missing`, `<field> must be text`, `fact_ids must be a list of text`, `id is empty`, `claim is empty` | Fix the field. |
| Citation list | `fact_ids is empty` | Cite at least one fact. |
| Citation exists | `fact id <id> does not exist` | Use an id from the evidence file. |
| Citation is unique | `fact id <id> exists in more than one evidence file; cite it as one of: <list>` | Use the qualified form. |
| Provenance and confidence values | `<field> must be one of <values>` | Provenance: `incident_time`, `current`, `inferred`. Confidence: `high`, `medium`, `low`. |
| Provenance matches the evidence (kinds in section 2) | `provenance is <value> but no cited fact containing the excerpt has kind <kind>` | Cite the fact of that kind, or use provenance `inferred`. |
| Provenance with no excerpt match | `provenance is <value> but no cited fact has kind <kind>` | Same. |
| Id prefix | `id must start with <analyst>-` | Rename the finding. |
| Id unique | `id <id> repeats an earlier finding` | Give it a new number. |
| `time` readable | `time <value> cannot be parsed` | Write a time with a zone, or drop `time`. |
| Entry is an object | `finding is not an object` | Fix the list. |

A whole file can be unreadable (listed under `unreadable`, none of its findings are checked):

| Message | Cause |
| --- | --- |
| `cannot be read: <reason>` | The file cannot be opened |
| `not valid JSON` | It does not parse |
| `top level is not an object` | It is not a JSON object |
| `findings is missing or not a list` | `findings` absent or not a list |
| `analyst field <value> does not match the file name <name>` | `analyst` differs from the file stem |

## 4. findings/checked.json after the check

The check writes it; do not edit it. Only findings under `valid` can be cited in `report.json`.

| Key | Holds |
| --- | --- |
| `valid` | The accepted findings, redacted. Each keeps the fields you wrote, plus `analyst`; `fact_ids` in qualified form; `fact_summaries` (citation to the fact's summary); `matched_text` (at most 500 characters of the string that held the excerpt); `asked` (citation to what that fact was asked) |
| `rejected` | `analyst`, `id`, `reasons` (list of messages) for each refused finding |
| `unreadable` | `file`, `reason` for each unreadable file |
| `requests` | The `requests` objects, each with `analyst` |
| `checked` | Analyst name to its list of `checked` text |
| `warnings` | Notes: `evidence file <name> does not record what was asked`, `evidence file <name> is unreadable and was skipped`, `a fact in <name> has no text id and was skipped` |

Run the check again after you change any findings file; judging and validation read the last result.

## 5. report.json

`judge.py run` reads the draft first; `report.py validate` and `render` check all of it. The column "Filled" says when you set the field:
before = write it before judging; after = set it from `judgments/summary.json` once judging is done.

| Field | Required | Allowed values | Filled |
| --- | --- | --- | --- |
| `status` | yes | `cause_found` or `unresolved` (rules below) | after |
| `summary` | yes | Object | before |
| `summary.what_broke` | yes | Non-empty text | before |
| `summary.impact` | yes | Non-empty text | before |
| `summary.scope` | yes | Non-empty text. Judging sends it as the observed scope. | before |
| `summary.top_cause` | yes | A cause `id`, or `null` when `status` is `unresolved` | after |
| `symptoms` | yes | List of text with at least one non-empty entry | before |
| `causes` | yes | List of cause objects. Judging needs at least one. | before |
| `causes[].id` | yes | An id (rules below) | before |
| `causes[].label` | yes | `candidate`, `probable`, or `confirmed` | after |
| `causes[].statement` | yes | Non-empty text | before |
| `causes[].supporting` | yes | List of finding ids; may be empty | before |
| `causes[].contradicting` | yes | List of finding ids; may be empty | before |
| `hypotheses` | yes | List of hypothesis objects; may be empty | before |
| `hypotheses[].id` | yes | An id | before |
| `hypotheses[].statement` | yes | Non-empty text | before |
| `hypotheses[].prediction` | yes | Non-empty text: what must be seen if it is true | before |
| `hypotheses[].test` | yes | Non-empty text: the read that tested it | before |
| `hypotheses[].result` | yes | `confirmed`, `rejected`, or `inconclusive` | before |
| `hypotheses[].finding_ids` | yes | List of finding ids; may be empty | before |
| `hypotheses[].cause` | no | A cause `id`, or `null` | before |
| `actions` | yes | List of action objects; may be empty | before |
| `actions[].id` | yes | An id | before |
| `actions[].type` | yes | `mitigation` or `permanent_fix` | before |
| `actions[].label` | yes | `recommended` or `candidate` | after |
| `actions[].cause` | yes | The `id` of a cause in this report | before |
| `actions[].title` | yes | Non-empty text | before |
| `actions[].target` | yes | Object | before |
| `actions[].target.account_alias` | yes | Non-empty text; an account alias of the config | before |
| `actions[].target.account_id` | yes | Text; the key must be present. Fill it from the evidence whenever a fact holds it: the 12 digits inside the resource's ARN, which the fact that states the resource's state carries in `data["arn"]`. An empty value is accepted. | before |
| `actions[].target.region` | yes | Non-empty text | before |
| `actions[].target.service` | yes | Non-empty text | before |
| `actions[].target.resource_id` | yes | Non-empty text | before |
| `actions[].target.arn` | yes | Text; the key must be present. Fill it from the evidence whenever a fact holds it: the fact that states a resource's state carries its ARN in `data["arn"]`, and related ARNs under clear names (`task_definition_arn`, `target_group_arns`, `listeners`); where AWS gives only an id, the fact has `data["resource_id"]` and `arn` stays empty. Never construct an ARN. An empty value is accepted. | before |
| `actions[].current_state` | yes | Non-empty text | before |
| `actions[].required_state` | yes | Non-empty text | before |
| `actions[].change` | yes | Non-empty text: the exact change. Judging rates how specific an action is from `title`, `target`, `current_state`, `required_state`, `change` as written, so an empty `account_id` or `arn` leaves that rating less to go on. | before |
| `actions[].rationale` | yes | Non-empty text | before |
| `actions[].finding_ids` | yes | List of finding ids with at least one valid | before |
| `actions[].risk` | yes | Non-empty text | before |
| `actions[].blast_radius` | yes | Non-empty text | before |
| `actions[].preconditions` | yes | List of text; may be empty | before |
| `actions[].verification` | yes | List of text with at least one non-empty step | before |
| `actions[].rollback` | yes | List of text with at least one non-empty step | before |
| `open_questions` | yes | List of text; may be empty | before |
| `coverage` | yes | Object | before |
| `coverage.typesafe` | yes | `available`, or text starting `unavailable: ` or `failed: `. Copy the `typesafe` value of `judgments/summary.json`; with no summary stored it must start `unavailable: `. | after |
| `coverage.not_checked` | yes | List of objects; may be empty | before |
| `coverage.not_checked[].what` | yes | Non-empty text | before |
| `coverage.not_checked[].why` | yes | Non-empty text | before |
| `map_changes` | yes | List; each item is text or an object, shown as a bullet in section 8 of the report; may be empty | before |
| `run` | yes | Object | before |
| `run.engineer` | yes | Text; may be empty | before |
| `run.duration_minutes` | yes | A number | before |

Ids. A cause, hypothesis, or action id matches `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`; ids are unique within their list.
A finding id in `supporting`, `contradicting`, or `finding_ids` has the same form and must be a finding under `valid` in `checked.json`.
At judging, a cause id may not be `insufficient_evidence` or `none_match`: those names are used by the questions.

Status rules.

| Status | What validation requires |
| --- | --- |
| `cause_found` | `summary.top_cause` names a cause labelled `confirmed` or `probable`, and a hypothesis with result `confirmed` belongs to it (a hypothesis with no cause counts only when the report has exactly one cause) |
| `unresolved` | `summary.top_cause` is `null` or empty, no cause is `confirmed`, no action is `recommended` |
| either | With three or more `rejected` hypotheses and none `confirmed`, the status must be `unresolved` |

Label rules checked on the draft (the judged ceiling is in section 6):

- A `confirmed` or `probable` cause lists a supporting finding. A `confirmed` cause has no contradicting finding and at least one supporting finding with provenance `incident_time`.
- A `recommended` action belongs to a cause labelled `confirmed`.
- Every action cites at least one valid finding, and its `target.account_alias` is configured.
- With `coverage.typesafe` starting `unavailable: `, no cause is `confirmed`. Starting `failed: `, no cause is above `candidate`.
- Any text that looks like a secret is refused, in values and in keys.

| Message | Meaning |
| --- | --- |
| `<path>: missing` | A required field is absent |
| `<path>: must be text`, `<path>: is empty`, `<path>: must be a list of text`, `<path>: must be an object`, `<path>: must be a list`, `<path>: must be a number` | Wrong type or empty |
| `<path>: must be one of <values>` | A value outside the allowed set |
| `<path>: not a valid id (letters, digits, . _ : -, up to 128, starting with a letter or digit)` | Id form |
| `<path>: duplicate id` | Two items of a list share an id |
| `<path>: not a valid finding (it does not exist or failed its evidence check)` | A cited finding is not under `valid` |
| `symptoms: needs at least one non-empty symptom` | Empty symptoms |
| `<path>: needs at least one non-empty step` | Empty `verification` or `rollback` |
| `<path>.finding_ids: needs at least one valid finding` | An action cites no valid finding |
| `<path>.cause: not a known cause id` | An action or hypothesis names a missing cause |
| `<path>.target.account_alias: not an account in the config` | Unknown alias |
| `summary.top_cause: not a known cause id` | `cause_found` with a missing cause |
| `summary.top_cause: the top cause must be labelled confirmed or probable` | Weak top cause |
| `status is cause_found but no confirmed hypothesis belongs to the top cause` | No confirmed hypothesis for it |
| `status: three or more hypotheses were rejected and none confirmed, so status must be unresolved` | Status rule |
| `<path>: contains what looks like a secret (<category>); remove it` | Secret scan; rewrite the words |
| `report: nested deeper than 50 levels` | Nesting |

## 6. What judging writes and what each label needs

`judge.py run --case-dir <case>` reads from `report.json`: `symptoms`, `summary.scope`, each cause's `id`, `statement`, `supporting`, `contradicting`,
and each action's `id`, `cause`, `title`, `target`, `current_state`, `required_state`, `change`. It reads each cited finding's `claim` and the summary of its cited facts from `checked.json`.
It writes `judgments/summary.json` and one `judgments/<nnn>-<kind>.json` per question; both are script files.

| Key of summary.json | Holds |
| --- | --- |
| `status` | `complete`, `unavailable` (TypeSafe could not be reached), or `failed` (a malformed or missing answer; run it again) |
| `typesafe` | `available`, `unavailable: <reason>`, or `failed: <reason>; judging must be run again`. Copy it to `coverage.typesafe`. |
| `judged`, `model`, `thresholds`, `uncalibrated` | Whether a judging run wrote it, the model, the thresholds used |
| `findings` | Per finding id: `relation`, `confidence`, `verdict` (`verified`, `contradicted`, `unsupported`, `uncertain`) |
| `causes` | Per cause id: `label`, `gates`, `rank_probability`, `symptom_fit`, `scope`, `reasons`, `digest` |
| `actions` | Per action id: `label`, `target`, `target_confidence`, `specific`, `reasons`, `digest` |
| `ask_engineer` | Questions for the engineer, for example when the ranking changed with the option order |
| `adhoc` | The ad hoc questions asked (section 8) |
| `draft_digest` | Ties the summary to the draft (section 7) |

A finding verdict: relation `supports` with confidence at least 0.8 is `verified`; `contradicts` at least 0.6 is `contradicted`; `says_nothing` at least 0.8 is `unsupported`; anything else is `uncertain`.
A verdict answers one question: whether the evidence a finding cites supports that finding's own claim. It does not say whether the finding helps or hurts a cause.
Which way a finding counts for a cause is decided only by which list of the cause it stands on in `report.json`, `supporting` or `contradicting`.
A finding that rules a cause out is `verified` (its relation is `supports`: its evidence supports its own claim) and still counts against the cause it is listed under as `contradicting`.
Only the first 40 findings are judged, contradicting ones first; the rest are `uncertain` and not asked.

| Threshold | Value | Constant |
| --- | --- | --- |
| Finding judged contradicting | 0.6 | `compose.CONTRADICT_CONFIDENCE` |
| Symptom fit (score as a share of its top level) | 0.67 | `compose.SYMPTOM_FIT_MIN` |
| Remediation target confidence | 0.6 | `compose.ACTION_TARGET_CONFIDENCE` |
| Action specific probability | 0.7 | `compose.ACTION_SPECIFIC_MIN` |
| Finding judged supporting (config default) | 0.8 | `config.DEFAULT_THRESHOLDS[evidence_supports]` |
| Ranking probability (config default) | 0.6 | `config.DEFAULT_THRESHOLDS[cause_top_probability]` |

The six gates of a cause:

| Gate | Passes when |
| --- | --- |
| `evidence` | The cause lists at least one supporting finding and every one is `verified` |
| `no_contradiction` | No supporting finding is `contradicted`, no contradicting finding is `verified`, and every contradicting finding was judged |
| `rank` | The ranking picked this cause in both option orders (shuffled and reversed) and its lower probability is at least 0.6 |
| `timing` | A supporting finding has provenance `incident_time` and a `time` no later than the incident start plus 300 seconds. No supporting finding with a `time` counts as not passed. |
| `symptom_fit` | The score divided by its top level is at least 0.67 |
| `scope` | The scope answer is `matches` (the others are `broader`, `narrower`, `unrelated`) |

Cause label: all six gates pass: `confirmed`. Otherwise, if `no_contradiction` failed or the ranking did not pick the cause twice: `candidate`.
Otherwise exactly one failed gate: `probable`; two or more: `candidate`. A contradicting finding judged `uncertain` caps the label at `probable`.
Action label: `recommended` only when the cause is `confirmed`, the target answer is `addresses_cause` with confidence at least 0.6, and the specific probability is at least 0.7. Otherwise `candidate`, with `reasons`.
When TypeSafe is unavailable the label is your draft label capped at `probable` (a value that is not a label counts as `candidate`), or `candidate` when answers already in hand rule the cause out; every action is `candidate`.
When judging failed every label is `candidate`.

What validation requires of a label, once a summary exists: a cause label is at most the one in the summary; an action is `recommended` only if the summary says so; a supporting finding judged
`contradicted` or `unsupported` cannot support a cause; an action cannot cite a `contradicted` finding; `coverage.typesafe` equals the summary's `typesafe`.
A weaker label than the summary's is always accepted.

Refusals before the first question (nothing is sent; exit 1 for the first five, exit 2 for the rest):

| Message | Cause |
| --- | --- |
| `report.json: symptoms must be a list of strings` | Wrong type |
| `report.json: summary must be an object` | Wrong type |
| `report.json: causes must be a non-empty list` | No causes: a report without causes cannot be judged |
| `report.json: every cause needs an id and a statement` | Missing |
| `report.json: every action needs an id` | Missing |
| `report.json: duplicate <kind> id <id>` | Repeated id |
| `report.json: action <id> names a cause that does not exist` | Bad `cause` |
| `report.json: the cause id <id> is reserved for a question option; rename the cause` | Reserved id |
| `report.json: <field> of cause <id> must be a list of finding ids` | Wrong type |
| `cause <id> <list> names finding <id>, which is not in findings/checked.json` | Uncited or refused finding |
| `finding <id> cites <n> facts; the limit is 10. Split the finding or cite fewer facts` | Too many facts |
| `the state for <name> is <n> characters, over the limit of 8000; shorten it` | Text too long |
| `findings/checked.json is in an old shape (finding <id>); run the findings check again` | Stale check |

## 7. Edits after judging

The summary stores a digest of each cause, each action, and the draft. Validation recomputes them.

| Part of report.json | After an edit |
| --- | --- |
| `causes[].label`, `actions[].label`, and the keys `confidence` and `reasons` of a cause or action | Allowed. These are the only fields a cause or action digest leaves out. |
| `status`, `summary.top_cause`, `coverage.typesafe` | Allowed; they must agree with the labels and the summary (section 5) |
| `summary.what_broke`, `summary.impact`, `hypotheses`, `open_questions`, `coverage.not_checked`, `map_changes`, `run` | Allowed: no digest covers them |
| Any other field of a cause (including `supporting`, `contradicting`, `statement`, an extra key) | That cause counts as `candidate` |
| Any other field of an action | That action counts as `candidate`; it cannot be `recommended` |
| `symptoms`, `summary.scope`, adding or removing a cause or action | Every cause and action counts as `candidate` |
| A cited finding changed by a new findings check (its `checked.json` entry) | The causes that cite it count as `candidate` |
| A cause edited | An action of that cause cannot be `recommended` |

The messages, all from `report.py validate`:

| Message | Meaning |
| --- | --- |
| `causes[<n>]: edited after judging (or its stored digest is missing); it counts as candidate, so run the judgments again` | One cause changed |
| `actions[<n>]: edited after judging (or its stored digest is missing); it counts as candidate, so run the judgments again` | One action changed |
| `draft: the draft or the case changed after judging (or the stored draft digest is missing); every cause and action counts as candidate, so run the judgments again` | Report-level change |
| `<path>: labelled <label>, stronger than the judged label <judged>` | Label above the summary |
| `<path>: recommended, but the summary labels it candidate` | Action above the summary |

After such an edit, run `judge.py run` again, set the labels again, and validate. Running it again renames the old summary to `summary.json.stale`.
If `report.json`, the summary, or `checked.json` changes after `report.py render`, the next `report.py` call renames `report.md` and `work-order.json` to `.stale`; render again.

## 8. The ad hoc question file

`judge.py adhoc --case-dir <case> --question-file <file>` asks one question the fixed set does not cover. The answer is printed and the question is listed under `adhoc` in the summary.

| Field | Required | Allowed values |
| --- | --- | --- |
| `id` | yes | 1 to 40 characters: a lower-case letter, then lower-case letters, digits, or underscores. Not one of the fixed ids: `evidence_relation`, `symptom_fit`, `scope_fit`, `cause_rank`, `remediation_target`, `action_specific`, `resource_match`. |
| `reason` | yes | Non-empty text, listed in the report |
| `state` | yes | The facts the question is about, any JSON that is not `null`; at most 8000 characters when sent |
| `question` | yes | Object (below); at most 2000 characters as JSON |

`question` has `type`, `instructions` (non-empty text), and by type:

| `type` | `criteria` |
| --- | --- |
| `choice` | Object of at least two options, name to non-blank description. No `criteria_from` and no `fallback`. |
| `score` | List of 2 to 10 non-blank strings, lowest level first |
| `noul` | None: a probability question |

| Message | Cause |
| --- | --- |
| `the question file must hold a JSON object` | Not an object |
| `<name> must be a non-empty string` | `id` or `reason` empty |
| `state is required` | No `state` |
| `question must be an object` | Wrong type |
| `id must be 1 to 40 characters: a lower-case letter, then lower-case letters, digits, or underscores` | Bad id |
| `id <id> belongs to a fixed question; choose another id` | Fixed id |
| `question '<id>' needs non-empty instructions` | No instructions |
| `question '<id>' is a noul and must not have criteria` | `noul` with criteria |
| `question '<id>' needs a criteria object with at least two options` | Short `choice` |
| `question '<id>' is a score and needs a criteria list of 2 to 10 strings` | Bad `score` |
| `an ad hoc question must list its options in criteria, not criteria_from` | `criteria_from` used |
| `the question text is over the limit of 2000 characters` | Too long |

## 9. report.md and work-order.json

`report.py render` writes both, only when validation passes. Do not edit them.
`report.md` has the title `# Triage report: <number> <title>` and nine sections, in this order:

1. `## 1. Summary`: what broke, impact, scope, symptoms, the top cause with its label.
2. `## 2. Incident and window`: the incident fields, the window, the target.
3. `## 3. Timeline`: incident times, the incident's own timeline and notes, and every `incident_time` fact, ordered by time.
4. `## 4. Findings`: each valid finding by analyst, with its cited facts and its verdict.
5. `## 5. Ranked causes`: the causes numbered in the order they stand in `report.json`, with gates, hypotheses, and reasons.
6. `## 6. Remediation work order`: mitigations first, then permanent fixes; a `candidate` is marked as needing more evidence.
7. `## 7. Coverage notes`: not checked, evidence errors, TypeSafe, questions for the engineer, ad hoc questions, rejected findings, open questions.
8. `## 8. Proposed service map changes`: `map_changes`.
9. `## 9. Run details`: engineer, duration, skill version, case folder, render time.

`work-order.json` holds exactly these keys: `incident` (`number`, `title`, `url`), `generated_at`, `skill_version`, `cause`, `actions`, `open_questions`, `coverage_gaps`.
`cause` has `statement`, `label`, `finding_ids`: the top cause with its supporting findings, or label `unresolved` and the statement `No cause was established.`
Each entry of `actions` has `id`, `type`, `label`, `title`, `target`, `current_state`, `required_state`, `change`, `rationale`, `finding_ids`, `risk`, `blast_radius`, `preconditions`, `verification`, `rollback`.
`coverage_gaps` lists each `not_checked` entry as `<what>: <why>`, a TypeSafe note when it was not `available`, unreadable finding files, and evidence errors.

The Slack message takes `status`, the top cause's `label` and `statement`, and the `title` and `label` of at most 3 actions from `report.json`; `publish.py slack-message` refuses with
`report.json: status is cause_found but top_cause <id> is not in causes` or `report.json: <where> has no <key>`. The Confluence title comes from `case.json`.
A 12-digit number in the report that is not a configured account id is an audit hit.

## 10. Limits

| Limit | Value | Constant |
| --- | --- | --- |
| Shortest excerpt that may be part of a longer string | 12 | `findings.MIN_EXCERPT` |
| Longest excerpt | 300 | `findings.MAX_EXCERPT` |
| Shortest whole value an excerpt may equal | 3 | `findings.MIN_WHOLE_VALUE` |
| Non-space characters that must remain after cutting asked values | 12 | `findings.MIN_FOUND_TEXT` |
| Longest `matched_text` | 500 | `findings.MAX_MATCHED_TEXT` |
| Asked entries kept per cited fact | 20 | `findings.MAX_ASKED_ENTRIES` |
| Facts per evidence file | 200 | `evidence.MAX_FACTS` |
| Longest fact summary | 500 | `evidence.MAX_SUMMARY` |
| Longest fact excerpt | 500 | `evidence.MAX_EXCERPT` |
| Longest string in `data` | 500 | `evidence.MAX_DATA_STRING` |
| Keys in `data` | 50 | `evidence.MAX_DATA_KEYS` |
| Longest key in `data` | 100 | `evidence.MAX_KEY_LENGTH` |
| Entries in a list or object in `data` | 200 | `evidence.MAX_NESTED_ENTRIES` |
| Longest evidence error message | 300 | `evidence.MAX_ERROR_MESSAGE` |
| Seconds after the incident start the timing gate allows | 300 | `compose.TIMING_TOLERANCE_SECONDS` |
| Findings judged per run | 40 | `compose.MAX_FINDINGS_JUDGED` |
| Facts one finding may cite for judging | 10 | `judge.MAX_FACTS_PER_FINDING` |
| Characters of one state sent for judging | 8000 | `judge.MAX_STATE_CHARS` |
| Characters of an ad hoc question | 2000 | `judge.MAX_ADHOC_QUESTION_CHARS` |
| Nesting depth of `report.json` | 50 | `report.MAX_DEPTH` |
| Actions named in the Slack message | 3 | `publish.SLACK_ACTION_LIMIT` |
| Characters of the Slack message | 1500 | `publish.SLACK_LIMIT` |
