# AI Triage Judgments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Check Claude's conclusions with TypeSafe: each finding against its evidence, each cause against the symptoms and scope, the ranking of causes, and each remediation action. Turn the answers into labels in code.

**Architecture:** Claude investigates and TypeSafe acts as an independent checker. Code owns the workflow: it builds small states, asks a fixed, reviewed set of typed questions, stores every request and answer, and combines the answers with explicit rules. The model never decides what happens next.

**Tech Stack:** Python 3.10+, `typesafe-sdk==0.7.2` (the official client), PyYAML 6.0.3, pytest 9.1.1.

**Spec:** `LLM_Skills/AI_Triage/docs/specs/2026-10-04-ai-triage-design.md`, section 8. This is build stage 4. It depends on the stage 3 contracts in `docs/plans/2026-10-04-ai-triage-03-method-code.md` ("Shared Contracts").

This plan specifies interfaces, behaviour, and required tests. Each task is implemented test-first.

## Global Constraints

- All paths are relative to `LLM_Skills/AI_Triage/`. Run tests with `./run-tests.sh tests/<file>` from that folder.
- Branch `claude-skill`. Never commit to `master`. Never push.
- The repository is a public fork. Use only placeholder account IDs (`111111111111`, `222222222222`), `example.com` hostnames, and invented resource names.
- **No live calls in the test suite.** Tests use a fake judge. One opt-in live test may exist, skipped unless `AI_TRIAGE_LIVE_TYPESAFE=1`.
- **The API key is read only from `TYPESAFE_API_KEY`.** It is never printed, logged, stored, or included in an error message.
- **Honest numbers.** Every probability and confidence in a summary comes from a stored response. When TypeSafe is unavailable the summary says so and no cause is labelled above `probable`.
- **What is sent.** Only redacted text. Account IDs are replaced by account aliases. A state holds one claim or one cause with its own evidence, never a whole case.
- **Time and numbers in code.** No question asks the model to compare times, count, or do arithmetic. Code computes those and the rules use them directly.
- **Fixed questions.** Questions live in `skill/ai-triage/judgments/questions.json`. Code supplies state and, for ranking and matching, the option list. Code never rewrites a question's instructions.
- Option order is shuffled for every choice question whose options are built at run time, and ranking is asked twice with different orders.
- Thresholds come from `config.typesafe_thresholds` and are labelled uncalibrated in every summary.
- Python 3.10+. Type hints on public functions. Test-first, with pristine test output. Conventional commits with a body that says why.
- Use `ts_check.py` for the red-phase check and the done check, as the implementer rules describe.

## Shared Contracts

### Answers, as plain data

Every answer is stored and passed around as a plain dict, whatever the client returns:

- noul: `{"type": "noul", "noul": 0.93}`
- choice: `{"type": "choice", "choice": "supports", "confidence": 0.91, "probabilities": {"supports": 0.93, "contradicts": 0.02, "says_nothing": 0.05}}`
- score: `{"type": "score", "score": 2.4, "confidence": 0.8, "probabilities": [0.0, 0.1, 0.4, 0.5], "levels": 4}`

### `judgments/` in the case folder

- `judgments/<nnn>-<kind>.json`, numbered from 001 in the order asked: `{"kind": ..., "subject": ..., "state": ..., "questions": {...}, "answers": {...}, "model": ..., "request_id": ..., "usage": {...}}`.
- `judgments/summary.json`:

```json
{
  "typesafe": "available",
  "model": "jev-1.13.0",
  "thresholds": {"evidence_supports": 0.8, "cause_top_probability": 0.6, "ask_engineer_below": 0.5},
  "uncalibrated": true,
  "findings": {
    "compute-1": {"relation": "supports", "confidence": 0.93, "verdict": "verified"}
  },
  "causes": {
    "C1": {
      "label": "confirmed",
      "gates": {"evidence": true, "no_contradiction": true, "rank": true, "timing": true, "symptom_fit": true, "scope": true},
      "rank_probability": 0.72,
      "symptom_fit": 0.83,
      "scope": "matches",
      "reasons": []
    }
  },
  "actions": {
    "A1": {"label": "recommended", "target": "addresses_cause", "target_confidence": 0.9, "specific": 0.88, "reasons": []}
  },
  "ask_engineer": [],
  "adhoc": []
}
```

Finding `verdict` is `verified`, `contradicted`, `unsupported`, or `uncertain`. Cause `label` is `confirmed`, `probable`, or `candidate`. Action `label` is `recommended` or `candidate`. `typesafe` is `available` or `unavailable: <reason>`.

### Interfaces from earlier stages

- `triage.config.TriageConfig`: `typesafe_model`, `typesafe_thresholds`, `accounts`.
- `triage.case.load_case`; `triage.findings.valid_findings`, `load_facts`; `triage.redact.Redactor`; `triage.window.parse_time`.
- `report.json` contract, including `symptoms` and `summary.scope`.

---

### Task 1: Question set and judge client

**Files:**
- Create: `skill/ai-triage/judgments/questions.json`
- Create: `skill/ai-triage/scripts/triage/questions.py`
- Create: `skill/ai-triage/scripts/triage/judge_client.py`
- Modify: `skill/ai-triage/requirements.txt` (add the line `typesafe-sdk==0.7.2`)
- Test: `tests/test_questions.py`, `tests/test_judge_client.py`

**Interfaces:**
- Consumes: nothing from this plan.
- Produces:
  - `questions.py`: `QuestionError(Exception)` with `.errors`; `load_questions(path: Path) -> dict[str, dict]`; `default_questions_path(skill_dir: Path) -> Path`; `REQUIRED_IDS: tuple[str, ...]`; `build_choice(question: dict, options: dict[str, str], order: Sequence[str]) -> dict` (returns a question with its `criteria` set to `options` in the given order, followed by the question's `fallback` option).
  - `judge_client.py`: `JudgeUnavailable(Exception)` with `reason: str`; `JudgeReply(answers: dict[str, dict], model: str, request_id: str | None, usage: dict)`; `class Judge(Protocol)` with `ask(state: Any, questions: dict[str, dict]) -> JudgeReply`; `TypeSafeJudge(model: str, timeout: float = 30.0)` implementing it with the official client; `to_plain(answer: Any, question: dict) -> dict`.

**The question file**

Write this file exactly. The wording was chosen to follow TypeSafe's guidance: one narrow judgment per question, positive phrasing, options that stand on their own, and a fallback option where nothing may fit.

```json
{
  "version": 1,
  "questions": {
    "evidence_relation": {
      "type": "choice",
      "instructions": "How does `evidence` relate to `claim`?",
      "criteria": {
        "supports": "The evidence states or directly implies that the claim is true",
        "contradicts": "The evidence states or directly implies that the claim is false",
        "says_nothing": "The evidence does not address the claim either way"
      }
    },
    "symptom_fit": {
      "type": "score",
      "instructions": "How much of what is listed in `symptoms` would the cause described in `hypothesis` produce?",
      "criteria": [
        "The cause would produce none of the listed symptoms",
        "The cause would produce some of the listed symptoms and leaves most of them unexplained",
        "The cause would produce most of the listed symptoms",
        "The cause would produce every listed symptom"
      ]
    },
    "scope_fit": {
      "type": "choice",
      "instructions": "Compare what the cause described in `hypothesis` would affect with what `observed_scope` says was affected.",
      "criteria": {
        "matches": "The cause would affect the same things that were observed to be affected",
        "broader": "The cause would affect more than what was observed to be affected",
        "narrower": "The cause would affect less than what was observed to be affected",
        "unrelated": "The cause would affect different things from what was observed to be affected"
      }
    },
    "cause_rank": {
      "type": "choice",
      "instructions": "Which entry in `candidates` is best supported by its own evidence as the cause of `symptoms`?",
      "criteria_from": "candidates",
      "fallback": {"insufficient_evidence": "No candidate is clearly supported by its evidence"}
    },
    "remediation_target": {
      "type": "choice",
      "instructions": "What does the change described in `action` do about the problem described in `cause`?",
      "criteria": {
        "addresses_cause": "The change removes or corrects the cause itself",
        "addresses_symptom_only": "The change reduces the effects and leaves the cause in place",
        "unrelated": "The change does not act on the cause or on its effects"
      }
    },
    "action_specific": {
      "type": "noul",
      "instructions": "Does `action` name the exact resource to change, its current value, and the value it must have, in enough detail to carry out without further investigation?"
    },
    "resource_match": {
      "type": "choice",
      "instructions": "Which entry in `candidates` is the service that `incident` is about?",
      "criteria_from": "candidates",
      "fallback": {"none_match": "No candidate is clearly the service the incident is about"}
    }
  }
}
```

**Behaviour: questions**

- `load_questions` validates the file and reports every problem: `version` is 1; each question has a `type` of `noul`, `choice`, or `score` and non-empty `instructions`; a `choice` has either a `criteria` object with at least two options, or `criteria_from` together with a `fallback` holding exactly one option; a `score` has a `criteria` list of 2 to 10 non-empty strings; a `noul` has no `criteria`. Unknown keys are reported.
- `REQUIRED_IDS` is the seven ids above. A file missing one is invalid.
- `build_choice` refuses a question without `criteria_from`, fewer than one option, and an option name equal to the fallback name. The fallback is always last.

**Behaviour: client**

- `TypeSafeJudge.ask` imports `typesafe_sdk` inside the method. A missing package raises `JudgeUnavailable("the typesafe-sdk package is not installed")`. A missing or empty `TYPESAFE_API_KEY` raises `JudgeUnavailable("TYPESAFE_API_KEY is not set")` before any client is built.
- It builds `Noul`, `Choice`, and `Score` objects from the plain question dicts, calls `TypeSafeClient().system_one(state, questions, model=self.model, timeout=self.timeout)` inside a `with` block, and converts the result with `to_plain`.
- From the client's result: noul answers are in `result.nouls[id].noul`; choice answers in `result.choices[id]` with `.choice`, `.confidence`, `.probabilities`; score answers in `result.scores[id]` with `.score`, `.confidence`, `.probabilities`. `result.model`, `result.request_id`, and `result.usage` (`input_tokens`, `output_tokens`) fill the reply.
- Any `typesafe_sdk.TypeSafeError` raises `JudgeUnavailable` with a short reason built from the exception class name and, for an API error, its status. The reason never contains the key, request headers, or the request body.
- `to_plain` returns the plain shapes in "Shared Contracts". For a score it adds `"levels"`, the number of criteria in the question.

**Required tests**

- [ ] The shipped `questions.json` loads, and holds exactly `REQUIRED_IDS`.
- [ ] One test per validation problem; several problems reported together.
- [ ] `build_choice`: order kept, fallback last, each refusal.
- [ ] `TypeSafeJudge` with a stand-in `typesafe_sdk` module placed in `sys.modules`: the questions are built with the right classes and arguments; the model and timeout are passed; each answer type converts to the plain shape; the reply carries model, request id, and usage.
- [ ] Unavailable cases: package missing, key missing, key blank, an SDK error with a status, a connection error. The reason never contains the key (set a recognisable key value in the test and assert it is absent from the reason and from `repr` of the exception).
- [ ] One live test, skipped unless `AI_TRIAGE_LIVE_TYPESAFE=1`, asking `evidence_relation` about an invented claim and asserting only the shape of the answer.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** with `./run-tests.sh tests/test_questions.py tests/test_judge_client.py` and confirm they fail.
- [ ] **Step 3: Implement.** Check the client's real class and attribute names against the installed package (`.venv-dev/bin/python -c "import typesafe_sdk; help(typesafe_sdk.TypeSafeClient.system_one)"`) after `./run-tests.sh` has installed it.
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): add the reviewed question set and the TypeSafe client`.

### Task 2: Judging and composition

**Files:**
- Create: `skill/ai-triage/scripts/triage/judge.py`
- Create: `skill/ai-triage/scripts/triage/compose.py`
- Create: `skill/ai-triage/scripts/judge.py`
- Test: `tests/test_judge.py`, `tests/test_compose.py`, `tests/test_judge_cli.py`
- Modify: `tests/fakes.py` (add `FakeJudge`)

**Interfaces:**
- Consumes: Task 1; `load_case`, `valid_findings`, `load_facts`, `Redactor`, `parse_time`, `TriageConfig`.
- Produces:
  - `tests/fakes.py`: `FakeJudge(answers: dict[str, dict] | Callable[[Any, dict], dict[str, dict]], fail_with: str | None = None)` with `.calls: list[tuple[state, questions]]`. With `fail_with` set it raises `JudgeUnavailable(fail_with)`.
  - `triage/judge.py`: `prepare_state(value: Any, config: TriageConfig, redactor: Redactor) -> Any`; `JudgmentStore(case_dir: Path)` with `save(kind: str, subject: str, state, questions, reply) -> Path`; `judge_findings(...)`, `judge_causes(...)`, `rank_causes(...)`, `judge_actions(...)`, `match_resource(...)`, each returning plain data described below; `run_judgments(case_dir: Path, config: TriageConfig, judge: Judge, questions: dict[str, dict], rng: random.Random) -> dict` (writes and returns the summary).
  - `triage/compose.py`: `finding_verdict(answer: dict, thresholds: dict) -> str`; `timing_gate(cause: dict, findings: dict[str, dict], incident_start: datetime) -> bool | None`; `cause_label(gates: dict[str, bool]) -> str`; `action_label(cause_label: str, target: dict, specific: float) -> tuple[str, list[str]]`; `cap_label(label: str, cap: str) -> str`; `LABEL_ORDER = ("candidate", "probable", "confirmed")`; constants `CONTRADICT_CONFIDENCE = 0.6`, `SYMPTOM_FIT_MIN = 0.67`, `ACTION_TARGET_CONFIDENCE = 0.6`, `ACTION_SPECIFIC_MIN = 0.7`, `TIMING_TOLERANCE_SECONDS = 300`, `MAX_FINDINGS_JUDGED = 40`.
  - Command `judge.py run --case-dir D`, `judge.py locate --case-dir D`, `judge.py adhoc --case-dir D --question-file F`. Exit codes: 0 done (also when TypeSafe is unavailable: the summary records it), 1 the report draft or question file is unusable, 2 usage or config error.

**Behaviour: what is asked**

`run_judgments` reads `report.json` (the draft Claude wrote), `findings/checked.json`, and `case.json`.

1. **Findings.** For each valid finding that any cause lists under `supporting` or `contradicting`, at most `MAX_FINDINGS_JUDGED`: state `{"claim": <claim>, "evidence": [<summary and excerpt of each cited fact>]}`, question `evidence_relation`. A finding beyond the cap gets the verdict `uncertain` and a reason.
2. **Causes.** For each cause: state `{"hypothesis": <statement>, "symptoms": <report symptoms>, "observed_scope": <summary.scope>}`, questions `symptom_fit` and `scope_fit` in one request.
3. **Ranking.** State `{"symptoms": [...], "candidates": {<cause id>: {"statement": ..., "supporting_evidence": [<claims of its verified supporting findings>]}}}`. The question is `cause_rank` built with `build_choice`, options being cause id to statement. It is asked twice: once in an order shuffled with `rng`, once in the reverse of that order.
4. **Actions.** For each action: state `{"cause": <its cause's statement>, "action": {title, target, current_state, required_state, change}}`, questions `remediation_target` and `action_specific` in one request.

Every state passes through `prepare_state` before it is sent: the `Redactor` is applied, and every 12-digit number equal to a configured account id is replaced by that account's alias, and any other 12-digit number by `<ACCOUNT>`.

Every request and reply is stored with `JudgmentStore`.

**Behaviour: composition**

- Finding verdict: `supports` with confidence at or above `evidence_supports` is `verified`. `contradicts` with confidence at or above `CONTRADICT_CONFIDENCE` is `contradicted`. `says_nothing` with confidence at or above `evidence_supports` is `unsupported`. Anything else is `uncertain`.
- Gates for a cause, each `true` or `false`:
  - `evidence`: it has at least one supporting finding and every supporting finding is `verified`.
  - `no_contradiction`: no supporting finding is `contradicted`, and no finding listed under `contradicting` is `verified`.
  - `rank`: the cause is the choice in both orderings, and the lower of its two probabilities is at or above `cause_top_probability`.
  - `timing`: `timing_gate` is true. It is true when at least one supporting finding with provenance `incident_time` has a `time` no later than the incident start plus `TIMING_TOLERANCE_SECONDS`. It is `None`, which counts as a missed gate, when no supporting finding has a time.
  - `symptom_fit`: the score divided by its highest level is at or above `SYMPTOM_FIT_MIN`.
  - `scope`: the choice is `matches`.
- `cause_label`: `confirmed` when every gate is true. `candidate` when `no_contradiction` is false, or when the cause is not the choice in both orderings. Otherwise `probable` when exactly one gate is false, and `candidate` when two or more are.
- Each false gate adds a plain sentence to the cause's `reasons`, for example `Ranking picked this cause with probability 0.48, below 0.6`.
- When the two orderings choose different options, `ask_engineer` gains `The ranking of causes changed with the order of the options; the evidence does not separate <a> from <b>.`
- `action_label`: `recommended` when the cause's label is `confirmed`, the target choice is `addresses_cause` with confidence at or above `ACTION_TARGET_CONFIDENCE`, and `specific` is at or above `ACTION_SPECIFIC_MIN`. Otherwise `candidate`, with a reason for each miss.
- **Unavailable.** When any call raises `JudgeUnavailable`, judging stops. The summary has `typesafe: "unavailable: <reason>"`, empty `findings`, every cause labelled with `cap_label(<the label in the report draft>, "probable")` and the reason `TypeSafe was unavailable; this label is Claude's own estimate, capped at probable`, and every action labelled `candidate`.

**Behaviour: locate and ad hoc**

- `locate` is used when the service map matched several candidates. State: `{"incident": {title, description, monitors, labels, hostnames}, "candidates": {"<service>/<environment>": "<account>, <region>, resources: <resource keys and string values>"}}`, question `resource_match` built with shuffled options. It prints `{"decision": "<service>/<environment>" | "ask", "confidence": ..., "probabilities": {...}}`. The decision is `ask` when the choice is `none_match`, when the confidence is below `ask_engineer_below`, or when TypeSafe is unavailable. It stores the judgment.
- `adhoc` runs one question that Claude wrote for a judgment the fixed set does not cover. The file is `{"id": ..., "reason": ..., "state": ..., "question": {...}}`; the question is validated with the same rules as the question file. The answer is printed and stored, and the id and reason are appended to `adhoc` in the summary, creating a minimal summary when none exists.

**Required tests**

- [ ] `prepare_state`: redaction applied at every depth; a configured account id becomes its alias; another 12-digit number becomes `<ACCOUNT>`; the input is not mutated. Build 12-digit test values from the config fixture, not as new literals.
- [ ] The four kinds of request: the exact state and question ids sent, using `FakeJudge.calls`. Ranking is sent twice with reversed option order and the fallback last both times.
- [ ] No state contains a whole case: assert each state's JSON is under 6000 characters for a realistic case, and that a finding state holds only that finding's facts.
- [ ] `finding_verdict`: each branch and each threshold boundary.
- [ ] `timing_gate`: before the start, within the tolerance, after it, no times, only `current` findings.
- [ ] `cause_label` and reasons: all gates true; each single gate false; two false; a contradiction; unstable ranking.
- [ ] `action_label`: each miss.
- [ ] Unavailable at the first call and at a later call: the summary shape, the caps, and that no further call is made.
- [ ] The finding cap.
- [ ] Store: files numbered in order, with state, questions, answers, model, request id, usage.
- [ ] `locate`: a clear match, `none_match`, low confidence, unavailable.
- [ ] `adhoc`: stored, listed in the summary, an invalid question file exits 1.
- [ ] Command: `run` writes `judgments/summary.json` and prints its path; a missing `report.json` exits 1. Give `main` a `judge` parameter so tests inject `FakeJudge`.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): judge findings, causes, and actions and compose labels`.

### Task 3: Report integration

**Files:**
- Modify: `skill/ai-triage/scripts/triage/report.py`
- Modify: `tests/test_report.py`

**Interfaces:**
- Consumes: `judgments/summary.json`; `compose.LABEL_ORDER`, `compose.cap_label`.
- Produces: no new names. `validate_report` and `render_report` gain behaviour.

**Behaviour**

- `validate_report`, when `judgments/summary.json` exists:
  - a cause's label may not be stronger than its label in the summary (this rule already exists; keep it and use `LABEL_ORDER`);
  - an action's label may not be `recommended` unless the summary labels it `recommended`;
  - `coverage.typesafe` must equal the summary's `typesafe` value;
  - a finding the summary marks `contradicted` or `unsupported` may not appear under any cause's `supporting`.
- `validate_report`, when the summary does not exist: `coverage.typesafe` must start with `unavailable: `, and the existing rule that no cause is `confirmed` applies.
- `render_report`:
  - section 4 shows each finding's verdict and confidence when the summary has them;
  - section 5 shows, for each cause, the gates as a short list of passed and missed checks with their reasons, the ranking probability, the symptom fit, and the scope answer;
  - section 6 shows each action's target answer and reasons for a `candidate` label;
  - section 7 states `TypeSafe: available (model <name>); thresholds are uncalibrated` or the unavailable reason, lists `ask_engineer` entries, and lists ad hoc questions with their reasons.

**Required tests**

- [ ] Each new validation rule, with and without the summary file.
- [ ] Rendering with a summary: verdicts, gates, reasons, the TypeSafe line, ad hoc entries. Rendering without one still works.
- [ ] Every existing test in `tests/test_report.py` still passes. Where an existing test built a `confirmed` cause without a summary, give it a summary rather than weakening the rule.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests** and confirm they pass.
- [ ] **Step 5: Commit** as `feat(ai-triage): bind report labels to the stored judgments`.
