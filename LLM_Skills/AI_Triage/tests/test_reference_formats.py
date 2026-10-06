"""reference/formats.md and its two example files must agree with the code that reads the files they describe.

The examples are run through the real commands on a case built from the cert-expired replay. The field tables of
the reference are parsed and compared with the examples and with what the code requires. Every refusal message the
reference quotes must be one the code can produce.
"""
from __future__ import annotations

import copy
import json
import random
import re
import shutil
from pathlib import Path

import pytest

from conftest import SKILL_SRC
from replay_support import REPLAY_DIR, apply_judged_labels, favourable_judge, start_case
from triage import compose, digest, evidence, findings as findings_module, judge as judge_module, report as report_module
from triage import questions as questions_module
from triage import case as case_module, config as config_module, publish as publish_module
from triage.case import CaseError, load_case, parse_incident
from triage.config import load_config
from triage.findings import check_findings
from triage.judge import run_judgments
from triage.questions import default_questions_path, load_questions
from triage.report import check_case_inputs, validate_report

REFERENCE = SKILL_SRC / "reference" / "formats.md"
FINDINGS_EXAMPLE = SKILL_SRC / "templates" / "findings.example.json"
REPORT_EXAMPLE = SKILL_SRC / "templates" / "report.example.json"
SOURCE_DIRS = (SKILL_SRC / "scripts", SKILL_SRC / "scripts" / "triage")
# Lists whose items are free-form: their keys are not fields the code knows.
# Not ecs-bad-deploy: that recording is the one agents are tested on, and the examples must not solve it.
SCENARIO = "cert-expired"
FREE_FORM = {"requests", "map_changes"}
CODE_MODULES = {"findings": findings_module, "evidence": evidence, "compose": compose, "judge": judge_module,
                "report": report_module, "publish": publish_module, "case": case_module, "questions": questions_module,
                "config": config_module}
MIN_QUOTED_MESSAGES = 40
MIN_PIECE = 8


# --- reading the reference ------------------------------------------------------------------

def reference_text() -> str:
    return REFERENCE.read_text()


def sections(text: str) -> dict[str, str]:
    """Level 2 headings (without their number) to the text under them, subsections included."""
    parts = re.split(r"^## ", text, flags=re.MULTILINE)[1:]
    return {re.sub(r"^\d+\.\s*", "", part.split("\n", 1)[0]).strip(): part.split("\n", 1)[1] for part in parts}


def section(text: str, name: str) -> str:
    found = [body for title, body in sections(text).items() if title.startswith(name)]
    assert len(found) == 1, f"the reference needs exactly one section starting with {name!r}"
    return found[0]


def tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    """Every Markdown table as (header cells, rows of cells)."""
    found, lines, position = [], text.splitlines(), 0
    while position < len(lines):
        if lines[position].startswith("|") and position + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[position + 1]):
            header = _cells(lines[position])
            rows, position = [], position + 2
            while position < len(lines) and lines[position].startswith("|"):
                rows.append(_cells(lines[position]))
                position += 1
            found.append((header, rows))
        else:
            position += 1
    return found


def _cells(line: str) -> list[str]:
    inner = line.strip().strip("|")
    return [cell.strip().replace("\\|", "|") for cell in re.split(r"(?<!\\)\|", inner)]


def inline_code(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def field_rows(text: str) -> dict[str, bool]:
    """Path to required, from every table whose first header cell is Field and that has a Required column."""
    rows: dict[str, bool] = {}
    for header, body in tables(text):
        if header[0] != "Field" or "Required" not in header:
            continue
        required_at = header.index("Required")
        for cells in body:
            names = inline_code(cells[0])
            assert len(names) == 1, f"a field row must name one path in code: {cells[0]!r}"
            assert cells[required_at].lower().startswith(("yes", "no")), f"Required must start with yes or no: {cells}"
            assert names[0] not in rows, f"{names[0]} is listed twice"
            rows[names[0]] = cells[required_at].lower().startswith("yes")
    return rows


# --- walking and changing documents ---------------------------------------------------------

def paths_of(value, prefix: str = "") -> set[str]:
    """Every dict key as a dotted path; list items are written as [] and a free-form list is not entered."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            found.add(path)
            if path in FREE_FORM:
                continue
            found |= paths_of(item, path)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                found |= paths_of(item, prefix + "[]")
    return found


def without(document, path: str):
    """A copy of the document with the key at `path` removed; inside a list only the last item loses it."""
    changed = copy.deepcopy(document)
    parts, target = path.split("."), changed
    for position, part in enumerate(parts):
        name, is_list = (part[:-2], True) if part.endswith("[]") else (part, False)
        last = position == len(parts) - 1
        if last and not is_list:
            del target[name]
            return changed
        target = target[name]
        if is_list:
            target = target[-1]
            if last:
                raise AssertionError("a path cannot end in []")
    return changed


# --- the case the examples run in -----------------------------------------------------------

@pytest.fixture(scope="module")
def examples() -> dict:
    return {"findings": json.loads(FINDINGS_EXAMPLE.read_text()), "report": json.loads(REPORT_EXAMPLE.read_text())}


@pytest.fixture(scope="module")
def built(tmp_path_factory, examples):
    """The cert-expired case with only the example findings, checked, and the example report judged."""
    base = tmp_path_factory.mktemp("formats")
    case = start_case(REPLAY_DIR / SCENARIO, base)
    findings_dir = case.case_dir / "findings"
    for path in findings_dir.glob("*.json"):
        path.unlink()
    analyst = examples["findings"]["analyst"]
    shutil.copyfile(FINDINGS_EXAMPLE, findings_dir / f"{analyst}.json")
    case.script("findings check", "findings.py", "check", "--case-dir", str(case.case_dir))
    checked = json.loads((findings_dir / "checked.json").read_text())
    config = load_config(case.skill_dir / "config" / "triage-config.yaml")
    questions = load_questions(default_questions_path(case.skill_dir))
    shutil.copyfile(REPORT_EXAMPLE, case.case_dir / "report.json")
    return {"case": case, "checked": checked, "config": config, "questions": questions, "base": base}


@pytest.fixture(scope="module")
def judged(built, examples):
    """The same case after judging the example report with a judge that favours its top cause."""
    case, base = built["case"], built["base"]
    scenario = base / "example-scenario"
    scenario.mkdir()
    shutil.copyfile(REPORT_EXAMPLE, scenario / "report.json")
    shutil.copyfile(REPLAY_DIR / SCENARIO / "expected.json", scenario / "expected.json")
    incident = json.loads((REPLAY_DIR / SCENARIO / "incident.json").read_text())
    summary = run_judgments(case.case_dir, built["config"], favourable_judge(scenario), built["questions"],
                            random.Random(incident["number"]))
    return {**built, "summary": summary}


# --- the examples are accepted by the real code ---------------------------------------------

def test_example_findings_are_all_accepted_by_the_findings_check(built, examples):
    checked = built["checked"]
    assert checked["rejected"] == [] and checked["unreadable"] == []
    assert checked["warnings"] == []
    expected = {finding["id"] for finding in examples["findings"]["findings"]}
    assert {item["id"] for item in checked["valid"]} == expected
    assert checked["checked"] == {examples["findings"]["analyst"]: examples["findings"]["checked"]}
    assert len(checked["requests"]) == len(examples["findings"]["requests"])


def test_example_report_passes_the_draft_validation_judging_applies_first(built):
    case_dir = built["case"].case_dir
    report = judge_module.load_report_draft(case_dir, judge_module._reserved_ids(built["questions"]))
    found = judge_module.load_checked_findings(case_dir)
    judge_module._check_findings_shape(found)
    judge_module._check_cited_findings(report, found)
    judge_module._check_citation_counts(report["causes"], found)


def test_judging_the_example_report_completes(judged):
    summary = judged["summary"]
    assert summary["status"] == "complete" and summary["typesafe"] == "available"
    assert summary["causes"]["C1"]["label"] == "confirmed" and all(summary["causes"]["C1"]["gates"].values())
    assert summary["causes"]["C2"]["label"] == "candidate" and summary["causes"]["C2"]["gates"]["no_contradiction"] is False


def test_example_report_is_valid_with_its_own_labels_after_judging(judged):
    case = judged["case"]
    result = case.script("report validate", "report.py", "validate", "--case-dir", str(case.case_dir))
    assert "report is valid" in result["stdout"]


def test_example_report_is_valid_with_the_labels_the_summary_allows(judged):
    case = judged["case"]
    shutil.copyfile(REPORT_EXAMPLE, case.case_dir / "report.json")
    apply_judged_labels(case.case_dir)
    result = case.script("report validate", "report.py", "validate", "--case-dir", str(case.case_dir))
    assert "report is valid" in result["stdout"]
    shutil.copyfile(REPORT_EXAMPLE, case.case_dir / "report.json")


def test_example_report_renders_with_the_nine_sections(judged):
    case = judged["case"]
    now = json.loads((REPLAY_DIR / SCENARIO / "incident.json").read_text())["observed_at"]
    case.script("report render", "report.py", "render", "--case-dir", str(case.case_dir), "--now", now)
    text = (case.case_dir / "report.md").read_text()
    headings = [line for line in text.splitlines() if line.startswith("# ") or line.startswith("## ")]
    assert len(headings) == len(report_module.REQUIRED_HEADINGS)
    assert all(heading.startswith(required) for heading, required in zip(headings, report_module.REQUIRED_HEADINGS))
    work_order = json.loads((case.case_dir / "work-order.json").read_text())
    keys = tuple(work_order)
    optional = report_module.WORK_ORDER_OPTIONAL_KEYS
    assert tuple(key for key in keys if key not in optional) == report_module.WORK_ORDER_KEYS
    assert set(keys) - set(report_module.WORK_ORDER_KEYS) <= set(optional)


# --- the field tables ------------------------------------------------------------------------

def test_findings_tables_list_exactly_the_fields_of_the_example(examples):
    listed = field_rows(section(reference_text(), "The findings file"))
    assert set(listed) == paths_of(examples["findings"])


def test_report_tables_list_exactly_the_fields_of_the_example(examples):
    listed = field_rows(section(reference_text(), "report.json"))
    assert set(listed) == paths_of(examples["report"])


def test_findings_required_column_matches_what_the_check_requires(built, examples):
    case_dir = built["case"].case_dir
    findings_dir = case_dir / "findings"
    listed = field_rows(section(reference_text(), "The findings file"))
    analyst = examples["findings"]["analyst"]
    for path, required in sorted(listed.items()):
        mutated = without(examples["findings"], path)
        (findings_dir / f"{analyst}.json").write_text(json.dumps(mutated))
        result = check_findings(case_dir)
        refused = bool(result["rejected"] or result["unreadable"])
        assert refused == required, f"{path}: the reference says required={required}, the check says refused={refused}"
    (findings_dir / f"{analyst}.json").write_text(json.dumps(examples["findings"]))
    check_findings(case_dir)


def test_report_required_column_matches_what_validation_requires(judged, examples):
    """Each field is removed before judging, so that validation answers about the field and not about the digest."""
    case_dir = judged["case"].case_dir
    scenario = judged["base"] / "example-scenario"
    incident = json.loads((REPLAY_DIR / SCENARIO / "incident.json").read_text())

    def judge_and_validate(report: dict) -> list[str]:
        (case_dir / "report.json").write_text(json.dumps(report))
        run_judgments(case_dir, judged["config"], favourable_judge(scenario), judged["questions"],
                      random.Random(incident["number"]))
        found, input_problems = check_case_inputs(case_dir)
        assert input_problems == []
        return validate_report(report, load_case(case_dir), found, judged["config"])

    baseline = examples["report"]
    assert judge_and_validate(baseline) == []
    listed = field_rows(section(reference_text(), "report.json"))
    for path, required in sorted(listed.items()):
        changed = without(baseline, path)
        if required:  # judging may refuse the draft; validation of the changed report is what is asked
            found, _ = check_case_inputs(case_dir)
            problems = validate_report(changed, load_case(case_dir), found, judged["config"])
        else:
            problems = judge_and_validate(changed)
        assert bool(problems) == required, f"{path}: the reference says required={required}; problems: {problems}"
    judge_and_validate(baseline)
    (case_dir / "report.json").write_text(json.dumps(baseline))


def test_work_order_section_lists_every_key():
    text = section(reference_text(), "report.md and work-order.json")
    names = report_module.WORK_ORDER_KEYS + report_module.WORK_ORDER_OPTIONAL_KEYS + report_module.WORK_ORDER_ACTION_KEYS
    assert [name for name in names if f"`{name}`" not in text] == []


def test_edits_table_does_not_call_a_digested_field_free():
    allowed = [cells[0] for _, rows in tables(section(reference_text(), "Edits after judging")) for cells in rows
               if cells[1].startswith("Allowed")]
    named = {name for cell in allowed for name in inline_code(cell)}
    digested = {"summary.what_broke", "summary.impact", "hypotheses", "open_questions", "coverage.not_checked", "map_changes"}
    assert named.isdisjoint(digested) and {"status", "summary.top_cause", "coverage.typesafe", "run"} <= named


def test_incident_table_lists_the_fields_case_init_reads_and_which_it_requires():
    listed: dict[str, bool] = {}
    for header, body in tables(section(reference_text(), "The incident file")):
        if header[0] != "Field":
            continue
        for cells in body:
            for name in inline_code(cells[0]):
                listed[name] = cells[1].lower().startswith("yes")
    incident = json.loads((REPLAY_DIR / SCENARIO / "incident.json").read_text())
    assert set(parse_incident(incident)) == set(listed)
    for name, required in listed.items():
        reduced = {key: value for key, value in incident.items() if key != name}
        try:
            parse_incident(reduced)
            refused = False
        except CaseError:
            refused = True
        assert refused == required, name


def test_reference_explains_what_a_finding_verdict_answers():
    text = " ".join(section(reference_text(), "What judging writes").split())
    assert "whether the evidence a finding cites supports that finding's own claim" in text
    assert "which list of the cause" in text
    text = section(reference_text(), "report.json")
    for field in ("account_id", "arn"):
        row = next(line for line in text.splitlines() if line.startswith(f"| `actions[].target.{field}`"))
        assert "whenever a fact holds it" in row


def test_every_listed_value_set_is_the_codes(examples):
    text = reference_text()
    code_sets = {
        "statuses": report_module.STATUSES,
        "hypothesis results": report_module.HYPOTHESIS_RESULTS,
        "action types": report_module.ACTION_TYPES,
        "action labels": report_module.ACTION_LABELS,
        "cause labels": compose.LABEL_ORDER,
        "provenance": findings_module.PROVENANCES,
        "confidence": findings_module.CONFIDENCES,
        "fact kinds": evidence.KINDS,
        "finding verdicts": report_module.FINDING_VERDICTS,
        "question types": questions_module.QUESTION_TYPES,
        "report.md headings": tuple(heading.split(". ", 1)[-1] for heading in report_module.REQUIRED_HEADINGS[1:]),
        "work order keys": report_module.WORK_ORDER_KEYS,
        "work order action keys": report_module.WORK_ORDER_ACTION_KEYS,
        "fields left out of digests": digest.POST_JUDGING_CAUSE_FIELDS + digest.POST_JUDGING_ACTION_FIELDS,
        "fields judging reads": digest.JUDGED_CAUSE_FIELDS + digest.JUDGED_ACTION_FIELDS,
        "fixed question ids": questions_module.REQUIRED_IDS,
    }
    missing = {name: [word for word in words if word not in text] for name, words in code_sets.items()}
    assert {name: words for name, words in missing.items() if words} == {}


def test_limits_table_values_are_the_codes():
    checked = 0
    for header, body in tables(section(reference_text(), "Limits")):
        assert header == ["Limit", "Value", "Constant"]
        for cells in body:
            module_name, name = inline_code(cells[2])[0].split(".")
            assert getattr(CODE_MODULES[module_name], name) == int(cells[1]), cells
            checked += 1
    assert checked >= 20


def test_threshold_table_values_are_the_codes():
    checked = 0
    for header, body in tables(section(reference_text(), "What judging writes")):
        if header != ["Threshold", "Value", "Constant"]:
            continue
        for cells in body:
            reference = inline_code(cells[2])[0]
            module_name, name = reference.split(".", 1)
            key = None
            if name.endswith("]"):
                name, key = name[:-1].split("[")
            value = getattr(CODE_MODULES[module_name], name)
            assert (value[key] if key else value) == float(cells[1]), cells
            checked += 1
    assert checked == 6


# --- the refusal messages --------------------------------------------------------------------

def source_text() -> str:
    """The source of every script, with adjacent string literals joined so a message split over lines is whole."""
    text = "\n".join(path.read_text() for folder in SOURCE_DIRS for path in sorted(folder.glob("*.py")))
    text = re.sub(r"[\"']\s*\n\s*f?[\"']", "", text)
    for module in CODE_MODULES.values():
        for name, value in vars(module).items():
            if name.isupper() and isinstance(value, int) and not isinstance(value, bool):
                text = text.replace("{" + name + "}", str(value))
    return text


def quoted_messages(text: str) -> list[str]:
    found = []
    for header, body in tables(text):
        if "Message" not in header:
            continue
        column = header.index("Message")
        for cells in body:
            found += inline_code(cells[column])
    return found


def test_the_reference_quotes_many_messages():
    assert len(quoted_messages(reference_text())) >= MIN_QUOTED_MESSAGES


def test_every_quoted_message_is_one_the_code_can_produce():
    source = source_text()
    unknown = []
    for message in quoted_messages(reference_text()):
        pieces = [piece.strip() for piece in re.split(r"<[^>]*>", message)]
        pieces = [piece for piece in pieces if len(piece) >= MIN_PIECE]
        assert pieces, f"nothing fixed to look for in {message!r}"
        unknown += [message for piece in pieces if piece not in source]
    assert unknown == []


def test_quoted_findings_messages_are_really_given_for_the_case_they_describe(built, examples):
    """The findings check says what the reference says it says, for the refusals that are easy to cause."""
    case_dir = built["case"].case_dir
    analyst = examples["findings"]["analyst"]
    cases = {
        "excerpt is empty": {"excerpt": ""},
        f"excerpt is longer than {findings_module.MAX_EXCERPT} characters": {"excerpt": "x" * (findings_module.MAX_EXCERPT + 1)},
        "excerpt was not found in the summary, excerpt, or data of any cited fact": {"excerpt": "this text is in no cited fact at all"},
        "fact_ids is empty": {"fact_ids": []},
        "id must start with": {"id": "other-1"},
        "must be one of": {"provenance": "guess"},
        "cannot be parsed": {"time": "yesterday"},
    }
    text = reference_text()
    for expected, change in cases.items():
        assert expected in text, expected
        document = copy.deepcopy(examples["findings"])
        document["findings"][-1].update(change)
        (case_dir / "findings" / f"{analyst}.json").write_text(json.dumps(document))
        result = check_findings(case_dir)
        assert any(expected in reason for item in result["rejected"] for reason in item["reasons"]), expected
    (case_dir / "findings" / f"{analyst}.json").write_text(json.dumps(examples["findings"]))
    check_findings(case_dir)


# --- intake from OneUptime, the first values of the after-judging fields, the analyst prompt ---------------

INTAKE = SKILL_SRC / "reference" / "intake.md"
ANALYST_PROMPT = SKILL_SRC / "prompts" / "analyst-common.md"
INTAKE_SECTIONS = ("What this mapping is", "The calls, in order", "Field by field", "A worked example",
                   "When a call returns another shape")
INTAKE_TOOLS = ("list_incidents", "get_incident", "list_incident_state_timelines", "get_incident_state",
                "get_incident_severity", "get_monitor", "get_label", "list_incident_internal_notes",
                "list_incident_public_notes")


def intake_text() -> str:
    return INTAKE.read_text()


def test_intake_reference_has_its_sections_in_order():
    titles = [title for title in sections(intake_text())]
    assert [title for title in titles if title.startswith(INTAKE_SECTIONS)] == list(titles)
    assert len(titles) == len(INTAKE_SECTIONS)
    for title, expected in zip(titles, INTAKE_SECTIONS):
        assert title.startswith(expected)


def test_intake_reference_says_it_never_ran_against_a_live_oneuptime():
    first = " ".join(section(intake_text(), "What this mapping is").split())
    assert "has not run against a live OneUptime" in first
    assert "open_questions" in " ".join(section(intake_text(), "When a call returns another shape").split())


def test_intake_reference_names_every_field_case_init_reads():
    incident = json.loads((REPLAY_DIR / SCENARIO / "incident.json").read_text())
    named = set(inline_code(section(intake_text(), "Field by field")))
    missing = [name for name in parse_incident(incident) if name not in named]
    assert missing == []


def test_intake_reference_names_the_tools_and_the_configured_url():
    text = intake_text()
    assert [tool for tool in INTAKE_TOOLS if f"`{tool}`" not in text] == []
    assert "`oneuptime.url`" in text


def test_intake_worked_example_is_accepted_by_case_init():
    blocks = re.findall(r"```json\n(.*?)\n```", section(intake_text(), "A worked example"), flags=re.DOTALL)
    incident = json.loads(blocks[-1])
    parsed = parse_incident(incident)
    assert parsed["monitors"][0]["target"].startswith("https://") and all(isinstance(x, str) for x in parsed["labels"])
    assert parsed["resolved_at"] and parsed["state"] and parsed["severity"] and parsed["url"]
    assert "example.com" in parsed["url"]


def test_after_judging_fields_say_what_to_write_first():
    text = " ".join(section(reference_text(), "report.json").split())
    assert "Before judging write" in text
    for word in ("`candidate`", "`unresolved`", "judging step replaces"):
        assert word in text.split("Before judging write", 1)[1][:600]


def test_analyst_prompt_and_template_use_the_same_request_fields():
    request = json.loads(FINDINGS_EXAMPLE.read_text())["requests"][0]
    assert set(request) == {"what", "why"}
    prompt = ANALYST_PROMPT.read_text()
    assert "`what`" in prompt and "`why`" in prompt
    assert "~/.claude/skills/ai-triage/reference/formats.md" in prompt


def test_hypothesis_result_is_set_after_judging_and_edits_to_it_are_allowed():
    text = section(reference_text(), "report.json")
    row = next(line for line in text.splitlines() if line.startswith("| `hypotheses[].result`"))
    assert row.rstrip(" |").endswith("after")
    allowed = [cells[0] for _, rows in tables(section(reference_text(), "Edits after judging")) for cells in rows
               if cells[1].startswith("Allowed")]
    assert "hypotheses[].result" in {name for cell in allowed for name in inline_code(cell)}
    assert digest.POST_JUDGING_HYPOTHESIS_FIELDS == ("result",)
