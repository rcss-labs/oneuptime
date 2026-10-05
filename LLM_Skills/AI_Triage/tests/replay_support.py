"""Run the whole skill pipeline on a recorded incident, without AWS, Kubernetes, or a network.

A scenario folder (tests/replay/<name>) holds the incident, the canned answers of the tools, the config and
service map of the recorded world, the analysts' findings, and a report draft. run_pipeline copies the skill into a
temporary folder shaped like an installed skill, points every command at the scenario with AI_TRIAGE_FIXTURES, and
runs the commands the way the skill does: as subprocesses of the skill's scripts.
"""
from __future__ import annotations

import json
import os
import random
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from fakes import FakeJudge
from triage.config import load_config
from triage.fixtures import FIXTURE_ENV, LOG_ENV
from triage.judge import run_judgments
from triage.questions import default_questions_path, load_questions

TESTS_DIR = Path(__file__).resolve().parent
REPLAY_DIR = TESTS_DIR / "replay"
SKILL_SOURCE = TESTS_DIR.parent / "skill" / "ai-triage"
SCENARIOS = ("ecs-bad-deploy", "cert-expired")
SKILL_PARTS = ("scripts", "judgments", "templates", "VERSION")
LOG_NAME = "pipeline-commands.json"
CALL_LOG_NAME = "fixture-calls.jsonl"
COMMAND_TIMEOUT_SECONDS = 120


class PipelineError(Exception):
    """A step of the pipeline failed; the message names the step and what it printed."""


def _choice(name: str, confidence: float, question: dict) -> dict:
    options = list(question["criteria"])
    rest = (1 - confidence) / (len(options) - 1)
    return {"type": "choice", "choice": name, "confidence": confidence,
            "probabilities": {option: (confidence if option == name else rest) for option in options}}


def _expected(scenario: Path) -> dict:
    return json.loads((scenario / "expected.json").read_text())


def names_the_real_cause(scenario: Path, statement: str) -> bool:
    """The ground truth of a scenario: a statement holds every expected cause keyword and none of the words of
    the distractors (expected.json). The judges below read this, never the draft's own top cause."""
    expected, text = _expected(scenario), str(statement).lower()
    return (all(word.lower() in text for word in expected["cause_keywords"])
            and not any(word.lower() in text for word in expected["not_the_cause"]))


def _answers(scenario: Path, relation: str):
    """A judge's answers that favour a cause only when it is the real one (see names_the_real_cause): it fits the
    symptoms and scope, wins the ranking, and its actions address it. Any other cause fits poorly, loses the
    ranking, and its actions are judged unrelated. Findings are judged as `relation` (they are facts)."""

    def respond(state: Any, questions: dict[str, dict]) -> dict[str, dict]:
        favoured = isinstance(state, dict) and names_the_real_cause(scenario, state.get("hypothesis", state.get("cause", "")))
        winners = [cause_id for cause_id, candidate in (state.get("candidates") or {}).items()
                   if names_the_real_cause(scenario, candidate.get("statement", ""))] if isinstance(state, dict) else []
        answers: dict[str, dict] = {}
        for question_id, question in questions.items():
            if question_id == "evidence_relation":
                answers[question_id] = _choice(relation, 0.93, question)
            elif question_id == "symptom_fit":
                score = 2.5 if favoured else 0.3
                answers[question_id] = {"type": "score", "score": score, "confidence": 0.8,
                                        "probabilities": [0.0, 0.1, 0.4, 0.5], "levels": 4}
            elif question_id == "scope_fit":
                answers[question_id] = _choice("matches" if favoured else "broader", 0.9, question)
            elif question_id == "cause_rank":
                pick = winners[0] if winners else "insufficient_evidence"
                answers[question_id] = _choice(pick, 0.72, question)
            elif question_id == "remediation_target":
                answers[question_id] = _choice("addresses_cause" if favoured else "unrelated", 0.9, question)
            elif question_id == "action_specific":
                answers[question_id] = {"type": "noul", "noul": 0.88}
        return answers

    return respond


def favourable_judge(scenario: Path) -> FakeJudge:
    """A FakeJudge that answers every question in favour of the scenario's real cause and against any other."""
    return FakeJudge(_answers(scenario, "supports"))


def contradicting_judge(scenario: Path) -> FakeJudge:
    """Like favourable_judge, but every finding is judged as contradicting its claim's evidence."""
    return FakeJudge(_answers(scenario, "contradicts"))


def skill_style(argv: list[str], home: Path) -> str:
    """The command as the skill writes it: paths under HOME are double-quoted "$HOME/..." words."""
    prefix = str(home) + "/"
    words = [f'"$HOME/{word[len(prefix):]}"' if word.startswith(prefix) else shlex.quote(word) for word in argv]
    return " ".join(words)


def load_call_log(base: Path) -> list[dict]:
    """Every aws, kubectl, and OpenSearch call the replay answered or missed, with the recorded entry that answered it."""
    path = base / CALL_LOG_NAME
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


def load_log(base: Path) -> list[dict]:
    """The commands run_pipeline executed under `base`: step, argv (in the skill's form), returncode, stdout, stderr."""
    return json.loads((base / LOG_NAME).read_text())


@dataclass
class ReplayCase:
    scenario: Path
    base: Path
    skill_dir: Path
    case_dir: Path
    log: list[dict] = field(default_factory=list)

    @property
    def python(self) -> Path:
        return self.skill_dir / ".venv" / "bin" / "python"

    def _env(self) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if not key.startswith("AI_TRIAGE_")}
        env[FIXTURE_ENV] = str(self.scenario)
        env[LOG_ENV] = str(self.base / CALL_LOG_NAME)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    def command(self, step: str, argv: list[str], required: bool = True) -> dict:
        """Run argv (its first word is the skill's python, which is swapped for this interpreter) and log it."""
        real = [sys.executable, *argv[1:]]
        done = subprocess.run(real, capture_output=True, text=True, env=self._env(), cwd=self.base,
                              timeout=COMMAND_TIMEOUT_SECONDS)
        record = {"step": step, "argv": argv, "returncode": done.returncode, "stdout": done.stdout, "stderr": done.stderr}
        self.log.append(record)
        (self.base / LOG_NAME).write_text(json.dumps(self.log))
        if required and done.returncode != 0:
            raise PipelineError(f"{step} exited {done.returncode}: {(done.stderr or done.stdout).strip()[-600:]}")
        return record

    def script(self, step: str, name: str, *args: str, required: bool = True) -> dict:
        return self.command(step, [str(self.python), str(self.skill_dir / "scripts" / name), *args], required)

    def collect_evidence(self) -> None:
        plan = json.loads(self.log[-1]["stdout"])
        for planned in plan:
            if planned["tool"] == "skipped":
                continue
            self.command(f"plan: {planned['name']}", [str(self.python), *shlex.split(planned["command"])[1:]])

    def check_findings(self) -> None:
        shutil.copytree(self.scenario / "findings", self.case_dir / "findings", dirs_exist_ok=True)
        self.script("findings check", "findings.py", "check", "--case-dir", str(self.case_dir))
        self.script("timeline", "timeline.py", "--case-dir", str(self.case_dir))

    def judge(self, judge: FakeJudge, apply_labels: bool = False, draft: dict | None = None) -> dict:
        """Copy the canned report (or write `draft` instead), judge it in this process, and (as the skill's agent
        does) write the labels the judgments allow into report.json."""
        if draft is None:
            shutil.copyfile(self.scenario / "report.json", self.case_dir / "report.json")
        else:
            (self.case_dir / "report.json").write_text(json.dumps(draft, indent=2) + "\n")
        config = load_config(self.skill_dir / "config" / "triage-config.yaml")
        questions = load_questions(default_questions_path(self.skill_dir))
        incident = json.loads((self.scenario / "incident.json").read_text())
        summary = run_judgments(self.case_dir, config, judge, questions, random.Random(incident["number"]))
        # judge.py run needs TypeSafe, so the judging runs in this process; the command the skill would run is logged
        # in its own form, so that the guard test checks it too.
        self.log.append({"step": "judge run", "returncode": 0, "stdout": "", "stderr": "", "in_process": True,
                         "argv": [str(self.python), str(self.skill_dir / "scripts" / "judge.py"), "run",
                                  "--case-dir", str(self.case_dir)]})
        (self.base / LOG_NAME).write_text(json.dumps(self.log))
        if apply_labels:
            apply_judged_labels(self.case_dir)
        return summary

    def render(self, required: bool = False) -> dict:
        now = json.loads((self.scenario / "incident.json").read_text())["observed_at"]
        return self.script("report render", "report.py", "render", "--case-dir", str(self.case_dir), "--now", now,
                           required=required)

    def publish(self) -> None:
        case = str(self.case_dir)
        self.script("publish audit", "publish.py", "audit", "--case-dir", case)
        self.script("publish confluence", "publish.py", "confluence", "--case-dir", case)
        self.script("publish slack-message", "publish.py", "slack-message", "--case-dir", case)


def distractor_draft(scenario: Path) -> dict:
    """The canned report with the distractor named as the top cause: C2 is promoted, the findings that argued
    against it now support it, and both actions address it."""
    report = json.loads((scenario / "report.json").read_text())
    distractor = next(cause for cause in report["causes"] if cause["id"] != report["summary"]["top_cause"])
    report["summary"]["top_cause"] = distractor["id"]
    distractor["label"] = "confirmed"
    distractor["supporting"], distractor["contradicting"] = distractor["contradicting"], []
    for action in report["actions"]:
        action["cause"] = distractor["id"]
    return report


def apply_judged_labels(case_dir: Path) -> None:
    """Set each label in report.json to the one the judgments allow, and the TypeSafe coverage to the summary's."""
    summary = json.loads((case_dir / "judgments" / "summary.json").read_text())
    report = json.loads((case_dir / "report.json").read_text())
    for cause in report["causes"]:
        cause["label"] = summary["causes"].get(cause["id"], {}).get("label", "candidate")
    for action in report["actions"]:
        action["label"] = summary["actions"].get(action["id"], {}).get("label", "candidate")
    report["coverage"]["typesafe"] = summary["typesafe"]
    (case_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def _build_skill_dir(scenario: Path, base: Path) -> tuple[Path, Path]:
    """A skill folder shaped like an installed one, under a fake home, with the scenario's config and map."""
    home = base / "home"
    skill_dir = home / ".claude" / "skills" / "ai-triage"
    (skill_dir / "config").mkdir(parents=True)
    for part in SKILL_PARTS:
        source = SKILL_SOURCE / part
        if source.is_dir():
            shutil.copytree(source, skill_dir / part, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copyfile(source, skill_dir / part)
    config = yaml.safe_load((scenario / "triage-config.yaml").read_text())
    config["cases_dir"] = str(base / "cases")
    (skill_dir / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    shutil.copyfile(scenario / "service-map.yaml", skill_dir / "config" / "service-map.yaml")
    return skill_dir, home


def start_case(scenario: Path, base: Path) -> ReplayCase:
    """Steps 1 to 5: the skill folder, init, target, plan, every planned collector, the findings check, the timeline."""
    scenario, base = Path(scenario), Path(base)
    base.mkdir(parents=True, exist_ok=True)
    skill_dir, _ = _build_skill_dir(scenario, base)
    case = ReplayCase(scenario, base, skill_dir, case_dir=base)
    incident = json.loads((scenario / "incident.json").read_text())
    init = case.script("case init", "case.py", "init", "--incident", str(scenario / "incident.json"),
                       "--now", incident["observed_at"])
    summary = json.loads(init["stdout"])
    case.case_dir = Path(summary["case_dir"])
    candidates = summary["match"]["candidates"]
    if summary["match"]["status"] != "one" or len(candidates) != 1:
        raise PipelineError(f"the incident did not match exactly one service: {summary['match']}")
    case.script("case target", "case.py", "target", "--case-dir", str(case.case_dir),
                "--service", candidates[0]["service"], "--environment", candidates[0]["environment"])
    case.script("case plan", "case.py", "plan", "--case-dir", str(case.case_dir))
    case.collect_evidence()
    case.check_findings()
    return case


def run_pipeline(scenario: Path, tmp_path: Path, judge: FakeJudge) -> Path:
    """Run the whole code path on a scenario and return the case directory.

    The commands it ran, in the form the skill writes them, are logged under tmp_path (see load_log).
    """
    case = start_case(scenario, tmp_path)
    case.judge(judge, apply_labels=True)
    case.render(required=True)
    case.publish()
    return case.case_dir
