"""The shared command-line wrapper: one exit-code table, one line per error, never a traceback.

The I4 rows of the final quality review are reproduced here through the real commands.
"""
import json
import os
import subprocess
import sys

import pytest
import yaml

from conftest import SKILL_SRC
from helpers import WINDOW_END, WINDOW_START
from triage import cli
from triage.case import CaseError
from triage.config import ConfigError
from triage.service_map import MapError

SCRIPTS = SKILL_SRC / "scripts"
INCIDENT = {
    "number": "INC-7",
    "title": "Checkout API is down",
    "declared_at": "2026-10-04T10:45:00Z",
    "impact_started_at": "2026-10-04T10:42:00Z",
    "monitors": [{"name": "Checkout API", "type": "API", "target": "https://checkout.example.com/health"}],
    "labels": ["checkout"],
}
NOT_UTF8 = b"cases_dir: /tmp/caf\xe9\n"


def script(name, *args, stdin=None, env=None):
    """Run a command of run.py, or guard_hook.py (the one other entry point)."""
    entry = [str(SCRIPTS / name)] if name == "guard_hook.py" else [str(SCRIPTS / "run.py"), name]
    return subprocess.run([sys.executable, *entry, *map(str, args)], capture_output=True,
                          input=stdin, env={**os.environ, **(env or {})})


def text(result):
    return result.stdout.decode() + result.stderr.decode()


@pytest.fixture
def skill_dir(tmp_path, config_data, map_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    (root / "config" / "service-map.yaml").write_text(yaml.safe_dump(map_data))
    return root


@pytest.fixture
def case_dir(skill_dir, tmp_path):
    incident = tmp_path / "incident.json"
    incident.write_text(json.dumps(INCIDENT))
    result = script("case", "init", "--incident", incident, "--now", "2026-10-04T11:00:00Z", "--skill-dir", skill_dir)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["case_dir"]


# the wrapper itself

def test_config_case_and_map_errors_exit_2_with_their_lines(capsys):
    for error in (ConfigError(["a: bad", "b: bad"]), CaseError(["c: bad"]), MapError(["d: bad"])):
        def main(argv=None, error=error):
            raise error
        assert cli.run(main, [], name="probe") == 2
        err = capsys.readouterr().err
        assert "Traceback" not in err and all(line in err for line in error.errors)


def test_an_os_error_exits_2_with_the_path_and_the_reason(capsys):
    def main(argv=None):
        raise PermissionError(13, "Permission denied", "/cases/inc/run/evidence/x.json")
    assert cli.run(main, [], name="probe") == 2
    assert capsys.readouterr().err.strip() == "/cases/inc/run/evidence/x.json: Permission denied"


def test_any_other_error_exits_1_with_one_line_and_no_traceback(capsys, monkeypatch):
    monkeypatch.delenv("AI_TRIAGE_DEBUG", raising=False)

    def main(argv=None):
        raise KeyError("incident_start")
    assert cli.run(main, [], name="judge") == 1
    err = capsys.readouterr().err
    assert len(err.strip().splitlines()) == 1
    assert "judge" in err and "KeyError" in err and "Traceback" not in err


def test_debug_shows_the_traceback(capsys, monkeypatch):
    monkeypatch.setenv("AI_TRIAGE_DEBUG", "1")

    def main(argv=None):
        raise AttributeError("x")
    assert cli.run(main, [], name="judge") == 1
    assert "Traceback" in capsys.readouterr().err


def test_usage_exits_pass_through():
    def main(argv=None):
        raise SystemExit(2)
    with pytest.raises(SystemExit):
        cli.run(main, [], name="probe")


def test_the_table_names_every_code_the_scripts_use():
    for code in range(7):
        assert f"  {code}  " in cli.EXIT_CODES


@pytest.mark.parametrize("name", ["case", "collect", "discover", "findings", "judge", "map_suggest",
                                  "opensearch_query", "preflight", "publish", "report", "timeline",
                                  "validate_map", "verify_access"])
def test_every_command_help_ends_with_the_exit_code_table(name):
    result = script(name, "--help")
    assert result.returncode == 0
    assert result.stdout.decode().rstrip().endswith(cli.EXIT_CODES.rstrip())


# I4 row 1: a config that is not UTF-8

def bad_config_runs(skill_dir, case_dir):
    config = skill_dir / "config" / "triage-config.yaml"
    window = ["--start", WINDOW_START, "--end", WINDOW_END]
    return [
        ("validate_map", ["--config", config]),
        ("verify_access", ["--config", config]),
        ("preflight", ["--skill-dir", skill_dir]),
        ("case", ["show", "--case-dir", case_dir, "--skill-dir", skill_dir]),
        ("collect", ["ecs", "--account", "prod-main", *window, "--target", "cluster=c", "--target", "service=s",
                        "--skill-dir", skill_dir]),
        ("judge", ["locate", "--case-dir", case_dir, "--skill-dir", skill_dir]),
        ("publish", ["audit", "--case-dir", case_dir, "--skill-dir", skill_dir]),
        ("map_suggest", ["propose", "--case-dir", case_dir, "--service-name", "checkout", "--skill-dir", skill_dir]),
        ("discover", ["--hostname", "checkout.example.com", "--skill-dir", skill_dir]),
        ("opensearch_query", ["health", "--cluster", "logs-prod", "--skill-dir", skill_dir]),
        ("findings", ["--skill-dir", skill_dir, "check", "--case-dir", case_dir]),
        ("timeline", ["--case-dir", case_dir, "--skill-dir", skill_dir]),
        ("report", ["validate", "--case-dir", case_dir, "--skill-dir", skill_dir]),
    ]


def test_a_config_that_is_not_utf8_exits_2_in_every_script(skill_dir, case_dir):
    (skill_dir / "config" / "triage-config.yaml").write_bytes(NOT_UTF8)
    for name, args in bad_config_runs(skill_dir, case_dir):
        result = script(name, *args)
        expected = 1 if name == "preflight" else 2  # preflight reports the config as a failed check
        assert result.returncode == expected, (name, text(result))
        assert "not UTF-8 text" in text(result), (name, text(result))
        assert "Traceback" not in text(result), name


# I4 row 2: a service map that is not UTF-8

def test_a_service_map_that_is_not_utf8_never_gives_a_traceback(skill_dir, case_dir, tmp_path):
    (skill_dir / "config" / "service-map.yaml").write_bytes(b"services:\n  caf\xe9: {}\n")
    incident = tmp_path / "incident2.json"
    incident.write_text(json.dumps(INCIDENT))
    runs = [
        ("validate_map", ["--config", skill_dir / "config" / "triage-config.yaml",
                             "--map", skill_dir / "config" / "service-map.yaml"], 1),
        ("case", ["target", "--case-dir", case_dir, "--service", "checkout", "--environment", "prod",
                     "--skill-dir", skill_dir], 2),
    ]
    for name, args, code in runs:
        result = script(name, *args)
        assert result.returncode == code, (name, text(result))
        assert "not UTF-8 text" in text(result) and "Traceback" not in text(result), name
    for name, args in (("preflight", ["--skill-dir", skill_dir]),
                       ("case", ["init", "--incident", incident, "--now", "2026-10-04T11:00:01Z", "--skill-dir", skill_dir])):
        result = script(name, *args)
        assert "Traceback" not in text(result), name
        assert result.returncode in (0, 1, 2), name


# I4 row 3: a case folder that cannot be written

@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores folder permissions")
def test_an_unwritable_findings_folder_exits_2_with_the_path(skill_dir, case_dir):
    findings = os.path.join(case_dir, "findings")
    os.makedirs(findings, exist_ok=True)
    with open(os.path.join(findings, "a.json"), "w") as handle:
        json.dump({"analyst": "a", "findings": []}, handle)
    os.chmod(findings, 0o500)
    try:
        result = script("findings", "--skill-dir", skill_dir, "check", "--case-dir", case_dir)
    finally:
        os.chmod(findings, 0o700)
    assert result.returncode == 2, text(result)
    assert "Permission denied" in text(result) and "Traceback" not in text(result)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores folder permissions")
def test_an_unwritable_evidence_folder_exits_2_in_collect(skill_dir, case_dir):
    evidence = os.path.join(case_dir, "evidence")
    os.makedirs(evidence, exist_ok=True)
    os.chmod(evidence, 0o500)
    fixtures = os.path.join(os.path.dirname(case_dir), "fixtures")
    os.makedirs(fixtures, exist_ok=True)
    with open(os.path.join(fixtures, "aws.json"), "w") as handle:
        json.dump([], handle)
    try:
        result = script("collect", "ecs", "--account", "prod-main", "--start", WINDOW_START, "--end", WINDOW_END,
                        "--target", "cluster=c", "--target", "service=s", "--case-dir", case_dir, "--skill-dir", skill_dir,
                        env={"AI_TRIAGE_FIXTURES": fixtures})
    finally:
        os.chmod(evidence, 0o700)
    assert result.returncode == 2, text(result)
    assert "Permission denied" in text(result) and "Traceback" not in text(result)


@pytest.mark.parametrize("subcommand", ["run", "adhoc"])
def test_judge_writes_that_fail_exit_2_with_the_path(capsys, tmp_path, subcommand):
    # judge run and judge adhoc fail in their summary writers (os.replace, write_text) with PermissionError;
    # the wrapper turns that into one line with the path, whatever function raised it.
    target = tmp_path / "judgments" / "summary.json"

    def main(argv=None):
        raise PermissionError(13, "Permission denied", str(target))
    assert cli.run(main, [subcommand], name="judge") == 2
    assert capsys.readouterr().err.strip() == f"{target}: Permission denied"


# I4 rows 4 and 5: case files with the wrong shape

@pytest.mark.parametrize("content", ["{}", '{"case_dir": 5, "publish": "x"}'])
@pytest.mark.parametrize("record", [["record-confluence", "--page-id", "1", "--url", "https://wiki.example.com/p/1"],
                                    ["record-slack", "--destination", "#incidents"]])
def test_a_case_json_of_the_wrong_shape_gives_one_line(skill_dir, case_dir, content, record):
    with open(os.path.join(case_dir, "case.json"), "w") as handle:
        handle.write(content)
    result = script("publish", record[0], "--case-dir", case_dir, *record[1:], "--skill-dir", skill_dir)
    assert result.returncode in (1, 2), text(result)
    assert "Traceback" not in text(result)
    assert len(result.stderr.decode().strip().splitlines()) == 1


@pytest.mark.parametrize("content", ["[]", '"x"', "5", "null"])
def test_an_incident_json_that_is_not_an_object_gives_one_line_in_judge_locate(skill_dir, case_dir, content):
    with open(os.path.join(case_dir, "incident.json"), "w") as handle:
        handle.write(content)
    result = script("judge", "locate", "--case-dir", case_dir, "--skill-dir", skill_dir)
    assert result.returncode in (1, 2), text(result)
    assert "Traceback" not in text(result)
    assert len(result.stderr.decode().strip().splitlines()) == 1


# I4 row 6: hook input that is not UTF-8

def test_hook_input_that_is_not_utf8_fails_closed_and_exits_0(skill_dir):
    payload = b'{"tool_name": "Bash", "tool_input": {"command": "aws s3 ls \xff"}}'
    result = script("guard_hook.py", stdin=payload, env={"AI_TRIAGE_SKILL_DIR": str(skill_dir), "AI_TRIAGE_TEST": "1"})
    assert result.returncode == 0, text(result)
    assert "deny" in result.stdout.decode()


# M6: exit codes that agree across scripts

def load_script(name):
    import importlib
    return importlib.import_module(f"triage.commands.{name}")


@pytest.mark.parametrize("statuses, expected", [
    ([("collected", 0), ("already collected", None), ("skipped", None)], 0),
    ([("collected", 0), ("failed", 1)], 1),
    ([("failed", 3), ("collected", 0)], 3),
    ([("failed", 3), ("failed", 1)], 3),
    ([("timed out", None), ("collected", 0)], 1),
    ([("not started", None)], 1),
])
def test_case_collect_exits_3_for_an_expired_sign_in_and_1_for_any_other_failure(skill_dir, case_dir, monkeypatch,
                                                                                capsys, statuses, expected):
    case_script = load_script("case")
    ran = []

    def fake_run(commands, case_dir):
        ran.append(True)
        return [{"name": f"c{n}", "status": status, "exit_code": code} for n, (status, code) in enumerate(statuses)]
    monkeypatch.setattr(case_script, "plan_collection", lambda *a, **k: [])
    monkeypatch.setattr(case_script, "run_collection", fake_run)
    assert case_script.main(["collect", "--case-dir", case_dir, "--skill-dir", str(skill_dir)]) == expected
    assert ran  # every planned command ran before the exit code was chosen


def test_timeline_prints_a_message_not_a_repr(skill_dir, case_dir, monkeypatch, capsys):
    timeline_script = load_script("timeline")

    def broken(case_dir):
        raise KeyError("incident_start")
    monkeypatch.setattr(timeline_script, "build_timeline", broken)
    assert timeline_script.main(["--case-dir", case_dir, "--skill-dir", str(skill_dir)]) == 2
    err = capsys.readouterr().err
    assert "KeyError(" not in err and "missing incident_start" in err
