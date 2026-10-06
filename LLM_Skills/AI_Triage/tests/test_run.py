"""run.py: the one entry point. It dispatches to triage/commands/<name>.py through the shared wrapper."""
import subprocess
import sys

import pytest

from conftest import SKILL_SRC
from triage import cli
from triage.commands import COMMANDS

SCRIPTS = SKILL_SRC / "scripts"
RUN = SCRIPTS / "run.py"


def run(*args):
    return subprocess.run([sys.executable, str(RUN), *map(str, args)], capture_output=True, text=True)


def test_the_commands_are_the_modules_of_the_commands_package():
    modules = {path.stem for path in (SCRIPTS / "triage" / "commands").glob("*.py")} - {"__init__", "common"}
    assert set(COMMANDS) == modules
    assert COMMANDS == ("case", "collect", "discover", "findings", "judge", "map_suggest", "opensearch_query",
                        "preflight", "publish", "report", "timeline", "validate_map", "verify_access")


def test_the_old_entry_scripts_are_gone():
    assert sorted(path.name for path in SCRIPTS.glob("*.py")) == ["guard_hook.py", "run.py"]


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_lists_every_command_and_ends_with_the_exit_code_table(flag):
    result = run(flag)
    assert result.returncode == 0, result.stderr
    listed = [line.split()[0] for line in result.stdout.split("commands:\n", 1)[1].split("\n\n", 1)[0].splitlines()]
    assert listed == list(COMMANDS)
    assert "  case  " in result.stdout and "Create a case folder for an incident" in result.stdout
    assert result.stdout.rstrip().endswith(cli.EXIT_CODES.rstrip())


@pytest.mark.parametrize("args, problem", [((), "no command given"), (("nosuch",), "unknown command nosuch"),
                                           (("case.py",), "unknown command case.py"),
                                           (("--skill-dir", "/tmp/x", "case"), "unknown command --skill-dir")])
def test_a_missing_or_unknown_command_is_a_usage_error(args, problem):
    result = run(*args)
    assert result.returncode == 2
    assert result.stdout == ""
    assert f"run.py: {problem}; one of: case, collect," in result.stderr


@pytest.mark.parametrize("name", COMMANDS)
def test_every_command_help_names_run_py_and_ends_with_the_exit_code_table(name):
    result = run(name, "--help")
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(f"usage: run.py {name} ")
    assert result.stdout.rstrip().endswith(cli.EXIT_CODES.rstrip())


def test_a_usage_error_inside_a_command_keeps_argparse_exit_2():
    result = run("case", "nosuch")
    assert result.returncode == 2
    assert result.stderr.startswith("usage: run.py case ")


def test_an_unexpected_error_names_the_command(tmp_path, monkeypatch, capsys):
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_entry", RUN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from triage.commands import timeline

    def broken(argv=None):
        raise RuntimeError("x")
    monkeypatch.setattr(timeline, "main", broken)
    monkeypatch.delenv("AI_TRIAGE_DEBUG", raising=False)
    assert module.main(["timeline", "--case-dir", str(tmp_path)]) == 1
    assert capsys.readouterr().err.strip() == "timeline: unexpected RuntimeError; run again with AI_TRIAGE_DEBUG=1 to see where"
