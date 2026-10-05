import subprocess
import sys

from conftest import EXAMPLE_CONFIG, EXAMPLE_MAP, SKILL_SRC

SCRIPT = SKILL_SRC / "scripts" / "validate_map.py"


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_valid_files_exit_zero():
    result = run("--config", str(EXAMPLE_CONFIG), "--map", str(EXAMPLE_MAP))
    assert result.returncode == 0
    assert "OK: 2 accounts, 2 services" in result.stdout


def test_invalid_map_exits_one_and_lists_errors(tmp_path):
    bad = tmp_path / "service-map.yaml"
    bad.write_text("services:\n  a:\n    environments: {}\n")
    result = run("--config", str(EXAMPLE_CONFIG), "--map", str(bad))
    assert result.returncode == 1
    assert "Service map is invalid:" in result.stderr
    assert "at least one environment is required" in result.stderr


def test_missing_config_exits_two_like_the_other_scripts(tmp_path):
    result = run("--config", str(tmp_path / "none.yaml"), "--map", str(EXAMPLE_MAP))
    assert result.returncode == 2
    assert "Config is invalid:" in result.stderr


def test_unknown_flag_exits_two():
    assert run("--nope").returncode == 2
