import os
import subprocess
import sys

import pytest

from conftest import ROOT

INSTALL = ROOT / "install.sh"


def stub(path, body):
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


@pytest.fixture
def sandbox(tmp_path):
    """A fake HOME and a PATH holding stub aws, python3, and kubectl commands."""
    home, bin_dir = tmp_path / "home", tmp_path / "bin"
    home.mkdir()
    bin_dir.mkdir()
    stub(bin_dir / "aws", 'echo "aws-cli/2.34.4 Python/3.13.11 Darwin/27.0.0"')
    stub(bin_dir / "python3", f'exec "{sys.executable}" "$@"')
    stub(bin_dir / "kubectl", "exit 0")
    return home, bin_dir


def install(sandbox, *args, skip_venv=True):
    home, bin_dir = sandbox
    env = {"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin"}
    if skip_venv:
        env["AI_TRIAGE_SKIP_VENV"] = "1"
    return subprocess.run(["bash", str(INSTALL), *args], capture_output=True, text=True, env=env)


def dest(sandbox):
    return sandbox[0] / ".claude" / "skills" / "ai-triage"


def test_help(sandbox):
    result = install(sandbox, "--help")
    assert result.returncode == 0 and result.stdout.startswith("Usage: install.sh")


def test_unknown_option_is_a_usage_error(sandbox):
    result = install(sandbox, "--force")
    assert result.returncode == 2 and "Unknown option: --force" in result.stderr


def test_dry_run_changes_nothing(sandbox):
    result = install(sandbox, "--dry-run", skip_venv=False)
    assert result.returncode == 0
    assert "[dry-run] Nothing was changed." in result.stdout
    assert "-m pip install" in result.stdout
    assert not (sandbox[0] / ".claude").exists()
    assert not (sandbox[0] / ".ai-triage").exists()


def test_fresh_install_creates_the_skill_and_config(sandbox):
    result = install(sandbox)
    assert result.returncode == 0, result.stderr
    target = dest(sandbox)
    assert (target / "SKILL.md").is_file()
    assert os.access(target / "scripts" / "guard_hook.sh", os.X_OK)
    assert (target / "scripts" / "triage" / "guard.py").is_file()
    for name in ("triage-config", "service-map"):
        example = (target / "config" / f"{name}.example.yaml").read_text()
        assert (target / "config" / f"{name}.yaml").read_text() == example
    assert "Next steps:" in result.stdout
    assert not list(target.rglob("__pycache__"))


def test_upgrade_keeps_config_and_backs_it_up(sandbox):
    assert install(sandbox).returncode == 0
    target = dest(sandbox)
    (target / "config" / "triage-config.yaml").write_text("mine: true\n")
    (target / "config" / "service-map.yaml").write_text("services: {}\n")
    (target / "config" / "kubeconfig").write_text("kind: Config\n")
    (target / "scripts" / "stale.py").write_text("# left over from an old version\n")

    result = install(sandbox)

    assert result.returncode == 0, result.stderr
    assert (target / "config" / "triage-config.yaml").read_text() == "mine: true\n"
    assert (target / "config" / "service-map.yaml").read_text() == "services: {}\n"
    assert (target / "config" / "kubeconfig").read_text() == "kind: Config\n"
    assert not (target / "scripts" / "stale.py").exists()
    assert "Kept your existing triage-config.yaml" in result.stdout
    backups = list((sandbox[0] / ".ai-triage" / "backups").iterdir())
    assert len(backups) == 1
    assert (backups[0] / "config" / "triage-config.yaml").read_text() == "mine: true\n"


def test_home_folder_with_a_space_in_its_name(sandbox, tmp_path):
    home = tmp_path / "First Last"
    home.mkdir()
    spaced = (home, sandbox[1])
    assert install(spaced).returncode == 0
    (dest(spaced) / "config" / "triage-config.yaml").write_text("mine: true\n")
    result = install(spaced)
    assert result.returncode == 0, result.stderr
    assert (dest(spaced) / "config" / "triage-config.yaml").read_text() == "mine: true\n"
    assert len(list((home / ".ai-triage" / "backups").iterdir())) == 1


def test_missing_aws_cli_is_a_prerequisite_error(sandbox):
    (sandbox[1] / "aws").unlink()
    result = install(sandbox)
    assert result.returncode == 3 and "the aws command was not found" in result.stderr
    assert not dest(sandbox).exists()


def test_old_aws_cli_is_a_prerequisite_error(sandbox):
    stub(sandbox[1] / "aws", 'echo "aws-cli/1.32.0 Python/3.11"')
    result = install(sandbox)
    assert result.returncode == 3 and "AWS CLI version 2 is required" in result.stderr


def test_old_python_is_a_prerequisite_error(sandbox):
    stub(sandbox[1] / "python3", "exit 1")
    result = install(sandbox)
    assert result.returncode == 3 and "Python 3.10 or newer is required" in result.stderr


def test_missing_kubectl_is_only_a_warning(sandbox):
    (sandbox[1] / "kubectl").unlink()
    result = install(sandbox)
    assert result.returncode == 0 and "Warning: kubectl was not found" in result.stdout
