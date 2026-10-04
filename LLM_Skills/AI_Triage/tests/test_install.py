import hashlib
import os
import subprocess
import sys

import pytest

from conftest import ROOT, SKILL_SRC

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


def run_with_env(sandbox, env_overrides, remove=(), *args):
    """Run install.sh with a hand-built environment, to test bad HOME values."""
    home, bin_dir = sandbox
    env = {"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin", "AI_TRIAGE_SKIP_VENV": "1"}
    env.update(env_overrides)
    for name in remove:
        env.pop(name, None)
    return subprocess.run(["bash", str(INSTALL), *args], capture_output=True, text=True, env=env)


def test_unset_home_is_refused(sandbox):
    result = run_with_env(sandbox, {}, remove=("HOME",))
    assert result.returncode == 1 and "HOME is not set to a directory" in result.stderr


def test_empty_home_is_refused(sandbox):
    result = run_with_env(sandbox, {"HOME": ""})
    assert result.returncode == 1 and "HOME is not set to a directory" in result.stderr


def test_home_that_is_a_file_is_refused(sandbox, tmp_path):
    not_a_directory = tmp_path / "a-file"
    not_a_directory.write_text("x")
    result = run_with_env(sandbox, {"HOME": str(not_a_directory)})
    assert result.returncode == 1 and "HOME is not set to a directory" in result.stderr


def source_fingerprint():
    return {
        str(path.relative_to(SKILL_SRC)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(SKILL_SRC.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    }


def assert_source_untouched(before):
    """Every file that existed before is still there, unchanged. New files from other work are ignored."""
    after = source_fingerprint()
    assert {name: after.get(name) for name in before} == before


LINK_ERROR = "the install folder points into the repository; remove the link and run again"


def test_destination_linked_to_the_source_is_refused_and_source_is_untouched(sandbox):
    skills = sandbox[0] / ".claude" / "skills"
    skills.mkdir(parents=True)
    (skills / "ai-triage").symlink_to(SKILL_SRC)
    before = source_fingerprint()

    result = install(sandbox)

    assert result.returncode == 1 and LINK_ERROR in result.stderr
    assert_source_untouched(before)
    assert not (sandbox[0] / ".ai-triage").exists()


def test_destination_inside_the_source_through_a_linked_parent_is_refused(sandbox):
    claude = sandbox[0] / ".claude"
    claude.mkdir()
    (claude / "skills").symlink_to(SKILL_SRC.parent)  # skill/, so the destination is skill/ai-triage
    before = source_fingerprint()

    result = install(sandbox)

    assert result.returncode == 1 and LINK_ERROR in result.stderr
    assert_source_untouched(before)


def test_dry_run_only_says_what_it_would_do(sandbox):
    fresh = install(sandbox, "--dry-run")
    assert fresh.returncode == 0
    assert "[dry-run] Would create triage-config.yaml from the example" in fresh.stdout
    assert "[dry-run] Would create service-map.yaml from the example" in fresh.stdout

    assert install(sandbox).returncode == 0
    upgrade = install(sandbox, "--dry-run")
    assert upgrade.returncode == 0
    assert "[dry-run] Would back up your config to " in upgrade.stdout
    assert "[dry-run] Would keep your existing triage-config.yaml" in upgrade.stdout

    for output in (fresh.stdout, upgrade.stdout):
        for line in output.splitlines():
            if line.startswith("[dry-run]"):
                assert line.startswith("[dry-run] Would ") or line == "[dry-run] Nothing was changed.", line
        for claim in ("Backed up", "Created ", "Kept "):
            assert claim not in output
    assert not (sandbox[0] / ".ai-triage").exists()


def test_two_installs_in_a_row_leave_distinct_backups(sandbox):
    assert install(sandbox).returncode == 0
    (dest(sandbox) / "config" / "triage-config.yaml").write_text("first: true\n")
    assert install(sandbox).returncode == 0
    (dest(sandbox) / "config" / "triage-config.yaml").write_text("second: true\n")
    assert install(sandbox).returncode == 0

    backups = sorted((sandbox[0] / ".ai-triage" / "backups").iterdir())
    assert len(backups) == 2
    assert {b.joinpath("config", "triage-config.yaml").read_text() for b in backups} == {"first: true\n", "second: true\n"}
    assert all(b.name.count("-") == 2 and b.name.rsplit("-", 1)[1].isdigit() for b in backups)


def test_a_linked_config_folder_is_backed_up_as_files(sandbox, tmp_path):
    assert install(sandbox).returncode == 0
    elsewhere = tmp_path / "shared-config"
    elsewhere.mkdir()
    (elsewhere / "triage-config.yaml").write_text("mine: true\n")
    (elsewhere / "service-map.yaml").write_text("services: {}\n")
    config = dest(sandbox) / "config"
    for child in config.iterdir():
        child.unlink()
    config.rmdir()
    config.symlink_to(elsewhere)

    result = install(sandbox)

    assert result.returncode == 0, result.stderr
    (backup,) = (sandbox[0] / ".ai-triage" / "backups").iterdir()
    saved = backup / "config"
    assert saved.is_dir() and not saved.is_symlink()
    assert (saved / "triage-config.yaml").read_text() == "mine: true\n"
    assert not (saved / "triage-config.yaml").is_symlink()


def test_links_inside_the_config_folder_are_backed_up_as_links(sandbox, tmp_path):
    assert install(sandbox).returncode == 0
    config = dest(sandbox) / "config"
    big = tmp_path / "big-folder"
    big.mkdir()
    (big / "huge.bin").write_text("x")
    (config / "kubeconfig").symlink_to("/nonexistent/kubeconfig-gone")
    (config / "loop").symlink_to("..")
    (config / "certs").symlink_to(big)

    result = install(sandbox)

    assert result.returncode == 0, result.stderr
    (backup,) = (sandbox[0] / ".ai-triage" / "backups").iterdir()
    for name in ("kubeconfig", "loop", "certs"):
        assert (backup / "config" / name).is_symlink()
    assert (backup / "config" / "certs").readlink() == big


def test_failed_config_backup_stops_before_anything_is_replaced(sandbox):
    assert install(sandbox).returncode == 0
    target = dest(sandbox)
    (target / "scripts" / "stale.py").write_text("# old\n")
    secret = target / "config" / "triage-config.yaml"
    secret.chmod(0o000)
    try:
        result = install(sandbox)
    finally:
        secret.chmod(0o644)

    assert result.returncode == 1
    assert f"could not back up your config folder: {target / 'config'}" in result.stderr
    assert (target / "scripts" / "stale.py").exists()
