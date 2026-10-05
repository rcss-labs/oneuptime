import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import EXAMPLE_CONFIG, EXAMPLE_MAP, SKILL_SRC
from fakes import SSO_EXPIRED_ERROR, FakeAws
from triage.preflight import FAIL, OK, SIGN_IN, WARN, exit_code, render_text, run_preflight

# What Claude Code's own snapshot holds today: two options, plain aliases, and its grep function.
CLEAN_SNAPSHOT = """# Snapshot file
unalias -a 2>/dev/null || true
nvm () {
\tsetopt localoptions shwordsplit
\tIFS=: read -A parts
}
setopt nohashdirs
setopt login
alias -- ..='cd ..'
alias -- cp='cp -i'
unalias grep 2>/dev/null || true
function grep {
  command grep "$@"
}
export PATH=/usr/bin:/bin
"""
ROLE = "AWSReservedSSO_ai-triage-read-only_0123456789abcdef"


def identity(account_id):
    return {"Account": account_id, "Arn": f"arn:aws:sts::{account_id}:assumed-role/{ROLE}/engineer@example.com"}


@pytest.fixture
def skill_dir(tmp_path):
    """A skill folder as the installer leaves it, with cases kept inside tmp_path."""
    config_dir = tmp_path / "skill" / "config"
    config_dir.mkdir(parents=True)
    data = yaml.safe_load(EXAMPLE_CONFIG.read_text())
    data["cases_dir"] = str(tmp_path / "cases")
    (config_dir / "triage-config.yaml").write_text(yaml.safe_dump(data))
    shutil.copy(EXAMPLE_MAP, config_dir / "service-map.yaml")
    (config_dir / "kubeconfig").write_text("apiVersion: v1\nkind: Config\n")
    snapshots = tmp_path / "shell-snapshots"
    snapshots.mkdir()
    (snapshots / "snapshot-zsh-1-clean.sh").write_text(CLEAN_SNAPSHOT)
    return tmp_path / "skill"


def signed_in():
    return FakeAws(
        {
            "triage-prod-main sts get-caller-identity": identity("111111111111"),
            "triage-staging sts get-caller-identity": identity("222222222222"),
        }
    )


def run(skill_dir, accounts=(), runner=None, env=None, missing=(), snapshots_dir=None):
    return run_preflight(
        skill_dir,
        accounts,
        runner=runner or signed_in(),
        env={"TYPESAFE_API_KEY": "set"} if env is None else env,
        which=lambda name: None if name in missing else f"/usr/bin/{name}",
        snapshots_dir=snapshots_dir or skill_dir.parent / "shell-snapshots",
    )


def by_name(checks):
    return {check.name: check for check in checks}


def test_everything_ready(skill_dir, tmp_path):
    checks = run(skill_dir)
    assert {check.status for check in checks} == {OK}
    assert exit_code(checks) == 0
    assert (tmp_path / "cases").is_dir()
    assert by_name(checks)["Config"].detail == "2 accounts"
    assert by_name(checks)["Service map"].detail == "2 services"


def test_missing_config_stops_early(tmp_path):
    checks = run(tmp_path)
    assert [check.name for check in checks] == ["Config"]
    assert checks[0].status == FAIL and exit_code(checks) == 1


def test_invalid_map_fails_but_other_checks_still_run(skill_dir):
    (skill_dir / "config" / "service-map.yaml").write_text("services:\n  a:\n    environments: {}\n")
    checks = by_name(run(skill_dir))
    assert checks["Service map"].status == FAIL
    assert checks["Sign-in: prod-main"].status == OK


def test_expired_sign_in_gives_the_login_command(skill_dir):
    runner = signed_in()
    runner.answers["triage-staging sts get-caller-identity"] = SSO_EXPIRED_ERROR
    checks = run(skill_dir, runner=runner)
    staging = by_name(checks)["Sign-in: staging"]
    assert staging.status == SIGN_IN
    assert staging.fix == "aws sso login --profile triage-staging"
    assert exit_code(checks) == 3


def test_wrong_account_is_a_failure(skill_dir):
    runner = signed_in()
    runner.answers["triage-staging sts get-caller-identity"] = identity("111111111111")
    checks = run(skill_dir, runner=runner)
    assert by_name(checks)["Sign-in: staging"].status == FAIL and exit_code(checks) == 1


def test_only_named_accounts_are_signed_in_checked(skill_dir):
    runner = signed_in()
    checks = by_name(run(skill_dir, ["prod-main"], runner=runner))
    assert "Sign-in: prod-main" in checks and "Sign-in: staging" not in checks
    assert all("triage-prod-main" in argv for argv in runner.calls)


def test_unknown_account_fails(skill_dir):
    checks = run(skill_dir, ["nope"])
    assert by_name(checks)["Accounts"].status == FAIL


def test_missing_aws_cli_fails_without_calling_it(skill_dir):
    runner = signed_in()
    checks = by_name(run(skill_dir, runner=runner, missing=("aws",)))
    assert checks["AWS CLI"].status == FAIL and runner.calls == []


def test_missing_kubectl_or_kubeconfig_fails_when_clusters_are_configured(skill_dir):
    assert by_name(run(skill_dir, missing=("kubectl",)))["kubectl"].status == FAIL
    (skill_dir / "config" / "kubeconfig").unlink()
    assert "kubeconfig does not exist" in by_name(run(skill_dir))["kubectl"].detail


def test_kubectl_is_not_checked_without_clusters(skill_dir):
    path = skill_dir / "config" / "triage-config.yaml"
    data = yaml.safe_load(path.read_text())
    data.pop("eks_clusters")
    path.write_text(yaml.safe_dump(data))
    (skill_dir / "config" / "service-map.yaml").write_text("services: {}\n")
    assert "kubectl" not in by_name(run(skill_dir, missing=("kubectl",)))


def test_missing_typesafe_key_is_a_warning_not_a_failure(skill_dir):
    checks = run(skill_dir, env={})
    assert by_name(checks)["TypeSafe key"].status == WARN
    assert exit_code(checks) == 0


def test_unwritable_cases_folder_fails(skill_dir, tmp_path):
    (tmp_path / "cases").write_text("a file where the folder should be")
    assert by_name(run(skill_dir))["Cases folder"].status == FAIL


def test_text_output_shows_fixes_only_for_problems(skill_dir):
    runner = signed_in()
    runner.answers["triage-staging sts get-caller-identity"] = SSO_EXPIRED_ERROR
    text = render_text(run(skill_dir, runner=runner))
    assert "[sign-in] Sign-in: staging" in text
    assert "fix: aws sso login --profile triage-staging" in text
    assert text.count("fix:") == 1


def test_cli_reports_a_missing_config_as_json(tmp_path):
    script = SKILL_SRC / "scripts" / "preflight.py"
    result = subprocess.run(
        [sys.executable, str(script), "--json", "--skill-dir", str(tmp_path)], capture_output=True, text=True
    )
    assert result.returncode == 1
    body = json.loads(result.stdout)
    assert body["exit_code"] == 1 and body["checks"][0]["name"] == "Config"


# replay mode

def test_preflight_command_in_replay_mode_uses_fixtures_and_treats_tools_as_present(skill_dir, tmp_path, monkeypatch, capsys):
    import preflight

    replay = tmp_path / "replay"
    replay.mkdir()
    (replay / "aws.json").write_text(json.dumps([
        {"match": ["sts", "get-caller-identity"], "contains": ["triage-prod-main"], "result": identity("111111111111")},
        {"match": ["sts", "get-caller-identity"], "contains": ["triage-staging"], "result": identity("222222222222")},
    ]))
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(replay))
    monkeypatch.setenv("TYPESAFE_API_KEY", "set")
    monkeypatch.setattr("shutil.which", lambda name: None)

    def real_call_fails(*args, **kwargs):
        raise AssertionError("a real subprocess was started in replay mode")

    monkeypatch.setattr("subprocess.run", real_call_fails)
    code = preflight.main(["--json", "--skill-dir", str(skill_dir)])
    captured = capsys.readouterr()
    checks = {check["name"]: check for check in json.loads(captured.out)["checks"]}
    assert code == 0
    assert checks["AWS CLI"]["status"] == OK
    assert checks["kubectl"]["status"] == "skipped"
    assert "replay" in checks["kubectl"]["detail"]
    assert checks["Sign-in: prod-main"]["status"] == OK
    assert captured.err.count("REPLAY MODE") == 1
    assert f"REPLAY MODE: answers come from {replay}; nothing is called." in captured.err


def test_preflight_command_with_a_bad_fixture_directory_exits_2(skill_dir, tmp_path, monkeypatch, capsys):
    import preflight

    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(tmp_path / "nowhere"))
    assert preflight.main(["--skill-dir", str(skill_dir)]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_replay_skips_the_kubeconfig_check_even_when_the_file_is_missing(skill_dir):
    (skill_dir / "config" / "kubeconfig").unlink()
    checks = run_preflight(skill_dir, runner=signed_in(), env={"TYPESAFE_API_KEY": "set"},
                           which=lambda name: f"replay/{name}", replay=True)
    assert by_name(checks)["kubectl"].status == "skipped"
    assert exit_code(checks) == 0



# ---- fix round 5, ruling 3: the shell environment ------------------------------

SHELL = "Shell environment"


def shell_check(skill_dir, extra, name="snapshot-zsh-2-newer.sh"):
    snapshots = skill_dir.parent / "shell-snapshots"
    newest = snapshots / name
    newest.write_text(CLEAN_SNAPSHOT + extra)
    os.utime(newest, (2_000_000_000, 2_000_000_000))
    return by_name(run(skill_dir))[SHELL]


def test_a_clean_snapshot_passes_and_grep_is_expected(skill_dir):
    check = by_name(run(skill_dir))[SHELL]
    assert check.status == OK


@pytest.mark.parametrize(
    "extra, named",
    [
        ("aws () {\n\techo hi\n}\n", "aws"),
        ("function kubectl {\n  echo hi\n}\n", "kubectl"),
        ("function jq() {\n  echo hi\n}\n", "jq"),
        ("alias -- head='head -n 1'\n", "head"),
        ("alias tail='tail -f'\n", "tail"),
        ("alias -g -- wc='rm'\n", "wc"),
        ("alias -g pods=delete\n", "pods"),
        ("setopt magicequalsubst\n", "magicequalsubst"),
        ("setopt MAGIC_EQUAL_SUBST\n", "magicequalsubst"),
        ("setopt rc_quotes\n", "rcquotes"),
        ("setopt cshjunkiequotes\n", "cshjunkiequotes"),
        ("setopt shwordsplit\n", "shwordsplit"),
        ("setopt globsubst\n", "globsubst"),
        ("setopt ksharrays\n", "ksharrays"),
        ("setopt ignorebraces\n", "ignorebraces"),
        ("setopt nohashdirs globsubst\n", "globsubst"),
        ("\tsetopt globsubst\n", "globsubst"),  # an indented top-level line still applies
        ("IFS=/\n", "IFS"),
        ("export IFS=:\n", "IFS"),
        ("typeset -g IFS=:\n", "IFS"),
    ],
)
def test_a_shadowing_definition_option_or_ifs_fails(skill_dir, extra, named):
    check = shell_check(skill_dir, extra)
    assert check.status == FAIL
    assert named in check.detail
    assert check.fix


def test_a_function_on_the_skill_python_fails(skill_dir):
    python = skill_dir / ".venv" / "bin" / "python"
    check = shell_check(skill_dir, f"function {python} {{\n  echo hi\n}}\n")
    assert check.status == FAIL and str(python) in check.detail


@pytest.mark.parametrize(
    "extra",
    ["setopt nomagicequalsubst\n", "unsetopt shwordsplit\n", "alias -- grepx=grep\n", "function rg {\n  rg\n}\n",
     "f () {\n\tsetopt globsubst\n\tIFS=:\n}\n", "# setopt globsubst\n"],
)
def test_harmless_lines_do_not_fail(skill_dir, extra):
    assert shell_check(skill_dir, extra).status == OK


def test_only_the_newest_snapshot_counts(skill_dir):
    snapshots = skill_dir.parent / "shell-snapshots"
    old = snapshots / "snapshot-zsh-0-old.sh"
    old.write_text(CLEAN_SNAPSHOT + "function aws {\n  echo\n}\n")
    os.utime(old, (1_000_000, 1_000_000))
    assert by_name(run(skill_dir))[SHELL].status == OK
    assert shell_check(skill_dir, "function aws {\n  echo\n}\n").status == FAIL


def test_without_a_snapshot_folder_the_shell_is_not_checked(skill_dir, tmp_path):
    check = by_name(run(skill_dir, snapshots_dir=tmp_path / "missing"))[SHELL]
    assert check.status == "skipped" and "not checked" in check.detail
    empty = tmp_path / "empty"
    empty.mkdir()
    assert by_name(run(skill_dir, snapshots_dir=empty))[SHELL].status == "skipped"


def test_replay_mode_skips_the_shell_check(skill_dir):
    shell_check(skill_dir, "function aws {\n  echo\n}\n")
    checks = run_preflight(skill_dir, runner=signed_in(), env={"TYPESAFE_API_KEY": "set"},
                           which=lambda name: f"replay/{name}", replay=True,
                           snapshots_dir=skill_dir.parent / "shell-snapshots")
    assert by_name(checks)[SHELL].status == "skipped"


def test_the_default_snapshot_folder_is_under_home(skill_dir, tmp_path):
    home = tmp_path / "home"
    (home / ".claude" / "shell-snapshots").mkdir(parents=True)
    (home / ".claude" / "shell-snapshots" / "snapshot-zsh-9.sh").write_text("setopt globsubst\n")
    checks = run_preflight(skill_dir, runner=signed_in(), env={"TYPESAFE_API_KEY": "set", "HOME": str(home)},
                           which=lambda name: f"/usr/bin/{name}")
    assert by_name(checks)[SHELL].status == FAIL


# ---- round 5 minor follow-up, N2: more snapshot spellings ------------------------


@pytest.mark.parametrize(
    "extra, named",
    [
        ("jq() { echo hi; }\n", "jq"),
        ("aws () { echo hi; }\n", "aws"),
        ("function kubectl { echo hi; }\n", "kubectl"),
        ("function sort() { echo; }\n", "sort"),
        ("  head () {\n    echo\n  }\n", "head"),
        ("function sort uniq {\n  echo\n}\n", "uniq"),
        ("alias -- 'wc'='rm'\n", "wc"),
        ('alias "tail=tail -f"\n', "tail"),
        ("alias 'cut'=x\n", "cut"),
        ("unsetopt norcquotes\n", "rcquotes"),
        ("setopt nonomagicequalsubst\n", "magicequalsubst"),
        ("set -o globsubst\n", "globsubst"),
        ("set -o KSH_ARRAYS\n", "ksharrays"),
        ("set -y\n", "shwordsplit"),
        ("set -ey\n", "shwordsplit"),
        ("emulate sh\n", "emulate sh"),
        ("emulate -R ksh\n", "emulate ksh"),
        ("options[shwordsplit]=on\n", "shwordsplit"),
        ("options[GLOB_SUBST]=on\n", "globsubst"),
        ("aliases[jq]='rm'\n", "jq"),
        ("galiases[pods]=delete\n", "pods"),
        ("functions[aws]='echo'\n", "aws"),
    ],
)
def test_other_spellings_of_shadows_and_options_fail(skill_dir, extra, named):
    check = shell_check(skill_dir, extra)
    assert check.status == FAIL, extra
    assert named in check.detail


@pytest.mark.parametrize(
    "extra",
    ["unsetopt shwordsplit\n", "set +o globsubst\n", "set -e\n", "options[shwordsplit]=off\n", "emulate zsh\n",
     "setopt nonomatch\n", "rg() { command rg; }\n", "alias 'gs'='git status'\n", "set -o vi\n"],
)
def test_other_harmless_spellings_pass(skill_dir, extra):
    assert shell_check(skill_dir, extra).status == OK, extra
