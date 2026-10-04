import json
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import EXAMPLE_CONFIG, EXAMPLE_MAP, SKILL_SRC
from fakes import SSO_EXPIRED_ERROR, FakeAws
from triage.preflight import FAIL, OK, SIGN_IN, WARN, exit_code, render_text, run_preflight

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
    return tmp_path / "skill"


def signed_in():
    return FakeAws(
        {
            "triage-prod-main sts get-caller-identity": identity("111111111111"),
            "triage-staging sts get-caller-identity": identity("222222222222"),
        }
    )


def run(skill_dir, accounts=(), runner=None, env=None, missing=()):
    return run_preflight(
        skill_dir,
        accounts,
        runner=runner or signed_in(),
        env={"TYPESAFE_API_KEY": "set"} if env is None else env,
        which=lambda name: None if name in missing else f"/usr/bin/{name}",
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
