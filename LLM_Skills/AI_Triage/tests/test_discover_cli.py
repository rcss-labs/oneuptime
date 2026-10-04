import json

import pytest
import yaml

import discover
from fakes import SSO_EXPIRED_ERROR, FakeAws
from test_discover import HOSTNAME, dns_answers, full_walk, lb_answers


@pytest.fixture
def skill_dir(tmp_path, config_data):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return tmp_path


def run(skill_dir, capsys, runner, *extra, hostname=HOSTNAME):
    code = discover.main(["--hostname", hostname, "--skill-dir", str(skill_dir), *extra], runner=runner)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_found_prints_discovery_and_proposed_entry(skill_dir, capsys):
    code, out, _ = run(skill_dir, capsys, FakeAws(full_walk()), "--service-name", "shop", "--monitor", "Shop API")
    data = json.loads(out)
    assert code == 0
    assert set(data) == {"discovery", "service_name", "proposed_entry", "validation"}
    assert data["discovery"]["resources"]["ecs_service"] == "shop/shop-api"
    assert data["proposed_entry"]["match"] == {"hostnames": [HOSTNAME], "monitors": ["Shop API"]}
    assert data["proposed_entry"]["source"] == "discovered"


def test_account_option_limits_the_search(skill_dir, capsys):
    code, out, _ = run(skill_dir, capsys, FakeAws(full_walk()), "--account", "staging")
    assert code == 0
    assert json.loads(out)["discovery"]["account"] == "staging"


def test_nothing_found_exits_1(skill_dir, capsys):
    code, out, _ = run(skill_dir, capsys, FakeAws({}))
    data = json.loads(out)
    assert code == 1
    assert data["discovery"]["resources"] == {}
    assert data["proposed_entry"] is None


def test_unknown_account_exits_2(skill_dir, capsys):
    code, _, err = run(skill_dir, capsys, FakeAws({}), "--account", "nope")
    assert code == 2
    assert "nope" in err


def test_missing_config_exits_2(tmp_path, capsys):
    code, _, err = run(tmp_path, capsys, FakeAws({}))
    assert code == 2
    assert "not found" in err


def test_missing_hostname_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exit_info:
        discover.main([])
    assert exit_info.value.code == 2


def test_expired_sign_in_exits_3(skill_dir, capsys):
    code, _, err = run(skill_dir, capsys, FakeAws({"route53 list-hosted-zones": SSO_EXPIRED_ERROR}))
    assert code == 3
    assert "aws sso login --profile triage-prod-main" in err


def test_proposed_entry_for_a_load_balancer_only(skill_dir, capsys):
    code, out, _ = run(skill_dir, capsys, FakeAws({**dns_answers(), **lb_answers()}))
    assert code == 0
    assert json.loads(out)["proposed_entry"]["environments"]["discovered"]["resources"] == {"load_balancer": "shop-alb"}


# replay mode

def real_call_fails(*args, **kwargs):
    raise AssertionError("a real subprocess was started in replay mode")


def test_replay_mode_discovers_from_fixtures_and_prints_the_banner_once(skill_dir, tmp_path, monkeypatch, capsys):
    replay = tmp_path / "replay"
    replay.mkdir()
    entries = [{"match": key.split(), "result": value} for key, value in full_walk().items()]
    (replay / "aws.json").write_text(json.dumps(entries))
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(replay))
    monkeypatch.setattr("subprocess.run", real_call_fails)
    code = discover.main(["--hostname", HOSTNAME, "--skill-dir", str(skill_dir)])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["discovery"]["resources"]["ecs_service"] == "shop/shop-api"
    assert captured.err.count("REPLAY MODE") == 1
    assert f"REPLAY MODE: answers come from {replay}; nothing is called." in captured.err


def test_an_injected_runner_wins_over_the_environment(skill_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(tmp_path))
    code, out, err = run(skill_dir, capsys, FakeAws(full_walk()))
    assert code == 0
    assert "REPLAY MODE" not in err


def test_a_bad_fixture_directory_exits_2(skill_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(tmp_path / "nowhere"))
    monkeypatch.setattr("subprocess.run", real_call_fails)
    assert discover.main(["--hostname", HOSTNAME, "--skill-dir", str(skill_dir)]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_service_name_reaches_the_output_and_validation_is_empty(skill_dir, capsys):
    code, out, _ = run(skill_dir, capsys, FakeAws({**dns_answers(), **lb_answers()}), "--service-name", "shop")
    data = json.loads(out)
    assert data["service_name"] == "shop"
    assert data["validation"] == []


def test_service_name_is_null_when_not_given(skill_dir, capsys):
    _, out, _ = run(skill_dir, capsys, FakeAws({**dns_answers(), **lb_answers()}))
    assert json.loads(out)["service_name"] is None


def test_validation_reports_the_missing_index_pattern(skill_dir, capsys):
    code, out, _ = run(skill_dir, capsys, FakeAws(full_walk()), "--service-name", "shop")
    data = json.loads(out)
    assert code == 0
    assert data["proposed_entry"]["environments"]["discovered"]["resources"]["opensearch"] == {"cluster": "logs-prod"}
    assert any("services.shop" in problem and "index_pattern" in problem for problem in data["validation"])


def test_nothing_found_has_empty_validation(skill_dir, capsys):
    _, out, _ = run(skill_dir, capsys, FakeAws({}), "--service-name", "shop")
    data = json.loads(out)
    assert data["validation"] == [] and data["proposed_entry"] is None and data["service_name"] == "shop"
