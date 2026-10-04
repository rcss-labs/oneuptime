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
    assert set(data) == {"discovery", "proposed_entry"}
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


def test_service_name_defaults_from_the_hostname(skill_dir, capsys):
    code, out, _ = run(skill_dir, capsys, FakeAws({**dns_answers(), **lb_answers()}))
    assert code == 0
    assert json.loads(out)["proposed_entry"]["environments"]["discovered"]["resources"] == {"load_balancer": "shop-alb"}
