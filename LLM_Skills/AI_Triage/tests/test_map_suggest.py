import json
from datetime import date, datetime, timezone

import pytest
import yaml

from triage.case import create_case, load_case, parse_incident, set_target_from_discovery, set_target_from_map
from triage.config import parse_config
from triage.map_suggest import SuggestError, apply, entry_yaml, propose, proposed_entry
from triage.service_map import load_map, parse_map

TODAY = date(2026, 10, 4)
NOW = datetime(2026, 10, 4, 11, 0, 0, tzinfo=timezone.utc)
INCIDENT = {
    "number": "INC-9",
    "title": "Orders API is down",
    "declared_at": "2026-10-04T10:45:00Z",
    "monitors": [{"name": "Orders API", "type": "API", "target": "https://orders.example.com/health"}],
    "hostnames": ["orders.example.com"],
}
DISCOVERY = {
    "account": "prod-main",
    "region": "eu-west-1",
    "resources": {"ecs_service": "orders/orders-api", "log_groups": ["/ecs/orders-api"]},
}
COMMENTED_MAP = """# My services. Keep this comment.
services:
  # the first one
  alpha:
    match:
      monitors: ["Alpha"]
    environments:
      prod:
        account: prod-main
        region: eu-west-1
        resources:
          ecs_service: alpha/alpha   # trailing note
    source: confirmed
    last_verified: 2026-10-04
"""


@pytest.fixture
def config(config_data, tmp_path):
    config_data["cases_dir"] = str(tmp_path / "cases")
    return parse_config(config_data)


@pytest.fixture
def skill_dir(tmp_path):
    root = tmp_path / "skill"
    root.mkdir()
    return root


def make_case(config, skill_dir, discovery=DISCOVERY):
    case_dir = create_case(parse_incident(INCIDENT), config, parse_map({"services": {}}, config), NOW, skill_dir)
    if discovery is not None:
        set_target_from_discovery(case_dir, config, discovery)
    return case_dir


def write_map(tmp_path, text):
    path = tmp_path / "service-map.yaml"
    path.write_bytes(text.encode())
    return path


def run_apply(case_dir, config, path, name="orders-api", environment="prod"):
    return apply(case_dir, config, path, name, environment, TODAY, NOW)


# proposed_entry and entry_yaml

def test_proposed_entry_for_a_full_discovered_target(config, skill_dir):
    case = load_case(make_case(config, skill_dir))
    case["target"]["depends_on"] = ["alpha"]
    case["incident"]["monitors"] = INCIDENT["monitors"]  # case.json keeps no monitors; propose adds them from incident.json
    entry = proposed_entry(case, "orders-api", "prod", TODAY)
    assert entry == {
        "match": {"monitors": ["Orders API"], "hostnames": ["orders.example.com"]},
        "environments": {"prod": {"account": "prod-main", "region": "eu-west-1",
                                  "resources": DISCOVERY["resources"], "depends_on": ["alpha"]}},
        "source": "discovered",
        "last_verified": "2026-10-04",
    }
    assert list(entry) == ["match", "environments", "source", "last_verified"]


def test_proposed_entry_leaves_out_empty_depends_on(config, skill_dir):
    case = load_case(make_case(config, skill_dir))
    environment = proposed_entry(case, "orders-api", "prod", TODAY)["environments"]["prod"]
    assert "depends_on" not in environment


def test_proposed_entry_refuses_a_map_sourced_case(config, skill_dir, config_data):
    service_map = parse_map({"services": {"alpha": yaml.safe_load(COMMENTED_MAP)["services"]["alpha"]}}, config)
    case_dir = make_case(config, skill_dir, discovery=None)
    set_target_from_map(case_dir, service_map, config, "alpha", "prod")
    with pytest.raises(SuggestError, match="this run used the service map; there is nothing to add"):
        proposed_entry(load_case(case_dir), "orders-api", "prod", TODAY)


def test_proposed_entry_refuses_a_case_without_a_target(config, skill_dir):
    case_dir = make_case(config, skill_dir, discovery=None)
    with pytest.raises(SuggestError, match="nothing to add"):
        proposed_entry(load_case(case_dir), "orders-api", "prod", TODAY)


def test_entry_yaml_is_indented_ordered_and_round_trips(config, skill_dir):
    entry = proposed_entry(load_case(make_case(config, skill_dir)), "orders-api", "staging", TODAY)
    block = entry_yaml("orders-api", entry)
    lines = block.splitlines()
    assert lines[0] == "  orders-api:"
    assert all(line.startswith("    ") for line in lines[1:])
    keys = [line.strip().split(":")[0] for line in lines if line.startswith("    ") and not line.startswith("     ")]
    assert keys == ["match", "environments", "source", "last_verified"]
    assert block.endswith("\n")
    assert yaml.safe_load("services:\n" + block) == {"services": {"orders-api": entry}}


# propose

def test_propose_returns_the_block_for_a_valid_suggestion(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    result = propose(make_case(config, skill_dir), config, path, "orders-api", "prod", TODAY)
    assert result["service_name"] == "orders-api" and result["valid"] is True
    assert result["yaml"].startswith("  orders-api:\n")
    assert path.read_bytes() == COMMENTED_MAP.encode()


def test_propose_refuses_a_map_sourced_case(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    case_dir = make_case(config, skill_dir, discovery=None)
    service_map = load_map(path, config)
    set_target_from_map(case_dir, service_map, config, "alpha", "prod")
    with pytest.raises(SuggestError, match="nothing to add"):
        propose(case_dir, config, path, "orders-api", "prod", TODAY)


def test_propose_refuses_an_existing_service_name(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    with pytest.raises(SuggestError, match="alpha.*edit the entry by hand"):
        propose(make_case(config, skill_dir), config, path, "alpha", "prod", TODAY)


def test_propose_reports_map_errors_for_an_invalid_result(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    discovery = {**DISCOVERY, "resources": {"not_a_resource": "x"}}
    with pytest.raises(SuggestError, match="not_a_resource"):
        propose(make_case(config, skill_dir, discovery), config, path, "orders-api", "prod", TODAY)


def test_propose_without_any_match_keys_is_invalid(config, skill_dir, tmp_path):
    incident = {"number": "INC-10", "title": "T", "declared_at": "2026-10-04T10:45:00Z"}
    case_dir = create_case(parse_incident(incident), config, parse_map({"services": {}}, config), NOW, skill_dir)
    set_target_from_discovery(case_dir, config, DISCOVERY)
    with pytest.raises(SuggestError, match="match"):
        propose(case_dir, config, write_map(tmp_path, COMMENTED_MAP), "orders-api", "prod", TODAY)


def test_propose_asks_for_the_index_pattern_when_opensearch_has_only_a_cluster(config, skill_dir, tmp_path):
    discovery = {**DISCOVERY, "resources": {"opensearch": {"cluster": "logs-prod"}}}
    case_dir = make_case(config, skill_dir, discovery)
    with pytest.raises(SuggestError) as caught:
        propose(case_dir, config, write_map(tmp_path, COMMENTED_MAP), "orders-api", "prod", TODAY)
    message = str(caught.value)
    assert "index pattern" in message and "by hand" in message
    assert "  orders-api:" in message and "cluster: logs-prod" in message


def test_propose_refuses_an_unsafe_service_name(config, skill_dir, tmp_path):
    with pytest.raises(SuggestError, match="service name"):
        propose(make_case(config, skill_dir), config, write_map(tmp_path, COMMENTED_MAP), "Bad: name", "prod", TODAY)


def test_propose_refuses_a_map_that_is_not_valid_yet(config, skill_dir, tmp_path):
    path = write_map(tmp_path, "services:\n  broken: 3\n")
    with pytest.raises(SuggestError, match="broken"):
        propose(make_case(config, skill_dir), config, path, "orders-api", "prod", TODAY)


# apply

def test_apply_appends_to_a_populated_map_and_keeps_it_byte_for_byte(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    case_dir = make_case(config, skill_dir)
    backup = run_apply(case_dir, config, path)
    new = path.read_bytes()
    assert new.startswith(COMMENTED_MAP.encode())
    assert b"  orders-api:\n" in new[len(COMMENTED_MAP):]
    loaded = load_map(path, config)
    assert set(loaded.services) == {"alpha", "orders-api"}
    assert loaded.services["orders-api"].source == "discovered"
    assert backup.name == "service-map.yaml.bak-20261004-110000"
    assert backup.parent == path.parent and backup.read_bytes() == COMMENTED_MAP.encode()


def test_apply_adds_a_newline_when_the_file_has_none(config, skill_dir, tmp_path):
    original = COMMENTED_MAP.rstrip("\n")
    path = write_map(tmp_path, original)
    run_apply(make_case(config, skill_dir), config, path)
    assert path.read_bytes().startswith(original.encode() + b"\n  orders-api:")
    assert "orders-api" in load_map(path, config).services


def test_apply_to_an_empty_file(config, skill_dir, tmp_path):
    path = write_map(tmp_path, "")
    backup = run_apply(make_case(config, skill_dir), config, path)
    assert path.read_text().startswith("services:\n  orders-api:\n")
    assert set(load_map(path, config).services) == {"orders-api"}
    assert backup.read_bytes() == b""


def test_apply_to_a_comments_only_file_keeps_the_comments(config, skill_dir, tmp_path):
    path = write_map(tmp_path, "# my map\n# nothing yet")
    run_apply(make_case(config, skill_dir), config, path)
    assert path.read_text().startswith("# my map\n# nothing yet\nservices:\n  orders-api:\n")
    assert set(load_map(path, config).services) == {"orders-api"}


def test_apply_to_a_file_holding_empty_services(config, skill_dir, tmp_path):
    path = write_map(tmp_path, "# header\nservices: {}\n")
    run_apply(make_case(config, skill_dir), config, path)
    text = path.read_text()
    assert text.startswith("# header\nservices:\n  orders-api:\n") and "{}" not in text
    assert set(load_map(path, config).services) == {"orders-api"}


def test_apply_restores_the_original_when_the_result_does_not_load(config, skill_dir, tmp_path):
    original = COMMENTED_MAP + "extra: 1\n"
    path = write_map(tmp_path, original)
    case_dir = make_case(config, skill_dir)
    with pytest.raises(SuggestError, match="could not be updated automatically; add the entry by hand"):
        run_apply(case_dir, config, path)
    assert path.read_bytes() == original.encode()
    assert "map_change" not in load_case(case_dir)


def test_apply_records_the_change_in_the_case(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    case_dir = make_case(config, skill_dir)
    backup = run_apply(case_dir, config, path)
    case = load_case(case_dir)
    assert case["map_change"] == {"service_name": "orders-api", "backup": str(backup), "at": "2026-10-04T11:00:00Z"}
    assert json.loads((case_dir / "case.json").read_text())["target"]["source"] == "discovered"


def test_apply_changes_nothing_when_propose_would_refuse(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    with pytest.raises(SuggestError):
        run_apply(make_case(config, skill_dir), config, path, name="alpha")
    assert path.read_bytes() == COMMENTED_MAP.encode()
    assert [p.name for p in tmp_path.glob("service-map.yaml*")] == ["service-map.yaml"]


def test_propose_puts_the_monitor_names_from_incident_json_in_the_match_block(config, skill_dir, tmp_path):
    result = propose(make_case(config, skill_dir), config, write_map(tmp_path, COMMENTED_MAP), "orders-api", "prod", TODAY)
    match = yaml.safe_load("services:\n" + result["yaml"])["services"]["orders-api"]["match"]
    assert match == {"monitors": ["Orders API"], "hostnames": ["orders.example.com"]}
