import fcntl
import json
import shutil
import os
from datetime import date, datetime, timezone

import pytest
import yaml

from triage.case import CaseError, create_case, load_case, parse_incident, save_case, set_target_from_discovery, set_target_from_map
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
        # Written straight into case.json: set_target_from_discovery now refuses the incomplete
        # discoveries that these tests need, and map_suggest must still cope with an old case.json.
        case = load_case(case_dir)
        case["target"] = {"source": "discovered", "service": None, "environment": None,
                          "account": discovery["account"], "region": discovery["region"],
                          "resources": dict(discovery["resources"]), "depends_on": []}
        save_case(case_dir, case)
    return case_dir


def write_map(tmp_path, text):
    path = tmp_path / "service-map.yaml"
    path.write_bytes(text.encode())
    return path


def map_files(folder):
    """Every file the map and its helpers could leave, apart from the lock file, which stays by design."""
    return sorted(p.name for p in folder.iterdir() if "service-map" in p.name and not p.name.endswith(".lock"))


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
    assert lines[0] == '  "orders-api":'
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
    assert result["yaml"].startswith('  "orders-api":\n')
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
    assert "missing: index pattern" in message and "missing: cluster" not in message
    assert "index pattern" in message and "by hand" in message
    assert '  "orders-api":' in message and "cluster: logs-prod" in message


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
    assert b'  "orders-api":\n' in new[len(COMMENTED_MAP):]
    loaded = load_map(path, config)
    assert set(loaded.services) == {"alpha", "orders-api"}
    assert loaded.services["orders-api"].source == "discovered"
    assert backup.name == "service-map.yaml.bak-20261004-110000"
    assert backup.parent == path.parent and backup.read_bytes() == COMMENTED_MAP.encode()


def test_apply_adds_a_newline_when_the_file_has_none(config, skill_dir, tmp_path):
    original = COMMENTED_MAP.rstrip("\n")
    path = write_map(tmp_path, original)
    run_apply(make_case(config, skill_dir), config, path)
    assert path.read_bytes().startswith(original.encode() + b'\n  "orders-api":')
    assert "orders-api" in load_map(path, config).services


def test_apply_to_an_empty_file(config, skill_dir, tmp_path):
    path = write_map(tmp_path, "")
    backup = run_apply(make_case(config, skill_dir), config, path)
    assert path.read_text().startswith('services:\n  "orders-api":\n')
    assert set(load_map(path, config).services) == {"orders-api"}
    assert backup.read_bytes() == b""


def test_apply_to_a_comments_only_file_keeps_the_comments(config, skill_dir, tmp_path):
    path = write_map(tmp_path, "# my map\n# nothing yet")
    run_apply(make_case(config, skill_dir), config, path)
    assert path.read_text().startswith('# my map\n# nothing yet\nservices:\n  "orders-api":\n')
    assert set(load_map(path, config).services) == {"orders-api"}


def test_apply_to_a_file_holding_empty_services(config, skill_dir, tmp_path):
    path = write_map(tmp_path, "# header\nservices: {}\n")
    run_apply(make_case(config, skill_dir), config, path)
    text = path.read_text()
    assert text.startswith('# header\nservices:\n  "orders-api":\n') and "{}" not in text
    assert set(load_map(path, config).services) == {"orders-api"}


def test_apply_restores_the_original_when_the_result_does_not_load(config, skill_dir, tmp_path):
    original = COMMENTED_MAP + "extra: 1\n"
    path = write_map(tmp_path, original)
    case_dir = make_case(config, skill_dir)
    with pytest.raises(SuggestError, match="could not be updated automatically; add the entry by hand") as caught:
        run_apply(case_dir, config, path)
    assert '  "orders-api":' in str(caught.value)
    assert path.read_bytes() == original.encode()
    backups = list(tmp_path.glob("service-map.yaml.bak-*"))
    assert len(backups) == 1 and backups[0].read_bytes() == original.encode()
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
    assert map_files(tmp_path) == ["service-map.yaml"]


def test_propose_puts_the_monitor_names_from_incident_json_in_the_match_block(config, skill_dir, tmp_path):
    result = propose(make_case(config, skill_dir), config, write_map(tmp_path, COMMENTED_MAP), "orders-api", "prod", TODAY)
    match = yaml.safe_load("services:\n" + result["yaml"])["services"]["orders-api"]["match"]
    assert match == {"monitors": ["Orders API"], "hostnames": ["orders.example.com"]}


# fix round 1: atomic write, backups, lock, quoted keys, empty-services rewrite

@pytest.mark.parametrize("name", ["0x1f", "017", "yes", "null", "2026-10-04"])
def test_names_that_yaml_would_read_as_other_types_stay_text(config, skill_dir, tmp_path, name):
    path = write_map(tmp_path, COMMENTED_MAP)
    run_apply(make_case(config, skill_dir), config, path, name=name)
    loaded = load_map(path, config)
    assert set(loaded.services) == {"alpha", name}
    assert list(yaml.safe_load(path.read_text())["services"]) == ["alpha", name]


def test_an_existing_int_key_counts_as_the_same_name(config, skill_dir, tmp_path):
    text = COMMENTED_MAP + COMMENTED_MAP.split("services:\n", 1)[1].replace("alpha:", "123:").replace("alpha/alpha", "x/x")
    path = write_map(tmp_path, text)
    assert 123 in yaml.safe_load(text)["services"]
    with pytest.raises(SuggestError, match="123.*already"):
        run_apply(make_case(config, skill_dir), config, path, name="123")
    assert path.read_bytes() == text.encode()


def test_a_failed_replace_leaves_the_map_and_no_temporary_file(config, skill_dir, tmp_path, monkeypatch):
    path = write_map(tmp_path, COMMENTED_MAP)

    def broken_replace(source, target):
        raise OSError("disk full")

    monkeypatch.setattr("triage.map_suggest.os.replace", broken_replace)
    with pytest.raises(SuggestError, match=r"\.bak-20261004-110000"):
        run_apply(make_case(config, skill_dir), config, path)
    assert path.read_bytes() == COMMENTED_MAP.encode()
    assert map_files(tmp_path) == [
        "service-map.yaml", "service-map.yaml.bak-20261004-110000"]


def test_an_unexpected_error_while_checking_leaves_the_map(config, skill_dir, tmp_path, monkeypatch):
    path = write_map(tmp_path, COMMENTED_MAP)
    real_load = load_map
    calls = []

    def flaky_load(target, cfg):
        calls.append(target)
        if len(calls) > 0:
            raise OSError("io error")
        return real_load(target, cfg)

    monkeypatch.setattr("triage.map_suggest.load_map", flaky_load)
    with pytest.raises(SuggestError, match="bak-"):
        run_apply(make_case(config, skill_dir), config, path)
    assert path.read_bytes() == COMMENTED_MAP.encode()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_a_read_only_map_is_refused_without_a_stray_backup(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    path.chmod(0o444)
    try:
        with pytest.raises(SuggestError, match="not writable"):
            run_apply(make_case(config, skill_dir), config, path)
    finally:
        path.chmod(0o644)
    assert map_files(tmp_path) == ["service-map.yaml"]


def test_two_applies_in_the_same_second_keep_two_backups(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    first = run_apply(make_case(config, skill_dir), config, path, name="svc-one")
    after_first = path.read_bytes()
    second = run_apply(load_case_dir(config, skill_dir), config, path, name="svc-two")
    assert first != second
    assert first.read_bytes() == COMMENTED_MAP.encode() and second.read_bytes() == after_first


def load_case_dir(config, skill_dir):
    incident = {**INCIDENT, "number": "INC-10"}
    case_dir = create_case(parse_incident(incident), config, parse_map({"services": {}}, config), NOW, skill_dir)
    set_target_from_discovery(case_dir, config, DISCOVERY)
    return case_dir


def test_a_live_run_holding_the_lock_stops_apply(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    case_dir = make_case(config, skill_dir)
    with open(tmp_path / "service-map.yaml.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(SuggestError, match="another run is applying"):
            run_apply(case_dir, config, path)
    assert path.read_bytes() == COMMENTED_MAP.encode()


def test_a_lock_file_left_by_a_killed_run_does_not_block(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    (tmp_path / "service-map.yaml.lock").write_text("")
    run_apply(make_case(config, skill_dir), config, path)
    assert "orders-api" in load_map(path, config).services


def test_a_failed_backup_write_leaves_no_partial_backup(config, skill_dir, tmp_path, monkeypatch):
    path = write_map(tmp_path, COMMENTED_MAP)

    def full_disk(descriptor):
        raise OSError("no space left")

    monkeypatch.setattr("triage.map_suggest.os.fsync", full_disk)
    with pytest.raises(SuggestError, match="no space left") as caught:
        run_apply(make_case(config, skill_dir), config, path)
    assert "\n" not in str(caught.value)
    assert path.read_bytes() == COMMENTED_MAP.encode()
    assert map_files(tmp_path) == ["service-map.yaml"]


def test_a_runtime_error_while_loading_is_one_line_and_leaves_the_map(config, skill_dir, tmp_path, monkeypatch):
    path = write_map(tmp_path, COMMENTED_MAP)

    def broken_load(target, cfg):
        raise RuntimeError("odd failure")

    monkeypatch.setattr("triage.map_suggest.load_map", broken_load)
    with pytest.raises(SuggestError, match="odd failure") as caught:
        run_apply(make_case(config, skill_dir), config, path)
    assert "\n" not in str(caught.value)
    assert path.read_bytes() == COMMENTED_MAP.encode()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_a_temporary_file_this_run_did_not_create_is_kept(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    stranger = tmp_path / f".service-map.yaml.tmp-{os.getpid()}"
    stranger.write_text("not ours")
    with pytest.raises(SuggestError):
        run_apply(make_case(config, skill_dir), config, path)
    assert stranger.read_text() == "not ours" and path.read_bytes() == COMMENTED_MAP.encode()


@pytest.mark.parametrize("incident_json", ["[]", '{"monitors": 5}', '{"monitors": "abc"}', '{"monitors": [5]}'])
def test_an_incident_file_of_the_wrong_shape_is_one_line(config, skill_dir, tmp_path, incident_json):
    path = write_map(tmp_path, COMMENTED_MAP)
    case_dir = make_case(config, skill_dir)
    (case_dir / "incident.json").write_text(incident_json)
    with pytest.raises(SuggestError, match="incident.json") as caught:
        propose(case_dir, config, path, "orders-api", "prod", TODAY)
    assert "\n" not in str(caught.value)


@pytest.mark.parametrize("original, line_after", [
    ("---\n# c\nservices: {}\n# trailing\n", "services:\n"),
    ("﻿# bom comment\nservices: {}\n", "services:\n"),
    ("# h\nservices: {} # nothing yet\n# t\n", "services: # nothing yet\n"),
    ("# h\nservices:\n# t\n", "services:\n"),
    ("# h\nservices: ~\n", "services:\n"),
    ("# h\nservices: {}", "services:\n"),
])
def test_an_empty_services_map_rewrites_only_that_line(config, skill_dir, tmp_path, original, line_after):
    path = write_map(tmp_path, original)
    run_apply(make_case(config, skill_dir), config, path)
    new = path.read_bytes().decode("utf-8")
    lines = original.split("\n")
    index = next(i for i, line in enumerate(lines) if line.startswith("services:"))
    head = "\n".join(lines[:index]) + ("\n" if index else "")
    assert new.startswith(head + line_after + '  "orders-api":\n')
    tail = "\n".join(lines[index + 1:])
    assert new.endswith(tail)
    assert set(load_map(path, config).services) == {"orders-api"}


def test_an_empty_services_map_keeps_windows_line_endings(config, skill_dir, tmp_path):
    original = "# h\r\nservices: {}\r\n# t\r\n"
    path = write_map(tmp_path, original)
    run_apply(make_case(config, skill_dir), config, path)
    new = path.read_bytes()
    assert new.startswith(b'# h\r\nservices:\r\n  "orders-api":\r\n') and new.endswith(b"# t\r\n")
    assert b"\n" not in new.replace(b"\r\n", b"")
    assert set(load_map(path, config).services) == {"orders-api"}


def test_an_empty_services_map_that_cannot_be_rewritten_exactly_is_refused_with_the_block(config, skill_dir, tmp_path):
    original = "{services: {}}\n"
    path = write_map(tmp_path, original)
    with pytest.raises(SuggestError, match="paste") as caught:
        run_apply(make_case(config, skill_dir), config, path)
    assert '  "orders-api":' in str(caught.value)
    assert path.read_bytes() == original.encode()
    assert map_files(tmp_path) == ["service-map.yaml"]


def test_apply_creates_a_missing_map(config, skill_dir, tmp_path):
    path = tmp_path / "service-map.yaml"
    backup = run_apply(make_case(config, skill_dir), config, path)
    assert backup is None
    assert path.read_text().startswith('services:\n  "orders-api":\n')
    assert set(load_map(path, config).services) == {"orders-api"}
    assert map_files(tmp_path) == ["service-map.yaml"]


def test_the_opensearch_message_names_what_is_missing(config, skill_dir, tmp_path):
    discovery = {**DISCOVERY, "resources": {"opensearch": {"index_pattern": "app-logs-*"}}}
    case_dir = make_case(config, skill_dir, discovery)
    with pytest.raises(SuggestError, match="missing: cluster"):
        propose(case_dir, config, write_map(tmp_path, COMMENTED_MAP), "orders-api", "prod", TODAY)


# final review fixes

def test_a_case_folder_outside_the_cases_root_is_refused(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    case_dir = make_case(config, skill_dir)
    copy = tmp_path / "elsewhere" / "INC-9" / "run"
    shutil.copytree(case_dir, copy)
    for function in (lambda: propose(copy, config, path, "orders-api", "prod", TODAY),
                     lambda: run_apply(copy, config, path)):
        with pytest.raises(CaseError, match="not a case folder under"):
            function()
    assert path.read_bytes() == COMMENTED_MAP.encode()
    assert map_files(tmp_path) == ["service-map.yaml"]


def test_apply_removes_its_lock_file_when_it_finishes(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    run_apply(make_case(config, skill_dir), config, path)
    assert not (tmp_path / "service-map.yaml.lock").exists()


def test_apply_removes_its_lock_file_when_it_fails(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    with pytest.raises(SuggestError):
        run_apply(make_case(config, skill_dir), config, path, name="alpha")
    assert not (tmp_path / "service-map.yaml.lock").exists()


def test_apply_keeps_a_lock_file_that_another_live_run_holds(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    case_dir = make_case(config, skill_dir)
    lock = tmp_path / "service-map.yaml.lock"
    with open(lock, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(SuggestError, match="another run is applying"):
            run_apply(case_dir, config, path)
    assert lock.exists()


# safety checks that the first reviews left untested, and the newer resource keys

def test_two_services_lines_are_refused_with_the_block(config, skill_dir, tmp_path):
    original = "services: {}\nservices: {}\n"
    path = write_map(tmp_path, original)
    with pytest.raises(SuggestError, match="could not be edited exactly"):
        run_apply(make_case(config, skill_dir), config, path)
    assert path.read_bytes() == original.encode()


def test_the_new_map_must_keep_every_earlier_entry_unchanged(config, skill_dir, tmp_path, monkeypatch):
    path = write_map(tmp_path, COMMENTED_MAP)
    from triage import map_suggest

    real = map_suggest._new_content

    def altering(original, data, block):
        return real(original, data, block).replace(b"source: confirmed", b"source: discovered")

    monkeypatch.setattr(map_suggest, "_new_content", altering)
    with pytest.raises(SuggestError, match="could not be updated automatically"):
        run_apply(make_case(config, skill_dir), config, path)
    assert path.read_bytes() == COMMENTED_MAP.encode()


def test_the_new_map_keeps_the_permissions_of_the_old_one(config, skill_dir, tmp_path):
    path = write_map(tmp_path, COMMENTED_MAP)
    path.chmod(0o640)
    run_apply(make_case(config, skill_dir), config, path)
    assert path.stat().st_mode & 0o777 == 0o640
    assert "orders-api" in load_map(path, config).services


def test_a_proposal_with_alarms_ecr_and_opensearch_domain_validates(config, skill_dir, tmp_path):
    resources = {"alarms": ["orders-5xx"], "ecr_repository": "orders-api", "opensearch_domain": "logs-domain"}
    case_dir = make_case(config, skill_dir, {**DISCOVERY, "resources": resources})
    path = write_map(tmp_path, COMMENTED_MAP)
    result = propose(case_dir, config, path, "orders-api", "prod", TODAY)
    assert result["valid"] is True
    run_apply(case_dir, config, path)
    loaded = load_map(path, config).services["orders-api"].environments["prod"]
    assert loaded.resources == resources
