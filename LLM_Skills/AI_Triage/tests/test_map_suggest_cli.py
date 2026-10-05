import fcntl
import json
import shutil
import subprocess
import sys

import pytest
import yaml

from pathlib import Path

from conftest import SKILL_SRC

COMMAND = SKILL_SRC / "scripts" / "map_suggest.py"
INCIDENT = {
    "number": "INC-9",
    "title": "Orders API is down",
    "declared_at": "2026-10-04T10:45:00Z",
    "monitors": [{"name": "Orders API", "type": "API", "target": "https://orders.example.com/health"}],
}
DISCOVERY = {"account": "prod-main", "region": "eu-west-1", "resources": {"ecs_service": "orders/orders-api"}}
MAP_TEXT = "# mine\nservices: {}\n"


@pytest.fixture
def skill_dir(tmp_path, config_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    (root / "config" / "service-map.yaml").write_text(MAP_TEXT)
    return root


def run(skill_dir, *args):
    return subprocess.run([sys.executable, str(COMMAND), *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True)


def make_case(skill_dir, tmp_path, discovery=DISCOVERY):
    case_script = SKILL_SRC / "scripts" / "case.py"
    incident = tmp_path / "incident.json"
    incident.write_text(json.dumps(INCIDENT))
    out = subprocess.run([sys.executable, str(case_script), "init", "--incident", str(incident),
                          "--now", "2026-10-04T11:00:00Z", "--skill-dir", str(skill_dir)],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    case_dir = json.loads(out.stdout)["case_dir"]
    if discovery is not None and discovery["resources"].get("opensearch") == {"cluster": "logs-prod"}:
        # case.py target refuses an OpenSearch resource without an index pattern; write the target as an old case.json held it.
        path = Path(case_dir) / "case.json"
        case = json.loads(path.read_text())
        case["target"] = {"source": "discovered", "service": None, "environment": None, "account": discovery["account"],
                          "region": discovery["region"], "resources": discovery["resources"], "depends_on": []}
        path.write_text(json.dumps(case))
    elif discovery is not None:
        found = tmp_path / "discovery.json"
        found.write_text(json.dumps(discovery))
        done = subprocess.run([sys.executable, str(case_script), "target", "--case-dir", case_dir,
                               "--discovery", str(found), "--skill-dir", str(skill_dir)],
                              capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    return case_dir


@pytest.fixture
def case_dir(skill_dir, tmp_path):
    return make_case(skill_dir, tmp_path)


@pytest.fixture
def map_file(skill_dir):
    return skill_dir / "config" / "service-map.yaml"


def test_help_works():
    result = subprocess.run([sys.executable, str(COMMAND), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "propose" in result.stdout and "apply" in result.stdout


def test_propose_prints_the_block_and_changes_nothing(skill_dir, case_dir, map_file):
    result = run(skill_dir, "propose", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith('  "orders-api":\n')
    assert yaml.safe_load("services:\n" + result.stdout)["services"]["orders-api"]["environments"]["prod"]
    assert map_file.read_text() == MAP_TEXT
    assert [p.name for p in map_file.parent.iterdir() if "service-map" in p.name and not p.name.endswith(".lock")] == ["service-map.yaml"]


def test_propose_uses_the_environment_option(skill_dir, case_dir):
    result = run(skill_dir, "propose", "--case-dir", case_dir, "--service-name", "orders-api", "--environment", "staging")
    assert "staging:" in result.stdout and "prod:" not in result.stdout


def test_apply_appends_backs_up_and_prints_the_backup(skill_dir, case_dir, map_file):
    result = run(skill_dir, "apply", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 0, result.stderr
    assert "orders-api" in map_file.read_text() and map_file.read_text().startswith("# mine\nservices:\n")
    backups = list(map_file.parent.glob("service-map.yaml.bak-*"))
    assert len(backups) == 1 and backups[0].read_text() == MAP_TEXT
    assert str(backups[0]) in result.stdout
    recorded = json.loads(open(f"{case_dir}/case.json").read())["map_change"]
    assert recorded["service_name"] == "orders-api" and recorded["backup"] == str(backups[0])


def test_a_map_sourced_case_exits_1(skill_dir, tmp_path, map_file):
    case_dir = make_case(skill_dir, tmp_path, discovery=None)
    result = run(skill_dir, "propose", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 1 and "nothing to add" in result.stderr


def test_an_existing_service_name_exits_1(skill_dir, case_dir, map_file):
    assert run(skill_dir, "apply", "--case-dir", case_dir, "--service-name", "orders-api").returncode == 0
    result = run(skill_dir, "apply", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 1 and "edit the entry by hand" in result.stderr


def test_opensearch_without_an_index_pattern_exits_1_and_prints_the_block(skill_dir, tmp_path):
    discovery = {**DISCOVERY, "resources": {"opensearch": {"cluster": "logs-prod"}}}
    case_dir = make_case(skill_dir, tmp_path, discovery)
    result = run(skill_dir, "propose", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 1 and "index pattern" in result.stderr and '"orders-api":' in result.stderr


def test_a_missing_case_exits_2(skill_dir, tmp_path):
    result = run(skill_dir, "propose", "--case-dir", str(tmp_path / "nope"), "--service-name", "orders-api")
    assert result.returncode == 2 and "not a case folder" in result.stderr


def test_a_missing_config_exits_2(tmp_path, case_dir):
    empty = tmp_path / "empty-skill"
    empty.mkdir()
    result = run(empty, "propose", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 2


def test_a_missing_service_name_is_a_usage_error(skill_dir, case_dir):
    assert run(skill_dir, "propose", "--case-dir", case_dir).returncode == 2


def test_a_live_lock_makes_apply_exit_1_and_changes_nothing(skill_dir, case_dir, map_file):
    with open(map_file.with_name("service-map.yaml.lock"), "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        result = run(skill_dir, "apply", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 1 and "another run is applying" in result.stderr
    assert map_file.read_text() == MAP_TEXT


def test_a_wrongly_shaped_incident_file_exits_1_with_one_line(skill_dir, case_dir):
    (Path(case_dir) / "incident.json").write_text("[]")
    result = run(skill_dir, "propose", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 1 and "Traceback" not in result.stderr and len(result.stderr.strip().splitlines()) == 1


def test_apply_without_a_map_file_creates_it(skill_dir, case_dir, map_file):
    map_file.unlink()
    result = run(skill_dir, "apply", "--case-dir", case_dir, "--service-name", "orders-api")
    assert result.returncode == 0, result.stderr
    assert "orders-api" in yaml.safe_load(map_file.read_text())["services"]
    

def test_propose_says_which_environment_it_assumed_and_how_to_change_it(skill_dir, case_dir):
    result = run(skill_dir, "propose", "--case-dir", case_dir, "--service-name", "orders-api")
    assert "environment prod" in result.stderr and "--environment" in result.stderr
    named = run(skill_dir, "propose", "--case-dir", case_dir, "--service-name", "orders-api", "--environment", "staging")
    assert "environment staging" in named.stderr


def test_a_case_folder_outside_the_cases_root_exits_2(skill_dir, case_dir, tmp_path):
    copy = tmp_path / "elsewhere" / "INC-9" / "run"
    shutil.copytree(case_dir, copy)
    result = run(skill_dir, "propose", "--case-dir", str(copy), "--service-name", "orders-api")
    assert result.returncode == 2 and "not a case folder" in result.stderr


def test_apply_leaves_no_lock_file(skill_dir, case_dir, map_file):
    assert run(skill_dir, "apply", "--case-dir", case_dir, "--service-name", "orders-api").returncode == 0
    assert not map_file.with_name("service-map.yaml.lock").exists()
