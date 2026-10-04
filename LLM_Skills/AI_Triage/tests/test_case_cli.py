import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conftest import SKILL_SRC

COMMAND = SKILL_SRC / "scripts" / "case.py"
INCIDENT = {
    "number": "INC-123",
    "title": "Checkout API is down",
    "declared_at": "2026-10-04T10:45:00Z",
    "impact_started_at": "2026-10-04T10:42:00Z",
    "monitors": [{"name": "Checkout API", "type": "API", "target": "https://checkout.example.com/health"}],
    "labels": ["checkout"],
}
NOW = "2026-10-04T11:00:00Z"


@pytest.fixture
def skill_dir(tmp_path, config_data, map_data):
    config_data["cases_dir"] = str(tmp_path / "cases")
    root = tmp_path / "skill"
    (root / "config").mkdir(parents=True)
    (root / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    (root / "config" / "service-map.yaml").write_text(yaml.safe_dump(map_data))
    return root


def run(skill_dir, *args):
    return subprocess.run([sys.executable, str(COMMAND), *args, "--skill-dir", str(skill_dir)],
                          capture_output=True, text=True)


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


@pytest.fixture
def case_dir(skill_dir, tmp_path):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "incident.json", INCIDENT), "--now", NOW)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["case_dir"]


def test_help_works():
    result = subprocess.run([sys.executable, str(COMMAND), "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "init" in result.stdout and "plan" in result.stdout


def test_init_prints_the_case_summary(skill_dir, tmp_path):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["case_dir"].endswith("INC-123/20261004-110000")
    assert Path(out["case_dir"], "case.md").is_file()
    assert out["window"] == {"start": "2026-10-04T09:42:00Z", "end": "2026-10-04T11:00:00Z"}
    assert out["incident_start"] == "2026-10-04T10:42:00Z"
    assert out["match"]["status"] == "one"


def test_init_reads_the_clock_when_now_is_not_given(skill_dir, tmp_path):
    incident = {**INCIDENT, "declared_at": "2999-01-01T00:00:00Z", "impact_started_at": None}
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", incident))
    assert result.returncode == 2  # the window would end before it starts


def test_init_lists_every_problem_and_exits_2(skill_dir, tmp_path):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", {"labels": "x"}), "--now", NOW)
    assert result.returncode == 2
    for word in ("number", "title", "declared_at", "labels"):
        assert word in result.stderr


@pytest.mark.parametrize("args", [["--incident", "missing.json"], ["--incident", "BAD", "--now", "later"]])
def test_init_usage_errors_exit_2(skill_dir, tmp_path, args):
    args = [str(tmp_path / "bad.json") if a == "BAD" else a for a in args]
    (tmp_path / "bad.json").write_text("{not json")
    assert run(skill_dir, "init", *args).returncode == 2


def test_init_twice_in_the_same_second_exits_2(skill_dir, tmp_path, case_dir):
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 2 and "already exists" in result.stderr


def test_init_works_without_a_service_map(skill_dir, tmp_path):
    (skill_dir / "config" / "service-map.yaml").unlink()
    result = run(skill_dir, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 0 and json.loads(result.stdout)["match"]["status"] == "none"


def test_init_with_a_missing_config_exits_2(tmp_path):
    result = run(tmp_path, "init", "--incident", write(tmp_path, "i.json", INCIDENT), "--now", NOW)
    assert result.returncode == 2


def test_target_from_the_map(skill_dir, case_dir):
    result = run(skill_dir, "target", "--case-dir", case_dir, "--service", "checkout-api", "--environment", "prod")
    assert result.returncode == 0, result.stderr
    target = json.loads(result.stdout)
    assert target["account"] == "prod-main" and target["source"] == "map"
    assert json.loads(Path(case_dir, "case.json").read_text())["target"] == target


def test_target_unknown_service_exits_2(skill_dir, case_dir):
    result = run(skill_dir, "target", "--case-dir", case_dir, "--service", "nope", "--environment", "prod")
    assert result.returncode == 2 and "nope" in result.stderr


def test_target_from_a_discovery_file(skill_dir, case_dir, tmp_path):
    discovery = {"hostname": "checkout.example.com", "account": "prod-main", "region": "eu-west-1",
                 "resources": {"rds": "checkout-prod-db"}, "steps": [], "notes": []}
    for payload in (discovery, {"discovery": discovery, "proposed_entry": {}}):
        result = run(skill_dir, "target", "--case-dir", case_dir, "--discovery", write(tmp_path, "d.json", payload))
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["source"] == "discovered"


def test_target_from_a_discovery_without_an_account_exits_2(skill_dir, case_dir, tmp_path):
    discovery = {"account": None, "region": None, "resources": {}}
    result = run(skill_dir, "target", "--case-dir", case_dir, "--discovery", write(tmp_path, "d.json", discovery))
    assert result.returncode == 2 and "account" in result.stderr


def test_target_needs_either_a_service_or_a_discovery(skill_dir, case_dir, tmp_path):
    assert run(skill_dir, "target", "--case-dir", case_dir).returncode == 2
    both = run(skill_dir, "target", "--case-dir", case_dir, "--service", "a", "--environment", "b",
               "--discovery", write(tmp_path, "d.json", {}))
    assert both.returncode == 2
    assert run(skill_dir, "target", "--case-dir", case_dir, "--service", "a").returncode == 2


def test_plan_prints_shell_quoted_commands(skill_dir, case_dir):
    run(skill_dir, "target", "--case-dir", case_dir, "--service", "checkout-api", "--environment", "prod")
    result = run(skill_dir, "plan", "--case-dir", case_dir)
    assert result.returncode == 0, result.stderr
    planned = json.loads(result.stdout)
    assert all(set(item) == {"domain", "tool", "name", "command", "reason"} for item in planned)
    ecs = next(item for item in planned if item["name"] == "ecs")
    assert ecs["command"].startswith(f"{skill_dir}/.venv/bin/python {skill_dir}/scripts/collect.py ecs ")
    assert "--target cluster=checkout --target service=checkout-api" in ecs["command"]
    assert {"changes", "platform", "opensearch"} <= {item["name"] for item in planned}
    log_group = next(item for item in planned if item["name"] == "logs")
    assert "log_groups=/ecs/checkout-api" in log_group["command"]


def test_plan_without_a_target_exits_2(skill_dir, case_dir):
    result = run(skill_dir, "plan", "--case-dir", case_dir)
    assert result.returncode == 2 and "target" in result.stderr


def test_show_prints_case_json(skill_dir, case_dir):
    result = run(skill_dir, "show", "--case-dir", case_dir)
    assert result.returncode == 0
    assert json.loads(result.stdout) == json.loads(Path(case_dir, "case.json").read_text())


def test_show_with_a_missing_case_exits_2(skill_dir, tmp_path):
    assert run(skill_dir, "show", "--case-dir", str(tmp_path / "nowhere")).returncode == 2
