import json

import pytest
import yaml

from triage.commands import collect
from fakes import FakeAws
from helpers import WINDOW_END, WINDOW_START
from triage.collectors import all_collectors


@pytest.fixture
def skill_dir(tmp_path, config_data):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return tmp_path


def alarms_args(skill_dir, *extra):
    return ["alarms", "--account", "prod-main", "--start", WINDOW_START, "--end", WINDOW_END,
            "--skill-dir", str(skill_dir), *extra]


ALARMS = {"cloudwatch describe-alarms": {"MetricAlarms": [{"AlarmName": "cpu-high", "StateValue": "OK"}]},
          "cloudwatch describe-alarm-history": {"AlarmHistoryItems": []}}


@pytest.mark.parametrize("name", sorted(all_collectors()))
def test_one_of_keys_are_declared_targets(name):
    collector = all_collectors()[name]
    assert set(collector.one_of) <= set(collector.required + collector.optional)


@pytest.mark.parametrize("target", ["alarm_names=cpu-high", "name_prefix=cpu-"])
def test_real_alarms_collector_runs_from_the_command_line(skill_dir, capsys, target):
    code = collect.main(alarms_args(skill_dir, "--target", target), runner=FakeAws(ALARMS))
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["collector"] == "alarms"
    assert any("cpu-high" in fact["summary"] for fact in document["facts"])


def test_real_alarms_collector_without_a_target_exits_4(skill_dir, capsys):
    assert collect.main(alarms_args(skill_dir), runner=FakeAws(ALARMS)) == 4
    assert "alarm_names" in capsys.readouterr().err
