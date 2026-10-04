import json
import textwrap

import pytest
import yaml

import collect

import triage.collectors as registry
from fakes import SSO_EXPIRED_ERROR, FakeAws
from helpers import WINDOW_END, WINDOW_START
from triage.collectors import Collector, all_collectors



@pytest.fixture
def skill_dir(tmp_path, config_data):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    return tmp_path


@pytest.fixture
def fake_collector(monkeypatch):
    calls = []

    def run(ctx, targets):
        calls.append((ctx, targets))
        ctx.aws("ecs", "list-clusters")
        ctx.evidence.add(kind="current", resource="r", summary="hello " + targets["thing"])

    entry = Collector("fake", "A fake collector", ("thing",), ("extra",), run)
    monkeypatch.setattr(collect, "all_collectors", lambda: {"fake": entry})
    return calls


def args(skill_dir, *extra, name="fake"):
    return [name, "--account", "prod-main", "--start", WINDOW_START, "--end", WINDOW_END,
            "--skill-dir", str(skill_dir), *extra]


# registry

def test_registry_contains_ecs():
    assert "ecs" in all_collectors()
    assert all_collectors()["ecs"].required == ("cluster", "service")


def add_module(tmp_path, monkeypatch, name, body):
    (tmp_path / f"{name}.py").write_text(textwrap.dedent(body))
    monkeypatch.setattr(registry, "__path__", [*registry.__path__, str(tmp_path)])


def test_registry_ignores_modules_without_collector(tmp_path, monkeypatch):
    add_module(tmp_path, monkeypatch, "zz_helperlike", "VALUE = 1\n")
    assert "zz_helperlike" not in all_collectors()
    assert "ecs" in all_collectors()


def test_registry_rejects_duplicate_names(tmp_path, monkeypatch):
    add_module(tmp_path, monkeypatch, "zz_dup", """
        from triage.collectors import Collector
        COLLECTOR = Collector("ecs", "dup", (), (), lambda ctx, targets: None)
    """)
    with pytest.raises(ValueError, match="ecs"):
        all_collectors()


# command

def test_list(capsys):
    assert collect.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert any(line.startswith("ecs") and "cluster" in line and "service" in line for line in out.splitlines())


def test_full_run_prints_json(skill_dir, fake_collector, capsys):
    code = collect.main(args(skill_dir, "--target", "thing=x"), runner=FakeAws({}))
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["collector"] == "fake"
    assert document["account"] == "prod-main"
    assert document["window"] == {"start": WINDOW_START, "end": WINDOW_END}
    assert document["facts"][0]["summary"] == "hello x"


def test_default_region_is_the_accounts_first(skill_dir, fake_collector):
    collect.main(args(skill_dir, "--target", "thing=x"), runner=FakeAws({}))
    assert fake_collector[0][0].region == "eu-west-1"


def test_region_option(skill_dir, fake_collector):
    collect.main(args(skill_dir, "--target", "thing=x", "--region", "us-east-1"), runner=FakeAws({}))
    assert fake_collector[0][0].region == "us-east-1"


def test_case_dir_writes_a_file(skill_dir, fake_collector, tmp_path, capsys):
    case = tmp_path / "case"
    code = collect.main(args(skill_dir, "--target", "thing=x", "--case-dir", str(case), "--suffix", "a b"), runner=FakeAws({}))
    assert code == 0
    path = case / "evidence" / "fake-prod-main-eu-west-1-ab.json"
    assert path.exists()
    assert capsys.readouterr().out.strip() == f"{path} facts=1 errors=0 truncated=False"


def test_unknown_collector(skill_dir, fake_collector, capsys):
    assert collect.main(args(skill_dir, name="nope")) == 4
    assert "fake" in capsys.readouterr().err


def test_missing_target_key(skill_dir, fake_collector, capsys):
    assert collect.main(args(skill_dir)) == 4
    assert "thing" in capsys.readouterr().err


def test_undeclared_target_key(skill_dir, fake_collector, capsys):
    assert collect.main(args(skill_dir, "--target", "thing=x", "--target", "bogus=1")) == 4
    err = capsys.readouterr().err
    assert "bogus" in err and "thing" in err


def test_optional_target_key_is_accepted(skill_dir, fake_collector):
    assert collect.main(args(skill_dir, "--target", "thing=x", "--target", "extra=1"), runner=FakeAws({})) == 0
    assert fake_collector[0][1] == {"thing": "x", "extra": "1"}


def test_bad_window(skill_dir, fake_collector, capsys):
    argv = ["fake", "--account", "prod-main", "--start", WINDOW_END, "--end", WINDOW_START,
            "--skill-dir", str(skill_dir), "--target", "thing=x"]
    assert collect.main(argv) == 2
    assert "after its start" in capsys.readouterr().err


def test_unknown_account(skill_dir, fake_collector, capsys):
    argv = args(skill_dir, "--target", "thing=x")
    argv[argv.index("prod-main")] = "nowhere"
    assert collect.main(argv) == 2
    assert "nowhere" in capsys.readouterr().err


def test_sign_in_expired(skill_dir, fake_collector, capsys):
    code = collect.main(args(skill_dir, "--target", "thing=x"), runner=FakeAws({"ecs list-clusters": SSO_EXPIRED_ERROR}))
    assert code == 3
    assert "Sign-in expired. Run: aws sso login --profile triage-prod-main" in capsys.readouterr().err


def test_bad_config_exits_2(tmp_path, fake_collector, capsys):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "triage-config.yaml").write_text("accounts: nonsense\n")
    assert collect.main(args(tmp_path, "--target", "thing=x")) == 2
    assert capsys.readouterr().err.strip()


def test_missing_config_exits_2(tmp_path, fake_collector, capsys):
    assert collect.main(args(tmp_path, "--target", "thing=x")) == 2
