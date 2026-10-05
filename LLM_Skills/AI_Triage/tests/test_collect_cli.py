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


# replay mode

@pytest.fixture
def no_real_calls(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("a real subprocess was started in replay mode")

    monkeypatch.setattr("subprocess.run", refuse)


@pytest.fixture
def replay_dir(tmp_path, monkeypatch):
    directory = tmp_path / "replay"
    directory.mkdir()
    (directory / "aws.json").write_text(json.dumps([{"match": ["ecs", "list-clusters"], "result": {"clusterArns": []}}]))
    (directory / "kubectl.json").write_text(json.dumps([{"match": ["get", "pods"], "contains": ["payments"], "stdout": "pod-a"}]))
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(directory))
    monkeypatch.setenv("AI_TRIAGE_FIXTURE_LOG", str(tmp_path / "calls.log"))
    return directory


def test_replay_mode_answers_from_fixtures_and_prints_the_banner_once(skill_dir, replay_dir, tmp_path, fake_collector, no_real_calls, capsys):
    code = collect.main(args(skill_dir, "--target", "thing=x"))
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["facts"][0]["summary"] == "hello x"
    assert captured.err.count("REPLAY MODE") == 1
    assert f"REPLAY MODE: answers come from {replay_dir}; nothing is called." in captured.err
    logged = [json.loads(line) for line in (tmp_path / "calls.log").read_text().splitlines()]
    assert [(entry["tool"], entry["argv"][1:3]) for entry in logged] == [("aws", ["ecs", "list-clusters"])]


def test_replay_mode_also_replays_kubectl(skill_dir, replay_dir, no_real_calls, monkeypatch, capsys):
    def run(ctx, targets):
        output = ctx.kubectl("platform-prod", ["get", "pods"], namespace="payments")
        ctx.evidence.add(kind="current", resource="r", summary=f"pods: {output}")

    monkeypatch.setattr(collect, "all_collectors", lambda: {"kube": Collector("kube", "Kube", (), (), run)})
    code = collect.main(args(skill_dir, name="kube"))
    assert code == 0
    assert json.loads(capsys.readouterr().out)["facts"][0]["summary"] == "pods: pod-a"


def test_an_injected_runner_wins_over_the_environment(skill_dir, replay_dir, fake_collector, capsys):
    fake = FakeAws({"ecs list-clusters": {"clusterArns": ["x"]}})
    code = collect.main(args(skill_dir, "--target", "thing=x"), runner=fake, kube_runner=FakeAws({}))
    assert code == 0
    assert fake.calls
    assert "REPLAY MODE" not in capsys.readouterr().err


def test_a_bad_fixture_directory_exits_2_and_never_runs_the_real_tool(skill_dir, fake_collector, no_real_calls, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("AI_TRIAGE_FIXTURES", str(tmp_path / "nowhere"))
    assert collect.main(args(skill_dir, "--target", "thing=x")) == 2
    assert "not a directory" in capsys.readouterr().err


@pytest.fixture
def one_of_collector(monkeypatch):
    entry = Collector("pick", "Needs one", (), ("a", "b", "c"), lambda ctx, targets: None, one_of=("a", "b"))
    monkeypatch.setattr(collect, "all_collectors", lambda: {"pick": entry})


def test_one_of_defaults_to_empty():
    assert Collector("x", "d", (), (), lambda ctx, targets: None).one_of == ()


def test_one_of_missing_exits_4(skill_dir, one_of_collector, capsys):
    assert collect.main(args(skill_dir, name="pick")) == 4
    err = capsys.readouterr().err
    assert "a" in err and "b" in err and "one of" in err


def test_one_of_empty_value_counts_as_missing(skill_dir, one_of_collector):
    assert collect.main(args(skill_dir, "--target", "a=", name="pick")) == 4


def test_one_of_satisfied(skill_dir, one_of_collector):
    assert collect.main(args(skill_dir, "--target", "b=x", name="pick"), runner=FakeAws({})) == 0


def test_list_shows_one_of(one_of_collector, capsys):
    assert collect.main(["--list"]) == 0
    assert "one of: a, b" in capsys.readouterr().out


def test_collector_exception_keeps_the_evidence(skill_dir, monkeypatch, capsys):
    def run(ctx, targets):
        ctx.evidence.add(kind="current", resource="r", summary="before the crash")
        raise ZeroDivisionError("division by zero")

    monkeypatch.setattr(collect, "all_collectors", lambda: {"boom": Collector("boom", "d", (), (), run)})
    assert collect.main(args(skill_dir, name="boom"), runner=FakeAws({})) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["facts"][0]["summary"] == "before the crash"
    assert document["errors"][0]["code"] == "CollectorError"
    assert "ZeroDivisionError: division by zero" in document["errors"][0]["message"]


def test_collector_exception_is_written_to_the_case_dir(skill_dir, monkeypatch, tmp_path):
    def run(ctx, targets):
        raise KeyError("nope")

    monkeypatch.setattr(collect, "all_collectors", lambda: {"boom": Collector("boom", "d", (), (), run)})
    case = tmp_path / "case"
    assert collect.main(args(skill_dir, "--case-dir", str(case), name="boom"), runner=FakeAws({})) == 0
    assert any((case / "evidence").iterdir())


def test_region_outside_the_account_is_rejected(skill_dir, fake_collector, capsys):
    assert collect.main(args(skill_dir, "--target", "thing=x", "--region", "ap-south-1")) == 2
    err = capsys.readouterr().err
    assert "eu-west-1" in err and "us-east-1" in err


def test_global_region_is_allowed_for_any_account(skill_dir, fake_collector):
    argv = args(skill_dir, "--target", "thing=x", "--region", "us-east-1")
    argv[argv.index("prod-main")] = "staging"
    assert collect.main(argv, runner=FakeAws({})) == 0


def test_one_of_whitespace_value_counts_as_missing(skill_dir, one_of_collector):
    assert collect.main(args(skill_dir, "--target", "a= ", name="pick")) == 4


def test_duplicate_target_key_exits_4(skill_dir, fake_collector, capsys):
    assert collect.main(args(skill_dir, "--target", "thing=a", "--target", "thing=b")) == 4
    assert "thing" in capsys.readouterr().err


def test_empty_required_target_exits_4(skill_dir, fake_collector):
    assert collect.main(args(skill_dir, "--target", "thing=")) == 4
    assert collect.main(args(skill_dir, "--target", "thing=  ")) == 4


def test_collector_error_has_no_command(skill_dir, monkeypatch, capsys):
    def run(ctx, targets):
        ctx.aws("ecs", "list-clusters")
        raise KeyError("unknown EKS cluster")

    monkeypatch.setattr(collect, "all_collectors", lambda: {"boom": Collector("boom", "d", (), (), run)})
    collect.main(args(skill_dir, name="boom"), runner=FakeAws({}))
    assert json.loads(capsys.readouterr().out)["errors"][0]["command"] == ""


def test_context_gets_a_clock(skill_dir, fake_collector):
    collect.main(args(skill_dir, "--target", "thing=x"), runner=FakeAws({}))
    assert fake_collector[0][0].now is not None
    assert fake_collector[0][0].now.tzinfo is not None


@pytest.mark.parametrize("value", [" , ", ",", ",,  ,"])
def test_one_of_comma_only_value_counts_as_missing(skill_dir, one_of_collector, value):
    assert collect.main(args(skill_dir, "--target", f"a={value}", name="pick")) == 4


def test_one_of_value_with_a_real_item_passes(skill_dir, one_of_collector):
    assert collect.main(args(skill_dir, "--target", "a= , x", name="pick"), runner=FakeAws({})) == 0


# Fix round 4

def test_existing_evidence_file_is_not_overwritten(skill_dir, fake_collector, tmp_path, capsys):
    case = tmp_path / "case"
    argv = args(skill_dir, "--target", "thing=x", "--case-dir", str(case))
    assert collect.main(argv, runner=FakeAws({})) == 0
    capsys.readouterr()
    assert collect.main(argv, runner=FakeAws({})) == 2
    assert "--suffix" in capsys.readouterr().err


@pytest.mark.parametrize("value", [",", " , ", ",,  ,"])
def test_comma_only_required_target_exits_4(skill_dir, fake_collector, value):
    assert collect.main(args(skill_dir, "--target", f"thing={value}")) == 4


def test_asked_holds_every_target_as_given(skill_dir, fake_collector, tmp_path):
    case = tmp_path / "case"
    argv = args(skill_dir, "--target", "thing=x", "--target", "extra=a, b", "--case-dir", str(case))
    assert collect.main(argv, runner=FakeAws({})) == 0
    document = json.loads(next((case / "evidence").iterdir()).read_text())
    assert document["asked"]["targets"] == {"thing": "x", "extra": ["a", "b"]}
    assert document["asked"]["window"] == {"start": WINDOW_START, "end": WINDOW_END}


def test_asked_is_written_when_the_collector_fails(skill_dir, monkeypatch, tmp_path):
    def run(ctx, targets):
        raise KeyError("nope")

    monkeypatch.setattr(collect, "all_collectors", lambda: {"boom": Collector("boom", "d", ("thing",), (), run)})
    case = tmp_path / "case"
    assert collect.main(args(skill_dir, "--target", "thing=y", "--case-dir", str(case), name="boom"), runner=FakeAws({})) == 0
    document = json.loads(next((case / "evidence").iterdir()).read_text())
    assert document["asked"]["targets"] == {"thing": "y"}
    assert document["errors"][0]["code"] == "CollectorError"
