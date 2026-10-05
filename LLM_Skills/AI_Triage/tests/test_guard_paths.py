import os

import pytest

from triage.guard_paths import (
    FILE_TOOLS,
    ProtectedRoots,
    UnresolvablePath,
    decide_file_tool,
    protected_reason,
    protected_roots,
    resolve_tool_path,
)
from triage.verdict import ASK, DENY, PASS

RUN_FILES = ["findings/checked.json", "audit.json", "case.json", "case.md", "report.md", "work-order.json",
             "slack-message.md", "timeline.md"]


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """A home with an installed skill folder and a case root holding one run folder."""
    home = tmp_path / "home"
    skill = home / ".claude" / "skills" / "ai-triage"
    (skill / "config").mkdir(parents=True)
    cases = home / ".ai-triage" / "cases"
    run = cases / "INC-1" / "20261004-101500"
    (run / "evidence").mkdir(parents=True)
    (run / "findings").mkdir()
    monkeypatch.setenv("HOME", str(home))
    roots = protected_roots(str(skill), str(cases))
    return {"home": home, "skill": skill, "cases": cases, "run": run, "roots": roots, "tmp": tmp_path}


def verdict(layout, path, cwd="/", tool="Write"):
    return decide_file_tool(tool, {FILE_TOOLS[tool]: path}, cwd, layout["roots"])


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit", "NotebookEdit"])
def test_every_file_tool_is_checked(layout, tool):
    result = verdict(layout, str(layout["skill"] / "config" / "service-map.yaml"), tool=tool)
    assert result.kind == DENY
    assert "map_suggest.py apply" in result.reason


def test_notebook_edit_reads_notebook_path(layout):
    target = str(layout["run"] / "evidence" / "x.ipynb")
    assert decide_file_tool("NotebookEdit", {"notebook_path": target}, "/", layout["roots"]).kind == DENY
    assert decide_file_tool("NotebookEdit", {"file_path": target}, "/", layout["roots"]).kind == ASK


@pytest.mark.parametrize("relative", ["scripts/triage/guard.py", "scripts/guard_hook.py", "config/service-map.yaml",
                                      "SKILL.md", "new-file.txt", "deep/new/dir/file"])
def test_anything_under_the_skill_folder_is_denied(layout, relative):
    assert verdict(layout, str(layout["skill"] / relative)).kind == DENY


@pytest.mark.parametrize(
    "relative, script",
    [("evidence/ecs.json", "collect.py"), ("evidence/new/deep.json", "collect.py"), ("judgments/q1.json", "judge.py"),
     ("findings/checked.json", "findings.py"), ("audit.json", "publish.py"), ("case.json", "case.py"),
     ("case.md", "case.py"), ("report.md", "report.py"), ("work-order.json", "report.py"),
     ("slack-message.md", "publish.py"), ("timeline.md", "timeline.py"), ("summary.json.stale", "judge.py"),
     ("findings/old.stale", "judge.py")],
)
def test_protected_run_files_are_denied_and_the_reason_names_the_script(layout, relative, script):
    result = verdict(layout, str(layout["run"] / relative))
    assert result.kind == DENY
    assert script in result.reason


@pytest.mark.parametrize("relative", ["report.json", "findings/ecs-analyst.json", "notes.md", "checked.json",
                                      "evidence.md", "findings/notes.txt"])
def test_other_run_files_pass(layout, relative):
    assert verdict(layout, str(layout["run"] / relative)).kind == PASS


def test_paths_outside_both_roots_pass(layout):
    assert verdict(layout, str(layout["tmp"] / "project" / "case.json")).kind == PASS
    assert verdict(layout, str(layout["cases"] / "INC-1" / "case.json")).kind == PASS  # not inside a run folder
    assert verdict(layout, str(layout["home"] / ".claude" / "skills" / "other" / "x")).kind == PASS


def test_a_relative_path_is_made_absolute_against_cwd(layout):
    assert verdict(layout, "evidence/ecs.json", cwd=str(layout["run"])).kind == DENY
    assert verdict(layout, "report.json", cwd=str(layout["run"])).kind == PASS
    assert verdict(layout, "../audit.json", cwd=str(layout["run"] / "findings")).kind == DENY


def test_tilde_is_expanded(layout):
    assert verdict(layout, "~/.claude/skills/ai-triage/config/service-map.yaml").kind == DENY
    assert verdict(layout, "~/.ai-triage/cases/INC-1/20261004-101500/case.md").kind == DENY


def test_dot_dot_cannot_dodge_the_check(layout):
    dodge = layout["tmp"] / "elsewhere"
    dodge.mkdir()
    assert verdict(layout, f"{dodge}/../home/.claude/skills/ai-triage/x").kind == DENY
    assert verdict(layout, f"{layout['run']}/findings/../audit.json").kind == DENY
    assert verdict(layout, f"{layout['run']}/missing/../audit.json").kind == DENY


def test_symbolic_links_cannot_dodge_the_check(layout):
    links = layout["tmp"] / "links"
    links.mkdir()
    os.symlink(layout["skill"], links / "skill")
    os.symlink(layout["run"], links / "run")
    os.symlink(layout["run"] / "evidence", links / "ev")
    assert verdict(layout, str(links / "skill" / "config" / "service-map.yaml")).kind == DENY
    assert verdict(layout, str(links / "run" / "case.json")).kind == DENY
    assert verdict(layout, str(links / "ev" / "new.json")).kind == DENY
    assert verdict(layout, str(links / "run" / "report.json")).kind == PASS


def test_a_symlinked_file_name_is_resolved(layout):
    target = layout["run"] / "audit.json"
    target.write_text("{}")
    link = layout["tmp"] / "innocent.json"
    os.symlink(target, link)
    assert verdict(layout, str(link)).kind == DENY


def test_letter_case_cannot_dodge_the_check(layout):
    # macOS file systems usually ignore letter case, so Evidence/ is the same folder as evidence/
    assert verdict(layout, str(layout["run"] / "Evidence" / "x.json")).kind == DENY
    assert verdict(layout, str(layout["run"] / "CASE.JSON")).kind == DENY
    assert verdict(layout, str(layout["run"] / "x.STALE")).kind == DENY
    upper_skill = str(layout["skill"]).replace("ai-triage", "AI-Triage")
    assert verdict(layout, upper_skill + "/config/service-map.yaml").kind == DENY


@pytest.mark.parametrize("tool_input", [{}, {"file_path": 5}, {"file_path": None}, {"file_path": ""},
                                        {"file_path": "a\x00b"}, {"file_path": ["x"]}])
def test_a_path_that_cannot_be_resolved_asks(layout, tool_input):
    assert decide_file_tool("Write", tool_input, "/", layout["roots"]).kind == ASK


def test_a_relative_path_without_a_usable_cwd_asks(layout):
    for cwd in ("", None, "relative/dir", 7):
        assert verdict(layout, "evidence/x.json", cwd=cwd).kind == ASK
    assert verdict(layout, str(layout["run"] / "case.json"), cwd=None).kind == DENY


def test_a_tool_input_that_is_not_an_object_asks(layout):
    assert decide_file_tool("Edit", "not a dict", "/", layout["roots"]).kind == ASK


def test_a_tilde_that_cannot_be_expanded_is_unresolvable(layout):
    with pytest.raises(UnresolvablePath):
        resolve_tool_path("~no-such-user-ai-triage/x", "/")


def test_the_default_case_root_and_installed_skill_folder_are_always_protected(layout):
    roots = protected_roots(str(layout["tmp"] / "some-checkout" / "skill"), "")
    assert protected_reason(str(layout["run"] / "case.json"), roots)
    assert protected_reason(str(layout["skill"] / "SKILL.md"), roots)
    assert protected_reason(str(layout["tmp"] / "some-checkout" / "skill" / "SKILL.md"), roots)


def test_protected_roots_are_resolved(layout):
    link = layout["tmp"] / "skill-link"
    os.symlink(layout["skill"], link)
    roots = protected_roots(str(link), str(layout["cases"]))
    assert isinstance(roots, ProtectedRoots)
    assert protected_reason(str(layout["skill"] / "x"), roots)


# ---- fix round 5, ruling 5 ------------------------------------------------------


@pytest.mark.parametrize("relative, script", [("incident.json", "case.py"), ("render.json", "report.py")])
def test_incident_and_render_records_are_protected(layout, relative, script):
    result = verdict(layout, str(layout["run"] / relative))
    assert result.kind == DENY and script in result.reason
    assert verdict(layout, str(layout["run"] / "findings" / relative)).kind == PASS


def test_the_docstring_names_the_hard_link_gap():
    import triage.guard_paths

    assert "hard link" in triage.guard_paths.__doc__
