"""Test that text files are read and written with explicit UTF-8 encoding."""
import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conftest import SKILL_SRC

COMMAND = SKILL_SRC / "scripts" / "case.py"
SCRIPTS_DIR = SKILL_SRC / "scripts"


def test_encoding_in_all_scripts():
    """Static test: no read_text(), write_text(, or text-mode open( lacks encoding=."""
    violations = []

    # Find all Python files in scripts/
    for py_file in sorted(SCRIPTS_DIR.rglob("*.py")):
        with open(py_file, 'r', encoding='utf-8') as f:
            try:
                tree = ast.parse(f.read())
            except SyntaxError as e:
                violations.append(f"{py_file}: syntax error: {e}")
                continue

        for node in ast.walk(tree):
            # Check for .read_text() or .write_text() calls
            if isinstance(node, ast.Call):
                # read_text() or write_text()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("read_text", "write_text"):
                        # Check if encoding= is present
                        if not any(
                            (isinstance(kw.arg, str) and kw.arg == "encoding")
                            or (isinstance(kw, ast.keyword) and kw.arg == "encoding")
                            for kw in node.keywords
                        ):
                            violations.append(f"{py_file}: {node.func.attr}() call without encoding=")

                # open() with text mode
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    # Check if mode is text (default or explicitly 'r', 'w', 'a', etc. without 'b')
                    mode_arg = None
                    has_encoding = False

                    for kw in node.keywords:
                        if kw.arg == "mode":
                            if isinstance(kw.value, ast.Constant):
                                mode_arg = kw.value.value
                        elif kw.arg == "encoding":
                            has_encoding = True

                    # Check positional args for mode
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        mode_arg = node.args[1].value

                    # Default mode is 'r' (text)
                    if mode_arg is None:
                        mode_arg = 'r'

                    # Text mode if no 'b' in mode
                    if isinstance(mode_arg, str) and 'b' not in mode_arg:
                        if not has_encoding:
                            violations.append(f"{py_file}: open() text-mode call without encoding=")

    assert not violations, "\n".join(violations)


def test_case_init_preserves_utf8_characters(tmp_path, config_data, map_data):
    """Test that case.py init preserves UTF-8 characters under Latin-1 locale."""
    # Create incident with en dash, accented letter, and Hebrew word
    incident = {
        "number": "INC-123",
        "title": "Café – שרות",  # café (accented), en dash, Hebrew word
        "declared_at": "2026-10-04T10:45:00Z",
        "impact_started_at": "2026-10-04T10:42:00Z",
        "monitors": [{"name": "Monitor – 日本", "type": "API", "target": "https://example.com"}],
        "labels": ["test"],
    }

    # Setup skill directory
    config_data["cases_dir"] = str(tmp_path / "cases")
    skill_dir = tmp_path / "skill"
    (skill_dir / "config").mkdir(parents=True)
    (skill_dir / "config" / "triage-config.yaml").write_text(yaml.safe_dump(config_data))
    (skill_dir / "config" / "service-map.yaml").write_text(yaml.safe_dump(map_data))

    # Write incident file with UTF-8 encoding
    incident_file = tmp_path / "incident.json"
    incident_file.write_text(json.dumps(incident), encoding="utf-8")

    # Run case.py init with Latin-1 locale and PYTHONUTF8=0
    env = {
        "LC_ALL": "en_US.ISO8859-1",
        "PYTHONUTF8": "0",
        "PATH": Path.cwd().parent,  # Preserve PATH
    }
    result = subprocess.run(
        [sys.executable, str(COMMAND), "init", "--incident", str(incident_file),
         "--now", "2026-10-04T11:00:00Z", "--skill-dir", str(skill_dir)],
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, f"case.py failed: {result.stderr}"

    # Read case.json from the returned case_dir
    output = json.loads(result.stdout)
    case_dir = Path(output["case_dir"])
    case_file = case_dir / "case.json"

    # Read case.json with UTF-8 encoding
    case_data = json.loads(case_file.read_text(encoding="utf-8"))

    # Verify the title was preserved correctly
    assert case_data["incident"]["title"] == incident["title"]
    assert "Café" in case_data["incident"]["title"]
    assert "–" in case_data["incident"]["title"]  # en dash
    assert "שרות" in case_data["incident"]["title"]  # Hebrew


def _has_keyword(node: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in node.keywords)


def _text_mode(mode) -> bool:
    return isinstance(mode, str) and "b" not in mode


def _positional_mode(node: ast.Call, index: int):
    if len(node.args) > index:
        return node.args[index].value if isinstance(node.args[index], ast.Constant) else None
    return "r"


def other_text_io_without_encoding(source: str) -> list[str]:
    """Path.open, io.open, os.fdopen and subprocess text output, each without encoding=."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or _has_keyword(node, "encoding"):
            continue
        attr, owner = node.func.attr, node.func.value
        owner_name = owner.id if isinstance(owner, ast.Name) else None
        mode = next((kw.value.value for kw in node.keywords if kw.arg == "mode" and isinstance(kw.value, ast.Constant)), None)
        if attr == "open" and owner_name == "io":
            if _text_mode(mode or _positional_mode(node, 1)):
                found.append(f"line {node.lineno}: io.open() without encoding=")
        elif attr == "fdopen" and owner_name == "os":
            if _text_mode(mode or _positional_mode(node, 1)):
                found.append(f"line {node.lineno}: os.fdopen() without encoding=")
        elif attr == "open" and owner_name not in {"io", "os", "tarfile", "zipfile", "gzip", "webbrowser"}:
            if _text_mode(mode or _positional_mode(node, 0)):
                found.append(f"line {node.lineno}: .open() without encoding=")
        elif attr in {"run", "Popen", "check_output"} and owner_name == "subprocess":
            text = any(kw.arg in {"text", "universal_newlines"} and not (isinstance(kw.value, ast.Constant)
                       and kw.value.value is False) for kw in node.keywords)
            if text:
                found.append(f"line {node.lineno}: subprocess.{attr}(text=True) without encoding=")
    return found


def test_the_wider_check_catches_each_kind_of_call():
    assert other_text_io_without_encoding("from pathlib import Path\nPath('x').open()\n")
    assert other_text_io_without_encoding("p.open('w')\n")
    assert other_text_io_without_encoding("import io\nio.open('x')\n")
    assert other_text_io_without_encoding("import os\nos.fdopen(3, 'w')\n")
    assert other_text_io_without_encoding("import subprocess\nsubprocess.run(['x'], text=True)\n")
    assert not other_text_io_without_encoding("p.open('rb')\nimport os\nos.open('x', 0)\nos.fdopen(3, 'wb')\n")
    assert not other_text_io_without_encoding("p.open(encoding='utf-8')\nsubprocess.run(['x'], text=True, encoding='utf-8')\n")
    assert not other_text_io_without_encoding("subprocess.run(['x'], capture_output=True)\n")


def test_no_other_text_io_without_encoding_in_scripts():
    violations = []
    for py_file in sorted(SCRIPTS_DIR.rglob("*.py")):
        for problem in other_text_io_without_encoding(py_file.read_text(encoding="utf-8")):
            violations.append(f"{py_file.relative_to(SCRIPTS_DIR)}: {problem}")
    assert not violations, "\n".join(violations)
