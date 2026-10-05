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
