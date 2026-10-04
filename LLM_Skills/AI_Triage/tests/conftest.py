"""Shared fixtures."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SKILL_SRC = ROOT / "skill" / "ai-triage"
EXAMPLE_CONFIG = SKILL_SRC / "config" / "triage-config.example.yaml"
EXAMPLE_MAP = SKILL_SRC / "config" / "service-map.example.yaml"


@pytest.fixture
def config_data() -> dict:
    """A fresh, valid config document that a test may mutate."""
    return copy.deepcopy(yaml.safe_load(EXAMPLE_CONFIG.read_text()))


@pytest.fixture
def map_data() -> dict:
    """A fresh, valid service map document that a test may mutate."""
    return copy.deepcopy(yaml.safe_load(EXAMPLE_MAP.read_text()))
