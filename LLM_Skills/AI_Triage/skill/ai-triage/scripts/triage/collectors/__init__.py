"""Registry of evidence collectors. A collector is a module with a module-level COLLECTOR."""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Callable

from triage.context import CollectContext


@dataclass(frozen=True)
class Collector:
    name: str
    description: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    run: Callable[[CollectContext, dict[str, str]], None]


def all_collectors() -> dict[str, Collector]:
    """Import every module in this package and return the COLLECTOR of each one that has it."""
    found: dict[str, Collector] = {}
    for module_info in pkgutil.iter_modules(__path__):
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        collector = getattr(module, "COLLECTOR", None)
        if collector is None:
            continue
        if collector.name in found:
            raise ValueError(f"two collectors are named {collector.name}")
        found[collector.name] = collector
    return found
