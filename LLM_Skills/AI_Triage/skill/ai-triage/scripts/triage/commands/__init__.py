"""The commands of run.py: one module per command, each with build_parser() and main(argv).

COMMANDS is the fixed list: run.py dispatches only these, and the guard trusts only these.
"""
from __future__ import annotations

COMMANDS = ("case", "collect", "discover", "findings", "judge", "map_suggest", "opensearch_query", "preflight",
            "publish", "report", "timeline", "validate_map", "verify_access")
