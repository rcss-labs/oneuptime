"""The outcome of checking one command."""
from __future__ import annotations

from dataclasses import dataclass

ALLOW = "allow"
DENY = "deny"
ASK = "ask"
PASS = "pass"  # no opinion: the normal permission flow decides

# Higher wins when several segments of one command line disagree.
PRECEDENCE = {DENY: 3, ASK: 2, PASS: 1, ALLOW: 0}


@dataclass(frozen=True)
class Verdict:
    kind: str
    reason: str = ""


def strictest(verdicts: list[Verdict]) -> Verdict:
    if not verdicts:
        return Verdict(PASS)
    return max(verdicts, key=lambda verdict: PRECEDENCE[verdict.kind])
