"""Decide what to do with one shell command line during a triage session."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from triage.config import TriageConfig
from triage.guard_aws import check_aws
from triage.guard_kubectl import check_kubectl
from triage.shell_parse import Segment, Unparseable, split_command
from triage.verdict import ALLOW, ASK, DENY, PASS, Verdict, strictest

SENSITIVE_WORD_RE = re.compile(r"(?<![A-Za-z0-9_])(aws|kubectl)(?![A-Za-z0-9_])")
# Filters that only transform what is piped into them.
PIPE_FILTERS = frozenset({"jq", "head", "tail", "grep", "sort", "uniq", "wc", "cut", "tr", "column"})
OPENSEARCH_SCRIPT = "opensearch_query.py"
KUBECONFIG_NAME = "kubeconfig"


@dataclass(frozen=True)
class GuardContext:
    profiles: frozenset[str]
    kubeconfig: str
    kube_contexts: frozenset[str]
    opensearch_hosts: frozenset[str]
    skill_dir: str


def context_from_config(config: TriageConfig, skill_dir: Path) -> GuardContext:
    return GuardContext(
        profiles=config.profiles(),
        kubeconfig=str(skill_dir / "config" / KUBECONFIG_NAME),
        kube_contexts=config.kube_contexts(),
        opensearch_hosts=config.opensearch_hosts(),
        skill_dir=str(skill_dir),
    )


def _expand(token: str) -> str:
    home = os.path.expanduser("~")
    return os.path.normpath(os.path.expanduser(token.replace("${HOME}", home).replace("$HOME", home)))


def _is_command(word: str, name: str) -> bool:
    return word == name or word.endswith("/" + name)


def _own_script(argv: tuple[str, ...], context: GuardContext) -> str | None:
    """Return the script name when argv runs a skill script with the skill's Python."""
    if len(argv) < 2:
        return None
    interpreter, script = _expand(argv[0]), _expand(argv[1])
    scripts_dir = os.path.join(context.skill_dir, "scripts")
    if interpreter != os.path.join(context.skill_dir, ".venv", "bin", "python"):
        return None
    if os.path.dirname(script) != scripts_dir or not script.endswith(".py"):
        return None
    return os.path.basename(script)


def _mentions_host(text: str, hosts: frozenset[str]) -> bool:
    lowered = text.lower()
    return any(host and host.lower() in lowered for host in hosts)


def is_sensitive(command: str, hosts: frozenset[str] = frozenset()) -> bool:
    return bool(SENSITIVE_WORD_RE.search(command)) or _mentions_host(command, hosts)


def _check_segment(segment: Segment, context: GuardContext) -> Verdict:
    if not segment.argv:
        return Verdict(PASS)
    text = " ".join(segment.env + segment.argv)
    own_script = _own_script(segment.argv, context)
    if _mentions_host(text, context.opensearch_hosts):
        if own_script == OPENSEARCH_SCRIPT:
            return Verdict(ALLOW, "OpenSearch query through the triage tool")
        return Verdict(DENY, "OpenSearch clusters may only be reached through the opensearch_query tool")
    if own_script is not None:
        return Verdict(ALLOW, f"triage script {own_script}")
    command = segment.argv[0]
    if _is_command(command, "aws"):
        return check_aws(segment.argv, segment.env, context.profiles)
    if _is_command(command, "kubectl"):
        return check_kubectl(segment.argv, segment.env, context.kubeconfig, context.kube_contexts)
    if SENSITIVE_WORD_RE.search(text):
        return Verdict(ASK, "aws or kubectl is used indirectly, which the guard cannot check")
    if command in PIPE_FILTERS and segment.preceded_by == "|":
        return Verdict(ALLOW, f"{command} filters piped output")
    return Verdict(PASS)


def decide(command: str, context: GuardContext | None, context_error: str = "") -> Verdict:
    """Return allow, deny, ask, or pass for a whole command line."""
    if context is None:
        if is_sensitive(command):
            return Verdict(DENY, f"the triage guard has no valid config ({context_error}); fix it before running this")
        return Verdict(PASS)
    try:
        segments = split_command(command)
    except Unparseable as exc:
        if is_sensitive(command, context.opensearch_hosts):
            return Verdict(ASK, f"the guard cannot check this command ({exc})")
        return Verdict(PASS)
    verdicts: list[Verdict] = []
    for segment in segments:
        verdict = _check_segment(segment, context)
        if verdict.kind == ALLOW and segment.writes_file:
            verdict = Verdict(PASS)  # writing a local file goes through the normal permission flow
        verdicts.append(verdict)
    return strictest(verdicts)
