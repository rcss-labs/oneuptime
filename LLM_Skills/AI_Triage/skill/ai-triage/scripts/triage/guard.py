"""Decide what to do with one shell command line during a triage session."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from triage.config import TriageConfig
from triage.guard_aws import check_aws
from triage.guard_kubectl import check_kubectl
from triage.guard_paths import CLOBBER_OPERATOR, protected_write_tripwire, redirect_targets
from triage.shell_parse import Segment, Unparseable, split_command
from triage.verdict import ALLOW, ASK, DENY, PASS, Verdict, strictest

SENSITIVE_WORD_RE = re.compile(
    r"(?<![A-Za-z0-9_])(aws|awscli|kubectl|eksctl|helm|boto3|botocore)(?![A-Za-z0-9_])"
)
OPENSEARCH_SCRIPT = "opensearch_query.py"
KUBECONFIG_NAME = "kubeconfig"
# The scripts the skill ships. A new script is not trusted until it is added here.
OWN_SCRIPTS = frozenset(
    {
        "preflight.py",
        "validate_map.py",
        "verify_access.py",
        "opensearch_query.py",
        "collect.py",
        "discover.py",
        "case.py",
        "findings.py",
        "timeline.py",
        "report.py",
        "judge.py",
        "publish.py",
        "map_suggest.py",
    }
)

ACCEPT_HITS_FLAG = "--accept-hits"
SKILL_DIR_FLAG = "--skill-dir"
APPLY_SUBCOMMAND = "apply"

JQ_FLAGS = frozenset({"-r", "-c", "-S", "-e", "-M", "--raw-output", "--compact-output", "--sort-keys"})
# jq programs that could read the environment or other files, shell-quote output, or never end.
JQ_FORBIDDEN = ("env", "$ENV", "input", "$__loc__", "@sh", "import", "include", "modulemeta", "get_search_list",
                "repeat", "while", "until", "recurse", "range", "limit")
WC_FLAGS = frozenset({"-l", "-c", "-w", "-m"})
SORT_FLAGS = frozenset({"-r", "-n", "-u", "-h"})
SORT_VALUE_FLAGS = frozenset({"-k", "-t"})
UNIQ_FLAGS = frozenset({"-c", "-d", "-u", "-i"})
CUT_VALUE_FLAGS = frozenset({"-d", "-f", "-c"})
TR_FLAGS = frozenset({"-d", "-s", "-c"})
DIGITS_RE = re.compile(r"^[0-9]+$")
DASH_NUMBER_RE = re.compile(r"^-[0-9]+$")


@dataclass(frozen=True)
class GuardContext:
    profiles: frozenset[str]
    kubeconfig: str
    kube_contexts: frozenset[str]
    opensearch_hosts: frozenset[str]
    skill_dir: str
    cases_dir: str = ""


def context_from_config(config: TriageConfig, skill_dir: Path) -> GuardContext:
    return GuardContext(
        profiles=config.profiles(),
        kubeconfig=str(skill_dir / "config" / KUBECONFIG_NAME),
        kube_contexts=config.kube_contexts(),
        opensearch_hosts=config.opensearch_hosts(),
        skill_dir=str(skill_dir),
        cases_dir=str(config.cases_dir),
    )


def _same_path(word: str, expected: str) -> bool:
    """True when word is expected, ignoring redundant slashes. A word with .. never matches."""
    if ".." in word.split("/"):
        return False
    return os.path.normpath(word) == os.path.normpath(expected)


def _own_script(argv: tuple[str, ...], context: GuardContext) -> str | None:
    """Return the script name when argv runs a listed skill script with the skill's Python."""
    if len(argv) < 2:
        return None
    interpreters = (os.path.join(context.skill_dir, ".venv", "bin", name) for name in ("python", "python3"))
    if not any(_same_path(argv[0], interpreter) for interpreter in interpreters):
        return None
    scripts_dir = os.path.join(context.skill_dir, "scripts")
    name = os.path.basename(os.path.normpath(argv[1]))
    if name in OWN_SCRIPTS and _same_path(argv[1], os.path.join(scripts_dir, name)):
        return name
    return None


def _mentions_host(text: str, hosts: frozenset[str]) -> bool:
    lowered = text.lower()
    return any(host and host.lower() in lowered for host in hosts)


def _mentions_tool(text: str) -> bool:
    without_quotes = text.replace("'", "").replace('"', "").replace("\\", "")
    return bool(SENSITIVE_WORD_RE.search(text) or SENSITIVE_WORD_RE.search(without_quotes))


def is_sensitive(command: str, hosts: frozenset[str] = frozenset()) -> bool:
    return _mentions_tool(command) or _mentions_host(command, hosts)


def _consume_flags(args: list[str], flags: frozenset[str], value_flags: frozenset[str] = frozenset()) -> int | None:
    """Return how many leading args are flags (with their values), or None when a value is missing."""
    index = 0
    while index < len(args):
        if args[index] in flags:
            index += 1
        elif args[index] in value_flags:
            if index + 1 >= len(args):
                return None
            index += 2
        else:
            break
    return index


def _only_flags(args: list[str], flags: frozenset[str], value_flags: frozenset[str] = frozenset()) -> bool:
    return _consume_flags(args, flags, value_flags) == len(args)


def _jq_ok(args: list[str]) -> bool:
    used = _consume_flags(args, JQ_FLAGS)
    rest = args[used:]
    if len(rest) != 1 or rest[0].startswith("-"):
        return False
    return not any(word in rest[0] for word in JQ_FORBIDDEN)


def _head_tail_ok(args: list[str]) -> bool:
    if not args:
        return True
    if len(args) == 1:
        return bool(DASH_NUMBER_RE.match(args[0]))
    return len(args) == 2 and args[0] in ("-n", "-c") and bool(DIGITS_RE.match(args[1]))


def _cut_ok(args: list[str]) -> bool:
    if not args:
        return False
    index = 0
    while index < len(args):
        if args[index] not in CUT_VALUE_FLAGS or index + 1 >= len(args):
            return False
        index += 2
    return True


def _tr_ok(args: list[str]) -> bool:
    operands = args[_consume_flags(args, TR_FLAGS):]
    return 1 <= len(operands) <= 2 and not any(len(word) > 1 and word.startswith("-") for word in operands)


def _column_ok(args: list[str]) -> bool:
    return _only_flags(args, frozenset({"-t"}), frozenset({"-s"}))


# grep is not here: Claude Code's shell snapshot defines grep as a function, so the guard cannot know what runs.
FILTER_RULES = {
    "jq": _jq_ok,
    "head": _head_tail_ok,
    "tail": _head_tail_ok,
    "wc": lambda args: _only_flags(args, WC_FLAGS),
    "sort": lambda args: _only_flags(args, SORT_FLAGS, SORT_VALUE_FLAGS),
    "uniq": lambda args: _only_flags(args, UNIQ_FLAGS),
    "cut": _cut_ok,
    "tr": _tr_ok,
    "column": _column_ok,
}


def _is_safe_filter(segment: Segment) -> bool:
    """A transform of piped text that cannot read or write a file or run code."""
    if segment.preceded_by != "|" or segment.env or segment.reads_file or segment.writes_file:
        return False
    rule = FILTER_RULES.get(segment.argv[0])
    return rule is not None and rule(list(segment.argv[1:]))


def _never_allow_with_env(verdict: Verdict, segment: Segment) -> Verdict:
    """Environment assignments change how a tool behaves, so they never ride on an allow."""
    if verdict.kind == ALLOW and segment.env:
        return Verdict(ASK, "environment variables are set on the command line")
    return verdict


def _check_segment(segment: Segment, context: GuardContext) -> Verdict:
    if not segment.argv:
        return Verdict(PASS)
    text = " ".join(segment.env + segment.argv)
    own_script = _own_script(segment.argv, context)
    if _mentions_host(text, context.opensearch_hosts):
        if own_script == OPENSEARCH_SCRIPT:
            return _never_allow_with_env(_own_script_verdict(segment, own_script), segment)
        return Verdict(DENY, "OpenSearch clusters may only be reached through the opensearch_query tool")
    if own_script is not None:
        return _own_script_verdict(segment, own_script)
    command = segment.argv[0]
    if command == "aws":
        return _never_allow_with_env(check_aws(segment.argv, segment.env, context.profiles), segment)
    if command == "kubectl":
        verdict = check_kubectl(segment.argv, segment.env, context.kubeconfig, context.kube_contexts)
        return _never_allow_with_env(verdict, segment)
    if _is_safe_filter(segment):
        return Verdict(ALLOW, f"{command} filters piped output")
    if _mentions_tool(text):
        return Verdict(ASK, "aws or kubectl is used indirectly, which the guard cannot check")
    return Verdict(PASS)


def _is_accept_hits(arg: str) -> bool:
    """--accept-hits, with or without =value, or any abbreviation argparse would expand to it."""
    head = arg.split("=", 1)[0]
    return arg.startswith(ACCEPT_HITS_FLAG) or (len(head) > 2 and ACCEPT_HITS_FLAG.startswith(head))


# Own-script options that point a script at other inputs or past a safety check; the engineer decides.
REDIRECTING_FLAGS = {
    SKILL_DIR_FLAG: "points the script at another skill folder, with its own config and service map",
    "--config": "points the script at another config",
    "--map": "points the script at another service map",
    "--allow-replay": "publishes a replay run, whose evidence comes from recordings",
}


def _carries_flag(arg: str, flag: str) -> bool:
    """The flag, with or without =value, or an abbreviation argparse would expand to it."""
    head = arg.split("=", 1)[0]
    return len(head) > 2 and flag.startswith(head)


def _is_apply(arg: str) -> bool:
    # Some Python versions let argparse expand an abbreviated subcommand, so a prefix counts too.
    return len(arg) >= 2 and APPLY_SUBCOMMAND.startswith(arg)


def _engineer_must_approve(name: str, args: tuple[str, ...]) -> str:
    """The reason an own-script call always needs the engineer, or "" when it does not."""
    if name == "map_suggest.py" and any(_is_apply(arg) for arg in args):
        return "map_suggest.py apply writes an entry to your service map"
    if name == "publish.py" and any(_is_accept_hits(arg) for arg in args):
        return "publish.py --accept-hits publishes although the audit found possible secrets"
    for flag, effect in REDIRECTING_FLAGS.items():
        if any(_carries_flag(arg, flag) for arg in args):
            return f"{name} {flag} {effect}"
    return ""


def _own_script_verdict(segment: Segment, name: str) -> Verdict:
    if segment.env or segment.reads_file:
        return Verdict(ASK, f"triage script {name} is run with environment variables or an input redirect")
    approval = _engineer_must_approve(name, segment.argv[2:])
    if approval:
        return Verdict(ASK, approval)
    return Verdict(ALLOW, f"triage script {name}" if name != OPENSEARCH_SCRIPT else "OpenSearch query through the triage tool")


def decide(command: str, context: GuardContext | None, context_error: str = "", cwd: str = "") -> Verdict:
    """Return allow, deny, ask, or pass for a whole command line run in cwd."""
    verdict = _decide_command(command, context, context_error)
    readable = command
    try:
        segments = split_command(readable)
    except Unparseable:
        if CLOBBER_OPERATOR not in command:
            return verdict  # never allowed, so it needs no tripwire
        readable = command.replace(CLOBBER_OPERATOR, ">")  # the scanner refuses >|; read it as > for the tripwire
        try:
            segments = split_command(readable)
        except Unparseable:
            return verdict
    skill_dir, cases_dir = (context.skill_dir, context.cases_dir) if context else ("", "")
    tripwire = protected_write_tripwire(segments, skill_dir, cases_dir, cwd, redirect_targets(readable))
    return strictest([verdict, Verdict(ASK, tripwire)]) if tripwire else verdict


def _decide_command(command: str, context: GuardContext | None, context_error: str) -> Verdict:
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
