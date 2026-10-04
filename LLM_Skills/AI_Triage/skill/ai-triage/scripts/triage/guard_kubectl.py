"""Decide whether one kubectl invocation is a triage read."""
from __future__ import annotations

import os
import re

from triage.verdict import ALLOW, ASK, DENY, Verdict

# Every option must be on one of these two lists, in this exact spelling. kubectl
# decides where the verb is by knowing each option's arity, so an option the
# guard does not know could move the verb. Anything not listed is denied.
SHORT_TO_LONG = {"-n": "--namespace", "-o": "--output", "-l": "--selector", "-c": "--container"}
VALUE_OPTIONS = frozenset(
    {
        "--kubeconfig",
        "--context",
        "-n",
        "--namespace",
        "-o",
        "--output",
        "-l",
        "--selector",
        "--field-selector",
        "--sort-by",
        "--since",
        "--since-time",
        "--tail",
        "-c",
        "--container",
        "--limit-bytes",
        "--request-timeout",
        "--max-log-requests",
        "--for",
        "--types",
        "--revision",
    }
)
FLAG_OPTIONS = frozenset(
    {
        "-A",
        "--all-namespaces",
        "-p",
        "--previous",
        "--timestamps",
        "--all-containers",
        "--show-labels",
        "--no-headers",
        "--ignore-not-found",
        "--prefix",
        "--containers",
    }
)
LOG_BOUNDS = ("--since", "--since-time", "--tail", "--limit-bytes")
OUTPUT_FORMATS = frozenset({"wide", "json", "yaml", "name"})
OUTPUT_PREFIXES = ("jsonpath=", "custom-columns=")
MAX_TAIL = 5000
SINCE_RE = re.compile(r"^[0-9]+[smh]$")
WHOLE_NUMBER_RE = re.compile(r"^[0-9]+$")
READ_VERBS = frozenset({"get", "describe", "logs", "events", "top", "version", "api-resources", "api-versions", "explain"})
READ_SUBCOMMANDS = {"rollout": frozenset({"status", "history"}), "auth": frozenset({"can-i", "whoami"})}
NAMESPACED_VERBS = frozenset({"get", "describe", "logs", "events", "top", "rollout"})
CLUSTER_SCOPED = frozenset(
    {
        "namespaces", "namespace", "ns",
        "nodes", "node", "no",
        "persistentvolumes", "persistentvolume", "pv",
        "storageclasses", "storageclass", "sc",
        "customresourcedefinitions", "customresourcedefinition", "crd", "crds",
        "clusterroles", "clusterrolebindings", "ingressclasses", "priorityclasses",
    }
)
SECRET_NAMES = frozenset({"secret", "secrets"})


class _Denied(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _bad_value(word: str) -> _Denied:
    return _Denied(f"kubectl option {word} has a value that is not allowed during triage")


def _check_value(name: str, value: str, word: str) -> None:
    if name == "--tail" and not (WHOLE_NUMBER_RE.match(value) and 1 <= int(value) <= MAX_TAIL):
        raise _bad_value(word)
    if name == "--since" and not SINCE_RE.match(value):
        raise _bad_value(word)
    if name == "--limit-bytes" and not (WHOLE_NUMBER_RE.match(value) and int(value) >= 1):
        raise _bad_value(word)
    if name == "--output" and value not in OUTPUT_FORMATS and not value.startswith(OUTPUT_PREFIXES):
        raise _bad_value(word)


def _parse(argv: tuple[str, ...]) -> tuple[dict[str, list[str]], list[str]]:
    """Return the values of every option given, and the positional words. Raises _Denied."""
    options: dict[str, list[str]] = {}
    positionals: list[str] = []
    index = 1
    while index < len(argv):
        word = argv[index]
        index += 1
        if not word.startswith("-"):
            positionals.append(word)
            continue
        name, equals, attached = word.partition("=")
        if equals and name.startswith("--") and name in VALUE_OPTIONS:
            value = attached
        elif word in VALUE_OPTIONS:
            if index >= len(argv):
                raise _Denied(f"kubectl option {word} needs a value")
            value = argv[index]
            index += 1
            name = word
        elif word in FLAG_OPTIONS:
            options.setdefault(word, [])
            continue
        else:
            raise _Denied(f"kubectl option {word} is not allowed during triage")
        name = SHORT_TO_LONG.get(name, name)
        _check_value(name, value, word)
        options.setdefault(name, []).append(value)
    return options, positionals


def _resource_kinds(arguments: list[str]) -> set[str]:
    """Resource kinds named by `get pods,secrets` or `describe secret/x`."""
    kinds: set[str] = set()
    for argument in arguments:
        for part in argument.split(","):
            kinds.add(part.split("/", 1)[0].split(".", 1)[0].lower())
    return kinds


def check_kubectl(argv: tuple[str, ...], env: tuple[str, ...], kubeconfig: str, contexts: frozenset[str]) -> Verdict:
    if any(assignment.startswith("KUBECONFIG=") for assignment in env):
        return Verdict(ASK, "KUBECONFIG is set on the command line")
    try:
        options, positionals = _parse(argv)
    except _Denied as denied:
        return Verdict(DENY, denied.reason)

    given_kubeconfigs = options.get("--kubeconfig", [])
    if not given_kubeconfigs:
        return Verdict(DENY, f"every kubectl command must set --kubeconfig {kubeconfig}")
    for given in given_kubeconfigs:
        if os.path.normpath(given) != os.path.normpath(kubeconfig):
            return Verdict(DENY, "kubectl must use the triage kubeconfig, not another one")
    given_contexts = options.get("--context", [])
    if not given_contexts:
        return Verdict(DENY, "every kubectl command must set --context to a triage context")
    for context in given_contexts:
        if context not in contexts:
            return Verdict(DENY, f"context '{context}' is not a triage context")

    if not positionals:
        return Verdict(ASK, "no kubectl verb given")
    verb, rest = positionals[0], positionals[1:]
    if verb in READ_SUBCOMMANDS:
        if not rest or rest[0] not in READ_SUBCOMMANDS[verb]:
            return Verdict(DENY, f"kubectl {verb} {rest[0] if rest else ''} is not a read".rstrip())
        rest = rest[1:]
    elif verb not in READ_VERBS:
        return Verdict(DENY, f"kubectl {verb} is not a read")

    if verb == "logs" and not any(bound in options for bound in LOG_BOUNDS):
        return Verdict(DENY, "kubectl logs must be bounded with --since, --since-time, --tail, or --limit-bytes")
    if verb in ("get", "describe") and _resource_kinds(rest) & SECRET_NAMES:
        return Verdict(DENY, "reading Kubernetes secrets is not allowed")
    kinds = _resource_kinds(rest[:1]) if verb in ("get", "describe") else set()

    has_namespace = any(name in options for name in ("--namespace", "-A", "--all-namespaces"))
    cluster_scoped = bool(kinds) and kinds <= CLUSTER_SCOPED
    if verb == "top" and rest[:1] and rest[0] in CLUSTER_SCOPED:
        cluster_scoped = True
    if verb in NAMESPACED_VERBS and not has_namespace and not cluster_scoped:
        return Verdict(DENY, "set a namespace with -n <namespace> or -A")
    return Verdict(ALLOW, f"kubectl {verb} is a read")
