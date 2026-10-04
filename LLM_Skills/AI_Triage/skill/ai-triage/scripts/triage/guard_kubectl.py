"""Decide whether one kubectl invocation is a triage read."""
from __future__ import annotations

import os

from triage.verdict import ALLOW, ASK, DENY, Verdict

VALUE_OPTIONS = frozenset(
    {
        "--kubeconfig",
        "--context",
        "-n",
        "--namespace",
        "--cluster",
        "--user",
        "--request-timeout",
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
        "--chunk-size",
        "--max-log-requests",
    }
)
FORBIDDEN_OPTIONS = ("--as", "--as-group", "--token", "--server", "-s", "--raw", "--insecure-skip-tls-verify")
UNBOUNDED_OPTIONS = ("-f", "--follow", "-w", "--watch", "--watch-only")
LOG_BOUNDS = ("--since", "--since-time", "--tail", "--limit-bytes")
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


def _has_option(argv: tuple[str, ...], names: tuple[str, ...]) -> str | None:
    for token in argv[1:]:
        for name in names:
            if token == name or token.startswith(name + "="):
                return name
    return None


def _option_values(argv: tuple[str, ...], name: str) -> list[str]:
    """Every value given for an option. kubectl lets an option repeat and uses the last."""
    values: list[str] = []
    for index, token in enumerate(argv):
        if token == name and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith(name + "="):
            values.append(token.split("=", 1)[1])
    return values


def _positionals(argv: tuple[str, ...]) -> list[str]:
    result: list[str] = []
    index = 1
    while index < len(argv):
        token = argv[index]
        if token.startswith("-"):
            index += 2 if token in VALUE_OPTIONS else 1
            continue
        result.append(token)
        index += 1
    return result


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
    forbidden = _has_option(argv, FORBIDDEN_OPTIONS)
    if forbidden:
        return Verdict(DENY, f"kubectl {forbidden} is not allowed during triage")

    given_kubeconfigs = _option_values(argv, "--kubeconfig")
    if not given_kubeconfigs:
        return Verdict(DENY, f"every kubectl command must set --kubeconfig {kubeconfig}")
    for given in given_kubeconfigs:
        if os.path.normpath(os.path.expanduser(given)) != os.path.normpath(kubeconfig):
            return Verdict(DENY, "kubectl must use the triage kubeconfig, not another one")
    given_contexts = _option_values(argv, "--context")
    if not given_contexts:
        return Verdict(DENY, "every kubectl command must set --context to a triage context")
    for context in given_contexts:
        if context not in contexts:
            return Verdict(DENY, f"context '{context}' is not a triage context")

    positionals = _positionals(argv)
    if not positionals:
        return Verdict(ASK, "no kubectl verb given")
    verb, rest = positionals[0], positionals[1:]
    if verb in READ_SUBCOMMANDS:
        if not rest or rest[0] not in READ_SUBCOMMANDS[verb]:
            return Verdict(DENY, f"kubectl {verb} {rest[0] if rest else ''} is not a read".rstrip())
        rest = rest[1:]
    elif verb not in READ_VERBS:
        return Verdict(DENY, f"kubectl {verb} is not a read")

    unbounded = _has_option(argv, UNBOUNDED_OPTIONS)
    if unbounded:
        return Verdict(DENY, f"kubectl {unbounded} never ends; bound the output instead")
    if verb == "logs" and _has_option(argv, LOG_BOUNDS) is None:
        return Verdict(DENY, "kubectl logs must be bounded with --since, --since-time, or --tail")
    kinds = _resource_kinds(rest[:1]) if verb in ("get", "describe") else set()
    if kinds & SECRET_NAMES:
        return Verdict(DENY, "reading Kubernetes secrets is not allowed")

    has_namespace = _has_option(argv, ("-n", "--namespace", "-A", "--all-namespaces")) is not None
    cluster_scoped = bool(kinds) and kinds <= CLUSTER_SCOPED
    if verb == "top" and rest[:1] and rest[0] in CLUSTER_SCOPED:
        cluster_scoped = True
    if verb in NAMESPACED_VERBS and not has_namespace and not cluster_scoped:
        return Verdict(DENY, "set a namespace with -n <namespace> or -A")
    return Verdict(ALLOW, f"kubectl {verb} is a read")
