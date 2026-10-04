"""Shared helpers for collector tests."""
from __future__ import annotations

import json
from pathlib import Path

from fakes import FakeAws
from triage.config import parse_config
from triage.context import CollectContext
from triage.evidence import Evidence
from triage.guard import KUBECONFIG_NAME
from triage.guard_aws import check_aws
from triage.guard_kubectl import check_kubectl
from triage.verdict import ALLOW
from triage.window import make_window

WINDOW_START = "2026-10-04T10:00:00Z"
WINDOW_END = "2026-10-04T12:00:00Z"
_SCOPE_OPTIONS = ("-n", "--context", "--kubeconfig")


class FakeKubectl:
    """Answers kubectl calls keyed by the verb and first argument, for example "get pods".

    Values are a JSON-serialisable result, a string (printed as is), or an
    (exit code, stderr) tuple for a failure.
    """

    def __init__(self, answers: dict[str, object]):
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        self.calls.append(argv)
        answer = self.answers.get(self._key(argv), {})
        if isinstance(answer, tuple):
            return answer[0], "", answer[1]
        return 0, answer if isinstance(answer, str) else json.dumps(answer), ""

    @staticmethod
    def _key(argv: list[str]) -> str:
        words, index = [], 1
        while index < len(argv):
            token = argv[index]
            if token in _SCOPE_OPTIONS:
                index += 2
            elif token.startswith("-"):
                index += 1
            else:
                words.append(token)
                index += 1
        return " ".join(words[:2])


def make_context(
    config_data: dict,
    tmp_path: Path,
    answers: dict[str, object],
    collector: str = "test",
    account: str = "prod-main",
    region: str = "eu-west-1",
    kube_answers: dict[str, object] | None = None,
) -> tuple[CollectContext, FakeAws, FakeKubectl]:
    config = parse_config(config_data)
    window = make_window(WINDOW_START, WINDOW_END, config.limits["max_window_hours"])
    evidence = Evidence(collector, account, region, window)
    fake_aws, fake_kubectl = FakeAws(answers), FakeKubectl(kube_answers or {})
    ctx = CollectContext(
        config, config.accounts[account], region, window, evidence, tmp_path,
        runner=fake_aws, kube_runner=fake_kubectl,
    )
    return ctx, fake_aws, fake_kubectl


def assert_read_only(ctx: CollectContext, fake_aws: FakeAws, fake_kubectl: FakeKubectl | None = None) -> None:
    """Fail unless every recorded call would be allowed by the real guards."""
    profiles = ctx.config.profiles()
    for argv in fake_aws.calls:
        verdict = check_aws(tuple(argv), (), profiles)
        assert verdict.kind == ALLOW, f"{' '.join(argv)}: {verdict.reason}"
    kubeconfig = str(ctx.skill_dir / "config" / KUBECONFIG_NAME)
    contexts = ctx.config.kube_contexts()
    for argv in fake_kubectl.calls if fake_kubectl else []:
        verdict = check_kubectl(tuple(argv), (), kubeconfig, contexts)
        assert verdict.kind == ALLOW, f"{' '.join(argv)}: {verdict.reason}"


def fact_summaries(ctx: CollectContext) -> list[str]:
    return [fact.summary for fact in ctx.evidence.facts]
