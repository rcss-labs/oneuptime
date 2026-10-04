"""A scripted stand-in for the AWS CLI, used by the tests."""
from __future__ import annotations

import json


class FakeAws:
    """Answers `aws <service> <operation>` calls from a table.

    Keys are "service operation" or "profile service operation"; the more
    specific key wins. Values are a JSON-serialisable result, or an
    (exit code, stderr) tuple for a failure.
    """

    def __init__(self, answers: dict[str, object], default: object = None):
        self.answers = answers
        self.default = {} if default is None else default
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        self.calls.append(argv)
        profile = argv[argv.index("--profile") + 1]
        key = f"{argv[1]} {argv[2]}"
        answer = self.answers.get(f"{profile} {key}", self.answers.get(key, self.default))
        if isinstance(answer, tuple):
            return answer[0], "", answer[1]
        return 0, json.dumps(answer), ""

    def called(self, service: str, operation: str) -> list[list[str]]:
        return [argv for argv in self.calls if argv[1:3] == [service, operation]]


def access_denied(action: str) -> tuple[int, str]:
    return 254, f"An error occurred (AccessDeniedException) when calling the {action} operation: not authorized"


SSO_EXPIRED_ERROR = (255, "Error loading SSO Token: Token for my-sso does not exist")


from typing import Any, Callable  # noqa: E402  (added with FakeJudge; the module above is unchanged)

from triage.judge_client import JudgeReply, JudgeUnavailable  # noqa: E402


class FakeJudge:
    """A scripted stand-in for the TypeSafe judge.

    `answers` is a table of question id to plain answer, or a function taking the
    state and the questions and returning that table. With `fail_with` set, every
    call raises JudgeUnavailable. `calls` records (state, questions) of each call.
    """

    def __init__(self, answers: dict[str, dict] | Callable[[Any, dict], dict[str, dict]] | None = None, fail_with: str | None = None):
        self.answers = answers if answers is not None else {}
        self.fail_with = fail_with
        self.calls: list[tuple[Any, dict]] = []

    def ask(self, state: Any, questions: dict[str, dict]) -> JudgeReply:
        self.calls.append((state, questions))
        if self.fail_with is not None:
            raise JudgeUnavailable(self.fail_with)
        if callable(self.answers):
            answers = self.answers(state, questions)
        else:
            answers = {question_id: self.answers[question_id] for question_id in questions}
        return JudgeReply(
            answers=answers,
            model="jev-test",
            request_id=f"req-{len(self.calls):03d}",
            usage={"input_tokens": 10 * len(self.calls), "output_tokens": 2},
        )
