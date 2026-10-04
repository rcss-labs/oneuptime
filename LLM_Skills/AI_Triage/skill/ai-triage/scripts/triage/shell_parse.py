"""Split a shell command line into simple command segments.

This is deliberately conservative. Anything it cannot split with confidence
raises Unparseable, and the guard then refuses to auto-approve the command.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

PUNCTUATION = set("();<>|&")
SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&"})
REDIRECTS = frozenset({">", ">>", "<", ">&", "<&", "&>", "&>>", ">|"})
HARMLESS_TARGETS = frozenset({"/dev/null"})
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
UNSUPPORTED_SNIPPETS = ("$(", "`", "<(", ">(", "<<")


class Unparseable(Exception):
    """The command uses shell features this splitter does not model."""


@dataclass(frozen=True)
class Segment:
    argv: tuple[str, ...]
    env: tuple[str, ...]
    writes_file: bool
    preceded_by: str  # the separator before this segment, "" for the first


def _is_operator(token: str) -> bool:
    return bool(token) and all(char in PUNCTUATION for char in token)


def split_command(command: str) -> list[Segment]:
    text = command.replace("\\\n", " ").strip()
    if "\n" in text:
        raise Unparseable("multi-line command")
    for snippet in UNSUPPORTED_SNIPPETS:
        if snippet in text:
            raise Unparseable(f"contains {snippet}")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise Unparseable(str(exc)) from exc

    segments: list[Segment] = []
    words: list[str] = []
    writes_file = False
    preceded_by = ""

    def flush(next_separator: str) -> None:
        nonlocal words, writes_file, preceded_by
        env: list[str] = []
        while words and ASSIGNMENT_RE.match(words[0]):
            env.append(words.pop(0))
        if words or env:
            segments.append(Segment(tuple(words), tuple(env), writes_file, preceded_by))
        words, writes_file, preceded_by = [], False, next_separator

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not _is_operator(token):
            words.append(token)
            index += 1
            continue
        if token in SEPARATORS:
            flush(token)
            index += 1
            continue
        if token in REDIRECTS:
            if index + 1 >= len(tokens) or _is_operator(tokens[index + 1]):
                raise Unparseable("redirect without a target")
            target = tokens[index + 1]
            if words and words[-1] in ("1", "2") and token != "<":
                words.pop()  # a file descriptor number such as the 2 in 2>/dev/null
            duplicates_descriptor = token in (">&", "<&") and (target.isdigit() or target == "-")
            if token != "<" and target not in HARMLESS_TARGETS and not duplicates_descriptor:
                writes_file = True
            index += 2
            continue
        raise Unparseable(f"unsupported operator {token}")
    flush("")
    return segments
