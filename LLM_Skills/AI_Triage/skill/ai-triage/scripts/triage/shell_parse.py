"""Split a shell command line into simple command segments.

This is a small quote-aware scanner, not a shell. It accepts only text whose
meaning it fully understands. Anything bash would expand, substitute, or
reinterpret in a way the guard cannot see raises Unparseable, and the guard then
refuses to auto-approve the command. The scanner targets bash and zsh as Claude
Code invokes them.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&"})
HARMLESS_TARGETS = frozenset({"/dev/null"})
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
BLANKS = " \t"
# Unquoted characters that bash would expand, group, or treat as a comment.
UNQUOTED_REFUSED = frozenset("{}*?[]#()")
# What may follow $HOME, or ~, for the expansion to be a plain path prefix.
AFTER_HOME = frozenset("/'\" \t\n")
DIGITS_RE = re.compile(r"^[0-9]+$")
WORD_SPLITTING_OR_GLOB = frozenset(" \t\n*?[]{}~")


class Unparseable(Exception):
    """The command uses shell features this splitter does not model."""


@dataclass(frozen=True)
class Segment:
    argv: tuple[str, ...]
    env: tuple[str, ...]
    writes_file: bool
    preceded_by: str  # the separator before this segment, "" for the first
    reads_file: bool = False


@dataclass(frozen=True)
class _Word:
    text: str
    first_quote: int | None  # index in text where quoting or escaping began


def _home_directory() -> str:
    home = os.environ.get("HOME", "")
    if not home:
        raise Unparseable("HOME is not set, so $HOME and ~ cannot be expanded")
    return home


class _Scanner:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens: list[_Word | str] = []
        self.chars: list[str] = []
        self.in_word = False
        self.first_quote: int | None = None

    def mark_quoted(self) -> None:
        if self.first_quote is None:
            self.first_quote = len(self.chars)

    def end_word(self) -> None:
        if self.in_word:
            self.tokens.append(_Word("".join(self.chars), self.first_quote))
        self.chars, self.in_word, self.first_quote = [], False, None

    def expand_home(self, index: int, quoted: bool) -> int:
        """Handle a `$` at text[index]; return the index after the expansion."""
        text = self.text
        if text.startswith("${HOME}", index):
            end = index + len("${HOME}")
        elif text.startswith("$HOME", index):
            end = index + len("$HOME")
        else:
            raise Unparseable("contains $ expansion")
        if self.chars:
            raise Unparseable("$HOME is only expanded at the start of a word")
        following = text[end] if end < len(text) else ""
        if following and following not in AFTER_HOME:
            raise Unparseable("contains $ expansion")
        home = _home_directory()
        if not quoted and any(char in WORD_SPLITTING_OR_GLOB for char in home):
            raise Unparseable("HOME would be split or expanded by the shell")
        self.chars.extend(home)
        self.in_word = True
        self.mark_quoted()
        return end

    def scan_double_quotes(self, index: int) -> int:
        text, size = self.text, len(self.text)
        self.mark_quoted()
        self.in_word = True
        index += 1
        while True:
            if index >= size:
                raise Unparseable("unterminated double quote")
            char = text[index]
            if char == '"':
                return index + 1
            if char == "\\":
                if index + 1 >= size:
                    raise Unparseable("unterminated double quote")
                following = text[index + 1]
                if following in '$`"\\':
                    self.chars.append(following)
                    index += 2
                elif following == "\n":
                    index += 2
                else:
                    self.chars.append("\\")
                    index += 1
                continue
            if char == "$":
                index = self.expand_home(index, quoted=True)
                continue
            if char == "`":
                raise Unparseable("contains a backtick")
            self.chars.append(char)
            index += 1

    def scan_operator(self, index: int) -> int:
        text = self.text
        char = text[index]
        if char in "<>" and self.in_word and self.first_quote is None and DIGITS_RE.match("".join(self.chars)):
            # Digits written right against a redirect are a descriptor, never an argument.
            if "".join(self.chars) not in ("1", "2"):
                raise Unparseable("unusual file descriptor in a redirect")
            self.chars, self.in_word = [], False
        self.end_word()
        following = text[index + 1] if index + 1 < len(text) else ""
        if char == ";":
            if following in (";", "&"):
                raise Unparseable("unsupported operator ;" + following)
            operator = ";"
        elif char == "&":
            if following == "&":
                operator = "&&"
            elif text.startswith("&>>", index):
                operator = "&>>"
            elif following == ">":
                operator = "&>"
            else:
                operator = "&"
        elif char == "|":
            operator = "||" if following == "|" else "|&" if following == "&" else "|"
        elif char == ">":
            if following == "(":
                raise Unparseable("process substitution")
            operator = {">": ">>", "&": ">&", "|": ">|"}.get(following, ">")
        else:  # "<"
            if following in ("<", "("):
                raise Unparseable("here-document, here-string, or process substitution")
            if following == ">":
                raise Unparseable("unsupported operator <>")
            operator = "<&" if following == "&" else "<"
        self.tokens.append(operator)
        return index + len(operator)

    def scan(self) -> list[_Word | str]:
        text, size = self.text, len(self.text)
        index = 0
        while index < size:
            char = text[index]
            if char in BLANKS:
                self.end_word()
                index += 1
            elif char == "\n":
                raise Unparseable("multi-line command")
            elif char == "\\":
                if index + 1 >= size:
                    raise Unparseable("trailing backslash")
                if text[index + 1] != "\n":  # backslash-newline is a line continuation
                    self.mark_quoted()
                    self.chars.append(text[index + 1])
                    self.in_word = True
                index += 2
            elif char == "'":
                end = text.find("'", index + 1)
                if end < 0:
                    raise Unparseable("unterminated single quote")
                self.mark_quoted()
                self.chars.extend(text[index + 1 : end])
                self.in_word = True
                index = end + 1
            elif char == '"':
                index = self.scan_double_quotes(index)
            elif char == "$":
                index = self.expand_home(index, quoted=False)
            elif char == "`":
                raise Unparseable("contains a backtick")
            elif char == "~":
                following = text[index + 1] if index + 1 < size else ""
                if self.in_word or (following and following not in "/ \t\n;&|<>"):
                    raise Unparseable("contains a ~ expansion")
                self.chars.extend(_home_directory())
                self.in_word = True
                self.mark_quoted()
                index += 1
            elif char in UNQUOTED_REFUSED:
                raise Unparseable(f"contains {char}")
            elif char in ";&|<>":
                index = self.scan_operator(index)
            elif ord(char) < 0x20 or ord(char) == 0x7F or (ord(char) > 0x7F and char.isspace()):
                raise Unparseable("contains a control character or unusual whitespace")
            elif char == "=" and not self.in_word:
                raise Unparseable("a word starting with = is expanded by zsh")
            else:
                self.chars.append(char)
                self.in_word = True
                index += 1
        self.end_word()
        return self.tokens


def _is_assignment(word: _Word) -> bool:
    match = ASSIGNMENT_RE.match(word.text)
    return bool(match) and (word.first_quote is None or match.end() <= word.first_quote)


def split_command(command: str) -> list[Segment]:
    if "\x00" in command:
        raise Unparseable("contains a NUL character")
    tokens = _Scanner(command.strip(" \t\n")).scan()

    segments: list[Segment] = []
    words: list[_Word] = []
    writes_file = reads_file = False
    preceded_by = ""

    def flush(next_separator: str) -> None:
        nonlocal words, writes_file, reads_file, preceded_by
        env: list[str] = []
        while words and _is_assignment(words[0]):
            env.append(words.pop(0).text)
        if words or env or writes_file or reads_file:
            segments.append(Segment(tuple(w.text for w in words), tuple(env), writes_file, preceded_by, reads_file))
        words, writes_file, reads_file, preceded_by = [], False, False, next_separator

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if isinstance(token, _Word):
            words.append(token)
            index += 1
        elif token in SEPARATORS:
            flush(token)
            index += 1
        else:  # a redirect: it consumes the next word as its target
            if index + 1 >= len(tokens) or not isinstance(tokens[index + 1], _Word):
                raise Unparseable("redirect without a target")
            target = tokens[index + 1].text
            if token in ("<", "<&"):
                reads_file = True
            else:
                duplicates_descriptor = token == ">&" and (target.isdigit() or target == "-")
                if target not in HARMLESS_TARGETS and not duplicates_descriptor:
                    writes_file = True
            index += 2
    flush("")
    return segments
