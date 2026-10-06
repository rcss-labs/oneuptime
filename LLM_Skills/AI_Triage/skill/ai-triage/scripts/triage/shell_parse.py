"""Split a shell command line into simple command segments.

This is a small quote-aware scanner, not a shell. It accepts only text whose
meaning it fully understands. Anything zsh (or bash) would expand, substitute, or
reinterpret in a way the guard cannot see raises Unparseable, and the guard then
refuses to auto-approve the command.

Outside quotes a word may hold only the characters in WORD_CHARS. Beyond those,
the scanner accepts single and double quotes, backslash escapes, $HOME at the
start of a word, blanks, the separators | and &&, and a fixed set of output
redirects. There is no input redirect: an unquoted < is always refused, which
also covers zsh numeric globs, process substitution, and here-documents.
"""
from __future__ import annotations

import os
import re
import string
from dataclasses import dataclass

SEPARATORS = frozenset({"&&", "|"})
HARMLESS_TARGETS = frozenset({"/dev/null"})
REDIRECT_OPERATORS = frozenset({">", ">>", "&>", "&>>"})  # the operators whose target is a file name
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
BLANKS = " \t"
# The only characters an unquoted word may contain; anything else is refused unless a rule below accepts it.
WORD_CHARS = frozenset(string.ascii_letters + string.digits + "-_./:=,@%+")
# What may follow $HOME for the expansion to be a plain path prefix.
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
    reads_file: bool = False  # always False now that input redirects are refused; kept for the guard


@dataclass(frozen=True)
class _Word:
    text: str
    first_quote: int | None  # index in text where quoting or escaping began


def _home_directory() -> str:
    home = os.environ.get("HOME", "")
    if not home:
        raise Unparseable("HOME is not set, so $HOME cannot be expanded")
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
        if text.startswith("${HOME}", index) and quoted:  # unquoted braces are outside the allow-list
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
        digits = "".join(self.chars) if self.in_word and self.first_quote is None else ""
        if DIGITS_RE.match(digits) and char in ">&":
            # Digits written right against a redirect are a descriptor, never an argument.
            # Only the descriptors 1 and 2 before > are accepted.
            if char != ">" or digits not in ("1", "2"):
                raise Unparseable("unusual file descriptor in a redirect")
            self.chars, self.in_word = [], False
        self.end_word()
        following = text[index + 1] if index + 1 < len(text) else ""
        if char == "&":
            if following == "&":
                operator = "&&"
            elif following == ">":
                # zsh drops a descriptor glued to &>, so &> must stand alone as a word start.
                if index > 0 and text[index - 1] not in BLANKS:
                    raise Unparseable("&> must follow whitespace")
                operator = "&>>" if text.startswith("&>>", index) else "&>"
            else:
                raise Unparseable("only && and &> may start with &")
        elif char == "|":
            if following in ("|", "&"):
                raise Unparseable("unsupported operator |" + following)
            operator = "|"
        else:  # ">"
            if following == "(":
                raise Unparseable("process substitution")
            if following == "|":
                raise Unparseable("unsupported operator >|")
            operator = {">": ">>", "&": ">&"}.get(following, ">")
        after = index + len(operator)
        if operator in REDIRECT_OPERATORS and text[after : after + 1] == "!":
            raise Unparseable("zsh clobber override")
        self.tokens.append(operator)
        return after

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
            elif char == "<":
                raise Unparseable("contains an unquoted < (input redirect or zsh numeric glob)")
            elif char in "&|>":
                index = self.scan_operator(index)
            elif char == "=" and not self.chars:
                # zsh ignores empty quotes here, so ''=ls is expanded just like =ls
                raise Unparseable("a word starting with = is expanded by zsh")
            elif char in WORD_CHARS:
                self.chars.append(char)
                self.in_word = True
                index += 1
            else:
                raise Unparseable(f"contains the unquoted character {char!r}")
        self.end_word()
        return self.tokens


def _is_assignment(word: _Word) -> bool:
    match = ASSIGNMENT_RE.match(word.text)
    return bool(match) and (word.first_quote is None or match.end() <= word.first_quote)


def redirect_targets(command: str) -> list[str]:
    """The file names of output redirects in a command split_command accepts (>&1 and >&2 are not files).

    The guard's tripwire reads them from the scanner's tokens: a segment does not keep its redirects."""
    tokens = _Scanner(command.strip(" \t\n")).scan()
    return [tokens[index + 1].text for index, token in enumerate(tokens[:-1])
            if isinstance(token, str) and token in REDIRECT_OPERATORS and isinstance(tokens[index + 1], _Word)]


def split_command(command: str) -> list[Segment]:
    if "\x00" in command:
        raise Unparseable("contains a NUL character")
    tokens = _Scanner(command.strip(" \t\n")).scan()

    segments: list[Segment] = []
    words: list[_Word] = []
    writes_file = has_redirect = False
    preceded_by = ""

    def flush(next_separator: str) -> None:
        nonlocal words, writes_file, has_redirect, preceded_by
        if (next_separator or preceded_by) and not (words or has_redirect):
            raise Unparseable(f"nothing on one side of {next_separator or preceded_by}")
        env: list[str] = []
        while words and _is_assignment(words[0]):
            env.append(words.pop(0).text)
        if (env or has_redirect) and not words:
            # zsh runs its null command (cat) for redirects alone and changes its own state for assignments alone
            raise Unparseable("a command with no command word")
        if words:
            segments.append(Segment(tuple(w.text for w in words), tuple(env), writes_file, preceded_by))
        words, writes_file, has_redirect, preceded_by = [], False, False, next_separator

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
            has_redirect = True
            if token == ">&":
                if target not in ("1", "2"):
                    raise Unparseable("only >&1 and >&2 are accepted")
            elif target not in HARMLESS_TARGETS:
                writes_file = True
            index += 2
    flush("")
    return segments
