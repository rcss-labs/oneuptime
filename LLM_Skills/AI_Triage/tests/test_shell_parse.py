import pytest

from triage.shell_parse import Unparseable, split_command


def argvs(command):
    return [segment.argv for segment in split_command(command)]


def test_single_command():
    [segment] = split_command("aws ecs list-clusters --profile triage-a --region eu-west-1")
    assert segment.argv[:3] == ("aws", "ecs", "list-clusters")
    assert segment.env == () and segment.writes_file is False and segment.preceded_by == ""


def test_pipes_and_lists_are_split_and_remember_their_separator():
    segments = split_command("aws a b | jq . && echo ok")
    assert [s.argv for s in segments] == [("aws", "a", "b"), ("jq", "."), ("echo", "ok")]
    assert [s.preceded_by for s in segments] == ["", "|", "&&"]


def test_quoted_operators_stay_inside_their_argument():
    assert argvs("aws logs filter-log-events --filter-pattern '\"ERROR\" | x'") == [
        ("aws", "logs", "filter-log-events", "--filter-pattern", '"ERROR" | x')
    ]


def test_leading_assignments_are_separated_from_argv():
    [segment] = split_command("FOO=1 AWS_PROFILE=admin aws s3 ls")
    assert segment.env == ("FOO=1", "AWS_PROFILE=admin")
    assert segment.argv == ("aws", "s3", "ls")


@pytest.mark.parametrize(
    "command",
    ["aws a b 2>/dev/null", "aws a b > /dev/null 2>&1", "aws a b 2>&1 | jq ."],
)
def test_harmless_redirects_do_not_count_as_writes(command):
    first = split_command(command)[0]
    assert first.writes_file is False
    assert "2" not in first.argv and "/dev/null" not in first.argv


@pytest.mark.parametrize("command", ["aws a b > out.json", "aws a b >> out.json", "aws a b &> all.txt"])
def test_redirect_to_a_file_is_flagged(command):
    assert split_command(command)[0].writes_file is True


def test_line_continuation_is_joined():
    assert argvs("aws ecs \\\n  list-clusters") == [("aws", "ecs", "list-clusters")]


@pytest.mark.parametrize(
    "command",
    [
        "echo $(aws sts get-caller-identity)",
        "echo `aws sts get-caller-identity`",
        "diff <(aws a b) <(aws c d)",
        "cat <<EOF\nhello\nEOF",
        "aws a b\naws c d",
        "(aws a b)",
        "aws a b 'unterminated",
        "aws a b >",
    ],
)
def test_unsupported_shell_features_are_unparseable(command):
    with pytest.raises(Unparseable):
        split_command(command)


def test_empty_command_has_no_segments():
    assert split_command("   ") == []


# ---- fix round 1: a tokenizer that knows about quoting ----------------------


@pytest.fixture
def home(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    return "/home/eng"


@pytest.mark.parametrize(
    "command",
    [
        "echo $X",
        "echo ${X:-a b}",
        'echo "$X"',
        'echo "${X:-a}"',
        "echo $'x'",
        "echo `date`",
        'echo "`date`"',
        "echo {a,b}",
        "echo {a..c}",
        "echo a}",
        "echo *",
        "echo a?",
        "echo a[0]",
        "echo a]",
        "echo a#; echo hidden",
        "echo # comment",
        "echo (a)",
        "echo a) b",
        "echo x~/y",
        "echo ~root/y",
        "echo ~x",
        "echo a ~+",
        "cat <<EOF",
        "cat <<< word",
        "cat <<-EOF",
        "diff <(a) <(b)",
        "tee >(cat)",
        "echo a <> f",
        "echo a ;; echo b",
        "echo a &>",
        "echo a | > ",
        "echo 'open",
        'echo "open',
        "echo a\\",
        "echo a\necho b",
        "echo a$HOME",
        "echo $HOMEX",
        "echo ${HOME}x",
        "echo $HOME;",
        'echo "a $HOME"',
        "echo $HOME$HOME",
    ],
)
def test_constructs_the_guard_cannot_see_through_are_unparseable(command, home):
    with pytest.raises(Unparseable):
        split_command(command)


@pytest.mark.parametrize(
    "word, literal",
    [
        ("'$X'", "$X"),
        ("'${X:-a b}'", "${X:-a b}"),
        ("'`date`'", "`date`"),
        ("'{a,b}'", "{a,b}"),
        ("'*'", "*"),
        ("'a?'", "a?"),
        ("'[0]'", "[0]"),
        ("'a#b'", "a#b"),
        ("'(x)'", "(x)"),
        ("'~/x'", "~/x"),
        ("'$HOME/x'", "$HOME/x"),
        ("'a;b'", "a;b"),
        ("'<<'", "<<"),
        ('"a;b | c && d"', "a;b | c && d"),
        ('"{a,b} * ? [x] # ( ) ~"', "{a,b} * ? [x] # ( ) ~"),
        ('"x\ny"', "x\ny"),
        ('"\\$X"', "$X"),
        ('"\\`"', "`"),
        ('"a\\b"', "a\\b"),
        ("\\$X", "$X"),
        ("\\*", "*"),
        ("a\\ b", "a b"),
        ("''", ""),
        ('""', ""),
    ],
)
def test_quoted_and_escaped_characters_are_literal(word, literal, home):
    [segment] = split_command(f"echo {word}")
    assert segment.argv == ("echo", literal)


def test_empty_quoted_word_is_a_real_argument(home):
    [segment] = split_command("aws x '' y")
    assert segment.argv == ("aws", "x", "", "y")


def test_dollar_home_is_expanded_at_the_start_of_a_word(home):
    assert argvs("echo $HOME/x $HOME") == [("echo", "/home/eng/x", "/home/eng")]
    assert argvs('echo "$HOME/x" "${HOME}" "$HOME"/y') == [("echo", "/home/eng/x", "/home/eng", "/home/eng/y")]
    assert argvs("echo $HOME'/x'") == [("echo", "/home/eng/x")]


def test_a_quoted_tilde_is_literal(home):
    assert argvs("echo '~' \"~/x\"") == [("echo", "~", "~/x")]


def test_home_expansion_needs_a_usable_home(monkeypatch):
    monkeypatch.delenv("HOME", raising=False)
    for command in ("echo $HOME/x", 'echo "$HOME/x"', "echo ~/x"):
        with pytest.raises(Unparseable):
            split_command(command)
    monkeypatch.setenv("HOME", "")
    with pytest.raises(Unparseable):
        split_command("echo ~/x")
    assert argvs("echo plain") == [("echo", "plain")]


def test_an_unquoted_home_that_bash_would_split_is_refused(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/First Last")
    with pytest.raises(Unparseable):
        split_command("echo $HOME/x")
    assert argvs('echo "$HOME/x"') == [("echo", "/Users/First Last/x")]


def test_descriptor_digit_is_not_an_argument_only_when_attached():
    attached = split_command("aws a b 2>/dev/null")[0]
    assert attached.argv == ("aws", "a", "b") and attached.writes_file is False
    spaced = split_command("aws a b 2 > /dev/null")[0]
    assert spaced.argv == ("aws", "a", "b", "2") and spaced.writes_file is False
    assert split_command("aws a b 1>out.txt")[0].writes_file is True
    with pytest.raises(Unparseable):  # round 2: any descriptor other than 1 or 2 is refused
        split_command("aws a b 3>out.txt")
    assert split_command("echo a2>f")[0].argv == ("echo", "a2")


@pytest.mark.parametrize("command", ["echo a >& 2", "echo a >&2", "echo a 2>&1", "echo a 1>&2", "echo a 2>& 1"])
def test_descriptor_duplication_is_not_a_file_write(command):
    assert split_command(command)[0].writes_file is False


@pytest.mark.parametrize(
    "command",
    ["echo a >>f", "echo a &>>f", "echo a &> f", "echo a 1>f", "echo a 2>>f", "echo a > '/dev/null2'"],
)
def test_other_output_redirects_to_files_are_writes(command):
    assert split_command(command)[0].writes_file is True


def test_input_redirect_is_unparseable():
    assert split_command("grep x")[0].reads_file is False
    for command in ("grep x < /etc/hosts", "grep x 0<f"):  # round 4: no input redirect at all
        with pytest.raises(Unparseable):
            split_command(command)


def test_pipe_ampersand_is_unparseable():
    with pytest.raises(Unparseable):  # round 4: only | and && separate commands
        split_command("a |& b | c")


def test_a_quoted_first_word_is_never_an_assignment():
    [segment] = split_command("'FOO=1' aws s3 ls")
    assert segment.env == () and segment.argv[0] == "FOO=1"
    [segment] = split_command('"FOO"=1 aws')
    assert segment.env == ()
    [segment] = split_command('FOO="a b" aws s3 ls')
    assert segment.env == ("FOO=a b",) and segment.argv == ("aws", "s3", "ls")


def test_backslash_newline_inside_double_quotes_is_a_continuation():
    assert argvs('echo "a\\\nb"') == [("echo", "ab")]


def test_hash_inside_a_word_is_never_a_comment():
    with pytest.raises(Unparseable):
        split_command("echo a#b")
    assert argvs("echo 'a#b'") == [("echo", "a#b")]


# ---- fix round 2 ------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    ["echo a 0<f", "echo a 3>f", "echo a 9>/dev/null b", "echo a 12>/dev/null", "echo a 0< f", "echo a 10<&0", "echo a 99>&1"],
)
def test_a_descriptor_other_than_1_or_2_is_unparseable(command):
    with pytest.raises(Unparseable):
        split_command(command)


def test_descriptors_1_and_2_are_dropped_and_a_spaced_digit_is_an_argument():
    assert split_command("echo a 2>/dev/null")[0].argv == ("echo", "a")
    assert split_command("echo a 1>/dev/null")[0].argv == ("echo", "a")
    assert split_command("echo a 9 >/dev/null")[0].argv == ("echo", "a", "9")
    assert split_command("echo a 12 > /dev/null")[0].argv == ("echo", "a", "12")


def test_a_quoted_digit_before_a_redirect_is_an_ordinary_argument():
    assert split_command("echo a '9'>/dev/null")[0].argv == ("echo", "a", "9")
    assert split_command('echo a "12">/dev/null')[0].argv == ("echo", "a", "12")
    assert split_command("echo a \\9>/dev/null")[0].argv == ("echo", "a", "9")


@pytest.mark.parametrize(
    "command",
    [
        "echo a\rb",
        "echo a\x0bb",
        "echo a\x0cb",
        "echo a\x00b",
        "echo a\x7fb",
        "echo a\x1bb",
        "echo a\u00a0b",
        "echo a\u2003b",
        "echo a\u3000b",
        "echo =ls",
        "=ls",
        "echo a =ls",
        "echo 'a\x00b'",
        'echo "a\x00b"',
    ],
)
def test_control_characters_odd_whitespace_and_a_leading_equals_are_unparseable(command):
    with pytest.raises(Unparseable):
        split_command(command)


def test_quoted_non_ascii_whitespace_and_equals_in_the_middle_are_literal():
    assert split_command("echo 'a\u00a0b' x=y a=b")[0].argv == ("echo", "a\u00a0b", "x=y", "a=b")
    assert split_command("echo '=ls'")[0].argv == ("echo", "=ls")
    assert split_command("echo 'é'")[0].argv == ("echo", "é")


# ---- fix round 3: redirects by allow-list ------------------------------------


@pytest.mark.parametrize(
    "command, writes, reads",
    [
        ("echo a > f", True, False), ("echo a >f", True, False),
        ("echo a >> f", True, False), ("echo a >>f", True, False),
        ("echo a 1> f", True, False), ("echo a 1>f", True, False),
        ("echo a 1>> f", True, False), ("echo a 1>>f", True, False),
        ("echo a 2> f", True, False), ("echo a 2>f", True, False),
        ("echo a 2>> f", True, False), ("echo a 2>>f", True, False),
        ("echo a &> f", True, False), ("echo a &>f", True, False),
        ("echo a &>> f", True, False), ("echo a &>>f", True, False),
        ("&> f echo a", True, False),
        ("echo a 2>&1", False, False), ("echo a 1>&2", False, False), ("echo a >&2", False, False),
        ("echo a >&1", False, False), ("echo a >& 2", False, False),
        ("echo a > /dev/null", False, False), ("echo a 2>/dev/null", False, False),
        ("echo a &>/dev/null", False, False), ("echo a &>> /dev/null", False, False),
    ],
)
def test_accepted_redirect_forms(command, writes, reads):
    [segment] = split_command(command)
    assert (segment.writes_file, segment.reads_file) == (writes, reads)
    assert segment.argv[-1] == "a" or segment.argv == ("echo", "a")


@pytest.mark.parametrize(
    "command",
    [
        "echo a >| f", "echo a >|f", "echo a >&- ", "echo a >&f", "echo a >& f", "echo a >&3", "echo a >&12",
        "echo a <& 0", "echo a <&0", "echo a 0<&0", "echo a <> f", "echo a >! f", "echo a >!f", "echo a >>! f",
        "echo a &>! f", "echo a &>>!f", "echo a &>| f", "echo a > | f", "echo a > ; echo b", "echo a >", "echo a &> ",
        "echo a 0< f", "echo a 3> f", "echo a 9>/dev/null", "echo a 12>/dev/null", "echo a 1< f", "echo a 2< f",
        "echo a 3>&1", "echo a 9>&2", "echo a 2>&3", "echo a 2>&-",
        "echo a 1&>/dev/null", "echo a 2&>/dev/null", "echo a 9&>/dev/null", "echo a 2&>>/dev/null", "echo a 12&>f",
        "echo a '2'&>/dev/null", 'echo a "2"&>/dev/null', "echo a \\2&>/dev/null", "echo a x&>f", "echo a;&>f",
        "echo a 2&", "echo a 2&& echo b",
    ],
)
def test_every_other_redirect_form_is_unparseable(command):
    with pytest.raises(Unparseable):
        split_command(command)


def test_a_digit_separated_by_space_is_an_ordinary_argument():
    assert split_command("echo 2 > /dev/null")[0].argv == ("echo", "2")
    assert split_command("echo -n 2 &>/dev/null")[0].argv == ("echo", "-n", "2")
    assert split_command("echo 9 &>f")[0].argv == ("echo", "9")


def test_double_ampersand_still_separates():
    assert [s.argv for s in split_command("echo a && echo b")] == [("echo", "a"), ("echo", "b")]
    assert [s.argv for s in split_command("echo a&&echo b")] == [("echo", "a"), ("echo", "b")]


# ---- fix round 4: no input redirect, unquoted characters by allow-list -------


@pytest.mark.parametrize(
    "command",
    [
        # zsh numeric globs (re-review round 3, Critical 1)
        "echo a <-> /dev/null", "echo a <1-30> /dev/null", "echo a <1-> /dev/null", "echo a <-9> /dev/null",
        "echo a x<-> /dev/null", "echo a <->", "echo a get <-> /dev/null pods",
        # every other input form
        "echo a < f", "echo a <f", "echo a<f", "echo a <<EOF", "echo a <<< w", "echo a <(b)", "echo a <> f",
        "echo a <&0", "echo a 0<f", "echo a 1<f",
    ],
)
def test_an_unquoted_less_than_is_always_unparseable(command):
    with pytest.raises(Unparseable):
        split_command(command)


@pytest.mark.parametrize("char", list("!^~#*?[]{}()<;&") +["|&", "||", "&!", "&|", ">&-", "=(x)", "$((1+1))"])
def test_characters_outside_the_allow_list_are_unparseable(char, home):
    for command in (f"echo a {char}", f"echo a{char}b", f"echo {char}a b"):
        with pytest.raises(Unparseable):
            split_command(command)


@pytest.mark.parametrize("char", ["\u00e9", "\u00a0", "\u2028", "\u200b", "\uff1b", "\x7f", "\x01", "`", "$"])
def test_non_ascii_control_and_stray_characters_are_unparseable(char):
    with pytest.raises(Unparseable):
        split_command(f"echo a{char}b")


def test_every_allowed_unquoted_character_is_kept_literally():
    word = "AZaz09-_./:=,@%+"
    assert split_command(f"echo {word} -n --x=y,z a@b%c+d")[0].argv == ("echo", word, "-n", "--x=y,z", "a@b%c+d")


def test_an_unquoted_braced_home_is_unparseable_but_a_double_quoted_one_is_fine(home):
    with pytest.raises(Unparseable):
        split_command("echo ${HOME}/y")
    assert argvs('echo "${HOME}/y"') == [("echo", "/home/eng/y")]


@pytest.mark.parametrize("command", ["echo ~", "echo ~/x", "~/bin/x a"])
def test_an_unquoted_tilde_is_unparseable(command, home):
    with pytest.raises(Unparseable):
        split_command(command)
