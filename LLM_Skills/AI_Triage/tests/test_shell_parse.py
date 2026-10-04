import pytest

from triage.shell_parse import Unparseable, split_command


def argvs(command):
    return [segment.argv for segment in split_command(command)]


def test_single_command():
    [segment] = split_command("aws ecs list-clusters --profile triage-a --region eu-west-1")
    assert segment.argv[:3] == ("aws", "ecs", "list-clusters")
    assert segment.env == () and segment.writes_file is False and segment.preceded_by == ""


def test_pipes_and_lists_are_split_and_remember_their_separator():
    segments = split_command("aws a b | jq . && echo ok ; echo done || true &")
    assert [s.argv for s in segments] == [("aws", "a", "b"), ("jq", "."), ("echo", "ok"), ("echo", "done"), ("true",)]
    assert [s.preceded_by for s in segments] == ["", "|", "&&", ";", "||"]


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
    ["aws a b 2>/dev/null", "aws a b > /dev/null 2>&1", "aws a b 2>&1 | jq .", "jq . < input.json"],
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
    assert argvs("echo $HOME/x ${HOME}/y $HOME") == [("echo", "/home/eng/x", "/home/eng/y", "/home/eng")]
    assert argvs('echo "$HOME/x" "${HOME}" "$HOME"/y') == [("echo", "/home/eng/x", "/home/eng", "/home/eng/y")]
    assert argvs("echo $HOME'/x'") == [("echo", "/home/eng/x")]


def test_tilde_is_expanded_only_at_the_start_of_a_word(home):
    assert argvs("echo ~/x ~") == [("echo", "/home/eng/x", "/home/eng")]
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
    assert split_command("aws a b 3>out.txt")[0].argv == ("aws", "a", "b", "3")
    assert split_command("echo a2>f")[0].argv == ("echo", "a2")


@pytest.mark.parametrize("command", ["echo a >& 2", "echo a >&2", "echo a 2>&1", "echo a >&-"])
def test_descriptor_duplication_is_not_a_file_write(command):
    assert split_command(command)[0].writes_file is False


@pytest.mark.parametrize(
    "command",
    ["echo a >| f", "echo a >>f", "echo a &>>f", "echo a &> f", "echo a >&f", "echo a > '/dev/null2'"],
)
def test_other_output_redirects_to_files_are_writes(command):
    assert split_command(command)[0].writes_file is True


def test_input_redirect_sets_reads_file_and_not_writes_file():
    [segment] = split_command("grep x < /etc/hosts")
    assert segment.reads_file is True and segment.writes_file is False
    assert segment.argv == ("grep", "x")
    assert split_command("grep x")[0].reads_file is False
    assert split_command("grep x 0<f")[0].reads_file is True


def test_pipe_ampersand_and_clobber_operators():
    segments = split_command("a |& b | c")
    assert [s.preceded_by for s in segments] == ["", "|&", "|"]


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
