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
