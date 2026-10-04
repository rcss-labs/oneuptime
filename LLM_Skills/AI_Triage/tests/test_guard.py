import pytest

from triage.config import parse_config
from triage.guard import GuardContext, context_from_config, decide
from triage.verdict import ALLOW, ASK, DENY, PASS

SKILL = "/home/eng/.claude/skills/ai-triage"
PY = f"{SKILL}/.venv/bin/python"
CONTEXT = GuardContext(
    profiles=frozenset({"triage-prod-main"}),
    kubeconfig=f"{SKILL}/config/kubeconfig",
    kube_contexts=frozenset({"triage-platform-prod"}),
    opensearch_hosts=frozenset({"opensearch.internal.example.com"}),
    skill_dir=SKILL,
)
AWS_OK = "--profile triage-prod-main --region eu-west-1"
KUBE_OK = f"--kubeconfig {SKILL}/config/kubeconfig --context triage-platform-prod -n payments"


def kind(command, context=CONTEXT):
    return decide(command, context).kind


@pytest.mark.parametrize(
    "command",
    [
        f"aws ecs describe-services --cluster a --services b {AWS_OK}",
        f"aws ecs describe-services --cluster a {AWS_OK} | jq '.services[0].events[:5]'",
        f"aws ecs list-tasks --cluster a {AWS_OK} 2>/dev/null | head -20",
        f"aws ecs list-clusters {AWS_OK} && aws rds describe-db-instances {AWS_OK}",
        f"kubectl {KUBE_OK} get pods -o wide | grep -v Running",
        f"{PY} {SKILL}/scripts/preflight.py --json",
        f"{PY} {SKILL}/scripts/opensearch_query.py --cluster logs-prod health",
        f'"{PY}" "{SKILL}/scripts/validate_map.py"',
    ],
)
def test_validated_reads_are_approved(command):
    assert kind(command) == ALLOW


@pytest.mark.parametrize(
    "command",
    [
        "aws ecs describe-services --cluster a --profile admin --region eu-west-1",
        f"aws ecs list-clusters {AWS_OK} && aws ecs stop-task --task t {AWS_OK}",
        f"aws ecs list-clusters {AWS_OK} && aws s3 rm s3://b/k {AWS_OK}",
        f"kubectl {KUBE_OK} delete pod p",
        "curl -s https://opensearch.internal.example.com/_cat/indices",
        "curl -XDELETE https://opensearch.internal.example.com/app-logs-2026",
        f"{PY} {SKILL}/scripts/preflight.py https://opensearch.internal.example.com",
        "python3 -c \"import urllib.request as u; u.urlopen('http://opensearch.internal.example.com/_search')\"",
    ],
)
def test_writes_wrong_identities_and_side_routes_are_blocked(command):
    assert kind(command) == DENY


@pytest.mark.parametrize(
    "command",
    [
        f"echo $(aws sts get-caller-identity {AWS_OK})",
        f"bash -c 'aws ecs list-clusters {AWS_OK}'",
        f"xargs aws ecs describe-tasks {AWS_OK}",
        "cat ~/.aws/config",
        f"aws ecs list-clusters {AWS_OK}\naws ecs list-services {AWS_OK}",
        f"AWS_PROFILE=admin aws ecs list-clusters {AWS_OK}",
    ],
)
def test_commands_the_guard_cannot_check_force_a_prompt(command):
    assert kind(command) == ASK


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status",
        "npm test",
        "echo $(date)",
        f"aws ecs list-clusters {AWS_OK} > clusters.json",
        f"aws ecs list-clusters {AWS_OK} | tee clusters.json",
        f"aws ecs list-clusters {AWS_OK} | xargs rm -rf",
        f"/usr/bin/python3 {SKILL}/scripts/preflight.py",
        f"{PY} /tmp/other.py",
        f"{PY} {SKILL}/scripts/../../evil.py",
    ],
)
def test_unrelated_or_mixed_commands_fall_through_to_the_normal_flow(command):
    assert kind(command) == PASS


def test_opensearch_host_is_matched_whatever_its_letter_case():
    assert kind("curl -s https://OpenSearch.Internal.Example.com/_cat/indices") == DENY


def test_aws_and_kubectl_are_recognised_by_bare_name_only():
    # The old test expected /usr/local/bin/aws to be allowed. That encoded a gap:
    # a file written to any folder can be named aws, so a path is never trusted.
    for command in (
        f"/usr/local/bin/aws ecs list-clusters {AWS_OK}",
        f"./aws ecs list-clusters {AWS_OK}",
        f"/tmp/x/aws ecs stop-task --task t {AWS_OK}",
        f"/tmp/evil/kubectl {KUBE_OK} get pods",
        f"./kubectl {KUBE_OK} get pods",
        f"'/usr/bin/aws' ecs list-clusters {AWS_OK}",
    ):
        assert kind(command) == ASK, command


def test_skill_folder_with_a_space_in_its_path_is_recognised():
    skill = "/Users/First Last/.claude/skills/ai-triage"
    context = GuardContext(
        profiles=CONTEXT.profiles,
        kubeconfig=f"{skill}/config/kubeconfig",
        kube_contexts=CONTEXT.kube_contexts,
        opensearch_hosts=CONTEXT.opensearch_hosts,
        skill_dir=skill,
    )
    assert kind(f'"{skill}/.venv/bin/python" "{skill}/scripts/preflight.py" --json', context) == ALLOW
    kubectl = f'kubectl --kubeconfig "{skill}/config/kubeconfig" --context triage-platform-prod -n payments get pods'
    assert kind(kubectl, context) == ALLOW


def test_deny_outranks_ask_and_reason_names_the_problem():
    verdict = decide(f'cat "$HOME/.aws/config" && aws ecs stop-task --task t {AWS_OK}', CONTEXT)
    assert verdict.kind == DENY and "not a known read" in verdict.reason


def test_without_a_valid_config_aws_and_kubectl_are_denied():
    verdict = decide(f"aws ecs list-clusters {AWS_OK}", None, "config file not found")
    assert verdict.kind == DENY and "config file not found" in verdict.reason
    assert decide("kubectl get pods", None, "x").kind == DENY
    assert decide("ls -la", None, "x").kind == PASS


def test_context_is_built_from_config(config_data, tmp_path):
    context = context_from_config(parse_config(config_data), tmp_path)
    assert context.profiles == frozenset({"triage-prod-main", "triage-staging"})
    assert context.kubeconfig == str(tmp_path / "config" / "kubeconfig")
    assert context.kube_contexts == frozenset({"triage-platform-prod"})
    assert context.opensearch_hosts == frozenset({"opensearch.internal.example.com"})


def test_home_relative_script_paths_are_recognised(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    command = '"$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/preflight.py"'
    assert kind(command) == ALLOW
    # round 4: an unquoted ~ is outside the allow-list, so the guard leaves it to the normal permission flow
    assert kind("~/.claude/skills/ai-triage/.venv/bin/python ~/.claude/skills/ai-triage/scripts/preflight.py") == PASS


# ---- fix round 1 -------------------------------------------------------------

SCRIPT = f"{SKILL}/scripts"


@pytest.mark.parametrize(
    "command",
    [
        # wave B C1: expansions and braces change the argv after the guard looked at it
        f"aws secretsmanager$E get-secret-value --secret-id prod/db {AWS_OK}",
        f"aws s3api$E get-object --bucket b --key k /tmp/out {AWS_OK}",
        f"aws lambda${{E}} get-function --function-name f {AWS_OK}",
        f"aws s3api get-objec{{t,}} --bucket b --key k {AWS_OK}",
        f"kubectl {KUBE_OK} get secrets$E",
        f"kubectl {KUBE_OK} get secret{{s,}}",
        f"aws ecs list-clusters {AWS_OK} $X",
        f"aws ecs list-clusters {AWS_OK} ${{X:-a b}}",
        f"aws ssm get-parameter --name n $'--with-decryption' {AWS_OK}",
        f"aws ecs list-clusters {AWS_OK} *",
        # wave A C1: a hash in the middle of a word hides the rest of the line
        f"aws ecs list-clusters {AWS_OK} a#; aws ecs stop-task --task t --profile admin",
        # wave B I2: indirect access is asked about, not passed
        f"python3 -m awscli ecs stop-task --profile admin --region eu-west-1",
        "eksctl delete cluster --name prod",
        "helm uninstall payments",
        "python3 -c 'import boto3; boto3.client(\"ecs\")'",
        "python3 -c 'import botocore'",
        f"a''ws ecs stop-task --profile admin --region eu-west-1",
        "k\\ubectl delete ns prod",
    ],
)
def test_reproductions_from_the_reviews_never_get_allow(command, monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    assert kind(command) in (ASK, DENY)


def test_quote_obfuscated_and_indirect_names_are_sensitive_without_config():
    assert decide("a''ws ecs stop-task --profile admin", None, "no config").kind == DENY
    assert decide('"kube"ctl delete ns prod', None, "no config").kind == DENY
    assert decide("helm uninstall x", None, "no config").kind == DENY
    assert decide("python3 -m awscli ecs ls", None, "no config").kind == DENY
    assert decide("ls", None, "no config").kind == PASS


@pytest.mark.parametrize(
    "filter_command",
    [
        "jq .",
        "jq -r .services[].serviceName".replace(".services[].serviceName", "'.services[].serviceName'"),
        "jq -r -c -S -e -M '.a'",
        "jq --raw-output --compact-output --sort-keys '.a | length'",
        "jq '.events[:5]'",
        "head",
        "head -n 5",
        "head -5",
        "head -c 4000",
        "tail -n 20",
        "tail -3",
        "tail -c 100",
        "grep ERROR",
        "grep -i -v -c -E -F -o -n -w timeout",
        "grep -e -dash",
        "grep -m 5 -A 2 -B 2 -C 1 -i 'x y'",
        "grep -i aws",
        "wc",
        "wc -l -c -w -m",
        "sort",
        "sort -r -n -u -h",
        "sort -k 2 -t ,",
        "uniq",
        "uniq -c -d -u -i",
        "cut -d , -f 1",
        "cut -c 1-5",
        "cut -d - -f 2",
        "tr -d -s -c abc",
        "tr a-z A-Z",
        "tr -d '\\n'",
        "column",
        "column -t",
        "column -t -s ,",
    ],
)
def test_strict_grammar_filters_after_a_pipe_are_allowed(filter_command):
    assert kind(f"aws ecs list-clusters {AWS_OK} | {filter_command}") == ALLOW


@pytest.mark.parametrize(
    "filter_command",
    [
        # wave B C2 reproductions
        "sort -o /home/eng/.bashrc",
        "uniq - /home/eng/.zshrc",
        "grep -r . /home/eng/.ssh",
        "jq -n env",
        "jq -n '$ENV'",
        "LD_PRELOAD=/tmp/x.so jq .",
        "tail -f /var/log/system.log",
        "tail -f",
        "head -c 4000 /home/eng/.ssh/id_example",
        "jq --rawfile a /home/eng/.ssh/id_example .",
        "jq --slurpfile a f .",
        "jq -f prog.jq",
        "jq --args . a b",
        "jq . file.json",
        "jq 'input'",
        "jq '$__loc__'",
        "jq '.a | @sh'",
        "jq 'env.HOME'",
        "jq -r",
        "jq -- -x",
        "head file.txt",
        "head -n x",
        "head -n 5 file",
        "grep",
        "grep a b",
        "grep -r x",
        "grep -R x",
        "grep -f patterns x",
        "grep --include=x y",
        "grep -m x y",
        "grep -iv x",
        "wc file",
        "wc -L",
        "sort file",
        "sort -o out",
        "sort --output=out",
        "uniq a b",
        "uniq - out",
        "cut",
        "cut -d,",
        "cut -f 1 file",
        "tr",
        "tr a b c",
        "tr -x a",
        "column file",
        "column -t file",
        "xargs rm",
        "tee out.txt",
    ],
)
def test_filters_outside_the_strict_grammar_are_not_allowed(filter_command):
    assert kind(f"aws ecs list-clusters {AWS_OK} | {filter_command}") == PASS


def test_a_filter_with_a_redirect_is_not_allowed():
    assert kind(f"aws ecs list-clusters {AWS_OK} | grep x < in.txt") == ASK  # round 4: < is unparseable
    assert kind(f"aws ecs list-clusters {AWS_OK} | grep x > out.txt") == PASS


def test_a_filter_not_preceded_by_a_plain_pipe_is_not_allowed():
    assert kind(f"aws ecs list-clusters {AWS_OK}; jq .") == ASK  # round 4: ; and |& are unparseable
    assert kind(f"aws ecs list-clusters {AWS_OK} |& jq .") == ASK
    assert kind("jq .") == PASS


def test_a_filter_that_mentions_aws_but_breaks_the_grammar_asks():
    assert kind(f"aws ecs list-clusters {AWS_OK} | grep -r aws .") == ASK


@pytest.mark.parametrize(
    "command",
    [
        f"PYTHONPATH=/tmp/evil {PY} {SCRIPT}/preflight.py",
        f"AWS_CONFIG_FILE=/tmp/cfg {PY} {SCRIPT}/verify_access.py",
        f"FOO=1 {PY} {SCRIPT}/validate_map.py",
        f"PYTHONPATH=/tmp/evil {PY} {SCRIPT}/opensearch_query.py --cluster logs-prod health",
    ],
)
def test_environment_and_input_redirects_never_ride_on_an_own_script(command):
    assert kind(command) == ASK


def test_an_input_redirect_on_an_own_script_is_never_allowed():
    # round 4: any unquoted < is unparseable; with no aws or kubectl in the text the guard passes it on
    assert kind(f"{PY} {SCRIPT}/preflight.py < /home/eng/.ssh/id_example") == PASS


@pytest.mark.parametrize(
    "command",
    [
        f"FOO=1 aws ecs list-clusters {AWS_OK}",
        f"HTTPS_PROXY=http://x aws ecs list-clusters {AWS_OK}",
        f"LD_PRELOAD=/tmp/x.so kubectl {KUBE_OK} get pods",
        f"PATH=/tmp/evil kubectl {KUBE_OK} get pods",
    ],
)
def test_any_environment_assignment_on_aws_or_kubectl_asks(command):
    assert kind(command) == ASK


def test_environment_assignment_does_not_hide_a_deny():
    assert kind(f"FOO=1 aws ecs stop-task --task t {AWS_OK}") == DENY


def test_environment_assignment_on_a_filter_is_not_allowed():
    assert kind(f"aws ecs list-clusters {AWS_OK} | LD_PRELOAD=/tmp/x.so jq .") == PASS


@pytest.mark.parametrize(
    "command",
    [
        f"{PY} {SCRIPT}/anything_new.py",
        f"{PY} {SCRIPT}/guard_hook.py",
        f"{PY} {SCRIPT}/preflight.sh",
        f"python3 {SCRIPT}/preflight.py",
        f"/usr/bin/python3 {SCRIPT}/preflight.py",
        f"{SKILL}/.venv/bin/python3.11 {SCRIPT}/preflight.py",
        f"{SKILL}/.venv/bin/pythonw {SCRIPT}/preflight.py",
        f"{PY} -c 'print(1)'",
        f"{PY} {SCRIPT}/../scripts/preflight.py",
        f"{PY} {SCRIPT}/sub/../preflight.py",
        f"{SKILL}/.venv/bin/../bin/python {SCRIPT}/preflight.py",
        f"{PY} ./scripts/preflight.py",
        f"{PY}",
        "'$HOME/.claude/skills/ai-triage/.venv/bin/python' '$HOME/.claude/skills/ai-triage/scripts/preflight.py'",
        "'~/.claude/skills/ai-triage/.venv/bin/python' '~/.claude/skills/ai-triage/scripts/preflight.py'",
        f"{PY} '$HOME/.claude/skills/ai-triage/scripts/preflight.py'",
    ],
)
def test_only_the_named_own_scripts_run_with_the_skill_python(command, monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    assert kind(command) == PASS


@pytest.mark.parametrize(
    "name",
    ["preflight.py", "validate_map.py", "verify_access.py", "opensearch_query.py", "collect.py", "discover.py",
     "case.py", "findings.py", "timeline.py", "report.py", "judge.py", "publish.py", "map_suggest.py"],
)
def test_every_listed_own_script_is_allowed(name):
    assert kind(f"{PY} {SCRIPT}/{name} --json") == ALLOW


def test_own_script_names_are_a_fixed_list():
    from triage.guard import OWN_SCRIPTS

    assert OWN_SCRIPTS == frozenset(
        {"preflight.py", "validate_map.py", "verify_access.py", "opensearch_query.py", "collect.py", "discover.py",
         "case.py", "findings.py", "timeline.py", "report.py", "judge.py", "publish.py", "map_suggest.py"}
    )


def test_an_own_script_with_a_redundant_slash_is_still_recognised():
    assert kind(f"{PY} {SCRIPT}//preflight.py") == ALLOW
    assert kind(f"{PY} {SCRIPT}/./preflight.py") == ALLOW


def test_home_paths_are_expanded_only_when_unquoted_or_double_quoted(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    py, script = "$HOME/.claude/skills/ai-triage/.venv/bin/python", "$HOME/.claude/skills/ai-triage/scripts/preflight.py"
    assert kind(f"{py} {script}") == ALLOW
    assert kind(f'"{py}" "{script}"') == ALLOW
    assert kind(f"'{py}' '{script}'") == PASS


def test_without_home_the_home_paths_cannot_be_checked(monkeypatch):
    monkeypatch.delenv("HOME", raising=False)
    command = '"$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/preflight.py"'
    assert kind(command) == PASS


def test_a_multi_line_command_mentioning_aws_asks():
    assert kind(f"cd /tmp\naws ecs stop-task --task t {AWS_OK}") == ASK


def test_a_module_that_names_awscli_is_asked_about_not_passed():
    assert kind(f"{PY} {SCRIPT}/triage/awscli.py") == ASK


# ---- fix round 2 ------------------------------------------------------------


def test_the_skill_interpreter_may_be_named_python_or_python3():
    assert kind(f"{SKILL}/.venv/bin/python3 {SCRIPT}/preflight.py") == ALLOW
    assert kind(f"{SKILL}/.venv/bin/python {SCRIPT}/preflight.py") == ALLOW
    assert kind(f"{SKILL}/.venv/bin/python3 {SCRIPT}/anything_new.py") == PASS
    assert kind(f"FOO=1 {SKILL}/.venv/bin/python3 {SCRIPT}/preflight.py") == ASK
    assert kind(f"{SKILL}/.venv/../.venv/bin/python3 {SCRIPT}/preflight.py") == PASS


# ---- fix round 3 -------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        # zsh drops the 2 before &>, bash keeps it: the verb is delete in zsh, get for a bash-style reading
        f"kubectl {KUBE_OK} 2&>/dev/null get delete namespace payments",
        f"kubectl {KUBE_OK} -n 2&>/dev/null get delete namespace payments",
        f"kubectl {KUBE_OK} 2&>>/dev/null get pods",
        f"aws ecs list-clusters 9&>/dev/null {AWS_OK}",
        f"aws ecs list-clusters {AWS_OK} 9>/dev/null",
        f"aws ecs list-clusters {AWS_OK} >| out.txt",
    ],
)
def test_descriptor_glued_redirects_never_get_allow(command):
    assert kind(command) in (ASK, DENY)


def test_a_spaced_digit_before_an_ampersand_redirect_is_an_argument_not_a_descriptor():
    assert kind(f"aws ecs list-clusters {AWS_OK} 2>/dev/null | head -3") == ALLOW
    assert kind(f"kubectl {KUBE_OK} get pods 2>&1 | head -3") == ALLOW


@pytest.mark.parametrize(
    "word", ["repeat", "while", "until", "recurse", "range", "limit"]
)
def test_jq_filters_that_could_never_end_are_not_allowed(word):
    assert kind(f"aws ecs list-clusters {AWS_OK} | jq '{word}(.)'") == PASS
    assert kind(f"aws ecs list-clusters {AWS_OK} | jq -r '[{word}(1;2)]'") == PASS


def test_the_three_everyday_commands_stay_allowed(monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    assert kind('"$HOME/.claude/skills/ai-triage/.venv/bin/python" "$HOME/.claude/skills/ai-triage/scripts/preflight.py"') == ALLOW
    assert kind(
        f"aws ecs describe-services --cluster c --services s {AWS_OK} --query 'services[0].events[:5]' 2>/dev/null | jq -r '.[]'"
    ) == ALLOW
    assert kind(
        'kubectl --kubeconfig "$HOME/.claude/skills/ai-triage/config/kubeconfig" --context triage-prod-main -n payments get pods -o json'.replace("triage-prod-main", "triage-platform-prod")
    ) == ALLOW


# ---- fix round 4 -------------------------------------------------------------

KUBE_HOME = '--kubeconfig "$HOME/.claude/skills/ai-triage/config/kubeconfig" --context triage-platform-prod -n payments'


@pytest.mark.parametrize(
    "command",
    [
        # re-review round 3, Critical 1: zsh numeric globs read as an input plus an output redirect
        f"kubectl {KUBE_HOME} get pods <-> /dev/null",
        f"aws ecs list-clusters {AWS_OK} <-> /dev/null",
        f"kubectl {KUBE_HOME} get delete<-> /dev/null",
        f"kubectl {KUBE_HOME} get <-> /dev/null pods",
    ],
)
def test_round_3_numeric_glob_reproductions_never_get_allow(command, monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    assert kind(command) in (ASK, DENY)


@pytest.mark.parametrize(
    "suffix",
    ["<1-30> /dev/null", "<1-> /dev/null", "<-9> /dev/null", "; echo", "& echo", "|| echo", "&! echo", "&| echo",
     "~", "a\u00a0b", "!!", "^a", "[ab]", "{a,b}", "#", "x\u00e9"],
)
def test_constructs_outside_the_allow_list_never_get_allow(suffix, monkeypatch):
    monkeypatch.setenv("HOME", "/home/eng")
    assert kind(f"kubectl {KUBE_HOME} get pods {suffix}") == ASK
    assert kind(f"aws ecs list-clusters {AWS_OK} {suffix}") == ASK


@pytest.mark.parametrize(
    "command",
    [
        f"aws ecs list-clusters {AWS_OK}; aws s3 rm s3://b/k {AWS_OK}",
        f"aws ecs list-clusters {AWS_OK}; grep -r password /etc",
        f"aws ecs list-clusters {AWS_OK} | grep x < /home/eng/.ssh/id_example",
    ],
)
def test_semicolon_lists_and_input_redirects_now_ask(command):
    # These were deny or pass before round 4; ; and < are now outside what the scanner accepts.
    assert kind(command) == ASK
