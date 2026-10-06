"""The service playbooks must have the fixed structure and give commands that exist and that the guard approves."""
from __future__ import annotations

import json
import re

import pytest

from conftest import SKILL_SRC
from skill_text_support import (
    FENCE_RE, PLAYBOOKS_DIR, fenced_commands, fill_placeholders, guard_kind_and_reason, is_secret_operation,
    make_guard_context, script_accepts,
)
from triage.collectors import all_collectors
from triage.collection_plan import RESOURCE_COLLECTOR
from triage.service_map import RESOURCE_KEYS
from triage.verdict import ALLOW

HEADINGS = ["When to open", "Collect", "What the facts mean", "Common causes", "Compare with", "Follow a lead"]
MIN_LINES, MAX_LINES = 40, 130
PLAYBOOKS = sorted(PLAYBOOKS_DIR.glob("*.md"))
IDS = [path.stem for path in PLAYBOOKS]
COLLECT_RE = re.compile(r"`run collect ([a-z0-9_]+)([^`]*)`")
OPENSEARCH_RE = re.compile(r"`run opensearch_query(?: ([a-z][a-z-]*))?")
TARGET_RE = re.compile(r"--target ([A-Za-z_]+)=")


def lines_outside_fences(text: str) -> list[tuple[int, str]]:
    result, inside = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(line):
            inside = not inside
        elif not inside:
            result.append((number, line))
    return result


def section(text: str, heading: str) -> str:
    body, active = [], False
    for _, line in lines_outside_fences(text):
        if line.startswith("## "):
            active = line[3:].strip() == heading
        elif active:
            body.append(line)
    return "\n".join(body)


def test_there_are_playbooks():
    assert PLAYBOOKS, "no playbooks found under skill/ai-triage/playbooks/"


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_structure_and_length(path):
    text = path.read_text()
    lines = text.splitlines()
    outside = lines_outside_fences(text)
    titles = [line for _, line in outside if line.startswith("# ")]
    assert len(titles) == 1 and re.fullmatch(r"# \S.* playbook", titles[0]) and lines[0] == titles[0], (
        f"{path.name}: the first line must be the only title, `# <Something> playbook`; found {titles}"
    )
    assert [line[3:].strip() for _, line in outside if line.startswith("## ")] == HEADINGS, (
        f"{path.name}: level-2 headings must be exactly {HEADINGS}"
    )
    assert MIN_LINES <= len(lines) <= MAX_LINES, f"{path.name}: {len(lines)} lines, want {MIN_LINES} to {MAX_LINES}"


def declared_targets(collector) -> set[str]:
    return set(collector.required) | set(collector.optional) | set(collector.one_of)


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_collect_commands_name_real_collectors_and_target_keys(path):
    collectors = all_collectors()
    problems = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        for match in COLLECT_RE.finditer(line):
            name, rest = match.group(1), match.group(2)
            if name not in collectors:
                problems.append(f"{path.name}:{number}: no collector named {name}")
                continue
            for key in TARGET_RE.findall(rest):
                if key not in declared_targets(collectors[name]):
                    problems.append(
                        f"{path.name}:{number}: collector {name} has no target key {key} "
                        f"(declares {sorted(declared_targets(collectors[name]))})"
                    )
        for match in OPENSEARCH_RE.finditer(line):
            subcommand = match.group(1)
            if subcommand is None:
                continue
            ok, message = script_accepts("opensearch_query", subcommand)
            if not ok:
                problems.append(f"{path.name}:{number}: opensearch_query has no subcommand {subcommand}: {message}")
    assert not problems, "\n" + "\n".join(problems)


def follow_a_lead_commands(path) -> list[tuple[int, str]]:
    text = path.read_text()
    start = next((n for n, line in enumerate(text.splitlines(), start=1) if line.strip() == "## Follow a lead"), None)
    if start is None:
        return []
    body = "\n".join(text.splitlines()[start:])
    found = fenced_commands(f"\n{body}")  # line numbers are offset by one; fixed below
    return [(number + start - 1, command) for number, command in found]


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_follow_a_lead_commands_get_allow_from_the_guard(path, monkeypatch):
    commands = follow_a_lead_commands(path)
    assert commands, f"{path.name}: no aws or kubectl command in a fenced block under Follow a lead"
    _, values = make_guard_context()
    problems = []
    for number, command in commands:
        kind, reason = guard_kind_and_reason(command, monkeypatch)
        if kind != ALLOW:
            problems.append(
                f"{path.name}:{number}: guard says {kind}: {reason}\n    command: {fill_placeholders(command, values)}"
            )
    assert not problems, "\n" + "\n".join(problems)


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_follow_a_lead_commands_never_return_secret_material(path):
    offenders = [f"{path.name}:{n}: {c}" for n, c in follow_a_lead_commands(path) if is_secret_operation(c)]
    assert not offenders, "\n" + "\n".join(offenders)


NON_PLAYBOOK_NAMES = {
    "skill", "readme", "agents", "claude", "reading", "formats", "case", "report", "work-order", "checked",
    "summary", "questions", "analyst-common", "redaction-audit",
}


def referenced_playbooks() -> list[tuple[str, str]]:
    """(file that refers, playbook name) for every playbook another playbook or SKILL.md refers to by file name."""
    found = []
    for source in [SKILL_SRC / "SKILL.md", *PLAYBOOKS]:
        for name in re.findall(r"playbooks/([A-Za-z0-9_-]+)\.md", source.read_text()):
            found.append((source.name, name))
        if source in PLAYBOOKS:
            for name in re.findall(r"`([a-z0-9_-]+)\.md`", source.read_text()):
                if name not in NON_PLAYBOOK_NAMES and not name.startswith("analyst-"):
                    found.append((source.name, name))
    return found


def test_every_referenced_playbook_exists():
    existing = {path.stem for path in PLAYBOOKS}
    missing = sorted({f"{source} refers to playbooks/{name}.md" for source, name in referenced_playbooks() if name not in existing})
    assert not missing, "\n" + "\n".join(missing)


def mentioned_collectors(path, names: set[str]) -> set[str]:
    """Collectors a playbook covers: its own name, `run collect <name>`, and backticked names in its opening and Collect sections."""
    text = path.read_text()
    found = {path.stem} & names
    scope = section(text, "When to open") + "\n" + section(text, "Collect")
    found |= {name for name in re.findall(r"`run collect ([a-z0-9_]+)", text) if name in names}
    found |= {name for name in re.findall(r"`([a-z0-9_]+)`", scope) if name in names}
    return found


def test_every_collector_is_covered_by_a_playbook():
    names = set(all_collectors())
    covered = set()
    for path in PLAYBOOKS:
        covered |= mentioned_collectors(path, names)
    assert not (names - covered), f"collectors that no playbook mentions: {sorted(names - covered)}"


# ---- the plan, target keys, commands that hide errors or lack a grant, wording of the facts ----

# Collectors the plan can plan: the ones its resource table feeds, and the two it always plans.
PLANNED_COLLECTORS = set(RESOURCE_COLLECTOR.values()) | {"changes", "platform"}
PLAN_RUNS_RE = re.compile(r"\bthe plan (?:already )?runs `([a-z0-9_]+)`")


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_the_plan_runs_only_collectors_it_can_plan(path):
    named = PLAN_RUNS_RE.findall(" ".join(path.read_text().split()))
    assert not [name for name in named if name not in PLANNED_COLLECTORS], (
        f"{path.name}: says the plan runs {sorted(set(named) - PLANNED_COLLECTORS)}, which it never plans"
    )


@pytest.mark.parametrize("name", ["vpc", "access"])
def test_vpc_and_access_say_the_plan_does_not_run_them(name):
    text = " ".join((PLAYBOOKS_DIR / f"{name}.md").read_text().split())
    assert "the plan does not run this" in text.lower(), f"{name}.md must say the plan does not run it"
    assert f"`run collect {name} " in text and "--case-dir <case>" in text.split("the plan does not run this", 1)[-1][:900]


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_target_keys_in_when_to_open_are_service_map_keys(path):
    tokens = re.findall(r"`([a-z][a-z0-9_]*)`", section(path.read_text(), "When to open"))
    assert not [t for t in tokens if t not in RESOURCE_KEYS], (
        f"{path.name}: When to open names {[t for t in tokens if t not in RESOURCE_KEYS]}, not service-map keys"
    )


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_no_command_hides_its_errors(path):
    assert "2>/dev/null" not in path.read_text(), f"{path.name}: a denial must stay visible; drop 2>/dev/null"


POLICY = json.loads((SKILL_SRC.parent.parent / "iam" / "ai-triage-inline-policy.json").read_text())
INLINE_ACTIONS = {
    action for statement in POLICY["Statement"] if statement["Effect"] == "Allow" for action in statement["Action"]
}
# What ViewOnlyAccess gives, as far as the branch review could establish (a trailing * is a prefix).
VIEW_ONLY = (
    "sqs:GetQueueUrl", "sqs:GetQueueAttributes", "sqs:ListDeadLetterSourceQueues", "eks:DescribeCluster",
    "eks:DescribeNodegroup", "eks:DescribeAddon", "eks:DescribeUpdate", "eks:ListNodegroups", "eks:ListAddons",
    "eks:ListUpdates", "acm:ListCertificates", "cloudwatch:GetMetricData", "cloudtrail:LookupEvents",
    "autoscaling:Describe*", "ec2:Describe*", "ecs:Describe*", "ecs:List*", "ecr:DescribeRepositories",
    "elasticache:Describe*", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
    "elasticfilesystem:DescribeFileSystems", "es:ListDomainNames", "iam:ListRoles", "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies", "lambda:ListEventSourceMappings", "logs:DescribeLogGroups", "rds:Describe*",
    "route53:List*", "dynamodb:DescribeTable", "dynamodb:ListTables",
)
IAM_PREFIX = {
    "elbv2": "elasticloadbalancing", "efs": "elasticfilesystem", "opensearch": "es", "configservice": "config",
    "service-quotas": "servicequotas",
}
API_GATEWAY_READS = {  # the paths the inline policy grants: /restapis, /apis, /account, /domainnames
    "get-rest-api", "get-rest-apis", "get-stage", "get-stages", "get-deployment", "get-deployments", "get-resources",
    "get-account", "get-domain-name", "get-domain-names", "get-api", "get-apis", "get-routes", "get-integrations",
}


def iam_action(command: str) -> str | None:
    match = re.match(r"aws ([a-z0-9-]+) ([a-z0-9-]+)", command)
    if not match:
        return None
    service, operation = match.groups()
    if service == "apigatewayv2":
        return "apigateway:GET" if operation.startswith("get-") else f"apigateway:GET({operation} is not a read)"
    if service == "apigateway":
        return "apigateway:GET" if operation in API_GATEWAY_READS else f"apigateway:GET({operation} is not granted)"
    prefix = IAM_PREFIX.get(service, service)
    return f"{prefix}:" + "".join(part.capitalize() for part in operation.split("-"))


def granted(action: str) -> bool:
    action = action.lower()
    if action in {a.lower() for a in INLINE_ACTIONS}:
        return True
    return any(action == g.lower() or (g.endswith("*") and action.startswith(g[:-1].lower())) for g in VIEW_ONLY)


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_commands_use_only_granted_actions(path):
    ungranted = []
    for number, command in follow_a_lead_commands(path):
        action = iam_action(command)
        if action and not granted(action):
            ungranted.append(f"{path.name}:{number}: {action}")
    assert not ungranted, "\n" + "\n".join(ungranted)


def test_the_usage_plans_command_is_gone():
    assert "get-usage-plans" not in (PLAYBOOKS_DIR / "apigateway.md").read_text()


@pytest.mark.parametrize("name", ["rds", "efs", "opensearch", "cloudwatch"])
def test_the_peak_is_not_called_the_lowest_point(name):
    text = " ".join((PLAYBOOKS_DIR / f"{name}.md").read_text().split()).lower()
    assert "the number is the lowest point" not in text and "peak" not in text.replace("peak bucket", "")


def test_cloudwatch_reads_a_metric_fact_as_the_collector_words_it():
    text = " ".join((PLAYBOOKS_DIR / "cloudwatch.md").read_text().split())
    for phrase in ("lowest", "highest", "during the incident", "in the same hours one week earlier",
                   "rose above the range of one week earlier", "fell below the range of one week earlier"):
        assert phrase in text, f"cloudwatch.md does not explain '{phrase}'"
    assert "neither the incident-part average nor an extreme left" in text


def test_cloudtrail_words_absence_as_what_was_asked():
    text = " ".join((PLAYBOOKS_DIR / "cloudtrail.md").read_text().split())
    assert "CloudTrail returned no write event naming" in text
    assert "by the lookups listed in the fact" in text
    assert "looked up by resource name only" in text and "--target event_sources=" in text
    assert "No change was recorded" not in text


def run_command_lines(path):
    return [(n, m.group(0)) for n, line in enumerate(path.read_text().splitlines(), start=1)
            for m in re.finditer(r"`run (?:collect|opensearch_query)[^`]*`", line)]


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_run_commands_carry_the_case_folder(path):
    missing = [f"{path.name}:{n}: {c}" for n, c in run_command_lines(path) if "--case-dir <case>" not in c]
    assert not missing, "\n" + "\n".join(missing)


@pytest.mark.parametrize("path", PLAYBOOKS, ids=IDS)
def test_every_run_collect_command_carries_a_suffix(path):
    """The plan already ran each collector once with no suffix, so a run by hand without one exits 2."""
    text = " ".join(path.read_text().split())
    missing = [match.group(0) for match in COLLECT_RE.finditer(text) if "--suffix" not in match.group(2)]
    assert not missing, "\n" + "\n".join(missing)


def test_cloudwatch_says_the_plan_reads_alarms_in_alarm_when_none_are_mapped():
    text = " ".join((PLAYBOOKS_DIR / "cloudwatch.md").read_text().split())
    assert "skipped `alarms` line" not in text
    assert "in_alarm=true" in text


def test_cloudfront_change_lookup_searches_the_cloudfront_event_source():
    """CloudFront records its events in us-east-1; the event_sources search is what reaches them."""
    text = (PLAYBOOKS_DIR / "cloudfront-waf.md").read_text()
    line = next(line for line in text.splitlines() if "`run collect changes" in line)
    assert "--target event_sources=cloudfront.amazonaws.com" in line and "--suffix" in line
