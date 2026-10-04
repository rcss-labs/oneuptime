import json
from datetime import date

import pytest

from fakes import SSO_EXPIRED_ERROR, FakeAws, access_denied
from triage.config import parse_config
from triage.discover import Discovery, Step, discover_hostname
from triage.guard_aws import check_aws
from triage.service_map import parse_map
from triage.verdict import ALLOW

HOSTNAME = "app.example.com"
ALB_DNS = "shop-alb-123.eu-west-1.elb.amazonaws.com"
LB_ARN = "arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/app/shop-alb/abc"
TG_ARN = "arn:aws:elasticloadbalancing:eu-west-1:111111111111:targetgroup/shop-tg/def"
CLUSTER_ARN = "arn:aws:ecs:eu-west-1:111111111111:cluster/shop"
SERVICE_ARN = "arn:aws:ecs:eu-west-1:111111111111:service/shop/shop-api"
TASK_DEF = "arn:aws:ecs:eu-west-1:111111111111:task-definition/shop-api:7"
DB_HOST = "shop-db.abc.eu-west-1.rds.amazonaws.com"
CACHE_HOST = "shop-cache.xyz.cache.amazonaws.com"
SEARCH_HOST = "opensearch.internal.example.com"
PASSWORD = "pass" + "word-" + "x9"


class RegionalAws(FakeAws):
    """A FakeAws that also accepts "region service operation" keys, for per-region answers."""

    def __call__(self, argv, timeout):
        region = argv[argv.index("--region") + 1]
        regional = self.answers.get(f"{region} {argv[1]} {argv[2]}")
        if regional is None:
            return super().__call__(argv, timeout)
        self.calls.append(argv)
        if isinstance(regional, tuple):
            return regional[0], "", regional[1]
        return 0, json.dumps(regional), ""


def dns_answers(target=ALB_DNS + "."):
    return {
        "route53 list-hosted-zones": {"HostedZones": [
            {"Id": "/hostedzone/ZSHORT", "Name": "com."},
            {"Id": "/hostedzone/ZEXAMPLE", "Name": "example.com."},
            {"Id": "/hostedzone/ZOTHER", "Name": "other.org."},
        ]},
        "route53 list-resource-record-sets": {"ResourceRecordSets": [
            {"Name": "app.example.com.", "Type": "A", "AliasTarget": {"DNSName": "dualstack." + target}},
            {"Name": "zzz.example.com.", "Type": "A"},
        ]},
    }


def lb_answers():
    return {
        "elbv2 describe-load-balancers": {"LoadBalancers": [
            {"LoadBalancerArn": "arn:other", "LoadBalancerName": "other", "DNSName": "other-1.elb.amazonaws.com"},
            {"LoadBalancerArn": LB_ARN, "LoadBalancerName": "shop-alb", "DNSName": ALB_DNS},
        ]},
        "elbv2 describe-target-groups": {"TargetGroups": [{"TargetGroupArn": TG_ARN}]},
    }


def task_definition(environment=None, group="/ecs/shop-api"):
    environment = environment if environment is not None else [
        {"name": "DATABASE_URL", "value": f"postgres://app:{PASSWORD}@{DB_HOST}:5432/app"},
        {"name": "REDIS_HOST", "value": CACHE_HOST + ":6379"},
        {"name": "SEARCH_URL", "value": f"https://{SEARCH_HOST}"},
        {"name": "API_TOKEN", "value": "t" + "k" * 12},
        {"name": "MODE", "value": "production"},
    ]
    return {"taskDefinition": {"containerDefinitions": [
        {"name": "api", "environment": environment,
         "logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": group}}},
        {"name": "sidecar", "environment": []},
    ]}}


def ecs_answers(environment=None):
    return {
        "ecs list-clusters": {"clusterArns": [CLUSTER_ARN]},
        "ecs list-services": {"serviceArns": [SERVICE_ARN]},
        "ecs describe-services": {"services": [
            {"serviceName": "unrelated", "taskDefinition": "td:1", "loadBalancers": []},
            {"serviceName": "shop-api", "taskDefinition": TASK_DEF,
             "loadBalancers": [{"targetGroupArn": TG_ARN}]},
        ]},
        "ecs describe-task-definition": task_definition(environment),
        "rds describe-db-instances": {"DBInstances": [
            {"DBInstanceIdentifier": "shop-db", "Endpoint": {"Address": DB_HOST}}]},
        "rds describe-db-clusters": {"DBClusters": []},
        "elasticache describe-replication-groups": {"ReplicationGroups": [
            {"ReplicationGroupId": "shop-cache",
             "NodeGroups": [{"PrimaryEndpoint": {"Address": CACHE_HOST}}]}]},
    }


@pytest.fixture
def config(config_data):
    return parse_config(config_data)


def full_walk(**extra):
    return {**dns_answers(), **lb_answers(), **ecs_answers(), **extra}


def commands(discovery):
    return [step.command for step in discovery.steps]


def test_full_walk_finds_every_resource(config):
    fake = FakeAws(full_walk())
    found = discover_hostname(HOSTNAME, config, runner=fake)

    assert found.account == "prod-main"
    assert found.region == "eu-west-1"
    assert found.resources == {
        "load_balancer": "shop-alb",
        "ecs_service": "shop/shop-api",
        "log_groups": ["/ecs/shop-api"],
        "rds": "shop-db",
        "elasticache": "shop-cache",
        "opensearch": {"cluster": "logs-prod"},
    }
    assert any("index pattern" in note for note in found.notes)
    assert all(step.command.startswith("aws ") and "--profile triage-prod-main" in step.command
               for step in found.steps)
    joined = "\n".join(commands(found))
    for expected in ("route53 list-hosted-zones", "route53 list-resource-record-sets --hosted-zone-id ZEXAMPLE",
                     "elbv2 describe-load-balancers", "elbv2 describe-target-groups",
                     "ecs describe-services", "ecs describe-task-definition", "rds describe-db-instances",
                     "elasticache describe-replication-groups"):
        assert expected in joined
    assert all(step.found for step in found.steps)
    assert "ZSHORT" not in joined


def test_dns_target_with_dualstack_prefix_and_trailing_dot_matches_the_load_balancer(config):
    found = discover_hostname(HOSTNAME, config, runner=FakeAws({**dns_answers(), **lb_answers()}))
    assert found.resources["load_balancer"] == "shop-alb"


def test_load_balancer_in_second_account(config):
    answers = {**full_walk(), "triage-prod-main elbv2 describe-load-balancers": {"LoadBalancers": []}}
    fake = FakeAws(answers)
    found = discover_hostname(HOSTNAME, config, runner=fake)
    assert found.account == "staging"
    assert found.region == "eu-west-1"
    assert found.resources["load_balancer"] == "shop-alb"
    assert any("--profile triage-staging" in step.command for step in found.steps)


def test_accounts_argument_limits_the_search(config):
    fake = FakeAws(full_walk())
    found = discover_hostname(HOSTNAME, config, runner=fake, accounts=["staging"])
    assert found.account == "staging"
    assert not any("triage-prod-main" in " ".join(argv) for argv in fake.calls)


def test_unknown_account_alias_raises(config):
    with pytest.raises(ValueError, match="nope"):
        discover_hostname(HOSTNAME, config, runner=FakeAws({}), accounts=["nope"])


def test_load_balancer_in_second_region(config):
    answers = {**full_walk(), "eu-west-1 elbv2 describe-load-balancers": {"LoadBalancers": []}}
    answers["us-east-1 elbv2 describe-load-balancers"] = lb_answers()["elbv2 describe-load-balancers"]
    fake = RegionalAws(answers)
    found = discover_hostname(HOSTNAME, config, runner=fake, accounts=["prod-main"])
    assert found.account == "prod-main"
    assert found.region == "us-east-1"
    assert any("--region us-east-1" in step.command for step in found.steps)


def test_no_hosted_zone_uses_hostname_directly(config):
    answers = {**lb_answers(), "route53 list-hosted-zones": {"HostedZones": []}}
    answers["elbv2 describe-load-balancers"] = {"LoadBalancers": [
        {"LoadBalancerArn": LB_ARN, "LoadBalancerName": "shop-alb", "DNSName": HOSTNAME}]}
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(answers))
    assert any("hosted zone" in note for note in found.notes)
    assert found.resources["load_balancer"] == "shop-alb"


def test_cname_value_gives_the_next_dns_name(config):
    answers = {**dns_answers(), **lb_answers()}
    answers["route53 list-resource-record-sets"] = {"ResourceRecordSets": [
        {"Name": "app.example.com.", "Type": "CNAME", "ResourceRecords": [{"Value": ALB_DNS}]}]}
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(answers))
    assert found.resources["load_balancer"] == "shop-alb"


def test_auto_scaling_group_behind_the_load_balancer(config):
    answers = {**dns_answers(), **lb_answers(),
               "autoscaling describe-auto-scaling-groups": {"AutoScalingGroups": [
                   {"AutoScalingGroupName": "unrelated", "TargetGroupARNs": []},
                   {"AutoScalingGroupName": "shop-asg", "TargetGroupARNs": [TG_ARN]}]},
               "ecs list-clusters": {"clusterArns": []}}
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(answers))
    assert found.resources == {"load_balancer": "shop-alb", "auto_scaling_group": "shop-asg"}


def test_ecs_match_skips_the_auto_scaling_lookup(config):
    fake = FakeAws(full_walk())
    discover_hostname(HOSTNAME, config, runner=fake)
    assert fake.called("autoscaling", "describe-auto-scaling-groups") == []


def test_nothing_found(config):
    found = discover_hostname(HOSTNAME, config, runner=FakeAws({}))
    assert found.resources == {}
    assert found.account is None and found.region is None
    assert found.notes
    with pytest.raises(ValueError):
        found.proposed_entry()


def test_denied_call_adds_a_note_and_the_walk_continues(config):
    answers = full_walk(**{"ecs describe-task-definition": access_denied("DescribeTaskDefinition")})
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(answers))
    assert any("AccessDeniedException" in note and "describe-task-definition" in note for note in found.notes)
    assert found.resources["ecs_service"] == "shop/shop-api"
    assert "rds" not in found.resources


def test_denied_dns_still_finds_the_load_balancer_by_hostname(config):
    answers = {**lb_answers(), "route53 list-hosted-zones": access_denied("ListHostedZones")}
    answers["elbv2 describe-load-balancers"] = {"LoadBalancers": [
        {"LoadBalancerArn": LB_ARN, "LoadBalancerName": "shop-alb", "DNSName": HOSTNAME}]}
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(answers))
    assert any("AccessDeniedException" in note for note in found.notes)
    assert found.resources["load_balancer"] == "shop-alb"


def test_expired_sign_in_raises(config):
    from triage.context import SignInExpired
    with pytest.raises(SignInExpired):
        discover_hostname(HOSTNAME, config, runner=FakeAws({"route53 list-hosted-zones": SSO_EXPIRED_ERROR}))


def test_environment_values_never_appear_in_the_output(config):
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(full_walk()))
    text = json.dumps(found.to_dict()) + json.dumps(found.proposed_entry())
    assert PASSWORD not in text
    assert "t" + "k" * 12 not in text
    assert "postgres://" not in text
    assert "5432" not in text
    assert "production" not in text


def test_secret_named_variable_is_not_mined_for_hosts(config):
    environment = [{"name": "DB_PASSWORD", "value": DB_HOST}]
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(full_walk(**{
        "ecs describe-task-definition": task_definition(environment)})))
    assert "rds" not in found.resources


def test_proposed_entry_is_accepted_by_parse_map(config, config_data):
    answers = full_walk()
    answers["ecs describe-task-definition"] = task_definition([
        {"name": "DATABASE_URL", "value": f"postgres://app:{PASSWORD}@{DB_HOST}:5432/app"}])
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(answers))
    entry = found.proposed_entry(monitors=["Shop API"], today=date(2026, 10, 4))
    assert entry == {
        "match": {"hostnames": [HOSTNAME], "monitors": ["Shop API"]},
        "environments": {"discovered": {"account": "prod-main", "region": "eu-west-1",
                                        "resources": found.resources}},
        "source": "discovered",
        "last_verified": "2026-10-04",
    }
    service_map = parse_map({"services": {"shop": entry}}, config)
    assert service_map.services["shop"].source == "discovered"


def test_proposed_entry_defaults_to_todays_utc_date(config):
    found = discover_hostname(HOSTNAME, config, runner=FakeAws({**dns_answers(), **lb_answers()}))
    assert date.fromisoformat(found.proposed_entry()["last_verified"])


def test_proposed_entry_without_account_raises():
    with pytest.raises(ValueError):
        Discovery(HOSTNAME, [], None, None, {}, []).proposed_entry()


def test_to_dict_shape(config):
    found = discover_hostname(HOSTNAME, config, runner=FakeAws({**dns_answers(), **lb_answers()}))
    data = found.to_dict()
    assert set(data) == {"hostname", "steps", "account", "region", "resources", "notes"}
    assert set(data["steps"][0]) == {"account", "region", "command", "found"}
    assert isinstance(found.steps[0], Step)


def test_every_argv_is_allowed_by_the_guard(config):
    fake = FakeAws(full_walk())
    discover_hostname(HOSTNAME, config, runner=fake)
    profiles = config.profiles()
    assert fake.calls
    for argv in fake.calls:
        verdict = check_aws(tuple(argv), (), profiles)
        assert verdict.kind == ALLOW, f"{' '.join(argv)}: {verdict.reason}"
        assert "--profile" in argv and "--region" in argv


def test_list_calls_are_bounded(config):
    fake = FakeAws(full_walk())
    discover_hostname(HOSTNAME, config, runner=fake)
    for service, operation in (("route53", "list-hosted-zones"), ("elbv2", "describe-load-balancers"),
                               ("ecs", "list-clusters"), ("ecs", "list-services"),
                               ("rds", "describe-db-instances")):
        for argv in fake.called(service, operation):
            assert "--max-items" in argv


def cluster_arns(count):
    return [f"arn:aws:ecs:eu-west-1:111111111111:cluster/c{i:02d}" for i in range(count)]


def test_cluster_cap_is_recorded(config):
    answers = {**dns_answers(), **lb_answers(), "ecs list-clusters": {"clusterArns": cluster_arns(12)},
               "ecs list-services": {"serviceArns": []}}
    fake = FakeAws(answers)
    found = discover_hostname(HOSTNAME, config, runner=fake)
    assert "Searched the first 10 of 12 ECS clusters" in found.notes
    assert len(fake.called("ecs", "list-services")) == 10


def test_target_group_cap_is_recorded(config):
    groups = [{"TargetGroupArn": f"{TG_ARN}{i}"} for i in range(12)]
    answers = {**dns_answers(), **lb_answers(), "elbv2 describe-target-groups": {"TargetGroups": groups},
               "ecs list-clusters": {"clusterArns": []}}
    found = discover_hostname(HOSTNAME, config, runner=FakeAws(answers))
    assert "Searched the first 10 of 12 target groups" in found.notes


def test_truncated_list_calls_are_recorded(config):
    answers = full_walk(**{
        "ecs list-clusters": {"clusterArns": [CLUSTER_ARN], "NextToken": "t"},
        "ecs list-services": {"serviceArns": [SERVICE_ARN], "NextToken": "t"},
        "rds describe-db-instances": {"DBInstances": [], "NextToken": "t"},
    })
    notes = "\n".join(discover_hostname(HOSTNAME, config, runner=FakeAws(answers)).notes)
    for expected in ("ECS clusters", "ECS services in cluster shop", "database instances"):
        assert expected in notes


def test_missing_load_balancer_error_means_not_found_here(config):
    answers = {**full_walk(), "eu-west-1 elbv2 describe-load-balancers": (254, "An error occurred (LoadBalancerNotFound) when calling the DescribeLoadBalancers operation: gone")}
    answers["us-east-1 elbv2 describe-load-balancers"] = lb_answers()["elbv2 describe-load-balancers"]
    found = discover_hostname(HOSTNAME, config, runner=RegionalAws(answers), accounts=["prod-main"])
    assert found.region == "us-east-1"
    assert any("LoadBalancerNotFound" in note for note in found.notes)


def cname_chain_runner(chain):
    """Answers record lookups from {name: record} and everything else from the full walk."""
    base = RegionalAws({**full_walk(), "route53 list-hosted-zones": {"HostedZones": [
        {"Id": "/hostedzone/ZEXAMPLE", "Name": "example.com."}]}})
    lookups = []

    def runner(argv, timeout):
        if argv[1:3] == ["route53", "list-resource-record-sets"]:
            name = argv[argv.index("--start-record-name") + 1]
            lookups.append(name)
            return 0, json.dumps({"ResourceRecordSets": [chain[name]] if name in chain else []}), ""
        return base(argv, timeout)

    runner.lookups = lookups
    return runner


def cname(name, target):
    return {"Name": name + ".", "Type": "CNAME", "ResourceRecords": [{"Value": target}]}


def test_dns_follows_up_to_three_cname_hops(config):
    runner = cname_chain_runner({
        HOSTNAME: cname(HOSTNAME, "a.example.com"),
        "a.example.com": cname("a.example.com", "b.example.com."),
        "b.example.com": {"Name": "b.example.com.", "Type": "A", "AliasTarget": {"DNSName": ALB_DNS}},
    })
    found = discover_hostname(HOSTNAME, config, runner=runner)
    assert runner.lookups == [HOSTNAME, "a.example.com", "b.example.com"]
    assert found.resources["load_balancer"] == "shop-alb"
    assert sum("list-resource-record-sets" in step.command for step in found.steps) == 3


def test_dns_stops_after_three_follow_ups(config):
    chain = {HOSTNAME: cname(HOSTNAME, "h1.example.com")}
    for number in range(1, 8):
        chain[f"h{number}.example.com"] = cname(f"h{number}.example.com", f"h{number + 1}.example.com")
    runner = cname_chain_runner(chain)
    found = discover_hostname(HOSTNAME, config, runner=runner)
    assert runner.lookups == [HOSTNAME, "h1.example.com", "h2.example.com", "h3.example.com"]
    assert any("3 hops" in note for note in found.notes)


def test_cname_loop_is_named_as_a_loop(config):
    runner = cname_chain_runner({
        HOSTNAME: cname(HOSTNAME, "b.example.com"),
        "b.example.com": cname("b.example.com", HOSTNAME),
    })
    found = discover_hostname(HOSTNAME, config, runner=runner)
    assert runner.lookups == [HOSTNAME, "b.example.com"]
    assert any("loop" in note and f"{HOSTNAME} → b.example.com → {HOSTNAME}" in note for note in found.notes)
    assert not any("hops" in note for note in found.notes)
