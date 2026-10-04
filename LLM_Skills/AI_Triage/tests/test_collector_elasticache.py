import json

from fakes import FakeAws, access_denied
from helpers import assert_read_only, make_context
from triage.collectors.elasticache import COLLECTOR

TARGETS = {"replication_group": "sessions"}
IN_WINDOW = "2026-10-04T10:42:10.123000+00:00"
OUTSIDE = "2026-10-04T07:00:00+00:00"
CLUSTER_NOT_FOUND = (254, "An error occurred (CacheClusterNotFound) when calling the DescribeCacheClusters operation: x")
NOT_FOUND = (254, "An error occurred (ReplicationGroupNotFoundFault) when calling the DescribeReplicationGroups operation: x")


def group(members=("sessions-001", "sessions-002"), **overrides):
    body = {
        "ReplicationGroupId": "sessions", "Status": "available", "MemberClusters": list(members),
        "AutomaticFailover": "enabled", "MultiAZ": "enabled",
        "NodeGroups": [{
            "NodeGroupId": "0001", "Status": "available",
            "PrimaryEndpoint": {"Address": "sessions.abc.use1.cache.example.com", "Port": 6379},
            "ReaderEndpoint": {"Address": "sessions-ro.abc.use1.cache.example.com", "Port": 6379},
        }],
    }
    body.update(overrides)
    return {"ReplicationGroups": [body]}


def cluster(name, status="available", group_id="sessions"):
    return {"CacheClusterId": name, "ReplicationGroupId": group_id, "CacheClusterStatus": status, "Engine": "redis",
            "EngineVersion": "7.0.7", "CacheNodeType": "cache.r6g.large",
            "CacheNodes": [{"CacheNodeId": "0001", "CacheNodeStatus": status}]}


class PerMember(FakeAws):
    """Answers describe-cache-clusters by --cache-cluster-id, as the real service does (an error for an unknown id)."""

    def __init__(self, answers, clusters):
        super().__init__(answers)
        self.clusters = clusters

    def __call__(self, argv, timeout):
        if argv[1:3] == ["elasticache", "describe-cache-clusters"]:
            member = argv[argv.index("--cache-cluster-id") + 1]
            self.answers["elasticache describe-cache-clusters"] = self.clusters.get(member, CLUSTER_NOT_FOUND)
        return super().__call__(argv, timeout)


def healthy_answers(**extra):
    answers = {
        "elasticache describe-replication-groups": group(),
        "elasticache describe-events": {"Events": []},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def members(*clusters):
    return {c["CacheClusterId"]: {"CacheClusters": [c]} for c in clusters}


def run(config_data, tmp_path, answers, clusters=None):
    clusters = clusters if clusters is not None else members(cluster("sessions-001"), cluster("sessions-002"))
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="elasticache")
    fake = PerMember(answers, clusters)
    ctx.runner, aws = fake, fake
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, aws


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "elasticache"
    assert COLLECTOR.required == ("replication_group",)
    assert COLLECTOR.optional == ()


def test_healthy_group(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers())
    state = ctx.evidence.facts[0]
    assert state.kind == "current" and state.id == "elasticache-0001"
    for word in ("sessions is available", "1 node group", "automatic failover enabled", "multi-AZ enabled",
                 "primary endpoint sessions.abc.use1.cache.example.com:6379", "reader endpoint sessions-ro"):
        assert word in state.summary
    member = by_summary(ctx, "Member sessions-001")[0]
    assert "redis 7.0.7" in member.summary and "cache.r6g.large" in member.summary and "available" in member.summary
    calls = aws.called("elasticache", "describe-cache-clusters")
    assert [c[c.index("--cache-cluster-id") + 1] for c in calls] == ["sessions-001", "sessions-002"]
    assert all("--show-cache-node-info" in c for c in calls)
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws)


def test_unhealthy_group_and_member(config_data, tmp_path):
    answers = healthy_answers(**{
        "elasticache describe-replication-groups": group(Status="modifying", AutomaticFailover="disabled"),
    })
    ctx, _ = run(config_data, tmp_path, answers, members(cluster("sessions-001"), cluster("sessions-002", status="rebooting cache cluster nodes")))
    assert "sessions is modifying" in ctx.evidence.facts[0].summary
    assert "automatic failover disabled" in ctx.evidence.facts[0].summary
    assert "rebooting cache cluster nodes" in by_summary(ctx, "Member sessions-002")[0].summary


def test_events_per_member_and_for_the_group(config_data, tmp_path):
    events = {"Events": [
        {"SourceIdentifier": "sessions-001", "Message": "Failover from master node sessions-001 to replica", "Date": IN_WINDOW},
        {"SourceIdentifier": "sessions-001", "Message": "old", "Date": OUTSIDE},
    ]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-events": events}))
    calls = aws.called("elasticache", "describe-events")
    requested = [(c[c.index("--source-type") + 1], c[c.index("--source-identifier") + 1]) for c in calls]
    assert ("replication-group", "sessions") in requested
    assert ("cache-cluster", "sessions-001") in requested and ("cache-cluster", "sessions-002") in requested
    assert all(c[c.index("--max-items") + 1] == "50" for c in calls)
    assert calls[0][calls[0].index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    failover = by_summary(ctx, "Failover from master")
    assert len(failover) == 3 and failover[0].kind == "incident_time" and failover[0].time == "2026-10-04T10:42:10Z"
    assert by_summary(ctx, "old") == []


def test_metrics_per_member(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers())
    calls = aws.called("cloudwatch", "get-metric-data")
    assert len(calls) == 4  # window and baseline for each of the two members
    queries = json.loads(calls[0][calls[0].index("--metric-data-queries") + 1])
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stats == {"EngineCPUUtilization": "Average", "DatabaseMemoryUsagePercentage": "Maximum", "Evictions": "Sum",
                     "CurrConnections": "Maximum", "ReplicationLag": "Maximum", "SwapUsage": "Maximum"}
    first = queries[0]["MetricStat"]["Metric"]
    assert first["Namespace"] == "AWS/ElastiCache"
    assert first["Dimensions"] == [{"Name": "CacheClusterId", "Value": "sessions-001"}]


def test_members_are_capped(config_data, tmp_path):
    names = [f"sessions-{n:03d}" for n in range(1, 13)]
    answers = healthy_answers(**{"elasticache describe-replication-groups": group(members=names)})
    ctx, aws = run(config_data, tmp_path, answers, members(*[cluster(n) for n in names]))
    assert len(aws.called("elasticache", "describe-cache-clusters")) == 10
    assert len(aws.called("elasticache", "describe-events")) == 11
    assert len(by_summary(ctx, "Member sessions-")) == 10
    assert by_summary(ctx, "12 members")


def test_a_member_the_service_does_not_know_is_reported(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(), members(cluster("sessions-001")))
    fact = by_summary(ctx, "Member sessions-002")[0]
    assert "not found" in fact.summary and fact.command
    assert ctx.evidence.errors == []


def test_a_cluster_mode_group_reports_its_configuration_endpoint(config_data, tmp_path):
    answers = healthy_answers(**{"elasticache describe-replication-groups": group(
        NodeGroups=[{"NodeGroupId": "0001", "Status": "available"}],
        ConfigurationEndpoint={"Address": "sessions.cfg.use1.cache.example.com", "Port": 6379})})
    ctx, _ = run(config_data, tmp_path, answers)
    assert "configuration endpoint sessions.cfg.use1.cache.example.com:6379" in ctx.evidence.facts[0].summary


def test_missing_group(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-replication-groups": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert ctx.evidence.facts[0].command
    assert ctx.evidence.errors == []
    assert aws.called("elasticache", "describe-cache-clusters") == []


def test_denied_group_lookup_is_an_error_not_a_missing_group(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-replication-groups": access_denied("DescribeReplicationGroups")}))
    assert ctx.evidence.facts == []
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-events": access_denied("DescribeEvents")}))
    assert {e["code"] for e in ctx.evidence.errors} == {"AccessDeniedException"}
    assert "sessions is available" in ctx.evidence.facts[0].summary
    assert aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws)


def test_secret_in_event_message_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "4" * 10
    events = {"Events": [{"Message": f"auth failed token={secret}", "Date": IN_WINDOW}]}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-events": events}))
    assert secret not in ctx.evidence.to_json()
    assert "auth failed" in ctx.evidence.to_json()
