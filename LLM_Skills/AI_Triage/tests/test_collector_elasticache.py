import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.elasticache import COLLECTOR

TARGETS = {"replication_group": "sessions"}
IN_WINDOW = "2026-10-04T10:42:10.123000+00:00"
OUTSIDE = "2026-10-04T07:00:00+00:00"
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


def healthy_answers(**extra):
    answers = {
        "elasticache describe-replication-groups": group(),
        "elasticache describe-cache-clusters": {"CacheClusters": [
            cluster("sessions-001"), cluster("sessions-002"), cluster("other-001", group_id="other")]},
        "elasticache describe-events": {"Events": []},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers):
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="elasticache")
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
    assert by_summary(ctx, "other-001") == []
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws)


def test_unhealthy_group_and_member(config_data, tmp_path):
    answers = healthy_answers(**{
        "elasticache describe-replication-groups": group(Status="modifying", AutomaticFailover="disabled"),
        "elasticache describe-cache-clusters": {"CacheClusters": [cluster("sessions-001"), cluster("sessions-002", status="rebooting cache cluster nodes")]},
    })
    ctx, _ = run(config_data, tmp_path, answers)
    assert "sessions is modifying" in ctx.evidence.facts[0].summary
    assert "automatic failover disabled" in ctx.evidence.facts[0].summary
    assert "rebooting cache cluster nodes" in by_summary(ctx, "Member sessions-002")[0].summary


def test_events_per_member_inside_the_window(config_data, tmp_path):
    events = {"Events": [
        {"SourceIdentifier": "sessions-001", "Message": "Failover from master node sessions-001 to replica", "Date": IN_WINDOW},
        {"SourceIdentifier": "sessions-001", "Message": "old", "Date": OUTSIDE},
    ]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-events": events}))
    calls = aws.called("elasticache", "describe-events")
    assert [c[c.index("--source-identifier") + 1] for c in calls] == ["sessions-001", "sessions-002"]
    assert all(c[c.index("--source-type") + 1] == "cache-cluster" for c in calls)
    assert calls[0][calls[0].index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    failover = by_summary(ctx, "Failover from master")
    assert len(failover) == 2 and failover[0].kind == "incident_time" and failover[0].time == "2026-10-04T10:42:10Z"
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
    answers = healthy_answers(**{
        "elasticache describe-replication-groups": group(members=names),
        "elasticache describe-cache-clusters": {"CacheClusters": [cluster(n) for n in names]},
    })
    ctx, aws = run(config_data, tmp_path, answers)
    assert len(aws.called("elasticache", "describe-events")) == 10
    assert len(by_summary(ctx, "Member sessions-")) == 10
    assert by_summary(ctx, "12 members")


def test_missing_group(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-replication-groups": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("elasticache", "describe-cache-clusters") == []


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-cache-clusters": access_denied("DescribeCacheClusters")}))
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert "sessions is available" in ctx.evidence.facts[0].summary
    assert aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws)


def test_secret_in_event_message_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "4" * 10
    events = {"Events": [{"Message": f"auth failed token={secret}", "Date": IN_WINDOW}]}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"elasticache describe-events": events}))
    assert secret not in ctx.evidence.to_json()
    assert "auth failed" in ctx.evidence.to_json()
