import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.opensearch_domain import COLLECTOR

TARGETS = {"domain": "logs-prod"}
IN_WINDOW = "2026-10-04T10:42:10.123000+00:00"
OUTSIDE = "2026-10-04T07:00:00+00:00"
NOT_FOUND = (254, "An error occurred (ResourceNotFoundException) when calling the DescribeDomain operation: x")


def domain(**overrides):
    body = {
        "DomainName": "logs-prod", "EngineVersion": "OpenSearch_2.11", "Processing": False,
        "Endpoint": "search-logs-prod.eu-west-1.es.example.com",
        "ClusterConfig": {"InstanceType": "r6g.large.search", "InstanceCount": 3},
        "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 100},
    }
    body.update(overrides)
    return {"DomainStatus": body}


def health(**overrides):
    body = {"ClusterHealth": "Green", "DomainState": "Active", "DataNodeCount": "3", "MasterEligibleNodeCount": "3",
            "TotalShards": "120", "TotalUnAssignedShards": "0"}
    body.update(overrides)
    return body


def change(status="COMPLETED", start=IN_WINDOW):
    return {"ChangeProgressStatus": {"ChangeId": "c" * 36, "Status": status, "StartTime": start,
                                     "ConfigChangeStatus": "ApplyingChanges", "TotalNumberOfStages": 5}}


def healthy_answers(**extra):
    answers = {
        "opensearch describe-domain": domain(),
        "opensearch describe-domain-health": health(),
        "opensearch describe-domain-change-progress": change(start=OUTSIDE),
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers):
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="opensearch_domain")
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, aws


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "opensearch_domain"
    assert COLLECTOR.required == ("domain",)
    assert COLLECTOR.optional == ()


def test_healthy_domain(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers())
    state = ctx.evidence.facts[0]
    assert state.kind == "current" and state.id == "opensearch_domain-0001"
    for word in ("logs-prod", "OpenSearch_2.11", "3 x r6g.large.search", "100 GiB gp3", "not processing a change",
                 "search-logs-prod.eu-west-1.es.example.com"):
        assert word in state.summary
    cluster = by_summary(ctx, "Cluster health is Green")[0]
    assert "3 data nodes" in cluster.summary and "120 shards" in cluster.summary and "0 unassigned" in cluster.summary
    assert by_summary(ctx, "configuration change") == []
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws)


def test_red_cluster_that_is_processing(config_data, tmp_path):
    answers = healthy_answers(**{
        "opensearch describe-domain": domain(Processing=True),
        "opensearch describe-domain-health": health(ClusterHealth="Red", TotalUnAssignedShards="14"),
    })
    ctx, _ = run(config_data, tmp_path, answers)
    assert "processing a change" in ctx.evidence.facts[0].summary
    assert "not processing" not in ctx.evidence.facts[0].summary
    assert "Cluster health is Red" in by_summary(ctx, "Red")[0].summary
    assert "14 unassigned" in by_summary(ctx, "Red")[0].summary


def test_change_in_progress_started_before_the_window_is_reported(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"opensearch describe-domain-change-progress": change("PROCESSING", OUTSIDE)}))
    fact = by_summary(ctx, "configuration change")[0]
    assert fact.kind == "incident_time" and "PROCESSING" in fact.summary and fact.time == "2026-10-04T07:00:00Z"


def test_change_finished_inside_the_window_is_reported(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"opensearch describe-domain-change-progress": change("COMPLETED")}))
    fact = by_summary(ctx, "configuration change")[0]
    assert "COMPLETED" in fact.summary and fact.time == "2026-10-04T10:42:10Z"


def test_old_finished_change_is_dropped(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers())
    assert by_summary(ctx, "configuration change") == []


def test_metrics_use_the_account_id_dimension(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m3", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [91.0]}]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    assert by_summary(ctx, "JVMMemoryPressure (Maximum): peak 91")
    call = aws.called("cloudwatch", "get-metric-data")[0]
    queries = json.loads(call[call.index("--metric-data-queries") + 1])
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stats == {"ClusterStatus.red": "Maximum", "ClusterStatus.yellow": "Maximum", "FreeStorageSpace": "Minimum",
                     "JVMMemoryPressure": "Maximum", "CPUUtilization": "Average", "ThreadpoolWriteRejected": "Sum",
                     "ThreadpoolSearchRejected": "Sum", "5xx": "Sum"}
    metric = queries[0]["MetricStat"]["Metric"]
    assert metric["Namespace"] == "AWS/ES"
    assert metric["Dimensions"] == [{"Name": "DomainName", "Value": "logs-prod"}, {"Name": "ClientId", "Value": "111111111111"}]


def test_missing_domain(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"opensearch describe-domain": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("opensearch", "describe-domain-health") == []


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"opensearch describe-domain-health": access_denied("DescribeDomainHealth")})
    ctx, aws = run(config_data, tmp_path, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert "OpenSearch_2.11" in ctx.evidence.facts[0].summary
    assert aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws)


def test_secret_looking_endpoint_text_is_redacted(config_data, tmp_path):
    secret = "pw" + "3" * 10
    answers = healthy_answers(**{"opensearch describe-domain": domain(Endpoint=f"https://admin:{secret}@search.example.com")})
    ctx, _ = run(config_data, tmp_path, answers)
    assert secret not in ctx.evidence.to_json()
    assert "search.example.com" in ctx.evidence.to_json()


def test_the_domain_is_never_queried_for_documents(config_data, tmp_path):
    _, aws = run(config_data, tmp_path, healthy_answers())
    assert {argv[1] for argv in aws.calls} == {"opensearch", "cloudwatch"}


def test_vpc_domain_endpoint_comes_from_the_endpoints_map(config_data, tmp_path):
    answers = healthy_answers(**{"opensearch describe-domain": domain(Endpoint=None, Endpoints={"vpc": "vpc-logs-prod.eu-west-1.es.example.com"})})
    ctx, _ = run(config_data, tmp_path, answers)
    assert "endpoint vpc-logs-prod.eu-west-1.es.example.com" in ctx.evidence.facts[0].summary
    assert "endpoint none" not in ctx.evidence.facts[0].summary


def test_not_found_fact_names_its_command_and_records_no_error(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"opensearch describe-domain": NOT_FOUND}))
    assert ctx.evidence.facts[0].command
    assert ctx.evidence.errors == []


def test_denied_describe_domain_is_an_error_not_a_missing_domain(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"opensearch describe-domain": access_denied("DescribeDomain")}))
    assert ctx.evidence.facts == []
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]


def test_pending_change_without_a_start_time_is_a_current_fact(config_data, tmp_path):
    pending = {"ChangeProgressStatus": {"ChangeId": "c" * 36, "Status": "PENDING"}}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"opensearch describe-domain-change-progress": pending}))
    fact = by_summary(ctx, "configuration change")[0]
    assert fact.kind == "current" and fact.time is None


def test_dual_stack_domain_reports_its_vpcv2_endpoint(config_data, tmp_path):
    answers = healthy_answers(**{"opensearch describe-domain": domain(Endpoint=None, Endpoints={"vpcv2": "vpc-v2-logs.eu-west-1.es.example.com"})})
    ctx, _ = run(config_data, tmp_path, answers)
    assert "endpoint vpc-v2-logs.eu-west-1.es.example.com" in ctx.evidence.facts[0].summary
