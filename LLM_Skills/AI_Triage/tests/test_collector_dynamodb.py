import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.dynamodb import COLLECTOR

TARGETS = {"table": "orders"}
OUTSIDE = "2026-10-04T07:00:00+00:00"
NOT_FOUND = (254, "An error occurred (ResourceNotFoundException) when calling the DescribeTable operation: x")


def table(**overrides):
    body = {
        "TableName": "orders", "TableStatus": "ACTIVE", "ItemCount": 123456,
        "BillingModeSummary": {"BillingMode": "PROVISIONED"},
        "ProvisionedThroughput": {"ReadCapacityUnits": 100, "WriteCapacityUnits": 50},
        "GlobalSecondaryIndexes": [{"IndexName": "by-customer", "IndexStatus": "ACTIVE"}],
    }
    body.update(overrides)
    return {"Table": body}


def healthy_answers(**extra):
    answers = {
        "dynamodb describe-table": table(),
        "application-autoscaling describe-scaling-activities": {"ScalingActivities": []},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers):
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="dynamodb")
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, aws


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "dynamodb"
    assert COLLECTOR.required == ("table",)
    assert COLLECTOR.optional == ()


def test_healthy_table(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers())
    state = ctx.evidence.facts[0]
    assert state.kind == "current" and state.id == "dynamodb-0001"
    for word in ("orders is ACTIVE", "PROVISIONED", "read capacity 100", "write capacity 50", "123456 items", "by-customer ACTIVE"):
        assert word in state.summary
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws)


def test_on_demand_table_with_a_building_index(config_data, tmp_path):
    answers = healthy_answers(**{"dynamodb describe-table": table(
        BillingModeSummary={"BillingMode": "PAY_PER_REQUEST"}, ProvisionedThroughput={"ReadCapacityUnits": 0, "WriteCapacityUnits": 0},
        GlobalSecondaryIndexes=[{"IndexName": "by-day", "IndexStatus": "CREATING"}], TableStatus="UPDATING")})
    ctx, _ = run(config_data, tmp_path, answers)
    summary = ctx.evidence.facts[0].summary
    assert "PAY_PER_REQUEST" in summary and "UPDATING" in summary and "by-day CREATING" in summary


def test_scaling_activities_inside_window(config_data, tmp_path):
    activities = {"ScalingActivities": [
        {"Description": "Setting write capacity to 100", "Cause": "alarm high", "StartTime": "2026-10-04T10:50:00+00:00", "StatusCode": "Successful"},
        {"Description": "Setting write capacity to 20", "Cause": "old", "StartTime": OUTSIDE, "StatusCode": "Successful"},
    ]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"application-autoscaling describe-scaling-activities": activities}))
    facts = by_summary(ctx, "write capacity to 100")
    assert len(facts) == 1 and facts[0].kind == "incident_time" and facts[0].time == "2026-10-04T10:50:00Z"
    assert by_summary(ctx, "write capacity to 20") == []
    call = aws.called("application-autoscaling", "describe-scaling-activities")[0]
    assert call[call.index("--resource-id") + 1] == "table/orders"
    assert call[call.index("--service-namespace") + 1] == "dynamodb"
    assert call[call.index("--max-items") + 1] == "20"
    assert_read_only(ctx, aws)


def test_metrics(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [840.0]}]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    assert by_summary(ctx, "ReadThrottleEvents (Sum): peak 840.0")
    call = aws.called("cloudwatch", "get-metric-data")[0]
    queries = json.loads(call[call.index("--metric-data-queries") + 1])
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stats == {"ReadThrottleEvents": "Sum", "WriteThrottleEvents": "Sum", "ThrottledRequests": "Sum",
                     "ConsumedReadCapacityUnits": "Sum", "ConsumedWriteCapacityUnits": "Sum", "SystemErrors": "Sum",
                     "SuccessfulRequestLatency": "Maximum"}
    assert queries[0]["MetricStat"]["Metric"]["Namespace"] == "AWS/DynamoDB"
    assert queries[0]["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "TableName", "Value": "orders"}]


def test_no_item_is_ever_read(config_data, tmp_path):
    _, aws = run(config_data, tmp_path, healthy_answers())
    operations = {argv[2] for argv in aws.calls if argv[1] == "dynamodb"}
    assert operations == {"describe-table"}


def test_missing_table(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"dynamodb describe-table": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("cloudwatch", "get-metric-data") == []


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"application-autoscaling describe-scaling-activities": access_denied("DescribeScalingActivities")})
    ctx, aws = run(config_data, tmp_path, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert "orders is ACTIVE" in ctx.evidence.facts[0].summary
    assert aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws)


def test_secret_in_scaling_cause_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "2" * 10
    activities = {"ScalingActivities": [{"Description": "scale", "Cause": f"token={secret}", "StartTime": "2026-10-04T10:50:00+00:00", "StatusCode": "Failed"}]}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"application-autoscaling describe-scaling-activities": activities}))
    assert secret not in ctx.evidence.to_json()


def test_scaling_activity_list_is_bounded_by_max_items(config_data, tmp_path):
    activities = {"ScalingActivities": [{"Description": f"a{n}", "StartTime": f"2026-10-04T10:{n:02d}:00+00:00", "StatusCode": "Successful"} for n in range(30)]}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"application-autoscaling describe-scaling-activities": activities}))
    assert len(by_summary(ctx, "Scaling activity")) <= 20
