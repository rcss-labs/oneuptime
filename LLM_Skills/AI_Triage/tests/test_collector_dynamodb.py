import json

from fakes import FakeAws, access_denied
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


OPERATIONS = ["GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "Scan", "BatchGetItem", "BatchWriteItem", "TransactWriteItems"]
PER_OPERATION = ["ThrottledRequests", "SystemErrors", "SuccessfulRequestLatency"]


class MetricsByQuery(FakeAws):
    """Returns a datapoint only for the (metric, dimensions) pairs in `data`, as CloudWatch does for exact dimension matches."""

    def __init__(self, answers, data):
        super().__init__(answers)
        self.data = data  # {(metric name, operation or None): value}
        self.queries = []

    def __call__(self, argv, timeout):
        if argv[1:3] == ["cloudwatch", "get-metric-data"]:
            queries = json.loads(argv[argv.index("--metric-data-queries") + 1])
            self.queries.append(queries)
            results = []
            for query in queries:
                metric = query["MetricStat"]["Metric"]
                dims = {d["Name"]: d["Value"] for d in metric["Dimensions"]}
                value = self.data.get((metric["MetricName"], dims.get("Operation")))
                if value is not None:
                    results.append({"Id": query["Id"], "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [value]})
            self.answers["cloudwatch get-metric-data"] = {"MetricDataResults": results}
        return super().__call__(argv, timeout)


def run_with_metrics(config_data, tmp_path, data):
    answers = healthy_answers()
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="dynamodb")
    fake = MetricsByQuery(answers, data)
    ctx.runner = fake
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, fake


def test_table_level_metrics(config_data, tmp_path):
    ctx, fake = run_with_metrics(config_data, tmp_path, {("ReadThrottleEvents", None): 840.0})
    assert by_summary(ctx, "ReadThrottleEvents (Sum): peak 840")
    queries = fake.queries[0]
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stats == {"ReadThrottleEvents": "Sum", "WriteThrottleEvents": "Sum",
                     "ConsumedReadCapacityUnits": "Sum", "ConsumedWriteCapacityUnits": "Sum"}
    assert queries[0]["MetricStat"]["Metric"]["Namespace"] == "AWS/DynamoDB"
    assert queries[0]["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "TableName", "Value": "orders"}]


def test_per_operation_metrics_are_queried_with_the_operation_dimension(config_data, tmp_path):
    _, fake = run_with_metrics(config_data, tmp_path, {})
    seen = {}
    for queries in fake.queries:
        for query in queries:
            metric = query["MetricStat"]["Metric"]
            dims = {d["Name"]: d["Value"] for d in metric["Dimensions"]}
            if "Operation" in dims:
                assert dims["TableName"] == "orders"
                seen.setdefault(metric["MetricName"], set()).add(dims["Operation"])
    assert seen == {name: set(OPERATIONS) for name in PER_OPERATION}
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"]
             for queries in fake.queries for q in queries if "SuccessfulRequestLatency" == q["MetricStat"]["Metric"]["MetricName"]}
    assert stats == {"SuccessfulRequestLatency": "Maximum"}


def test_only_per_operation_metrics_with_data_become_facts(config_data, tmp_path):
    ctx, _ = run_with_metrics(config_data, tmp_path, {("ThrottledRequests", "Query"): 12.0, ("SuccessfulRequestLatency", "PutItem"): 340.0})
    throttled = by_summary(ctx, "ThrottledRequests Query (Sum): peak 12")
    assert len(throttled) == 1 and throttled[0].kind == "incident_time"
    assert by_summary(ctx, "SuccessfulRequestLatency PutItem (Maximum): peak 340")
    assert by_summary(ctx, "ThrottledRequests Scan") == []
    assert by_summary(ctx, "throttling or system error was recorded") == []


def test_no_per_operation_data_is_stated_once(config_data, tmp_path):
    ctx, _ = run_with_metrics(config_data, tmp_path, {})
    fact = by_summary(ctx, "throttling or system error was recorded")[0]
    assert fact.kind == "derived" and "any of the 9 operations queried" in fact.summary and "GetItem" in fact.summary
    assert len(by_summary(ctx, "throttling or system error was recorded")) == 1
    assert by_summary(ctx, "ThrottledRequests GetItem") == []


def test_unreadable_per_operation_metrics_are_not_called_clean(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": access_denied("GetMetricData")}))
    assert by_summary(ctx, "throttling or system error was recorded") == []
    assert by_summary(ctx, "could not be read")
    assert {e["code"] for e in ctx.evidence.errors} == {"AccessDeniedException"}


def test_no_item_is_ever_read(config_data, tmp_path):
    _, aws = run(config_data, tmp_path, healthy_answers())
    operations = {argv[2] for argv in aws.calls if argv[1] == "dynamodb"}
    assert operations == {"describe-table"}


def test_missing_table(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"dynamodb describe-table": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert ctx.evidence.facts[0].command
    assert ctx.evidence.errors == []
    assert aws.called("cloudwatch", "get-metric-data") == []


def test_denied_describe_table_is_an_error_not_a_missing_table(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"dynamodb describe-table": access_denied("DescribeTable")}))
    assert ctx.evidence.facts == []
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]


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


def per_operation_calls(fake):
    return [q for q in fake.queries if any("Operation" in {d["Name"] for d in x["MetricStat"]["Metric"]["Dimensions"]} for x in q)]


def test_a_busy_table_without_throttling_still_gets_the_no_throttling_fact(config_data, tmp_path):
    ctx, _ = run_with_metrics(config_data, tmp_path, {("SuccessfulRequestLatency", "GetItem"): 12.5})
    assert by_summary(ctx, "SuccessfulRequestLatency GetItem (Maximum): peak 12.5")
    assert len(by_summary(ctx, "throttling or system error was recorded")) == 1


def test_no_such_fact_when_throttling_or_errors_have_data(config_data, tmp_path):
    for data in ({("ThrottledRequests", "Scan"): 3.0}, {("SystemErrors", "PutItem"): 1.0}):
        ctx, _ = run_with_metrics(config_data, tmp_path, data)
        assert by_summary(ctx, "throttling or system error was recorded") == []


def test_per_operation_metrics_cost_two_calls(config_data, tmp_path):
    _, fake = run_with_metrics(config_data, tmp_path, {("ThrottledRequests", "Query"): 12.0})
    calls = per_operation_calls(fake)
    assert len(calls) == 2


class BaselineDenied(MetricsByQuery):
    """Fails only the call that reads the week-earlier baseline."""

    def __call__(self, argv, timeout):
        if argv[1:3] == ["cloudwatch", "get-metric-data"] and argv[argv.index("--start-time") + 1].startswith("2026-09-27"):
            queries = json.loads(argv[argv.index("--metric-data-queries") + 1])
            if any(any(d["Name"] == "Operation" for d in q["MetricStat"]["Metric"]["Dimensions"]) for q in queries):
                return access_denied("GetMetricData")[0], "", access_denied("GetMetricData")[1]
        return super().__call__(argv, timeout)


def test_a_failed_baseline_is_named_and_the_window_is_still_reported(config_data, tmp_path):
    answers = healthy_answers()
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="dynamodb")
    ctx.runner = BaselineDenied(answers, {("ThrottledRequests", "Query"): 12.5})
    COLLECTOR.run(ctx, dict(TARGETS))
    assert by_summary(ctx, "ThrottledRequests Query (Sum): peak 12.5")
    fact = by_summary(ctx, "one-week baseline")[0]
    assert fact.kind == "derived" and "could not be read" in fact.summary and "window" in fact.summary
    assert by_summary(ctx, "per-operation throttling and system error metrics could not be read") == []


def test_no_throttling_is_not_stated_when_table_level_throttle_metrics_show_throttling(config_data, tmp_path):
    for metric in ("ReadThrottleEvents", "WriteThrottleEvents"):
        ctx, _ = run_with_metrics(config_data, tmp_path, {(metric, None): 40.0})
        assert by_summary(ctx, f"{metric} (Sum): peak 40")
        assert by_summary(ctx, "throttling or system error was recorded") == []


def test_zero_table_level_throttle_events_do_not_suppress_the_statement(config_data, tmp_path):
    ctx, _ = run_with_metrics(config_data, tmp_path, {("WriteThrottleEvents", None): 0.0})
    assert len(by_summary(ctx, "throttling or system error was recorded")) == 1
