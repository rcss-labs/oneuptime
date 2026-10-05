from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.lambda_function import COLLECTOR

IN_WINDOW = "2026-10-04T10:42:10.000+0000"
OUTSIDE = "2026-09-20T08:00:00.000+0000"


def configuration(**overrides):
    body = {
        "FunctionName": "orders-worker", "Runtime": "python3.12", "MemorySize": 512, "Timeout": 30,
        "State": "Active", "LastUpdateStatus": "Successful", "LastModified": OUTSIDE,
        "Environment": {"Variables": {"LOG_LEVEL": "info"}},
    }
    body.update(overrides)
    return body


def mapping(state="Enabled", result="OK", uuid="map-1"):
    return {"UUID": uuid, "EventSourceArn": "arn:aws:sqs:eu-west-1:111111111111:orders", "State": state,
            "LastProcessingResult": result}


def answers(**extra):
    base = {
        "lambda get-function-configuration": configuration(),
        "lambda get-function-concurrency": {},
        "lambda list-event-source-mappings": {"EventSourceMappings": []},
        "lambda get-account-settings": {"AccountLimit": {"ConcurrentExecutions": 1000, "UnreservedConcurrentExecutions": 900}},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    base.update(extra)
    return base


def run(config_data, tmp_path, replies):
    ctx, aws, kube = make_context(config_data, tmp_path, replies, collector="lambda")
    COLLECTOR.run(ctx, {"function": "orders-worker"})
    return ctx, aws, kube


def with_text(ctx, text):
    return [f for f in ctx.evidence.facts if text in f.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "lambda"
    assert COLLECTOR.required == ("function",)
    assert COLLECTOR.optional == ()


def test_healthy_function(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers())
    fact = ctx.evidence.facts[0]
    assert fact.kind == "current" and fact.resource == "function/orders-worker"
    for part in ("python3.12", "memory 512", "timeout 30", "Active", "Successful", "2026-09-20T08:00:00Z"):
        assert part in fact.summary
    assert "LOG_LEVEL" in fact.summary
    assert "inside the incident window" not in fact.summary
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


def test_recent_change_is_called_out(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-configuration": configuration(LastModified=IN_WINDOW)}))
    assert "modified inside the incident window" in ctx.evidence.facts[0].summary


def test_failed_update_shows_the_reason(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-configuration": configuration(
            State="Failed", StateReason="The function failed to initialise",
            LastUpdateStatus="Failed", LastUpdateStatusReason="Subnet has no free addresses")}))
    summary = ctx.evidence.facts[0].summary
    assert "Failed" in summary and "failed to initialise" in summary and "no free addresses" in summary


def test_missing_function(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-configuration": (254, "An error occurred (ResourceNotFoundException) when calling: not found")}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert ctx.evidence.errors == []
    assert aws.called("lambda", "get-account-settings") == []


def test_reserved_concurrency(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-concurrency": {"ReservedConcurrentExecutions": 5}}))
    assert with_text(ctx, "reserved concurrency 5")
    ctx2, _, _ = run(config_data, tmp_path, answers())
    assert with_text(ctx2, "no reserved concurrency")


def test_event_source_mappings(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers(**{
        "lambda list-event-source-mappings": {"EventSourceMappings": [
            mapping(), mapping(state="Disabled", result="PROBLEM: Function call failed", uuid="map-2")]}}))
    problem = with_text(ctx, "Disabled")[0]
    assert problem.kind == "current" and "PROBLEM: Function call failed" in problem.summary
    assert len(with_text(ctx, "Event source mapping")) == 2
    call = aws.called("lambda", "list-event-source-mappings")[0]
    assert call[call.index("--max-items") + 1] == "20"


def test_account_limit(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers())
    fact = with_text(ctx, "Account concurrency")[0]
    assert "1000" in fact.summary and "900" in fact.summary


def test_metrics(config_data, tmp_path):
    results = {"MetricDataResults": [
        {"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [40.0]},
        {"Id": "m1", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [7.0]},
    ]}
    ctx, aws, _ = run(config_data, tmp_path, answers(**{"cloudwatch get-metric-data": results}))
    assert with_text(ctx, "Errors (Sum): peak 40")
    assert with_text(ctx, "Throttles (Sum): peak 7")
    assert len([f for f in ctx.evidence.facts if "no data was returned" in f.summary]) == 3


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers(**{
        "lambda list-event-source-mappings": access_denied("ListEventSourceMappings")}))
    assert len(ctx.evidence.errors) == 1 and ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert with_text(ctx, "python3.12") and with_text(ctx, "Account concurrency")
    assert_read_only(ctx, aws, kube)


def test_environment_secrets_never_reach_the_document(config_data, tmp_path):
    password = "pw" + "4" * 10
    url_secret = "hunter" + "7" * 6
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-configuration": configuration(Environment={"Variables": {
            "DB_PASSWORD": password, "DATABASE_URL": f"postgres://app:{url_secret}@db.example.com/orders"}})}))
    document = ctx.evidence.to_json()
    assert password not in document and url_secret not in document
    assert "DB_PASSWORD" in document and "db.example.com" in document


def test_values_under_innocent_names_never_reach_the_document(config_data, tmp_path):
    values = {
        "SIGNING_SALT": "q9Zr7Lm2" + "Xc4Vb8Nt",
        "STRIPE_KEY": "rk_prod_" + "a1b2c3d4e5f6",
        "UPSTREAM_HEADER": "Basic " + "dXNlcjpwYXNz",
        "HMAC": "F00dFace" + "Cafe1234",
    }
    variables = {**values, "LOG_LEVEL": "info", "QUEUE_URL": "https://sqs.example.com/orders?x=" + "z" * 12}
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-configuration": configuration(Environment={"Variables": variables})}))
    document = ctx.evidence.to_json()
    for value in values.values():
        assert value not in document
    for name in values:
        assert name in document
    assert ctx.evidence.facts[0].data["environment"]["LOG_LEVEL"] == "info"
    assert ctx.evidence.facts[0].data["environment"]["QUEUE_URL"] == "https://sqs.example.com"


def test_access_denied_on_the_configuration_is_not_reported_as_not_found(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-configuration": access_denied("GetFunctionConfiguration")}))
    assert ctx.evidence.facts == []
    assert ctx.evidence.errors[0]["code"] == "AccessDeniedException"


def test_not_found_names_the_region(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "lambda get-function-configuration": (254, "An error occurred (ResourceNotFoundException) when calling the GetFunctionConfiguration operation: Function not found")}))
    assert "eu-west-1" in ctx.evidence.facts[0].summary


def test_missing_optional_fields_are_left_out(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "lambda list-event-source-mappings": {"EventSourceMappings": [
            {"UUID": "m", "EventSourceArn": "arn:aws:sqs:eu-west-1:111111111111:q", "State": "Enabled"}]}}))
    assert "None" not in with_text(ctx, "Event source mapping")[0].summary


def test_metrics_use_the_bare_function_name_when_given_an_arn(config_data, tmp_path):
    ctx, aws, _ = make_context(config_data, tmp_path, answers(), collector="lambda")
    COLLECTOR.run(ctx, {"function": "arn:aws:lambda:eu-west-1:111111111111:function:orders-worker"})
    call = aws.called("cloudwatch", "get-metric-data")[0]
    assert '"Value": "orders-worker"' in call[call.index("--metric-data-queries") + 1]


FUNCTION_ARN = "arn:aws:lambda:eu-west-1:111111111111:function:orders-worker:live"
ROLE_ARN = "arn:aws:iam::111111111111:role/orders-worker-role"
MAPPING_ARN = "arn:aws:lambda:eu-west-1:111111111111:event-source-mapping:1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"


def test_the_state_fact_holds_the_arns_from_the_answers(config_data, tmp_path):
    replies = answers(**{
        "lambda get-function-configuration": configuration(FunctionArn=FUNCTION_ARN, Role=ROLE_ARN, Version="7"),
        "lambda list-event-source-mappings": {"EventSourceMappings": [{**mapping(), "EventSourceMappingArn": MAPPING_ARN}]},
    })
    ctx, aws, kube = run(config_data, tmp_path, replies)
    data = ctx.evidence.facts[0].data
    assert data["arn"] == FUNCTION_ARN and data["role_arn"] == ROLE_ARN and data["version"] == "7"
    assert data["event_source_mapping_arns"] == [MAPPING_ARN]
    mapping_fact = with_text(ctx, "Event source mapping")[0]
    assert mapping_fact.data["arn"] == MAPPING_ARN
    assert_read_only(ctx, aws, kube)


def test_arn_lists_are_capped_with_an_omitted_count(config_data, tmp_path):
    many = [{**mapping(uuid=f"m{n}"), "EventSourceMappingArn": f"{MAPPING_ARN}{n:02d}"} for n in range(25)]
    ctx, _, _ = run(config_data, tmp_path, answers(**{"lambda list-event-source-mappings": {"EventSourceMappings": many}}))
    data = ctx.evidence.facts[0].data
    assert len(data["event_source_mapping_arns"]) == 20 and data["event_source_mapping_arns_omitted"] == 5


def test_an_answer_without_arns_writes_no_arn_keys(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers())
    data = ctx.evidence.facts[0].data
    assert not {"arn", "role_arn", "event_source_mapping_arns"} & set(data)
    assert ctx.evidence.errors == []
