import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.apigateway import COLLECTOR

IN_WINDOW = "2026-10-04T10:42:10+00:00"
OUTSIDE = "2026-10-01T07:00:00+00:00"
REST = {"api_id": "abc123"}
HTTP = {"api_id": "xyz789", "kind": "http"}
NOT_FOUND = (254, "An error occurred (NotFoundException) when calling the GetRestApi operation: Invalid API identifier")


def rest_stage(name="prod", updated=OUTSIDE, **overrides):
    body = {"stageName": name, "deploymentId": "dep1", "lastUpdatedDate": updated, "cacheClusterEnabled": True,
            "cacheClusterStatus": "AVAILABLE",
            "methodSettings": {"*/*": {"throttlingRateLimit": 100.0, "throttlingBurstLimit": 200}}}
    body.update(overrides)
    return body


def rest_answers(**extra):
    answers = {
        "apigateway get-rest-api": {"id": "abc123", "name": "orders-api"},
        "apigateway get-stages": {"item": [rest_stage()]},
        "apigateway get-deployments": {"items": [{"id": "dep1", "createdDate": OUTSIDE}]},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def http_stage(name="$default", updated=OUTSIDE):
    return {"StageName": name, "DeploymentId": "dep9", "LastUpdatedDate": updated,
            "DefaultRouteSettings": {"ThrottlingRateLimit": 50.0, "ThrottlingBurstLimit": 80}}


def http_answers(**extra):
    answers = {
        "apigatewayv2 get-api": {"ApiId": "xyz789", "Name": "events-api"},
        "apigatewayv2 get-stages": {"Items": [http_stage()]},
        "apigatewayv2 get-deployments": {"Items": [{"DeploymentId": "dep9", "CreatedDate": OUTSIDE}]},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers, targets):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="apigateway")
    COLLECTOR.run(ctx, dict(targets))
    return ctx, aws, kube


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def value_of(call, option):
    return call[call.index(option) + 1]


def queries(aws):
    return json.loads(value_of(aws.called("cloudwatch", "get-metric-data")[0], "--metric-data-queries"))


def test_declares_its_targets():
    assert COLLECTOR.name == "apigateway"
    assert COLLECTOR.required == ("api_id",)
    assert COLLECTOR.optional == ("stage", "kind")


def test_healthy_rest_api(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, rest_answers(), REST)
    stage = by_summary(ctx, "Stage prod")[0]
    assert stage.kind == "current"
    assert "deployment dep1" in stage.summary and "last updated 2026-10-01T07:00:00Z" in stage.summary
    assert "*/* rate 100.0 burst 200" in stage.summary and "cache enabled (AVAILABLE)" in stage.summary
    assert "inside the window" not in stage.summary
    assert not [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert value_of(aws.called("apigateway", "get-deployments")[0], "--max-items") == "5"
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


def test_stage_and_deployment_changed_inside_the_window(config_data, tmp_path):
    answers = rest_answers(**{
        "apigateway get-stages": {"item": [rest_stage(updated=IN_WINDOW)]},
        "apigateway get-deployments": {"items": [
            {"id": "dep2", "createdDate": IN_WINDOW, "description": "release 42"},
            {"id": "dep1", "createdDate": OUTSIDE}]}})
    ctx, _, _ = run(config_data, tmp_path, answers, REST)
    assert "was updated inside the window" in by_summary(ctx, "Stage prod")[0].summary
    deployments = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert len(deployments) == 1 and "dep2" in deployments[0].summary
    assert deployments[0].time == "2026-10-04T10:42:10Z" and deployments[0].excerpt == "release 42"


def test_stage_target_limits_stages_and_metrics(config_data, tmp_path):
    answers = rest_answers(**{"apigateway get-stages": {"item": [rest_stage("prod"), rest_stage("beta")]}})
    ctx, aws, _ = run(config_data, tmp_path, answers, {**REST, "stage": "beta"})
    assert by_summary(ctx, "Stage beta") and not by_summary(ctx, "Stage prod")
    stages = {d["Value"] for q in queries(aws) for d in q["MetricStat"]["Metric"]["Dimensions"] if d["Name"] == "Stage"}
    assert stages == {"beta"}


def test_rest_metrics(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [17.0]}]}
    ctx, aws, _ = run(config_data, tmp_path, rest_answers(**{"cloudwatch get-metric-data": results}), REST)
    sent = queries(aws)
    names = {(q["MetricStat"]["Metric"]["MetricName"], q["MetricStat"]["Stat"]) for q in sent}
    assert names == {("5XXError", "Sum"), ("4XXError", "Sum"), ("Latency", "Maximum"),
                     ("IntegrationLatency", "Maximum"), ("Count", "Sum")}
    metric = sent[0]["MetricStat"]["Metric"]
    assert metric["Namespace"] == "AWS/ApiGateway"
    assert metric["Dimensions"] == [{"Name": "ApiName", "Value": "orders-api"}, {"Name": "Stage", "Value": "prod"}]
    assert by_summary(ctx, "5XXError prod (Sum): peak 17.0")


def test_http_api(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [3.0]}]}
    answers = http_answers(**{
        "apigatewayv2 get-stages": {"Items": [http_stage(updated=IN_WINDOW)]},
        "apigatewayv2 get-deployments": {"Items": [{"DeploymentId": "dep9", "CreatedDate": IN_WINDOW,
                                                    "DeploymentStatus": "DEPLOYED"}]},
        "cloudwatch get-metric-data": results})
    ctx, aws, kube = run(config_data, tmp_path, answers, HTTP)
    stage = by_summary(ctx, "Stage $default")[0]
    assert "rate 50.0 burst 80" in stage.summary and "updated inside the window" in stage.summary
    assert [f for f in ctx.evidence.facts if f.kind == "incident_time" and "dep9" in f.summary]
    assert aws.called("apigateway", "get-stages") == []
    assert value_of(aws.called("apigatewayv2", "get-deployments")[0], "--max-items") == "5"
    sent = queries(aws)
    assert {q["MetricStat"]["Metric"]["MetricName"] for q in sent} == {"5xx", "4xx", "Latency", "IntegrationLatency", "Count"}
    assert sent[0]["MetricStat"]["Metric"]["Dimensions"] == [
        {"Name": "ApiId", "Value": "xyz789"}, {"Name": "Stage", "Value": "$default"}]
    assert_read_only(ctx, aws, kube)


def test_missing_api(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, rest_answers(**{"apigateway get-rest-api": NOT_FOUND}), REST)
    assert by_summary(ctx, "API abc123 was not found")
    assert aws.called("apigateway", "get-stages") == []


def test_denied_call_keeps_the_rest(config_data, tmp_path):
    answers = rest_answers(**{"apigateway get-deployments": access_denied("GetDeployments")})
    ctx, aws, kube = run(config_data, tmp_path, answers, REST)
    assert len(ctx.evidence.errors) == 1 and ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert by_summary(ctx, "Stage prod") and aws.called("cloudwatch", "get-metric-data")
    assert_read_only(ctx, aws, kube)


def test_denied_api_lookup_skips_metrics_but_keeps_stages(config_data, tmp_path):
    answers = rest_answers(**{"apigateway get-rest-api": access_denied("GetRestApi")})
    ctx, aws, _ = run(config_data, tmp_path, answers, REST)
    assert by_summary(ctx, "Stage prod") and not by_summary(ctx, "was not found")
    assert aws.called("cloudwatch", "get-metric-data") == []


def test_secret_in_a_deployment_description_is_redacted(config_data, tmp_path):
    secret = "pw" + "4" * 10
    answers = rest_answers(**{"apigateway get-deployments": {"items": [
        {"id": "dep2", "createdDate": IN_WINDOW, "description": f"deploy token={secret}"}]}})
    ctx, _, _ = run(config_data, tmp_path, answers, REST)
    assert secret not in ctx.evidence.to_json()


def test_usage_plans_and_api_keys_are_never_read(config_data, tmp_path):
    for answers, targets in ((rest_answers(), REST), (http_answers(), HTTP)):
        _, aws, _ = run(config_data, tmp_path, answers, targets)
        operations = {argv[2] for argv in aws.calls}
        assert not {op for op in operations if "usage-plan" in op or "api-key" in op}
