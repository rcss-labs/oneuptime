import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.cloudfront_waf import COLLECTOR

ACCOUNT = "111111111111"
GLOBAL_ACL = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:global/webacl/edge-acl/aaaa1111-2222-3333-4444-5555aaaa5555"
REGIONAL_ACL = f"arn:aws:wafv2:eu-west-1:{ACCOUNT}:regional/webacl/api-acl/bbbb1111-2222-3333-4444-5555aaaa5555"
ALB_ARN = f"arn:aws:elasticloadbalancing:eu-west-1:{ACCOUNT}:loadbalancer/app/web-alb/50dc6c495c0c9188"
IN_WINDOW = "2026-10-04T10:42:10+00:00"
OUTSIDE = "2026-10-01T07:00:00+00:00"
NO_SUCH_DISTRIBUTION = (254, "An error occurred (NoSuchDistribution) when calling the GetDistribution operation: missing")


def distribution(modified=OUTSIDE, status="Deployed"):
    return {"Distribution": {
        "Id": "E1EXAMPLE", "Status": status, "LastModifiedTime": modified, "DomainName": "d111.cloudfront.net",
        "DistributionConfig": {
            "Aliases": {"Quantity": 1, "Items": ["www.example.com"]},
            "Origins": {"Quantity": 2, "Items": [
                {"Id": "web", "DomainName": "origin.example.com"}, {"Id": "static", "DomainName": "static.example.com"}]},
            "DefaultCacheBehavior": {"TargetOriginId": "web"},
        }}}


def web_acl(arn=GLOBAL_ACL, name="edge-acl"):
    return {"WebACL": {
        "Name": name, "Id": arn.rsplit("/", 1)[-1], "ARN": arn, "DefaultAction": {"Allow": {}},
        "VisibilityConfig": {"MetricName": "edge-acl-metric"},
        "Rules": [
            {"Name": "rate-limit", "Priority": 1, "Action": {"Block": {}}, "VisibilityConfig": {"MetricName": "rate"}},
            {"Name": "managed-common", "Priority": 2, "OverrideAction": {"None": {}},
             "VisibilityConfig": {"MetricName": "common"}},
        ]}}


def sampled(requests):
    return {"SampledRequests": requests, "PopulationSize": len(requests)}


def sample(action="BLOCK", rule="rate-limit", uri="/login", country="DE", stamp=IN_WINDOW, **request):
    body = {"ClientIP": "10.1.2.3", "Country": country, "URI": uri, "Method": "POST",
            "Headers": [{"Name": "User-Agent", "Value": "probe-agent-9f3"}]}
    body.update(request)
    return {"Request": body, "Weight": 1, "Timestamp": stamp, "Action": action, "RuleNameWithinRuleGroup": rule}


def answers_for(**extra):
    answers = {
        "cloudfront get-distribution": distribution(),
        "wafv2 get-web-acl": web_acl(),
        "wafv2 get-sampled-requests": sampled([]),
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers, targets):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="cloudfront_waf")
    COLLECTOR.run(ctx, dict(targets))
    return ctx, aws, kube


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def value_of(call, option):
    return call[call.index(option) + 1]


def region_of(call):
    return value_of(call, "--region")


def test_declares_its_targets():
    assert COLLECTOR.name == "cloudfront_waf"
    assert COLLECTOR.required == ()
    assert COLLECTOR.optional == ("distribution_id", "web_acl_arn", "resource_arn")


def test_neither_target_is_reported_clearly(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {}, {})
    assert ctx.evidence.errors[0]["code"] == "MissingTarget"
    assert "distribution_id" in ctx.evidence.errors[0]["message"]
    assert aws.calls == []


def test_healthy_distribution_uses_us_east_1(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers_for(), {"distribution_id": "E1EXAMPLE"})
    fact = by_summary(ctx, "Distribution E1EXAMPLE")[0]
    assert fact.kind == "current"
    for text in ("Deployed", "last modified 2026-10-01T07:00:00Z", "d111.cloudfront.net", "www.example.com",
                 "origin.example.com", "static.example.com", "default cache behavior sends requests to origin web"):
        assert text in fact.summary
    assert "inside the window" not in fact.summary
    assert value_of(aws.called("cloudfront", "get-distribution")[0], "--id") == "E1EXAMPLE"
    assert all(region_of(call) == "us-east-1" for call in aws.calls)
    assert aws.called("wafv2", "get-web-acl") == []
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


def test_distribution_modified_inside_the_window(config_data, tmp_path):
    answers = answers_for(**{"cloudfront get-distribution": distribution(modified=IN_WINDOW, status="InProgress")})
    ctx, _, _ = run(config_data, tmp_path, answers, {"distribution_id": "E1EXAMPLE"})
    fact = by_summary(ctx, "Distribution E1EXAMPLE")[0]
    assert "InProgress" in fact.summary and "was modified inside the window" in fact.summary


def test_cloudfront_metrics_use_us_east_1_and_global_region_dimension(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [8.5]}]}
    ctx, aws, _ = run(config_data, tmp_path, answers_for(**{"cloudwatch get-metric-data": results}),
                      {"distribution_id": "E1EXAMPLE"})
    calls = aws.called("cloudwatch", "get-metric-data")
    assert calls and all(region_of(call) == "us-east-1" for call in calls)
    sent = json.loads(value_of(calls[0], "--metric-data-queries"))
    stats = {(q["MetricStat"]["Metric"]["MetricName"], q["MetricStat"]["Stat"]) for q in sent}
    assert stats == {("5xxErrorRate", "Average"), ("4xxErrorRate", "Average"), ("Requests", "Sum"),
                     ("OriginLatency", "Maximum")}
    metric = sent[0]["MetricStat"]["Metric"]
    assert metric["Namespace"] == "AWS/CloudFront"
    assert metric["Dimensions"] == [{"Name": "DistributionId", "Value": "E1EXAMPLE"},
                                    {"Name": "Region", "Value": "Global"}]
    assert by_summary(ctx, "5xxErrorRate (Average): peak 8.5")


def test_missing_distribution(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers_for(**{"cloudfront get-distribution": NO_SUCH_DISTRIBUTION}),
                      {"distribution_id": "E1EXAMPLE"})
    assert by_summary(ctx, "Distribution E1EXAMPLE was not found")
    assert aws.called("cloudwatch", "get-metric-data") == []


def test_global_web_acl_rules_and_scope(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers_for(), {"web_acl_arn": GLOBAL_ACL})
    call = aws.called("wafv2", "get-web-acl")[0]
    assert value_of(call, "--name") == "edge-acl" and value_of(call, "--scope") == "CLOUDFRONT"
    assert value_of(call, "--id") == "aaaa1111-2222-3333-4444-5555aaaa5555" and region_of(call) == "us-east-1"
    acl = by_summary(ctx, "Web ACL edge-acl")[0]
    assert acl.kind == "current" and "default action allow" in acl.summary
    rule = by_summary(ctx, "Rule rate-limit")[0]
    assert rule.kind == "current" and "priority 1" in rule.summary and "action block" in rule.summary
    assert "priority 2" in by_summary(ctx, "Rule managed-common")[0].summary
    assert "override" in by_summary(ctx, "Rule managed-common")[0].summary
    assert all(region_of(c) == "us-east-1" for c in aws.called("wafv2", "get-sampled-requests"))
    assert_read_only(ctx, aws, kube)


def test_resource_arn_finds_a_regional_acl(config_data, tmp_path):
    answers = answers_for(**{"wafv2 get-web-acl-for-resource": web_acl(REGIONAL_ACL, "api-acl"),
                             "wafv2 get-web-acl": web_acl(REGIONAL_ACL, "api-acl")})
    ctx, aws, kube = run(config_data, tmp_path, answers, {"resource_arn": ALB_ARN})
    assert value_of(aws.called("wafv2", "get-web-acl-for-resource")[0], "--resource-arn") == ALB_ARN
    call = aws.called("wafv2", "get-web-acl")[0]
    assert value_of(call, "--scope") == "REGIONAL" and region_of(call) == "eu-west-1"
    assert by_summary(ctx, "Web ACL api-acl")
    assert aws.called("cloudfront", "get-distribution") == []
    assert_read_only(ctx, aws, kube)


def test_resource_without_a_web_acl(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-web-acl-for-resource": {}}),
                      {"resource_arn": ALB_ARN})
    assert by_summary(ctx, "No web ACL is associated")
    assert aws.called("wafv2", "get-web-acl") == []


def test_blocked_sampled_requests_only(config_data, tmp_path):
    requests = [sample(), sample("ALLOW", "none", "/home"), sample(rule="geo-block", uri="/admin", country="FR")]
    ctx, aws, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-sampled-requests": sampled(requests)}),
                      {"web_acl_arn": GLOBAL_ACL})
    call = aws.called("wafv2", "get-sampled-requests")[0]
    assert value_of(call, "--web-acl-arn") == GLOBAL_ACL and value_of(call, "--rule-metric-name") == "edge-acl-metric"
    assert value_of(call, "--scope") == "CLOUDFRONT" and value_of(call, "--max-items") == "20"
    assert value_of(call, "--time-window") == "StartTime=2026-10-04T10:00:00Z,EndTime=2026-10-04T12:00:00Z"
    blocked = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert len(blocked) == 2
    first = blocked[0]
    assert first.time == "2026-10-04T10:42:10Z"
    assert "rate-limit" in first.summary and "/login" in first.summary and "DE" in first.summary
    assert "geo-block" in blocked[1].summary and "FR" in blocked[1].summary
    assert not by_summary(ctx, "/home")


def test_no_header_or_client_address_is_stored(config_data, tmp_path):
    requests = [sample(rule="rate-limit")]
    ctx, _, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-sampled-requests": sampled(requests)}),
                    {"web_acl_arn": GLOBAL_ACL})
    document = ctx.evidence.to_json()
    assert "/login" in document
    assert "probe-agent-9f3" not in document and "User-Agent" not in document
    assert "10.1.2.3" not in document and "ClientIP" not in document


def test_secret_in_a_rule_name_or_path_is_redacted(config_data, tmp_path):
    secret = "pw" + "3" * 10
    requests = [sample(uri=f"/reset?token={secret}")]
    ctx, _, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-sampled-requests": sampled(requests)}),
                    {"web_acl_arn": GLOBAL_ACL})
    assert secret not in ctx.evidence.to_json()


def test_denied_call_keeps_the_rest(config_data, tmp_path):
    answers = answers_for(**{"wafv2 get-sampled-requests": access_denied("GetSampledRequests")})
    ctx, aws, kube = run(config_data, tmp_path, answers, {"distribution_id": "E1EXAMPLE", "web_acl_arn": GLOBAL_ACL})
    assert len(ctx.evidence.errors) == 1 and ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert by_summary(ctx, "Distribution E1EXAMPLE") and by_summary(ctx, "Rule rate-limit")
    assert_read_only(ctx, aws, kube)


def test_sampled_requests_are_bounded(config_data, tmp_path):
    requests = [sample(uri=f"/p{n}") for n in range(300)]
    ctx, _, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-sampled-requests": sampled(requests)}),
                    {"web_acl_arn": GLOBAL_ACL})
    assert len(ctx.evidence.facts) <= 200
    assert len([f for f in ctx.evidence.facts if f.kind == "incident_time"]) <= 20
