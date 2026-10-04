import json
from datetime import datetime, timedelta, timezone

from fakes import FakeAws, access_denied
from helpers import assert_read_only, make_context
from triage.collectors.cloudfront_waf import COLLECTOR

ACCOUNT = "111111111111"
GLOBAL_ACL = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:global/webacl/edge-acl/aaaa1111-2222-3333-4444-5555aaaa5555"
REGIONAL_ACL = f"arn:aws:wafv2:eu-west-1:{ACCOUNT}:regional/webacl/api-acl/bbbb1111-2222-3333-4444-5555aaaa5555"
ALB_ARN = f"arn:aws:elasticloadbalancing:eu-west-1:{ACCOUNT}:loadbalancer/app/web-alb/50dc6c495c0c9188"
IN_WINDOW = "2026-10-04T10:42:10+00:00"
OUTSIDE = "2026-10-01T07:00:00+00:00"
NO_SUCH_DISTRIBUTION = (254, "An error occurred (NoSuchDistribution) when calling the GetDistribution operation: missing")


def distribution(modified=OUTSIDE, status="Deployed", web_acl_id=""):
    return {"Distribution": {
        "Id": "E1EXAMPLE", "Status": status, "LastModifiedTime": modified, "DomainName": "d111.cloudfront.net",
        "DistributionConfig": {
            "Aliases": {"Quantity": 1, "Items": ["www.example.com"]},
            "Origins": {"Quantity": 2, "Items": [
                {"Id": "web", "DomainName": "origin.example.com"}, {"Id": "static", "DomainName": "static.example.com"}]},
            "DefaultCacheBehavior": {"TargetOriginId": "web"},
            "WebACLId": web_acl_id,
        }}}


def web_acl(arn=GLOBAL_ACL, name="edge-acl", default="Allow", extra_rules=()):
    return {"WebACL": {
        "Name": name, "Id": arn.rsplit("/", 1)[-1], "ARN": arn, "DefaultAction": {default: {}},
        "VisibilityConfig": {"MetricName": "edge-acl-metric"},
        "Rules": [
            {"Name": "rate-limit", "Priority": 1, "Action": {"Block": {}}, "VisibilityConfig": {"MetricName": "rate"}},
            {"Name": "managed-common", "Priority": 2, "OverrideAction": {"None": {}},
             "VisibilityConfig": {"MetricName": "common"}},
            *extra_rules,
        ]}}


def block_rule(name, priority):
    return {"Name": name, "Priority": priority, "Action": {"Block": {}}, "VisibilityConfig": {"MetricName": f"m-{name}"}}


def sampled(requests, population=None, start="2026-10-04T10:00:00+00:00", end="2026-10-04T12:00:00+00:00"):
    return {"SampledRequests": requests, "PopulationSize": len(requests) if population is None else population,
            "TimeWindow": {"StartTime": start, "EndTime": end}}


def sample(action="BLOCK", uri="/login", country="DE", stamp=IN_WINDOW, **request):
    body = {"ClientIP": "10.1.2.3", "Country": country, "URI": uri, "Method": "POST",
            "Headers": [{"Name": "User-Agent", "Value": "probe-agent-9f3"}]}
    body.update(request)
    # AWS leaves RuleNameWithinRuleGroup out for a rule that is not inside a rule group.
    return {"Request": body, "Weight": 1, "Timestamp": stamp, "Action": action}


def answers_for(**extra):
    answers = {
        "cloudfront get-distribution": distribution(),
        "wafv2 get-web-acl": web_acl(),
        "wafv2 get-sampled-requests": sampled([]),
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


WINDOW_END = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


class SampleAws(FakeAws):
    """Answers get-sampled-requests by --rule-metric-name; the other operations come from the table."""

    def __init__(self, answers, by_metric):
        super().__init__(answers)
        self.by_metric = by_metric

    def __call__(self, argv, timeout):
        if argv[1:3] == ["wafv2", "get-sampled-requests"]:
            self.answers["wafv2 get-sampled-requests"] = self.by_metric.get(
                argv[argv.index("--rule-metric-name") + 1], sampled([]))
        return super().__call__(argv, timeout)


def run(config_data, tmp_path, answers, targets, now=None, by_metric=None):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="cloudfront_waf")
    if by_metric is not None:
        aws = ctx.runner = SampleAws(answers, by_metric)
    ctx.now = now or WINDOW_END + timedelta(minutes=30)
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
    assert COLLECTOR.one_of == ("distribution_id", "web_acl_arn", "resource_arn")


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
    assert ctx.evidence.errors == []
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


def test_blocked_requests_are_sampled_per_blocking_rule_and_named_by_the_call(config_data, tmp_path):
    acl = web_acl(default="Block", extra_rules=[block_rule("geo-block", 3)])
    by_metric = {
        "rate": sampled([sample(uri="/login"), sample("ALLOW", uri="/home")]),
        "m-geo-block": sampled([sample(uri="/admin", country="FR")]),
        "edge-acl-metric": sampled([sample(uri="/other", country="US")]),
    }
    ctx, aws, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-web-acl": acl}),
                      {"web_acl_arn": GLOBAL_ACL}, by_metric=by_metric)
    calls = aws.called("wafv2", "get-sampled-requests")
    assert [value_of(c, "--rule-metric-name") for c in calls] == ["rate", "m-geo-block", "edge-acl-metric"]
    first = calls[0]
    assert value_of(first, "--web-acl-arn") == GLOBAL_ACL and value_of(first, "--scope") == "CLOUDFRONT"
    assert value_of(first, "--max-items") == "20" and region_of(first) == "us-east-1"
    assert value_of(first, "--time-window") == "StartTime=2026-10-04T10:00:00Z,EndTime=2026-10-04T12:00:00Z"
    blocked = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert len(blocked) == 3
    assert "rule rate-limit" in blocked[0].summary and "/login" in blocked[0].summary and "DE" in blocked[0].summary
    assert blocked[0].time == "2026-10-04T10:42:10Z"
    assert "rule geo-block" in blocked[1].summary and "FR" in blocked[1].summary
    assert "default action" in blocked[2].summary and "/other" in blocked[2].summary
    assert not by_summary(ctx, "/home")
    assert "metric-name m-geo-block" in blocked[1].command or "m-geo-block" in blocked[1].command


def test_default_action_is_never_named_when_it_allows(config_data, tmp_path):
    requests = sampled([sample()])
    ctx, _, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-sampled-requests": requests}),
                    {"web_acl_arn": GLOBAL_ACL})
    assert not by_summary(ctx, "default action blocked") and not by_summary(ctx, "by the default action")


def test_at_most_five_blocking_rules_are_sampled(config_data, tmp_path):
    acl = web_acl(extra_rules=[block_rule(f"r{n}", 10 + n) for n in range(8)])
    _, aws, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-web-acl": acl}), {"web_acl_arn": GLOBAL_ACL})
    assert len(aws.called("wafv2", "get-sampled-requests")) == 5


def test_nothing_is_sampled_once_the_window_is_more_than_three_hours_old(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers_for(), {"web_acl_arn": GLOBAL_ACL},
                      now=WINDOW_END + timedelta(hours=3, minutes=1))
    assert aws.called("wafv2", "get-sampled-requests") == []
    note = [f for f in ctx.evidence.facts if f.kind == "derived"][0]
    assert "three hours" in note.summary


def test_sampling_is_still_done_just_inside_three_hours(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, answers_for(), {"web_acl_arn": GLOBAL_ACL},
                    now=WINDOW_END + timedelta(hours=2, minutes=59))
    assert len(aws.called("wafv2", "get-sampled-requests")) == 1


def test_reported_time_window_and_population_are_stated(config_data, tmp_path):
    answer = sampled([sample()], population=4800, start="2026-10-04T11:30:00+00:00", end="2026-10-04T12:00:00+00:00")
    ctx, _, _ = run(config_data, tmp_path, answers_for(**{"wafv2 get-sampled-requests": answer}),
                    {"web_acl_arn": GLOBAL_ACL})
    note = [f for f in ctx.evidence.facts if f.kind == "derived"][0]
    assert "2026-10-04T11:30:00Z" in note.summary and "2026-10-04T12:00:00Z" in note.summary
    assert "4800" in note.summary and "rate-limit" in note.summary


def test_no_header_or_client_address_is_stored(config_data, tmp_path):
    requests = [sample()]
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
    assert len([f for f in ctx.evidence.facts if f.kind == "incident_time"]) == 20


def test_the_distributions_own_web_acl_comes_from_its_configuration(config_data, tmp_path):
    answers = answers_for(**{"cloudfront get-distribution": distribution(web_acl_id=GLOBAL_ACL)})
    ctx, aws, kube = run(config_data, tmp_path, answers, {"distribution_id": "E1EXAMPLE"})
    call = aws.called("wafv2", "get-web-acl")[0]
    assert value_of(call, "--scope") == "CLOUDFRONT" and region_of(call) == "us-east-1"
    assert aws.called("wafv2", "get-web-acl-for-resource") == []
    assert by_summary(ctx, "Web ACL edge-acl")
    assert_read_only(ctx, aws, kube)


def test_a_classic_waf_id_or_an_empty_one_is_ignored(config_data, tmp_path):
    for value in ("", "a1b2c3d4-0000-1111-2222-3333aaaa5555"):
        answers = answers_for(**{"cloudfront get-distribution": distribution(web_acl_id=value)})
        _, aws, _ = run(config_data, tmp_path, answers, {"distribution_id": "E1EXAMPLE"})
        assert aws.called("wafv2", "get-web-acl") == []


def test_a_cloudfront_resource_arn_is_read_as_a_distribution(config_data, tmp_path):
    arn = f"arn:aws:cloudfront::{ACCOUNT}:distribution/E1EXAMPLE"
    answers = answers_for(**{"cloudfront get-distribution": distribution(web_acl_id=GLOBAL_ACL)})
    ctx, aws, _ = run(config_data, tmp_path, answers, {"resource_arn": arn})
    assert value_of(aws.called("cloudfront", "get-distribution")[0], "--id") == "E1EXAMPLE"
    assert aws.called("wafv2", "get-web-acl-for-resource") == []
    assert by_summary(ctx, "Distribution E1EXAMPLE") and by_summary(ctx, "Web ACL edge-acl")


def test_the_same_distribution_given_twice_is_read_once(config_data, tmp_path):
    arn = f"arn:aws:cloudfront::{ACCOUNT}:distribution/E1EXAMPLE"
    _, aws, _ = run(config_data, tmp_path, answers_for(), {"distribution_id": "E1EXAMPLE", "resource_arn": arn})
    assert len(aws.called("cloudfront", "get-distribution")) == 1


def test_regional_resource_lookup_uses_the_region_of_its_arn(config_data, tmp_path):
    arn = ALB_ARN.replace("eu-west-1", "eu-central-1")
    answers = answers_for(**{"wafv2 get-web-acl-for-resource": web_acl(REGIONAL_ACL.replace("eu-west-1", "eu-central-1"), "api-acl")})
    _, aws, _ = run(config_data, tmp_path, answers, {"resource_arn": arn})
    assert region_of(aws.called("wafv2", "get-web-acl-for-resource")[0]) == "eu-central-1"
    assert region_of(aws.called("wafv2", "get-web-acl")[0]) == "eu-central-1"


def test_metric_calls_do_not_change_the_evidence_region(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers_for(), {"distribution_id": "E1EXAMPLE"})
    assert ctx.evidence.region == "eu-west-1"
