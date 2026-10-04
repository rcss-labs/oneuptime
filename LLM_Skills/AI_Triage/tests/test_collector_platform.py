import pytest

from fakes import SSO_EXPIRED_ERROR, access_denied
from helpers import assert_read_only, make_context
from triage.collectors.platform import COLLECTOR
from triage.context import SignInExpired

OUTSIDE = "2026-10-04T07:00:00+00:00"


def health_event(service="EC2", start="2026-10-04T10:30:00+00:00", status="open", category="issue",
                 region="eu-west-1", end=None):
    event = {"arn": f"arn:aws:health:{region}::event/{service}/x", "service": service, "eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE",
            "eventTypeCategory": category, "region": region, "startTime": start, "statusCode": status}
    if end:
        event["endTime"] = end
    return event


def quota(name, value, usage=True):
    body = {"QuotaName": name, "QuotaCode": "L-1", "Value": value}
    if usage:
        body["UsageMetric"] = {"MetricNamespace": "AWS/Usage", "MetricName": "ResourceCount"}
    return body


def run(config_data, tmp_path, answers, targets=None):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="platform")
    COLLECTOR.run(ctx, dict(targets or {}))
    return ctx, aws, kube


def test_declares_its_targets():
    assert COLLECTOR.name == "platform"
    assert COLLECTOR.required == ()
    assert COLLECTOR.optional == ("service_codes",)


def test_health_events_inside_the_window_or_still_open(config_data, tmp_path):
    events = [
        health_event(start="2026-10-04T10:30:00+00:00", end="2026-10-04T10:50:00+00:00", status="closed"),
        health_event(service="RDS", start=OUTSIDE, status="open", category="scheduledChange"),
        health_event(service="S3", start=OUTSIDE, status="closed"),
    ]
    ctx, aws, kube = run(config_data, tmp_path, {"health describe-events": {"events": events}})
    facts = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert len(facts) == 2
    ec2 = next(f for f in facts if "EC2" in f.summary)
    assert ec2.time == "2026-10-04T10:30:00Z"
    assert "eu-west-1" in ec2.summary and "issue" in ec2.summary and "closed" in ec2.summary
    assert any("RDS" in f.summary and "open" in f.summary for f in facts)
    assert not any("S3" in f.summary for f in facts)
    assert_read_only(ctx, aws, kube)


def test_events_overlapping_the_window_are_kept(config_data, tmp_path):
    events = [
        health_event(service="EC2", start="2026-10-04T09:00:00+00:00", end="2026-10-04T10:30:00+00:00", status="closed"),
        health_event(service="RDS", start="2026-10-04T08:00:00+00:00", end="2026-10-04T09:30:00+00:00", status="closed"),
        health_event(service="S3", start="2026-10-04T12:30:00+00:00", status="upcoming"),
        health_event(service="SQS", start="2026-10-04T08:00:00+00:00", end="2026-10-04T13:00:00+00:00", status="closed"),
        health_event(service="ELB", start="2026-10-03T08:00:00+00:00", status="open"),
    ]
    ctx, _, _ = run(config_data, tmp_path, {"health describe-events": {"events": events}})
    text = " ".join(f.summary for f in ctx.evidence.facts)
    assert "EC2" in text and "SQS" in text and "ELB" in text
    assert "RDS" not in text and "S3" not in text


def test_health_facts_are_capped_at_thirty(config_data, tmp_path):
    events = [health_event(service=f"SVC{n}") for n in range(60)]
    ctx, _, _ = run(config_data, tmp_path, {"health describe-events": {"events": events}}, {"service_codes": "ecs"})
    assert len([f for f in ctx.evidence.facts if f.resource.startswith("health/")]) == 30


def test_health_call_uses_us_east_1_and_the_filter(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {})
    call = aws.called("health", "describe-events")[0]
    assert call[call.index("--region") + 1] == "us-east-1"
    assert call[call.index("--filter") + 1] == "eventStatusCodes=open,closed,upcoming"
    assert call[call.index("--max-items") + 1] == "100"
    assert aws.called("service-quotas", "list-service-quotas")[0][call.index("--region") + 1] == "eu-west-1"


def test_support_plan_case_is_a_fact_not_an_error(config_data, tmp_path):
    error = (254, "An error occurred (SubscriptionRequiredException) when calling the DescribeEvents operation: "
                  "AWS Premium Support Subscription is required")
    ctx, _, _ = run(config_data, tmp_path, {"health describe-events": error})
    assert ctx.evidence.errors == []
    fact = ctx.evidence.facts[0]
    assert fact.kind == "derived" and "Business or Enterprise support plan" in fact.summary


def test_default_service_codes_one_call_each(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {})
    calls = aws.called("service-quotas", "list-service-quotas")
    codes = [c[c.index("--service-code") + 1] for c in calls]
    assert codes == ["ecs", "lambda", "ec2", "rds", "elasticloadbalancing"]
    assert all(c[c.index("--max-items") + 1] == "50" for c in calls)


def test_quota_fact_lists_only_quotas_with_a_usage_metric_capped_at_ten(config_data, tmp_path):
    quotas = [quota(f"Quota {n}", n) for n in range(15)] + [quota("No usage", 5, usage=False)]
    ctx, aws, kube = run(config_data, tmp_path, {"service-quotas list-service-quotas": {"Quotas": quotas}},
                         {"service_codes": "lambda"})
    facts = [f for f in ctx.evidence.facts if f.kind == "current"]
    assert len(facts) == 1
    assert "lambda" in facts[0].summary and "Quota 9 = 9" in facts[0].summary
    assert "Quota 10" not in facts[0].summary and "No usage" not in facts[0].summary
    assert len(aws.called("service-quotas", "list-service-quotas")) == 1
    assert_read_only(ctx, aws, kube)


def test_service_without_usage_quotas_has_no_fact(config_data, tmp_path):
    answers = {"service-quotas list-service-quotas": {"Quotas": [quota("No usage", 5, usage=False)]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"service_codes": "ecs"})
    assert [f for f in ctx.evidence.facts if f.kind == "current"] == []


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = {"health describe-events": access_denied("DescribeEvents"),
               "service-quotas list-service-quotas": {"Quotas": [quota("Tasks", 100)]}}
    ctx, aws, kube = run(config_data, tmp_path, answers, {"service_codes": "ecs"})
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert any("Tasks" in f.summary for f in ctx.evidence.facts)
    assert_read_only(ctx, aws, kube)


def test_expired_sign_in_stops_the_run(config_data, tmp_path):
    with pytest.raises(SignInExpired):
        run(config_data, tmp_path, {"health describe-events": SSO_EXPIRED_ERROR})
