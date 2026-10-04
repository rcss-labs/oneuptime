import json

from fakes import access_denied
from helpers import assert_read_only, fact_summaries, make_context
from triage.collectors.edge import COLLECTOR

ACCOUNT = "111111111111"
LB_SUFFIX = "app/web-alb/50dc6c495c0c9188"
LB_ARN = f"arn:aws:elasticloadbalancing:eu-west-1:{ACCOUNT}:loadbalancer/{LB_SUFFIX}"
LISTENER_ARN = f"arn:aws:elasticloadbalancing:eu-west-1:{ACCOUNT}:listener/{LB_SUFFIX}/f2f7dc8efc522ab2"
TG_ARN = f"arn:aws:elasticloadbalancing:eu-west-1:{ACCOUNT}:targetgroup/web-tg/73e2d6bc24d8a067"
CERT_ARN = f"arn:aws:acm:eu-west-1:{ACCOUNT}:certificate/11111111-2222-3333-4444-5555aaaa5555"
DNS_NAME = "web-alb-123456.eu-west-1.elb.amazonaws.com"
TARGETS = {"load_balancer": "web-alb"}


def load_balancer(**overrides):
    body = {
        "LoadBalancerArn": LB_ARN, "DNSName": DNS_NAME, "LoadBalancerName": "web-alb", "Scheme": "internet-facing",
        "Type": "application", "State": {"Code": "active"},
        "AvailabilityZones": [{"ZoneName": "eu-west-1a"}, {"ZoneName": "eu-west-1b"}],
    }
    body.update(overrides)
    return {"LoadBalancers": [body]}


def listener(port=443, protocol="HTTPS", arn=LISTENER_ARN):
    body = {"ListenerArn": arn, "Port": port, "Protocol": protocol}
    if protocol == "HTTPS":
        body["Certificates"] = [{"CertificateArn": CERT_ARN}]
    return body


def target_group(arn=TG_ARN, name="web-tg"):
    return {
        "TargetGroupArn": arn, "TargetGroupName": name, "HealthCheckPath": "/health", "HealthCheckPort": "8080",
        "HealthCheckIntervalSeconds": 30, "HealthyThresholdCount": 5, "UnhealthyThresholdCount": 2,
    }


def target(target_id, state="healthy", reason=None, description=None):
    health = {"State": state}
    if reason:
        health.update(Reason=reason, Description=description)
    return {"Target": {"Id": target_id, "Port": 8080}, "TargetHealth": health}


def healthy_answers(**extra):
    answers = {
        "elbv2 describe-load-balancers": load_balancer(),
        "elbv2 describe-listeners": {"Listeners": [listener()]},
        "elbv2 describe-rules": {"Rules": [
            {"Priority": "default", "Actions": [{"Type": "forward", "TargetGroupArn": TG_ARN}]}]},
        "elbv2 describe-target-groups": {"TargetGroups": [target_group()]},
        "elbv2 describe-target-health": {"TargetHealthDescriptions": [target("i-0aaa"), target("i-0bbb")]},
        "elbv2 describe-target-group-attributes": {"Attributes": [
            {"Key": "deregistration_delay.timeout_seconds", "Value": "300"},
            {"Key": "slow_start.duration_seconds", "Value": "0"}]},
        "acm describe-certificate": {"Certificate": {"Status": "ISSUED", "NotAfter": "2027-10-04T00:00:00+00:00"}},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers, targets=None):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="edge")
    COLLECTOR.run(ctx, dict(targets or TARGETS))
    return ctx, aws, kube


def derived_facts(ctx):
    return [f for f in ctx.evidence.facts if f.kind == "derived" and "no data" not in f.summary]


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "edge"
    assert COLLECTOR.required == ("load_balancer",)
    assert COLLECTOR.optional == ("hostname",)


def test_healthy_load_balancer(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, healthy_answers())
    state = by_summary(ctx, "Load balancer web-alb")[0]
    assert state.kind == "current"
    for word in ("active", "internet-facing", "application", "eu-west-1a", DNS_NAME):
        assert word in state.summary
    listener_fact = by_summary(ctx, "Listener HTTPS 443")[0]
    assert listener_fact.kind == "current" and "11111111-2222-3333-4444-5555aaaa5555" in listener_fact.summary
    rules = by_summary(ctx, "rules forwarding to")[0]
    assert "1 rules" in rules.summary and "web-tg" in rules.summary
    group = by_summary(ctx, "Target group web-tg")[0]
    assert "/health" in group.summary and "8080" in group.summary and "30 seconds" in group.summary
    assert "healthy threshold 5" in group.summary and "unhealthy threshold 2" in group.summary
    health = by_summary(ctx, "Target group web-tg has")[0]
    assert "2 healthy" in health.summary
    attributes = by_summary(ctx, "deregistration delay")[0]
    assert "300 seconds" in attributes.summary and "slow start 0 seconds" in attributes.summary
    assert by_summary(ctx, "Certificate") and ctx.evidence.errors == []
    assert not [f for f in ctx.evidence.facts if "unhealthy target" in f.summary.lower()]
    assert_read_only(ctx, aws, kube)


def test_unhealthy_targets_get_a_fact_each(config_data, tmp_path):
    descriptions = [target("i-0aaa"), target("i-0bbb", "unhealthy", "Target.Timeout", "Request timed out"),
                    target("i-0ccc", "unhealthy", "Target.FailedHealthChecks", "Health checks failed")]
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**{
        "elbv2 describe-target-health": {"TargetHealthDescriptions": descriptions}}))
    summary = by_summary(ctx, "Target group web-tg has")[0].summary
    assert "1 healthy" in summary and "2 unhealthy" in summary
    timed_out = by_summary(ctx, "i-0bbb")[0]
    assert "Target.Timeout" in timed_out.summary and "Request timed out" in timed_out.summary
    assert by_summary(ctx, "i-0ccc")


def test_missing_load_balancer(config_data, tmp_path):
    answers = healthy_answers(**{"elbv2 describe-load-balancers": {"LoadBalancers": []}})
    ctx, aws, _ = run(config_data, tmp_path, answers)
    assert len(ctx.evidence.facts) == 1 and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("elbv2", "describe-listeners") == []


def test_denied_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"elbv2 describe-target-health": access_denied("DescribeTargetHealth")})
    ctx, aws, kube = run(config_data, tmp_path, answers)
    assert len(ctx.evidence.errors) == 1 and ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert by_summary(ctx, "Listener HTTPS 443") and by_summary(ctx, "Target group web-tg")
    assert_read_only(ctx, aws, kube)


def test_secret_in_target_health_description_is_redacted(config_data, tmp_path):
    secret = "pw" + "5" * 10
    descriptions = [target("i-0bbb", "unhealthy", "Target.Timeout", f"callback failed token={secret}")]
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**{
        "elbv2 describe-target-health": {"TargetHealthDescriptions": descriptions}}))
    assert secret not in ctx.evidence.to_json()


def test_at_most_five_listeners_and_ten_target_groups(config_data, tmp_path):
    listeners = [listener(8000 + n, "HTTP", f"{LISTENER_ARN}{n}") for n in range(7)]
    groups = [target_group(f"{TG_ARN}{n}", f"tg-{n}") for n in range(12)]
    answers = healthy_answers(**{"elbv2 describe-listeners": {"Listeners": listeners},
                                 "elbv2 describe-target-groups": {"TargetGroups": groups}})
    ctx, aws, _ = run(config_data, tmp_path, answers)
    assert len(aws.called("elbv2", "describe-rules")) == 5
    assert len(aws.called("elbv2", "describe-target-health")) == 10
    assert len(aws.called("elbv2", "describe-target-group-attributes")) == 10
    assert len(ctx.evidence.facts) <= 200


def certificate(not_after):
    return {"elbv2 describe-listeners": {"Listeners": [listener()]},
            "acm describe-certificate": {"Certificate": {"Status": "ISSUED", "NotAfter": not_after}}}


def test_certificate_that_expired_before_the_window(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**certificate("2026-10-01T12:00:00+00:00")))
    derived = [f for f in ctx.evidence.facts if f.kind == "derived" and "Certificate" in f.summary][0]
    assert "expired" in derived.summary and "3 days before" in derived.summary
    assert by_summary(ctx, "ISSUED")[0].kind == "current"


def test_certificate_expiring_in_ten_days(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**certificate("2026-10-14T12:00:00+00:00")))
    derived = [f for f in ctx.evidence.facts if f.kind == "derived" and "Certificate" in f.summary][0]
    assert "expires" in derived.summary and "10 days after" in derived.summary
    assert "expired" not in derived.summary


def test_certificate_valid_for_a_year_has_no_derived_fact(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**certificate("2027-10-04T12:00:00+00:00")))
    assert not derived_facts(ctx)
    current = by_summary(ctx, "ISSUED")[0]
    assert current.kind == "current" and "2027-10-04T12:00:00Z" in current.summary


def dns_answers(record):
    return healthy_answers(**{
        "route53 list-hosted-zones": {"HostedZones": [
            {"Id": "/hostedzone/ZSHORT", "Name": "com."},
            {"Id": "/hostedzone/ZLONG", "Name": "example.com."},
            {"Id": "/hostedzone/ZOTHER", "Name": "example.org."}]},
        "route53 list-resource-record-sets": {"ResourceRecordSets": [record]},
    })


def test_hostname_pointing_at_this_load_balancer(config_data, tmp_path):
    record = {"Name": "www.example.com.", "Type": "A", "AliasTarget": {"DNSName": f"dualstack.{DNS_NAME}."}}
    ctx, aws, kube = run(config_data, tmp_path, dns_answers(record), {**TARGETS, "hostname": "www.example.com"})
    call = aws.called("route53", "list-resource-record-sets")[0]
    assert call[call.index("--hosted-zone-id") + 1] == "ZLONG"
    assert call[call.index("--start-record-name") + 1] == "www.example.com"
    assert "--max-items" in call and "--max-items" in aws.called("route53", "list-hosted-zones")[0]
    fact = by_summary(ctx, "www.example.com")[0]
    assert fact.kind == "current" and "A" in fact.summary and DNS_NAME in fact.summary
    assert not derived_facts(ctx)
    assert_read_only(ctx, aws, kube)


def test_hostname_pointing_elsewhere(config_data, tmp_path):
    record = {"Name": "www.example.com.", "Type": "CNAME", "ResourceRecords": [{"Value": "old-lb.example.net"}]}
    ctx, _, _ = run(config_data, tmp_path, dns_answers(record), {**TARGETS, "hostname": "www.example.com"})
    derived = derived_facts(ctx)[0]
    assert "does not point at" in derived.summary and "old-lb.example.net" in derived.summary


def test_hostname_without_a_hosted_zone(config_data, tmp_path):
    answers = healthy_answers(**{"route53 list-hosted-zones": {"HostedZones": []}})
    ctx, aws, _ = run(config_data, tmp_path, answers, {**TARGETS, "hostname": "www.example.com"})
    assert by_summary(ctx, "No hosted zone")
    assert aws.called("route53", "list-resource-record-sets") == []


def queries(aws):
    call = aws.called("cloudwatch", "get-metric-data")[0]
    return json.loads(call[call.index("--metric-data-queries") + 1])


def test_application_load_balancer_metrics(config_data, tmp_path):
    results = {"MetricDataResults": [
        {"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [120.0]}]}
    ctx, aws, _ = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    sent = queries(aws)
    first = sent[0]["MetricStat"]
    assert first["Metric"]["Namespace"] == "AWS/ApplicationELB"
    assert first["Metric"]["MetricName"] == "HTTPCode_ELB_5XX_Count" and first["Stat"] == "Sum"
    assert first["Metric"]["Dimensions"] == [{"Name": "LoadBalancer", "Value": LB_SUFFIX}]
    names = {(q["MetricStat"]["Metric"]["MetricName"], q["MetricStat"]["Stat"]) for q in sent}
    assert {("HTTPCode_Target_5XX_Count", "Sum"), ("TargetResponseTime", "Maximum"), ("RequestCount", "Sum"),
            ("RejectedConnectionCount", "Sum"), ("TargetConnectionErrorCount", "Sum"),
            ("UnHealthyHostCount", "Maximum"), ("HealthyHostCount", "Minimum")} <= names
    host = next(q for q in sent if q["MetricStat"]["Metric"]["MetricName"] == "UnHealthyHostCount")
    assert {"Name": "TargetGroup", "Value": "targetgroup/web-tg/73e2d6bc24d8a067"} in host["MetricStat"]["Metric"]["Dimensions"]
    assert by_summary(ctx, "HTTPCode_ELB_5XX_Count (Sum): peak 120.0")


def test_network_load_balancer_uses_only_host_count_metrics(config_data, tmp_path):
    nlb_suffix = "net/web-nlb/abc123"
    nlb = load_balancer(Type="network", LoadBalancerArn=LB_ARN.replace(LB_SUFFIX, nlb_suffix))
    ctx, aws, _ = run(config_data, tmp_path, healthy_answers(**{"elbv2 describe-load-balancers": nlb}))
    sent = queries(aws)
    assert {q["MetricStat"]["Metric"]["Namespace"] for q in sent} == {"AWS/NetworkELB"}
    assert {q["MetricStat"]["Metric"]["MetricName"] for q in sent} == {"UnHealthyHostCount", "HealthyHostCount"}
    assert {"Name": "LoadBalancer", "Value": nlb_suffix} in sent[0]["MetricStat"]["Metric"]["Dimensions"]
