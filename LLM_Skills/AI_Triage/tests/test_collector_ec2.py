import base64

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.ec2 import COLLECTOR

IN_WINDOW = "2026-10-04T10:42:10+00:00"


def instance(instance_id="i-0aaa", state="running", reason=None):
    body = {
        "InstanceId": instance_id,
        "InstanceType": "m5.large",
        "LaunchTime": "2026-09-01T08:00:00+00:00",
        "State": {"Code": 16, "Name": state},
        "Placement": {"AvailabilityZone": "eu-west-1a"},
        "StateReason": reason or {},
    }
    return body


def described(*instances):
    return {"Reservations": [{"Instances": list(instances)}]}


def status(instance_id="i-0aaa", system="ok", instance_status="ok", events=()):
    return {
        "InstanceId": instance_id,
        "AvailabilityZone": "eu-west-1a",
        "InstanceState": {"Name": "running"},
        "SystemStatus": {"Status": system},
        "InstanceStatus": {"Status": instance_status},
        "Events": list(events),
    }


def console(text):
    return {"InstanceId": "i-0aaa", "Output": base64.b64encode(text.encode()).decode()}


def answers(**extra):
    base = {
        "ec2 describe-instances": described(instance()),
        "ec2 describe-instance-status": {"InstanceStatuses": [status()]},
        "ec2 get-console-output": console("boot ok"),
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    base.update(extra)
    return base


def run(config_data, tmp_path, replies, ids="i-0aaa"):
    ctx, aws, kube = make_context(config_data, tmp_path, replies, collector="ec2")
    COLLECTOR.run(ctx, {"instance_ids": ids})
    return ctx, aws, kube


def with_text(ctx, text):
    return [f for f in ctx.evidence.facts if text in f.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "ec2"
    assert COLLECTOR.required == ("instance_ids",)
    assert COLLECTOR.optional == ()


def test_healthy_instance(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers())
    fact = ctx.evidence.facts[0]
    assert fact.kind == "current" and fact.resource == "instance/i-0aaa"
    for part in ("running", "m5.large", "2026-09-01T08:00:00Z", "eu-west-1a"):
        assert part in fact.summary
    assert aws.called("ec2", "get-console-output") == []
    assert ctx.evidence.errors == []
    call = aws.called("ec2", "describe-instance-status")[0]
    assert "--include-all-instances" in call
    assert_read_only(ctx, aws, kube)


def test_state_reason_is_in_the_summary(config_data, tmp_path):
    reason = {"Code": "Client.InstanceInitiatedShutdown", "Message": "Client.InstanceInitiatedShutdown: shut down"}
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "ec2 describe-instances": described(instance(state="stopped", reason=reason))}))
    assert "Client.InstanceInitiatedShutdown" in ctx.evidence.facts[0].summary


def test_unhealthy_instance_with_event_and_console_tail(config_data, tmp_path):
    event = {"Code": "instance-retirement", "Description": "The instance is scheduled for retirement",
             "NotBefore": "2026-10-10T00:00:00+00:00"}
    long_output = "x" * 2000 + "Kernel panic - not syncing"
    ctx, aws, kube = run(config_data, tmp_path, answers(**{
        "ec2 describe-instance-status": {"InstanceStatuses": [status(system="impaired", events=[event])]},
        "ec2 get-console-output": console(long_output),
    }))
    impaired = with_text(ctx, "impaired")
    assert impaired and impaired[0].kind == "current"
    assert "system status impaired" in impaired[0].summary
    scheduled = with_text(ctx, "instance-retirement")
    assert len(scheduled) == 1 and "scheduled for retirement" in scheduled[0].summary
    console_fact = next(f for f in ctx.evidence.facts if f.excerpt.endswith("Kernel panic - not syncing"))
    assert len(console_fact.excerpt) <= 500
    assert "--latest" in aws.called("ec2", "get-console-output")[0]
    assert_read_only(ctx, aws, kube)


def test_healthy_status_adds_no_status_fact(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers())
    assert with_text(ctx, "impaired") == [] and with_text(ctx, "status checks") == []


def test_missing_instance(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers(**{"ec2 describe-instances": {"Reservations": []}}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("ec2", "describe-instance-status") == []


def test_access_denied_on_status_keeps_the_rest(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers(**{
        "ec2 describe-instance-status": access_denied("DescribeInstanceStatus")}))
    assert len(ctx.evidence.errors) == 1
    assert ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert with_text(ctx, "m5.large")
    assert_read_only(ctx, aws, kube)


def test_console_output_secrets_never_reach_the_document(config_data, tmp_path):
    secret = "pw" + "5" * 10
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "ec2 describe-instance-status": {"InstanceStatuses": [status(instance_status="impaired")]},
        "ec2 get-console-output": console(f"starting app password={secret} done"),
    }))
    document = ctx.evidence.to_json()
    assert secret not in document
    assert "starting app" in document


def test_more_than_ten_instances_are_capped(config_data, tmp_path):
    ids = [f"i-{n:04d}" for n in range(12)]
    ctx, aws, _ = run(config_data, tmp_path, answers(**{
        "ec2 describe-instances": described(*[instance(i) for i in ids[:10]])}), ids=",".join(ids))
    call = aws.called("ec2", "describe-instances")[0]
    assert call[call.index("--instance-ids") + 1:call.index("--instance-ids") + 11] == ids[:10]
    assert "i-0010" not in call
    derived = with_text(ctx, "instances were given")
    assert len(derived) == 1 and "10" in derived[0].summary and "12" in derived[0].summary


def test_metrics_are_added_per_instance(config_data, tmp_path):
    results = {"MetricDataResults": [
        {"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [97.5]},
        {"Id": "m1", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [1.0]},
    ]}
    ctx, aws, _ = run(config_data, tmp_path, answers(**{"cloudwatch get-metric-data": results}))
    assert with_text(ctx, "CPUUtilization")
    failed = with_text(ctx, "StatusCheckFailed (Maximum)")
    assert failed and failed[0].kind == "incident_time"
