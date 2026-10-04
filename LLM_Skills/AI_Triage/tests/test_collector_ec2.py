from fakes import FakeAws, access_denied
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
    # The AWS CLI has already decoded Output; it is plain text.
    return {"InstanceId": "i-0aaa", "Output": text}


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
    # With a filter, AWS answers an unknown id with an empty list, not an error.
    ctx, aws, _ = run(config_data, tmp_path, answers(**{"ec2 describe-instances": {"Reservations": []}}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current"
    assert ctx.evidence.facts[0].summary == "Instance i-0aaa was not found in eu-west-1"
    assert aws.called("ec2", "describe-instance-status") == []
    assert ctx.evidence.errors == []


def test_instances_are_looked_up_by_filter_not_by_id(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, answers(), ids="i-0aaa,i-0bbb")
    call = aws.called("ec2", "describe-instances")[0]
    assert "--instance-ids" not in call
    assert call[call.index("--filters") + 1] == "Name=instance-id,Values=i-0aaa,i-0bbb"


def test_one_unknown_id_does_not_blank_out_the_others(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers(), ids="i-0aaa,i-0bad")
    assert with_text(ctx, "Instance i-0aaa is running")
    missing = with_text(ctx, "Instance i-0bad was not found in eu-west-1")
    assert len(missing) == 1 and missing[0].kind == "current"
    status_call = aws.called("ec2", "describe-instance-status")[0]
    assert "i-0bad" not in status_call and "i-0aaa" in status_call
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


class ConsoleAws(FakeAws):
    """get-console-output fails with --latest and works without it, as on non-Nitro types."""

    def __call__(self, argv, timeout):
        if argv[1:3] == ["ec2", "get-console-output"] and "--latest" in argv:
            self.calls.append(argv)
            return 254, "", "An error occurred (UnsupportedOperation) when calling the GetConsoleOutput operation: not supported"
        return super().__call__(argv, timeout)


def test_console_output_falls_back_to_a_call_without_latest(config_data, tmp_path):
    replies = answers(**{"ec2 describe-instance-status": {"InstanceStatuses": [status(system="impaired")]},
                         "ec2 get-console-output": console("old kernel log tail")})
    ctx, _, kube = make_context(config_data, tmp_path, replies, collector="ec2")
    ctx.runner = fake = ConsoleAws(replies)
    COLLECTOR.run(ctx, {"instance_ids": "i-0aaa"})
    calls = fake.called("ec2", "get-console-output")
    assert len(calls) == 2 and "--latest" in calls[0] and "--latest" not in calls[1]
    assert any(f.excerpt == "old kernel log tail" for f in ctx.evidence.facts)
    assert_read_only(ctx, fake, kube)


def test_console_output_that_looks_like_base64_is_not_decoded_again(config_data, tmp_path):
    text = "QUJDREVGR0g="  # valid base64 characters, but the CLI already decoded the real output
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "ec2 describe-instance-status": {"InstanceStatuses": [status(system="impaired")]},
        "ec2 get-console-output": console(text)}))
    assert any(f.excerpt == text for f in ctx.evidence.facts)


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
    assert call[call.index("--filters") + 1] == "Name=instance-id,Values=" + ",".join(ids[:10])
    assert "i-0010" not in " ".join(call)
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


def test_console_access_denied_is_one_error_and_no_retry(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers(**{
        "ec2 describe-instance-status": {"InstanceStatuses": [status(system="impaired")]},
        "ec2 get-console-output": access_denied("GetConsoleOutput")}))
    assert len(aws.called("ec2", "get-console-output")) == 1
    errors = [e for e in ctx.evidence.errors if "get-console-output" in e["command"]]
    assert len(errors) == 1 and errors[0]["code"] == "AccessDeniedException"
    assert_read_only(ctx, aws, kube)


def test_an_unsupported_latest_leaves_no_error_when_the_plain_call_works(config_data, tmp_path):
    replies = answers(**{"ec2 describe-instance-status": {"InstanceStatuses": [status(system="impaired")]},
                         "ec2 get-console-output": console("tail")})
    ctx, _, _ = make_context(config_data, tmp_path, replies, collector="ec2")
    ctx.runner = ConsoleAws(replies)
    COLLECTOR.run(ctx, {"instance_ids": "i-0aaa"})
    assert not [e for e in ctx.evidence.errors if "get-console-output" in e["command"]]


def test_an_empty_latest_answer_is_retried_without_latest(config_data, tmp_path):
    class EmptyThenFull(FakeAws):
        def __call__(self, argv, timeout):
            if argv[1:3] == ["ec2", "get-console-output"] and "--latest" in argv:
                self.calls.append(argv)
                return 0, '{"InstanceId": "i-0aaa", "Output": ""}', ""
            return super().__call__(argv, timeout)

    replies = answers(**{"ec2 describe-instance-status": {"InstanceStatuses": [status(system="impaired")]},
                         "ec2 get-console-output": console("older tail")})
    ctx, _, _ = make_context(config_data, tmp_path, replies, collector="ec2")
    ctx.runner = fake = EmptyThenFull(replies)
    COLLECTOR.run(ctx, {"instance_ids": "i-0aaa"})
    assert len(fake.called("ec2", "get-console-output")) == 2
    assert any(f.excerpt == "older tail" for f in ctx.evidence.facts)
