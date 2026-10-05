from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.autoscaling import COLLECTOR

IN_WINDOW = "2026-10-04T10:50:00.000000+00:00"
OUTSIDE = "2026-10-04T07:00:00+00:00"


def group(**overrides):
    body = {
        "AutoScalingGroupName": "web-asg", "MinSize": 2, "MaxSize": 10, "DesiredCapacity": 4,
        "HealthCheckType": "ELB", "HealthCheckGracePeriod": 300,
        "Instances": [{"InstanceId": f"i-{n}", "HealthStatus": "Healthy", "LifecycleState": "InService"} for n in range(4)],
    }
    body.update(overrides)
    return {"AutoScalingGroups": [body]}


def activity(code="Successful", start=IN_WINDOW, description="Launching a new EC2 instance: i-1", cause="alarm high",
             message=None):
    return {"ActivityId": "a1", "Description": description, "Cause": cause, "StartTime": start,
            "StatusCode": code, "StatusMessage": message}


def refresh(status="InProgress", start=IN_WINDOW, end=None, percent=40, reason=None):
    body = {"InstanceRefreshId": "r1", "Status": status, "StartTime": start, "PercentageComplete": percent,
            "InstancesToUpdate": 3, "StatusReason": reason}
    if end:
        body["EndTime"] = end
    return body


def answers(**extra):
    base = {
        "autoscaling describe-auto-scaling-groups": group(),
        "autoscaling describe-scaling-activities": {"Activities": []},
        "autoscaling describe-instance-refreshes": {"InstanceRefreshes": []},
        "application-autoscaling describe-scalable-targets": {"ScalableTargets": []},
        "application-autoscaling describe-scaling-policies": {"ScalingPolicies": []},
    }
    base.update(extra)
    return base


def run(config_data, tmp_path, replies, **extra_targets):
    ctx, aws, kube = make_context(config_data, tmp_path, replies, collector="autoscaling")
    COLLECTOR.run(ctx, {"group": "web-asg", **extra_targets})
    return ctx, aws, kube


def with_text(ctx, text):
    return [f for f in ctx.evidence.facts if text in f.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "autoscaling"
    assert COLLECTOR.required == ("group",)
    assert COLLECTOR.optional == ("ecs_cluster", "ecs_service")


def test_group_state(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers())
    fact = ctx.evidence.facts[0]
    assert fact.kind == "current" and fact.resource == "autoscaling-group/web-asg"
    for part in ("min 2", "max 10", "desired 4", "4 instances", "ELB", "grace period 300"):
        assert part in fact.summary
    assert aws.called("application-autoscaling", "describe-scalable-targets") == []
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


def test_unhealthy_instances_are_counted(config_data, tmp_path):
    instances = [{"InstanceId": "i-1", "HealthStatus": "Unhealthy", "LifecycleState": "InService"},
                 {"InstanceId": "i-2", "HealthStatus": "Healthy", "LifecycleState": "Terminating"},
                 {"InstanceId": "i-3", "HealthStatus": "Healthy", "LifecycleState": "InService"}]
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "autoscaling describe-auto-scaling-groups": group(Instances=instances)}))
    assert "2 of 3 instances are not healthy and in service" in ctx.evidence.facts[0].summary


def test_missing_group(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, answers(**{"autoscaling describe-auto-scaling-groups": {"AutoScalingGroups": []}}))
    assert len(ctx.evidence.facts) == 1 and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("autoscaling", "describe-scaling-activities") == []


def test_activities_inside_the_window_and_failures_marked(config_data, tmp_path):
    activities = {"Activities": [
        activity(),
        activity(code="Failed", description="Launching a new EC2 instance: i-9", cause="capacity",
                 message="We currently do not have sufficient m5.large capacity"),
        activity(start=OUTSIDE, description="Terminating EC2 instance: i-0"),
    ]}
    ctx, aws, kube = run(config_data, tmp_path, answers(**{"autoscaling describe-scaling-activities": activities}))
    failed = with_text(ctx, "FAILED")
    assert len(failed) == 1 and failed[0].kind == "incident_time"
    assert "sufficient m5.large capacity" in failed[0].summary and failed[0].excerpt == "capacity"
    assert failed[0].time == "2026-10-04T10:50:00Z"
    assert with_text(ctx, "i-0") == []
    ok = [f for f in with_text(ctx, "Launching a new EC2 instance: i-1")]
    assert len(ok) == 1 and "FAILED" not in ok[0].summary
    call = aws.called("autoscaling", "describe-scaling-activities")[0]
    assert call[call.index("--max-items") + 1] == "30"
    assert_read_only(ctx, aws, kube)


def test_instance_refresh_in_progress_and_ended_in_window(config_data, tmp_path):
    refreshes = {"InstanceRefreshes": [
        refresh(),
        refresh(status="Successful", start="2026-10-04T10:05:00+00:00", end="2026-10-04T10:30:00+00:00", percent=100),
        refresh(status="Successful", start="2026-09-01T10:05:00+00:00", end="2026-09-01T10:30:00+00:00", percent=100),
    ]}
    ctx, aws, _ = run(config_data, tmp_path, answers(**{"autoscaling describe-instance-refreshes": refreshes}))
    found = with_text(ctx, "Instance refresh")
    assert len(found) == 2
    assert any("InProgress" in f.summary and "40%" in f.summary for f in found)
    assert any("Successful" in f.summary for f in found)
    call = aws.called("autoscaling", "describe-instance-refreshes")[0]
    assert call[call.index("--max-records") + 1] == "5"


def test_ecs_targets_add_application_autoscaling(config_data, tmp_path):
    targets = {"ScalableTargets": [{"ResourceId": "service/checkout/api", "MinCapacity": 2, "MaxCapacity": 8,
                                    "SuspendedState": {"DynamicScalingInSuspended": False, "DynamicScalingOutSuspended": True}}]}
    policies = {"ScalingPolicies": [{"PolicyName": "cpu-target", "PolicyType": "TargetTrackingScaling",
                                      "TargetTrackingScalingPolicyConfiguration": {
                                          "TargetValue": 60.0, "PredefinedMetricSpecification": {
                                              "PredefinedMetricType": "ECSServiceAverageCPUUtilization"}}}]}
    ctx, aws, kube = run(config_data, tmp_path, answers(**{
        "application-autoscaling describe-scalable-targets": targets,
        "application-autoscaling describe-scaling-policies": policies,
    }), ecs_cluster="checkout", ecs_service="api")
    target = with_text(ctx, "Scalable target")[0]
    assert "min 2" in target.summary and "max 8" in target.summary and "scale-out suspended" in target.summary
    policy = with_text(ctx, "cpu-target")[0]
    assert "60" in policy.summary and "ECSServiceAverageCPUUtilization" in policy.summary
    call = aws.called("application-autoscaling", "describe-scalable-targets")[0]
    assert call[call.index("--resource-ids") + 1] == "service/checkout/api"
    call = aws.called("application-autoscaling", "describe-scaling-policies")[0]
    assert call[call.index("--resource-id") + 1] == "service/checkout/api"
    assert_read_only(ctx, aws, kube)


def test_ecs_target_without_a_service_is_ignored(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, answers(), ecs_cluster="checkout")
    assert aws.called("application-autoscaling", "describe-scalable-targets") == []


def test_access_denied_keeps_the_rest(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, answers(**{
        "autoscaling describe-scaling-activities": access_denied("DescribeScalingActivities")}))
    assert len(ctx.evidence.errors) == 1 and ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert with_text(ctx, "desired 4")
    assert_read_only(ctx, aws, kube)


def test_secret_in_an_activity_cause_never_reaches_the_document(config_data, tmp_path):
    secret = "AKIA" + "C" * 16
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "autoscaling describe-scaling-activities": {"Activities": [activity(cause=f"user key {secret} changed it")]}}))
    assert secret not in ctx.evidence.to_json()


def test_facts_are_bounded_to_thirty_activities(config_data, tmp_path):
    many = {"Activities": [activity(start=f"2026-10-04T10:{n % 60:02d}:00+00:00", description=f"Activity {n}") for n in range(45)]}
    ctx, _, _ = run(config_data, tmp_path, answers(**{"autoscaling describe-scaling-activities": many}))
    assert len(with_text(ctx, "Activity ")) <= 30


def refresh_facts(config_data, tmp_path, *refreshes):
    ctx, _, _ = run(config_data, tmp_path, answers(**{"autoscaling describe-instance-refreshes": {"InstanceRefreshes": list(refreshes)}}))
    return with_text(ctx, "Instance refresh")


def test_refresh_that_started_in_the_window_and_ended_after_it_is_reported(config_data, tmp_path):
    found = refresh_facts(config_data, tmp_path, refresh(
        status="Successful", start="2026-10-04T11:30:00+00:00", end="2026-10-04T12:40:00+00:00", percent=100))
    assert len(found) == 1 and found[0].time == "2026-10-04T11:30:00Z"


def test_refresh_that_started_before_the_window_and_ended_inside_it_is_reported(config_data, tmp_path):
    assert len(refresh_facts(config_data, tmp_path, refresh(
        status="Successful", start="2026-10-04T09:00:00+00:00", end="2026-10-04T10:30:00+00:00"))) == 1


def test_refresh_that_spans_the_whole_window_is_reported(config_data, tmp_path):
    assert len(refresh_facts(config_data, tmp_path, refresh(
        status="Successful", start="2026-10-04T08:00:00+00:00", end="2026-10-04T14:00:00+00:00"))) == 1


def test_refresh_that_ended_before_the_window_is_dropped(config_data, tmp_path):
    assert refresh_facts(config_data, tmp_path, refresh(
        status="Successful", start="2026-10-04T08:00:00+00:00", end="2026-10-04T09:59:00+00:00")) == []


def test_refresh_that_started_after_the_window_is_dropped(config_data, tmp_path):
    assert refresh_facts(config_data, tmp_path, refresh(
        status="Successful", start="2026-10-04T12:05:00+00:00", end="2026-10-04T12:30:00+00:00")) == []
    assert refresh_facts(config_data, tmp_path, refresh(status="InProgress", start="2026-10-04T12:05:00+00:00")) == []


def test_active_refresh_that_started_before_the_window_end_says_its_status_is_current(config_data, tmp_path):
    found = refresh_facts(config_data, tmp_path, refresh(status="InProgress", start="2026-10-04T09:00:00+00:00"))
    assert len(found) == 1 and "status now" in found[0].summary


def test_absent_status_message_is_left_out(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers(**{"autoscaling describe-scaling-activities": {"Activities": [
        activity(code="Failed")]}}))
    assert "None" not in with_text(ctx, "FAILED")[0].summary


def test_no_suspended_process_is_stated(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers())
    assert "no process is suspended" in ctx.evidence.facts[0].summary


def test_processes_suspended_before_the_window(config_data, tmp_path):
    suspended = [
        {"ProcessName": "Launch", "SuspensionReason": "User suspended at 2026-10-01T08:00:00Z"},
        {"ProcessName": "ReplaceUnhealthy", "SuspensionReason": "User suspended at 2026-10-01T08:00:05Z"},
    ]
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "autoscaling describe-auto-scaling-groups": group(SuspendedProcesses=suspended)}))
    summary = ctx.evidence.facts[0].summary
    assert "suspended processes: Launch (User suspended at 2026-10-01T08:00:00Z)" in summary
    assert "ReplaceUnhealthy (User suspended at 2026-10-01T08:00:05Z)" in summary
    assert "inside the incident window" not in summary
    assert ctx.evidence.facts[0].data["suspended_processes"] == ["Launch", "ReplaceUnhealthy"]


def test_process_suspended_inside_the_window_states_the_time(config_data, tmp_path):
    suspended = [{"ProcessName": "Terminate", "SuspensionReason": "User suspended at 2026-10-04T10:15:00Z"}]
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "autoscaling describe-auto-scaling-groups": group(SuspendedProcesses=suspended)}))
    assert "Terminate suspended at 2026-10-04T10:15:00Z, inside the incident window" in ctx.evidence.facts[0].summary


def test_suspension_without_a_time_in_its_reason(config_data, tmp_path):
    suspended = [{"ProcessName": "AZRebalance", "SuspensionReason": "Suspended by the service"}]
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "autoscaling describe-auto-scaling-groups": group(SuspendedProcesses=suspended)}))
    assert "AZRebalance (Suspended by the service)" in ctx.evidence.facts[0].summary


GROUP_ARN = "arn:aws:autoscaling:eu-west-1:111111111111:autoScalingGroup:uuid-1:autoScalingGroupName/web-asg"
TG_ARN = "arn:aws:elasticloadbalancing:eu-west-1:111111111111:targetgroup/web/abc{}"


def test_group_fact_holds_the_arns_the_answer_returns(config_data, tmp_path):
    body = group(AutoScalingGroupARN=GROUP_ARN, LaunchTemplate={"LaunchTemplateId": "lt-0abc", "LaunchTemplateName": "web", "Version": "7"},
                 TargetGroupARNs=[TG_ARN.format(n) for n in range(25)])
    ctx, _, _ = run(config_data, tmp_path, answers(**{"autoscaling describe-auto-scaling-groups": body}))
    data = ctx.evidence.facts[0].data
    assert data["arn"] == GROUP_ARN
    assert data["launch_template"] == {"id": "lt-0abc", "name": "web", "version": "7"}
    assert data["target_group_arns"] == [TG_ARN.format(n) for n in range(20)]
    assert data["target_group_arns_omitted"] == 5


def test_launch_template_of_a_mixed_instances_policy(config_data, tmp_path):
    spec = {"LaunchTemplateId": "lt-0mix", "Version": "$Latest"}
    body = group(MixedInstancesPolicy={"LaunchTemplate": {"LaunchTemplateSpecification": spec}})
    ctx, _, _ = run(config_data, tmp_path, answers(**{"autoscaling describe-auto-scaling-groups": body}))
    assert ctx.evidence.facts[0].data["launch_template"] == {"id": "lt-0mix", "version": "$Latest"}


def test_group_without_arn_fields_writes_no_arn_keys(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, answers())
    data = ctx.evidence.facts[0].data
    assert "arn" not in data and "launch_template" not in data and "target_group_arns" not in data


def test_ecs_scaling_facts_hold_resource_id_and_arns(config_data, tmp_path):
    target_arn = "arn:aws:application-autoscaling:eu-west-1:111111111111:scalable-target/0abc"
    policy_arn = "arn:aws:autoscaling:eu-west-1:111111111111:scalingPolicy:u:resource/ecs/service/checkout/api:policyName/cpu"
    ctx, _, _ = run(config_data, tmp_path, answers(**{
        "application-autoscaling describe-scalable-targets": {"ScalableTargets": [
            {"ResourceId": "service/checkout/api", "MinCapacity": 2, "MaxCapacity": 8, "ScalableTargetARN": target_arn}]},
        "application-autoscaling describe-scaling-policies": {"ScalingPolicies": [
            {"PolicyName": "cpu", "PolicyType": "TargetTrackingScaling", "PolicyARN": policy_arn}]},
    }), ecs_cluster="checkout", ecs_service="api")
    target = with_text(ctx, "Scalable target")[0].data
    assert target["resource_id"] == "service/checkout/api" and target["arn"] == target_arn
    assert with_text(ctx, "Scaling policy cpu")[0].data["arn"] == policy_arn
