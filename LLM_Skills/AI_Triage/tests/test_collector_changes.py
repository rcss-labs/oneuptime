import pytest

from fakes import SSO_EXPIRED_ERROR, FakeAws, access_denied
from helpers import assert_read_only, fact_summaries, make_context
from triage.collectors.changes import COLLECTOR
from triage.context import SignInExpired

ACCOUNT = "111111111111"
INCIDENT = "2026-10-04T10:50:00Z"
OUTSIDE = "2026-10-04T07:00:00+00:00"


def event(name, when="2026-10-04T10:46:00+00:00", read_only="false", user="alice@example.com",
          source="ecs.amazonaws.com", resource="checkout-api"):
    return {
        "EventId": f"id-{name}-{when}", "EventName": name, "ReadOnly": read_only, "EventTime": when,
        "EventSource": source, "Username": user,
        "Resources": [{"ResourceType": "AWS::ECS::Service", "ResourceName": resource}],
        "CloudTrailEvent": '{"requestParameters": {"password": "hunter2-do-not-leak"}}',
    }


def run(config_data, tmp_path, answers, targets):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="changes")
    COLLECTOR.run(ctx, dict(targets))
    return ctx, aws, kube


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "changes"
    assert COLLECTOR.required == ()
    assert set(COLLECTOR.optional) == {"resource_names", "stack", "pipeline", "config_resource", "incident_start"}


def test_cloudtrail_event_fact_says_who_what_and_how_long_before(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")]}}
    ctx, aws, kube = run(config_data, tmp_path, answers, {"resource_names": "checkout-api", "incident_start": INCIDENT})
    fact = ctx.evidence.facts[0]
    assert fact.kind == "incident_time"
    assert fact.time == "2026-10-04T10:46:00Z"
    assert fact.resource == "checkout-api"
    assert "UpdateService" in fact.summary and "ecs.amazonaws.com" in fact.summary
    assert "4 minutes before the incident started" in fact.summary
    assert "alice@example.com" not in ctx.evidence.to_json()
    assert "hunter2" not in ctx.evidence.to_json()
    call = aws.called("cloudtrail", "lookup-events")[0]
    assert call[call.index("--lookup-attributes") + 1] == "AttributeKey=ResourceName,AttributeValue=checkout-api"
    assert call[call.index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-time") + 1] == "2026-10-04T10:55:00Z"
    assert call[call.index("--max-items") + 1] == "50"
    assert_read_only(ctx, aws, kube)


def test_gap_wording_after_the_incident(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService", when="2026-10-04T10:53:00+00:00")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "checkout-api", "incident_start": INCIDENT})
    assert ctx.evidence.facts[0].summary.endswith("3 minutes after the incident started")


def test_no_gap_without_incident_start(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "checkout-api"})
    assert "incident started" not in ctx.evidence.facts[0].summary


def test_read_only_events_are_dropped(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("DescribeServices", read_only="true"), event("UpdateService")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "checkout-api"})
    assert len(ctx.evidence.facts) == 1
    assert "UpdateService" in ctx.evidence.facts[0].summary


def test_events_are_capped_at_forty_per_name_newest_first(config_data, tmp_path):
    events = [event(f"Change{n}", when=f"2026-10-04T10:{n:02d}:00+00:00") for n in range(50)]
    ctx, _, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": events}}, {"resource_names": "a"})
    assert len(ctx.evidence.facts) == 40
    assert "Change49" in ctx.evidence.facts[0].summary


def test_one_call_per_resource_name_at_most_ten(config_data, tmp_path):
    names = ",".join(f"res-{n}" for n in range(14))
    ctx, aws, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": []}}, {"resource_names": names})
    assert len(aws.called("cloudtrail", "lookup-events")) == 10


def test_without_names_one_call_for_writes(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("PutRolePolicy", source="iam.amazonaws.com")]}}
    ctx, aws, kube = run(config_data, tmp_path, answers, {})
    calls = aws.called("cloudtrail", "lookup-events")
    assert len(calls) == 1
    assert calls[0][calls[0].index("--lookup-attributes") + 1] == "AttributeKey=ReadOnly,AttributeValue=false"
    assert len(ctx.evidence.facts) == 1
    assert_read_only(ctx, aws, kube)


def stack_event(status, when="2026-10-04T10:45:00+00:00", logical="web-stack", rtype="AWS::CloudFormation::Stack",
                reason=""):
    return {"StackName": "web-stack", "LogicalResourceId": logical, "ResourceType": rtype, "Timestamp": when,
            "ResourceStatus": status, "ResourceStatusReason": reason}


def test_stack_with_a_failed_update(config_data, tmp_path):
    events = [
        stack_event("UPDATE_IN_PROGRESS"),
        stack_event("UPDATE_FAILED", logical="Db", rtype="AWS::RDS::DBInstance", reason="Invalid parameter"),
        stack_event("UPDATE_ROLLBACK_IN_PROGRESS", when="2026-10-04T10:47:00+00:00"),
        stack_event("CREATE_COMPLETE", logical="Queue", rtype="AWS::SQS::Queue"),
        stack_event("UPDATE_COMPLETE", when=OUTSIDE),
        stack_event("UPDATE_IN_PROGRESS", logical="Queue", rtype="AWS::SQS::Queue"),
    ]
    ctx, aws, kube = run(config_data, tmp_path, {"cloudformation describe-stack-events": {"StackEvents": events}},
                         {"stack": "web-stack", "resource_names": "x", "incident_start": INCIDENT})
    stack_facts = [f for f in ctx.evidence.facts if f.resource.startswith("stack/")]
    texts = [f.summary for f in stack_facts]
    assert len(stack_facts) == 3
    assert any("UPDATE_FAILED" in t and "Db" in t for t in texts)
    assert any("UPDATE_ROLLBACK_IN_PROGRESS" in t for t in texts)
    assert any("UPDATE_IN_PROGRESS" in t and "web-stack" in t and "5 minutes before the incident started" in t for t in texts)
    failed = next(f for f in stack_facts if "UPDATE_FAILED" in f.summary)
    assert failed.kind == "incident_time" and failed.excerpt == "Invalid parameter"
    call = aws.called("cloudformation", "describe-stack-events")[0]
    assert call[call.index("--stack-name") + 1] == "web-stack"
    assert call[call.index("--max-items") + 1] == "50"
    assert_read_only(ctx, aws, kube)


def execution(status, start, end, trigger="StartPipelineExecution", detail="arn:aws:sts::%s:assumed-role/dev" % ACCOUNT):
    return {"pipelineExecutionId": f"ex-{status}-{start}", "status": status, "startTime": start,
            "lastUpdateTime": end, "trigger": {"triggerType": trigger, "triggerDetail": detail}}


def test_pipeline_executions_and_stages(config_data, tmp_path):
    answers = {
        "codepipeline list-pipeline-executions": {"pipelineExecutionSummaries": [
            execution("Failed", "2026-10-04T10:40:00+00:00", "2026-10-04T10:44:00+00:00"),
            execution("Succeeded", "2026-10-04T08:00:00+00:00", "2026-10-04T11:00:00+00:00"),
            execution("Succeeded", "2026-10-04T08:00:00+00:00", "2026-10-04T08:10:00+00:00"),
        ]},
        "codepipeline get-pipeline-state": {"pipelineName": "web", "stageStates": [
            {"stageName": "Source", "latestExecution": {"pipelineExecutionId": "e", "status": "Succeeded"}},
            {"stageName": "Deploy", "latestExecution": {"pipelineExecutionId": "e", "status": "Failed"}},
            {"stageName": "Approve"},
        ]},
    }
    ctx, aws, kube = run(config_data, tmp_path, answers, {"pipeline": "web", "resource_names": "x"})
    timed = [f for f in ctx.evidence.facts if f.kind == "incident_time" and f.resource == "pipeline/web"]
    assert len(timed) == 2
    failed = next(f for f in timed if "Failed" in f.summary)
    assert "StartPipelineExecution" in failed.summary and failed.time == "2026-10-04T10:40:00Z"
    current = [f for f in ctx.evidence.facts if f.kind == "current"]
    assert len(current) == 2
    assert any("Deploy" in f.summary and "Failed" in f.summary for f in current)
    assert any("Approve" in f.summary for f in current)
    call = aws.called("codepipeline", "list-pipeline-executions")[0]
    assert call[call.index("--pipeline-name") + 1] == "web" and call[call.index("--max-items") + 1] == "10"
    assert "web" in aws.called("codepipeline", "get-pipeline-state")[0]
    assert_read_only(ctx, aws, kube)


def test_config_history(config_data, tmp_path):
    items = [{"configurationItemCaptureTime": "2026-10-04T10:48:00+00:00", "configurationItemStatus": "OK",
              "resourceType": "AWS::EC2::SecurityGroup", "resourceId": "sg-0abc",
              "relatedEvents": ["evt-1", "evt-2"]}]
    ctx, aws, kube = run(config_data, tmp_path,
                         {"configservice get-resource-config-history": {"configurationItems": items}},
                         {"config_resource": "AWS::EC2::SecurityGroup/sg-0abc", "resource_names": "x",
                          "incident_start": INCIDENT})
    fact = next(f for f in ctx.evidence.facts if f.resource == "AWS::EC2::SecurityGroup/sg-0abc")
    assert fact.kind == "incident_time" and fact.time == "2026-10-04T10:48:00Z"
    assert "OK" in fact.summary and "2 minutes before the incident started" in fact.summary
    assert "evt-1" in fact.excerpt
    call = aws.called("configservice", "get-resource-config-history")[0]
    assert call[call.index("--resource-type") + 1] == "AWS::EC2::SecurityGroup"
    assert call[call.index("--resource-id") + 1] == "sg-0abc"
    assert call[call.index("--earlier-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--later-time") + 1] == "2026-10-04T12:00:00Z"
    assert call[call.index("--limit") + 1] == "10"
    assert_read_only(ctx, aws, kube)


def test_config_not_recording_the_resource(config_data, tmp_path):
    error = (254, "An error occurred (ResourceNotDiscoveredException) when calling the GetResourceConfigHistory "
                  "operation: Resource not discovered")
    ctx, _, _ = run(config_data, tmp_path, {"configservice get-resource-config-history": error},
                    {"config_resource": "AWS::EC2::SecurityGroup/sg-0abc", "resource_names": "x"})
    fact = next(f for f in ctx.evidence.facts if "AWS Config" in f.summary)
    assert fact.kind == "derived"
    assert "AWS Config does not record" in fact.summary
    assert ctx.evidence.errors == []


def test_bad_config_resource_is_a_missing_target_error(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {}, {"config_resource": "nonsense", "resource_names": "x"})
    assert ctx.evidence.errors[0]["code"] == "InvalidTarget"
    assert aws.called("configservice", "get-resource-config-history") == []


def test_other_config_errors_stay_errors(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path,
                    {"configservice get-resource-config-history": access_denied("GetResourceConfigHistory")},
                    {"config_resource": "AWS::EC2::SecurityGroup/sg-0abc", "resource_names": "x"})
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert not any("does not record" in s for s in fact_summaries(ctx))


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = {
        "cloudtrail lookup-events": access_denied("LookupEvents"),
        "cloudformation describe-stack-events": {"StackEvents": [stack_event("UPDATE_FAILED", logical="Db")]},
    }
    ctx, aws, kube = run(config_data, tmp_path, answers, {"resource_names": "x", "stack": "web-stack"})
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert by_summary(ctx, "UPDATE_FAILED")
    assert_read_only(ctx, aws, kube)


def test_expired_sign_in_stops_the_run(config_data, tmp_path):
    with pytest.raises(SignInExpired):
        run(config_data, tmp_path, {"cloudtrail lookup-events": SSO_EXPIRED_ERROR}, {"resource_names": "x"})


def test_nothing_changed_says_so_with_the_range_scanned(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": []}}, {"resource_names": "x"})
    assert ctx.evidence.errors == []
    assert fact_summaries(ctx) == [
        "No change was recorded for x between 2026-10-04T10:00:00Z and 2026-10-04T12:00:00Z"
    ]
    assert ctx.evidence.facts[0].kind == "derived"
    assert_read_only(ctx, aws, kube)


def test_only_read_events_counts_as_nothing_changed(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("DescribeServices", read_only="true")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "x"})
    assert fact_summaries(ctx)[0].startswith("No change was recorded for x")


def test_failed_lookup_is_not_reported_as_nothing_changed(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": access_denied("LookupEvents")},
                    {"resource_names": "x"})
    assert ctx.evidence.facts == []


def test_lookup_ends_five_minutes_after_the_incident_start(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": []}},
                      {"resource_names": "x", "incident_start": INCIDENT})
    call = aws.called("cloudtrail", "lookup-events")[0]
    assert call[call.index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-time") + 1] == "2026-10-04T10:55:00Z"
    assert fact_summaries(ctx) == [
        "No change was recorded for x between 2026-10-04T10:00:00Z and 2026-10-04T10:55:00Z"
    ]


def test_account_wide_lookup_also_ends_after_the_incident_start(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, {}, {"incident_start": INCIDENT})
    call = aws.called("cloudtrail", "lookup-events")[0]
    assert call[call.index("--end-time") + 1] == "2026-10-04T10:55:00Z"


def test_incident_start_after_the_window_keeps_the_window_end(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, {}, {"resource_names": "x", "incident_start": "2026-10-04T11:58:00Z"})
    call = aws.called("cloudtrail", "lookup-events")[0]
    assert call[call.index("--end-time") + 1] == "2026-10-04T12:00:00Z"


def test_cut_list_is_reported(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")], "NextToken": "abc"}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "checkout-api"})
    cut = [f for f in ctx.evidence.facts if "More change events exist" in f.summary]
    assert len(cut) == 1 and cut[0].kind == "derived"
    assert cut[0].summary == ("More change events exist for checkout-api than the 1 shown; "
                              "these are the newest in the period")


def test_cut_list_with_no_write_found_does_not_claim_nothing_changed(config_data, tmp_path):
    events = [event(f"Describe{n}", read_only="true") for n in range(50)]
    ctx, _, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": events, "NextToken": "abc"}},
                    {"resource_names": "x"})
    assert fact_summaries(ctx) == ["No change was found among the 50 newest events; older events were not read"]
    assert ctx.evidence.facts[0].kind == "derived"


def test_cut_list_count_is_the_number_returned(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")], "NextToken": "abc"}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "x"})
    assert any("than the 1 shown" in s for s in fact_summaries(ctx))


def test_incident_before_the_window_looks_at_the_whole_window(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {}, {"resource_names": "x", "incident_start": "2026-10-04T09:00:00Z"})
    call = aws.called("cloudtrail", "lookup-events")[0]
    assert call[call.index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-time") + 1] == "2026-10-04T12:00:00Z"


def test_complete_list_is_not_reported_as_cut(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "x"})
    assert not any("More change events" in s for s in fact_summaries(ctx))


def test_incident_start_without_a_timezone_is_an_error(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")]}}
    ctx, aws, _ = run(config_data, tmp_path, answers, {"resource_names": "x", "incident_start": "2026-10-04T10:50:00"})
    assert ctx.evidence.errors[0]["code"] == "InvalidTarget"
    assert "incident started" not in ctx.evidence.facts[0].summary
