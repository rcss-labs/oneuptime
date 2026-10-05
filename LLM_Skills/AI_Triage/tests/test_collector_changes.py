import json

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


class RegionAws(FakeAws):
    """Answers CloudTrail lookups made in us-east-1 from by_source (event source -> reply or error tuple)."""

    def __init__(self, answers, by_source, by_attribute=None):
        super().__init__(answers)
        self.by_source = by_source
        self.by_attribute = by_attribute or {}

    def __call__(self, argv, timeout):
        if argv[1:3] == ["cloudtrail", "lookup-events"] and argv[argv.index("--region") + 1] != "us-east-1":
            value = argv[argv.index("--lookup-attributes") + 1].split("AttributeValue=")[1]
            if value in self.by_attribute:
                self.calls.append(argv)
                token = argv[argv.index("--starting-token") + 1] if "--starting-token" in argv else "0"
                pages = self.by_attribute[value]
                return 0, json.dumps(pages[min(int(token), len(pages) - 1)]), ""
        if argv[1:3] == ["cloudtrail", "lookup-events"] and argv[argv.index("--region") + 1] == "us-east-1":
            self.calls.append(argv)
            attribute = argv[argv.index("--lookup-attributes") + 1]
            source = attribute.split("AttributeValue=")[1]
            answer = self.by_source.get(source, {"Events": []})
            if isinstance(answer, tuple):
                return answer[0], "", answer[1]
            return 0, json.dumps(answer), ""
        return super().__call__(argv, timeout)


def run(config_data, tmp_path, answers, targets, global_events=None, region="eu-west-1", by_attribute=None):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="changes", region=region)
    if region != "us-east-1":
        aws = ctx.runner = RegionAws(answers, global_events or {}, by_attribute)
    COLLECTOR.run(ctx, dict(targets))
    return ctx, aws, kube


def regional_lookups(aws):
    return [c for c in aws.called("cloudtrail", "lookup-events") if c[c.index("--region") + 1] != "us-east-1"]


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "changes"
    assert COLLECTOR.required == ()
    assert set(COLLECTOR.optional) == {"resource_names", "event_sources", "stack", "pipeline", "config_resource", "incident_start"}


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
    call = regional_lookups(aws)[0]
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
    changes = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert len(changes) == 40
    assert "Change49" in changes[0].summary


def test_complete_answer_with_more_writes_than_shown_says_how_many_were_left_out(config_data, tmp_path):
    events = [event(f"Change{n}", when=f"2026-10-04T10:{n:02d}:00+00:00") for n in range(45)]
    ctx, _, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": events}}, {"resource_names": "a"})
    notes = [f for f in ctx.evidence.facts if f.kind == "derived"]
    assert len(notes) == 1
    assert notes[0].summary == "5 older changes for a between 2026-10-04T10:00:00Z and 2026-10-04T12:00:00Z were not shown"


def test_account_wide_facts_say_any_resource(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": []}}, {})
    assert fact_summaries(ctx) == [
        "No change was recorded for any resource between 2026-10-04T10:00:00Z and 2026-10-04T12:00:00Z"
    ]


def test_incident_a_minute_before_the_window_looks_at_the_whole_window(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, {}, {"resource_names": "x", "incident_start": "2026-10-04T09:56:00Z"})
    call = regional_lookups(aws)[0]
    assert call[call.index("--end-time") + 1] == "2026-10-04T12:00:00Z"


def test_one_call_per_resource_name_at_most_ten(config_data, tmp_path):
    names = ",".join(f"res-{n}" for n in range(14))
    ctx, aws, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": []}}, {"resource_names": names})
    assert len(regional_lookups(aws)) == 10


def test_without_names_one_call_for_writes(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("PutRolePolicy", source="iam.amazonaws.com")]}}
    ctx, aws, kube = run(config_data, tmp_path, answers, {})
    calls = regional_lookups(aws)
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
        "CloudTrail returned no write event naming 'x' between 2026-10-04T10:00:00Z and 2026-10-04T12:00:00Z (looked up by resource name only; some services record ARNs or ids instead)"
    ]
    assert ctx.evidence.facts[0].kind == "derived"
    assert_read_only(ctx, aws, kube)


def test_only_read_events_counts_as_nothing_changed(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("DescribeServices", read_only="true")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "x"})
    assert fact_summaries(ctx)[0].startswith("CloudTrail returned no write event naming 'x'")


def test_failed_lookup_is_not_reported_as_nothing_changed(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": access_denied("LookupEvents")},
                    {"resource_names": "x"})
    assert ctx.evidence.facts == []


def test_lookup_ends_five_minutes_after_the_incident_start(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": []}},
                      {"resource_names": "x", "incident_start": INCIDENT})
    call = regional_lookups(aws)[0]
    assert call[call.index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-time") + 1] == "2026-10-04T10:55:00Z"
    assert fact_summaries(ctx) == [
        "CloudTrail returned no write event naming 'x' between 2026-10-04T10:00:00Z and 2026-10-04T10:55:00Z "
        "(looked up by resource name only; some services record ARNs or ids instead)"
    ]


def test_account_wide_lookup_also_ends_after_the_incident_start(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, {}, {"incident_start": INCIDENT})
    call = regional_lookups(aws)[0]
    assert call[call.index("--end-time") + 1] == "2026-10-04T10:55:00Z"


def test_incident_start_after_the_window_keeps_the_window_end(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path, {}, {"resource_names": "x", "incident_start": "2026-10-04T11:58:00Z"})
    call = regional_lookups(aws)[0]
    assert call[call.index("--end-time") + 1] == "2026-10-04T12:00:00Z"


def test_cut_list_is_reported(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")], "NextToken": "abc"}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "checkout-api"})
    cut = [f for f in ctx.evidence.facts if "More events exist" in f.summary]
    assert len(cut) == 1 and cut[0].kind == "derived"
    assert cut[0].summary == "More events exist than the 1 read; they may include changes"


def test_cut_list_with_no_write_found_does_not_claim_nothing_changed(config_data, tmp_path):
    events = [event(f"Describe{n}", read_only="true") for n in range(50)]
    ctx, _, _ = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": events, "NextToken": "abc"}},
                    {"resource_names": "x"})
    assert fact_summaries(ctx) == [
        "No change was found among the 50 newest events for x between 2026-10-04T10:00:00Z and "
        "2026-10-04T12:00:00Z; older events were not read"
    ]
    assert ctx.evidence.facts[0].kind == "derived"


def test_cut_list_count_is_the_number_returned(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")], "NextToken": "abc"}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "x"})
    assert any("than the 1 read" in s for s in fact_summaries(ctx))


def test_incident_before_the_window_looks_at_the_whole_window(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {}, {"resource_names": "x", "incident_start": "2026-10-04T09:00:00Z"})
    call = regional_lookups(aws)[0]
    assert call[call.index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-time") + 1] == "2026-10-04T12:00:00Z"


def test_complete_list_is_not_reported_as_cut(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "x"})
    assert not any("More events exist" in s for s in fact_summaries(ctx))


def test_incident_start_without_a_timezone_is_an_error(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")]}}
    ctx, aws, _ = run(config_data, tmp_path, answers, {"resource_names": "x", "incident_start": "2026-10-04T10:50:00"})
    assert ctx.evidence.errors[0]["code"] == "InvalidTarget"
    assert "incident started" not in ctx.evidence.facts[0].summary


GLOBAL_SOURCES = ["iam.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com",
                  "wafv2.amazonaws.com", "organizations.amazonaws.com"]


def test_global_service_events_in_us_east_1_become_facts(config_data, tmp_path):
    global_events = {
        "route53.amazonaws.com": {"Events": [event("ChangeResourceRecordSets", when="2026-10-04T10:45:00+00:00",
                                                   source="route53.amazonaws.com", resource="shop.example.com")]},
        "iam.amazonaws.com": {"Events": [event("PutRolePolicy", when="2026-10-04T10:45:00+00:00",
                                               source="iam.amazonaws.com", resource="checkout-task")]},
    }
    ctx, aws, kube = run(config_data, tmp_path, {"cloudtrail lookup-events": {"Events": []}},
                         {"resource_names": "checkout-api", "incident_start": INCIDENT}, global_events)
    facts = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert len(facts) == 2
    route53 = next(f for f in facts if "ChangeResourceRecordSets" in f.summary)
    assert "recorded in us-east-1" in route53.summary and "5 minutes before the incident started" in route53.summary
    assert route53.time == "2026-10-04T10:45:00Z"
    assert any("PutRolePolicy" in f.summary and "recorded in us-east-1" in f.summary for f in facts)
    assert_read_only(ctx, aws, kube)


def test_non_global_events_in_us_east_1_are_ignored(config_data, tmp_path):
    global_events = {"iam.amazonaws.com": {"Events": [
        event("PutBucketPolicy", source="s3.amazonaws.com"), event("RunInstances", source="ec2.amazonaws.com"),
        event("DescribeRoles", source="iam.amazonaws.com", read_only="true")]}}
    ctx, _, _ = run(config_data, tmp_path, {}, {"resource_names": "x"}, global_events)
    assert not [f for f in ctx.evidence.facts if f.kind == "incident_time"]


def test_one_lookup_per_global_source_in_us_east_1_over_the_same_period(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {}, {"resource_names": "x", "incident_start": INCIDENT})
    calls = [c for c in aws.called("cloudtrail", "lookup-events") if c[c.index("--region") + 1] == "us-east-1"]
    assert [c[c.index("--lookup-attributes") + 1] for c in calls] == [
        f"AttributeKey=EventSource,AttributeValue={source}" for source in GLOBAL_SOURCES]
    assert all(c[c.index("--start-time") + 1] == "2026-10-04T10:00:00Z" for c in calls)
    assert all(c[c.index("--end-time") + 1] == "2026-10-04T10:55:00Z" for c in calls)
    assert all(c[c.index("--max-items") + 1] == "50" for c in calls)


def test_failed_global_lookup_is_an_error_and_regional_facts_remain(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": [event("UpdateService")]}}
    ctx, _, _ = run(config_data, tmp_path, answers, {"resource_names": "checkout-api"},
                    {"iam.amazonaws.com": access_denied("LookupEvents")})
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert "us-east-1" in ctx.evidence.errors[0]["command"]
    assert any("UpdateService" in f.summary for f in ctx.evidence.facts)


def test_cut_global_lookup_says_older_events_were_not_read(config_data, tmp_path):
    reads = [event(f"Get{n}", source="iam.amazonaws.com", read_only="true") for n in range(50)]
    ctx, _, _ = run(config_data, tmp_path, {}, {"resource_names": "x"},
                    {"iam.amazonaws.com": {"Events": reads, "NextToken": "t"}})
    assert any("older events were not read" in s and "iam.amazonaws.com" in s for s in fact_summaries(ctx))


def test_in_us_east_1_there_is_no_extra_lookup(config_data, tmp_path):
    answers = {"cloudtrail lookup-events": {"Events": []}}
    ctx, aws, _ = run(config_data, tmp_path, answers, {"resource_names": "x"}, region="us-east-1")
    assert len(aws.called("cloudtrail", "lookup-events")) == 1


ECS = "ecs.amazonaws.com"
ELB = "elasticloadbalancing.amazonaws.com"
CHECKOUT_ARN = f"arn:aws:ecs:eu-west-1:{ACCOUNT}:service/checkout/checkout-api"


def arn_event(name, text, source=ECS, event_id=None, read_only="false", when="2026-10-04T10:46:00+00:00"):
    """An event whose Resources carry an ARN and whose record mentions text in its request parameters."""
    body = event(name, when=when, source=source, read_only=read_only, resource=f"{CHECKOUT_ARN.rsplit('/', 1)[0]}/{text}")
    body["CloudTrailEvent"] = '{"requestParameters": {"service": "%s"}}' % text
    body["EventId"] = event_id or f"id-{name}-{text}-{read_only}"
    return body


def source_run(config_data, tmp_path, by_attribute, sources=ECS, **extra):
    targets = {"resource_names": "checkout-api", "event_sources": sources, **extra}
    return run(config_data, tmp_path, {}, targets, by_attribute=by_attribute)


def test_declares_event_sources_as_optional_target():
    assert "event_sources" in COLLECTOR.optional


def test_event_found_only_by_event_source_is_a_fact(config_data, tmp_path):
    events = [
        arn_event("UpdateService", "checkout-api"),
        arn_event("UpdateService", "billing-api"),
        arn_event("DescribeServices", "checkout-api", read_only="true"),
    ]
    ctx, aws, kube = source_run(config_data, tmp_path, {ECS: [{"Events": events}]})
    facts = [f for f in ctx.evidence.facts if f.kind == "incident_time"]
    assert len(facts) == 1 and "UpdateService" in facts[0].summary
    call = [c for c in aws.called("cloudtrail", "lookup-events")
            if "AttributeKey=EventSource,AttributeValue=" + ECS in c][0]
    assert call[call.index("--start-time") + 1] == "2026-10-04T10:00:00Z"
    assert call[call.index("--end-time") + 1] == "2026-10-04T12:00:00Z"
    assert "hunter2" not in ctx.evidence.to_json() and "requestParameters" not in ctx.evidence.to_json()
    assert_read_only(ctx, aws, kube)


def test_name_match_is_whole_word_not_a_substring(config_data, tmp_path):
    events = [arn_event("UpdateService", "checkout-api-canary")]
    ctx, _, _ = source_run(config_data, tmp_path, {ECS: [{"Events": events}]})
    assert not [f for f in ctx.evidence.facts if f.kind == "incident_time"]


def test_same_event_from_both_lookups_is_written_once(config_data, tmp_path):
    same = arn_event("UpdateService", "checkout-api", event_id="evt-1")
    ctx, _, _ = source_run(config_data, tmp_path, {"checkout-api": [{"Events": [same]}], ECS: [{"Events": [same]}]})
    assert len([f for f in ctx.evidence.facts if f.kind == "incident_time"]) == 1


def test_source_lookup_follows_pages_up_to_ten_and_says_absence_is_not_established(config_data, tmp_path):
    pages = [{"Events": [arn_event("Other", "billing", event_id=f"e{n}") for n in range(50)], "NextToken": str(n + 1)}
             for n in range(20)]
    ctx, aws, _ = source_run(config_data, tmp_path, {ECS: pages})
    source_calls = [c for c in aws.called("cloudtrail", "lookup-events") if "AttributeKey=EventSource,AttributeValue=" + ECS in c]
    assert len(source_calls) == 10
    notes = [s for s in fact_summaries(ctx) if "stopped after 500 events" in s]
    assert len(notes) == 1 and "absence" in notes[0] and "not established" in notes[0] and ECS in notes[0]
    assert not any("returned no write event" in s for s in fact_summaries(ctx))


def test_absence_wording_names_what_was_asked(config_data, tmp_path):
    ctx, _, _ = source_run(config_data, tmp_path, {ECS: [{"Events": []}]}, sources=f"{ECS},{ELB}")
    assert fact_summaries(ctx) == [
        "CloudTrail returned no write event naming 'checkout-api' between 2026-10-04T10:00:00Z and "
        f"2026-10-04T12:00:00Z (looked up by resource name and by event source {ECS}, {ELB})"
    ]


def test_found_by_source_means_no_absence_fact(config_data, tmp_path):
    ctx, _, _ = source_run(config_data, tmp_path, {ECS: [{"Events": [arn_event("UpdateService", "checkout-api")]}]})
    assert not any("returned no write event" in s for s in fact_summaries(ctx))


def test_failed_source_lookup_is_an_error_and_no_absence_is_claimed(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {}, {"resource_names": "checkout-api", "event_sources": ECS},
                    by_attribute=None)
    assert not ctx.evidence.errors
    failing = {"cloudtrail lookup-events": access_denied("LookupEvents")}
    ctx, _, _ = run(config_data, tmp_path, failing, {"resource_names": "checkout-api", "event_sources": ECS})
    assert [e["code"] for e in ctx.evidence.errors].count("AccessDeniedException") == 2
    assert not any("returned no write event" in s for s in fact_summaries(ctx))
