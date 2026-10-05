import json

import pytest

from fakes import FakeAws, access_denied
from helpers import FakeKubectl, assert_read_only, fact_summaries, make_context
from triage.collectors.ecs import COLLECTOR

ACCOUNT = "111111111111"
TASK_DEF_ARN = f"arn:aws:ecs:eu-west-1:{ACCOUNT}:task-definition/checkout-api:42"
TARGETS = {"cluster": "checkout", "service": "checkout-api"}
IN_WINDOW = "2026-10-04T10:42:10.123000+00:00"
OUTSIDE = "2026-10-04T07:00:00+00:00"


def service(**overrides):
    body = {
        "serviceName": "checkout-api",
        "status": "ACTIVE",
        "desiredCount": 2,
        "runningCount": 2,
        "pendingCount": 0,
        "taskDefinition": TASK_DEF_ARN,
        "deployments": [
            {
                "id": "ecs-svc/1", "status": "PRIMARY", "taskDefinition": TASK_DEF_ARN,
                "desiredCount": 2, "runningCount": 2, "pendingCount": 0,
                "rolloutState": "COMPLETED", "rolloutStateReason": "ECS deployment completed",
                "createdAt": IN_WINDOW,
            }
        ],
        "events": [
            {"id": "e1", "createdAt": IN_WINDOW, "message": "(service checkout-api) has reached a steady state."},
            {"id": "e0", "createdAt": OUTSIDE, "message": "(service checkout-api) old event."},
        ],
    }
    body.update(overrides)
    return {"services": [body], "failures": []}


def container(image="registry.example.com/checkout:1", env=None, cpu=256, memory=512):
    return {"name": "app", "image": image, "cpu": cpu, "memory": memory,
            "environment": [{"name": k, "value": v} for k, v in (env or {"LOG_LEVEL": "info"}).items()]}


def task_definition(revision, **kwargs):
    return {"taskDefinition": {"family": "checkout-api", "revision": revision,
                               "containerDefinitions": [container(**kwargs)]}}


def healthy_answers(**extra):
    answers = {
        "ecs describe-services": service(),
        "ecs list-tasks": {"taskArns": []},
        "ecs describe-task-definition": task_definition(1),
        "application-autoscaling describe-scaling-activities": {"ScalingActivities": []},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="ecs")
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, aws, kube


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "ecs"
    assert COLLECTOR.required == ("cluster", "service")


def test_healthy_service(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, healthy_answers())
    summaries = fact_summaries(ctx)
    state = next(f for f in ctx.evidence.facts if f.kind == "current" and "ACTIVE" in f.summary)
    assert "desired 2" in state.summary and "running 2" in state.summary and "pending 0" in state.summary
    assert "checkout-api:42" in state.summary
    deployment = next(f for f in ctx.evidence.facts if f.kind == "incident_time" and "COMPLETED" in f.summary)
    assert deployment.time == "2026-10-04T10:42:10Z"
    assert deployment.excerpt == "ECS deployment completed"
    assert any("steady state" in (f.excerpt) for f in ctx.evidence.facts)
    assert ctx.evidence.errors == []
    assert "ecs-0001" == ctx.evidence.facts[0].id
    assert summaries
    assert_read_only(ctx, aws, kube)


def test_events_outside_the_window_are_dropped(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, healthy_answers())
    assert not any("old event" in fact.excerpt for fact in ctx.evidence.facts)


def test_events_are_capped_newest_first(config_data, tmp_path):
    events = [{"id": str(n), "createdAt": f"2026-10-04T10:{n:02d}:00+00:00", "message": f"event {n}"} for n in range(40)]
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**{"ecs describe-services": service(events=events)}))
    event_facts = [f for f in ctx.evidence.facts if f.excerpt.startswith("event ")]
    assert len(event_facts) == 30
    assert event_facts[0].excerpt == "event 39"
    assert event_facts[-1].excerpt == "event 10"


def test_missing_service(config_data, tmp_path):
    answers = healthy_answers(**{"ecs describe-services": {"services": [], "failures": [{"arn": "x", "reason": "MISSING"}]}})
    ctx, aws, _ = run(config_data, tmp_path, answers)
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current"
    assert "not found" in ctx.evidence.facts[0].summary
    assert aws.called("ecs", "list-tasks") == []


def failed_answers():
    stopped_arn = f"arn:aws:ecs:eu-west-1:{ACCOUNT}:task/checkout/abc123"
    failing = service(deployments=[{
        "id": "ecs-svc/2", "status": "PRIMARY", "taskDefinition": TASK_DEF_ARN,
        "desiredCount": 2, "runningCount": 0, "pendingCount": 2,
        "rolloutState": "FAILED", "rolloutStateReason": "tasks failed to start", "createdAt": IN_WINDOW,
    }])
    return healthy_answers(**{
        "ecs describe-services": failing,
        "ecs list-tasks": {"taskArns": [stopped_arn]},
        "ecs describe-tasks": {"tasks": [{
            "taskArn": stopped_arn, "stopCode": "EssentialContainerExited",
            "stoppedReason": "Essential container in task exited", "stoppedAt": "2026-10-04T10:43:00.000000+00:00",
            "containers": [{"name": "app", "exitCode": 137, "reason": "OutOfMemoryError: Container killed"}],
        }]},
    })


def test_failed_deployment_with_stopped_tasks(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, failed_answers())
    deployment = by_summary(ctx, "FAILED")[0]
    assert deployment.kind == "incident_time"
    assert deployment.excerpt == "tasks failed to start"
    stopped = by_summary(ctx, "EssentialContainerExited")[0]
    assert stopped.kind == "incident_time"
    assert stopped.time == "2026-10-04T10:43:00Z"
    assert "app" in stopped.summary and "137" in stopped.summary and "OutOfMemoryError" in stopped.summary
    list_tasks = aws.called("ecs", "list-tasks")[0]
    assert list_tasks[list_tasks.index("--desired-status") + 1] == "STOPPED"
    assert "--max-items" in list_tasks
    assert_read_only(ctx, aws, kube)


def test_stopped_task_outside_window_is_dropped(config_data, tmp_path):
    answers = failed_answers()
    answers["ecs describe-tasks"]["tasks"][0]["stoppedAt"] = OUTSIDE
    ctx, _, _ = run(config_data, tmp_path, answers)
    assert by_summary(ctx, "EssentialContainerExited") == []


def test_task_definition_fact_names_environment_variables(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, healthy_answers())
    fact = next(f for f in ctx.evidence.facts if "registry.example.com/checkout:1" in f.summary)
    assert fact.kind == "current"
    assert "LOG_LEVEL" in fact.summary
    assert "cpu 256" in fact.summary and "memory 512" in fact.summary


class RevisionAws(FakeAws):
    """Serves revision 42 and revision 41 of the task definition by the --task-definition value."""

    def __init__(self, answers, current, previous):
        super().__init__(answers)
        self.revisions = {"checkout-api:42": current, "checkout-api:41": previous}

    def __call__(self, argv, timeout):
        if argv[1:3] == ["ecs", "describe-task-definition"]:
            self.answers["ecs describe-task-definition"] = self.revisions[argv[argv.index("--task-definition") + 1]]
        return super().__call__(argv, timeout)


def test_task_definition_diff_by_name_without_values(config_data, tmp_path):
    secret = "pw" + "9" * 8
    old_secret = "old" + "8" * 8
    current = {"taskDefinition": {"family": "checkout-api", "revision": 42, "containerDefinitions": [
        container(image="registry.example.com/checkout:2", cpu=512,
                  env={"LOG_LEVEL": "debug", "DB_PASSWORD": secret, "NEW_FLAG": "on"})]}}
    previous = {"taskDefinition": {"family": "checkout-api", "revision": 41, "containerDefinitions": [
        container(image="registry.example.com/checkout:1", cpu=256,
                  env={"LOG_LEVEL": "info", "DB_PASSWORD": old_secret, "OLD_FLAG": "x"})]}}
    ctx, aws, kube = make_context(config_data, tmp_path, healthy_answers(), collector="ecs")
    fake = RevisionAws(healthy_answers(), current, previous)
    ctx.runner = fake
    COLLECTOR.run(ctx, dict(TARGETS))
    diff = next(f for f in ctx.evidence.facts if "between revision" in f.summary)
    changes = " | ".join(diff.data["changes"])
    assert "between revision 41 and 42" in diff.summary
    assert "checkout:1" in changes and "checkout:2" in changes
    assert "cpu" in changes
    assert "NEW_FLAG" in changes and "OLD_FLAG" in changes and "LOG_LEVEL" in changes
    assert "DB_PASSWORD" in changes and "values hidden" in changes
    document = ctx.evidence.to_json()
    assert secret not in document and old_secret not in document
    assert_read_only(ctx, fake)


def test_no_diff_for_revision_one(config_data, tmp_path):
    answers = healthy_answers(**{"ecs describe-services": service(taskDefinition=TASK_DEF_ARN.replace(":42", ":1"))})
    ctx, aws, _ = run(config_data, tmp_path, answers)
    assert by_summary(ctx, "between revision") == []
    assert len(aws.called("ecs", "describe-task-definition")) == 1


def test_secret_environment_value_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "7" * 10
    answers = healthy_answers(**{"ecs describe-task-definition": task_definition(1, env={"API_TOKEN": secret})})
    ctx, _, _ = run(config_data, tmp_path, answers)
    assert secret not in ctx.evidence.to_json()
    assert "API_TOKEN" in ctx.evidence.to_json()


def test_scaling_activities_inside_window(config_data, tmp_path):
    activities = {"ScalingActivities": [
        {"ActivityId": "a", "Description": "Setting desired count to 4", "Cause": "monitor alarm high",
         "StartTime": "2026-10-04T10:50:00.000000+00:00", "StatusCode": "Successful"},
        {"ActivityId": "b", "Description": "Setting desired count to 2", "Cause": "old",
         "StartTime": OUTSIDE, "StatusCode": "Successful"},
    ]}
    answers = healthy_answers(**{"application-autoscaling describe-scaling-activities": activities})
    ctx, aws, kube = run(config_data, tmp_path, answers)
    facts = by_summary(ctx, "desired count to 4")
    assert len(facts) == 1 and facts[0].kind == "incident_time"
    assert by_summary(ctx, "desired count to 2") == []
    call = aws.called("application-autoscaling", "describe-scaling-activities")[0]
    assert call[call.index("--resource-id") + 1] == "service/checkout/checkout-api"
    assert_read_only(ctx, aws, kube)


def test_metrics_are_added(config_data, tmp_path):
    results = {"MetricDataResults": [
        {"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [96.2]},
        {"Id": "m1", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [50.0]},
    ]}
    ctx, aws, _ = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    assert by_summary(ctx, "CPUUtilization (Average): peak 96.2")
    assert by_summary(ctx, "MemoryUtilization (Average): peak 50 at")
    queries = json.loads(aws.called("cloudwatch", "get-metric-data")[0][
        aws.called("cloudwatch", "get-metric-data")[0].index("--metric-data-queries") + 1])
    dims = queries[0]["MetricStat"]["Metric"]["Dimensions"]
    assert {"Name": "ClusterName", "Value": "checkout"} in dims
    assert {"Name": "ServiceName", "Value": "checkout-api"} in dims


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = failed_answers()
    answers["ecs describe-tasks"] = access_denied("DescribeTasks")
    ctx, aws, kube = run(config_data, tmp_path, answers)
    assert len(ctx.evidence.errors) == 1
    assert ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert by_summary(ctx, "FAILED")
    assert by_summary(ctx, "registry.example.com")
    assert_read_only(ctx, aws, kube)


# helpers

def test_assert_read_only_fails_on_a_write(config_data, tmp_path):
    ctx, aws, kube = make_context(config_data, tmp_path, {})
    # run_aws refuses writes, so call the fake runner directly as a buggy collector bypassing it would.
    aws(["aws", "ecs", "stop-task", "--cluster", "checkout", "--task", "abc", "--profile", "triage-prod-main",
         "--region", "eu-west-1"], 60)
    with pytest.raises(AssertionError, match="stop-task"):
        assert_read_only(ctx, aws, kube)


def test_assert_read_only_fails_on_a_kubectl_write(config_data, tmp_path):
    ctx, aws, kube = make_context(config_data, tmp_path, {})
    kube(["kubectl", "--kubeconfig", str(tmp_path / "config" / "kubeconfig"), "--context", "triage-platform-prod",
          "-n", "web", "delete", "pod", "x"], 60)
    with pytest.raises(AssertionError, match="delete"):
        assert_read_only(ctx, aws, kube)


def test_a_refused_write_through_the_context_is_an_evidence_error(config_data, tmp_path):
    ctx, aws, kube = make_context(config_data, tmp_path, {})
    assert ctx.aws("ecs", "stop-task", ["--task", "abc"]) is None
    assert ctx.evidence.errors[0]["code"] == "RefusedByGuard"
    assert ctx.kubectl("platform-prod", ["delete", "pod", "x"], namespace="web") is None
    assert ctx.evidence.errors[1]["code"] == "RefusedByGuard"
    assert aws.calls == [] and kube.calls == []


def test_assert_read_only_checks_kubectl(config_data, tmp_path):
    ctx, aws, kube = make_context(config_data, tmp_path, {}, kube_answers={"get pods": {"items": []}})
    ctx.kubectl("platform-prod", ["get", "pods"], namespace="web")
    assert_read_only(ctx, aws, kube)
    kube(["kubectl", "--kubeconfig", str(tmp_path / "config" / "kubeconfig"), "--context", "triage-platform-prod",
          "delete", "pod", "x"], 60)
    with pytest.raises(AssertionError, match="delete"):
        assert_read_only(ctx, aws, kube)


def test_fake_kubectl_records_calls_and_keys_by_verb(config_data, tmp_path):
    ctx, _, kube = make_context(config_data, tmp_path, {}, kube_answers={"get pods": {"items": [1]}})
    assert ctx.kubectl_json("platform-prod", ["get", "pods"], namespace="web") == {"items": [1]}
    assert len(kube.calls) == 1


def test_harmless_named_values_never_reach_the_document(config_data, tmp_path):
    dsn_secret = "a1b2" * 8
    hook_secret = "x" * 24
    env = {
        "SENTRY_DSN": f"https://{dsn_secret}@o1.ingest.example.com/1",
        "SLACK_WEBHOOK_URL": f"https://hooks.example.com/services/T0/B0/{hook_secret}",
        "CONN": "postgres://app:" + "pw" + "5" * 8 + "@db.example.com:5432/orders",
    }
    answers = healthy_answers(**{"ecs describe-task-definition": task_definition(1, env=env)})
    ctx, _, _ = run(config_data, tmp_path, answers)
    document = ctx.evidence.to_json()
    for secret in (dsn_secret, hook_secret, "pw" + "5" * 8):
        assert secret not in document
    assert "o1.ingest.example.com" not in document
    # CONN is not a secret name (ruling 1: the redactor decides), so only the URL origin of its value is shown.
    assert "postgres://db.example.com:5432" in document


def test_diff_reports_a_changed_host(config_data, tmp_path):
    current = {"taskDefinition": {"family": "checkout-api", "revision": 42, "containerDefinitions": [
        container(env={"DB_HOST": "https://b.example.com/x"})]}}
    previous = {"taskDefinition": {"family": "checkout-api", "revision": 41, "containerDefinitions": [
        container(env={"DB_HOST": "https://a.example.com/y"})]}}
    ctx, _, _ = make_context(config_data, tmp_path, healthy_answers(), collector="ecs")
    ctx.runner = RevisionAws(healthy_answers(), current, previous)
    COLLECTOR.run(ctx, dict(TARGETS))
    diff = next(f for f in ctx.evidence.facts if "between revision" in f.summary)
    assert "container app: DB_HOST changed from https://a.example.com to https://b.example.com" in diff.data["changes"]


def test_deployment_fact_separates_creation_from_current_state(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, healthy_answers())
    fact = next(f for f in ctx.evidence.facts if f.kind == "incident_time" and "Deployment" in f.summary)
    assert fact.summary == (
        "Deployment of checkout-api:42 was created; state read now: COMPLETED, 2 of 2 tasks running"
    )
    assert fact.time == "2026-10-04T10:42:10Z"


def test_task_level_cpu_and_memory_are_shown_and_diffed(config_data, tmp_path):
    def with_task_level(revision, cpu, memory):
        body = task_definition(revision)
        body["taskDefinition"].update({"cpu": cpu, "memory": memory})
        for entry in body["taskDefinition"]["containerDefinitions"]:
            entry.pop("cpu"), entry.pop("memory")
        return body

    ctx, _, _ = make_context(config_data, tmp_path, healthy_answers(), collector="ecs")
    ctx.runner = RevisionAws(healthy_answers(), with_task_level(42, "1024", "2048"), with_task_level(41, "512", "2048"))
    COLLECTOR.run(ctx, dict(TARGETS))
    current = next(f for f in ctx.evidence.facts if f.kind == "current" and "Task definition" in f.summary)
    assert "task cpu 1024" in current.summary and "task memory 2048" in current.summary
    diff = next(f for f in ctx.evidence.facts if "between revision" in f.summary)
    assert "task cpu 512 -> 1024" in diff.data["changes"]
    assert not any("task memory" in change for change in diff.data["changes"])


def test_no_stopped_tasks_adds_a_note(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, healthy_answers())
    note = next(f for f in ctx.evidence.facts if f.kind == "derived" and "stopped" in f.summary.lower())
    assert "No stopped tasks were found for service checkout-api" in note.summary


def test_previous_revision_comes_from_the_non_primary_deployment(config_data, tmp_path):
    older = TASK_DEF_ARN.replace(":42", ":39")
    svc = service()
    svc["services"][0]["deployments"].append({
        "id": "ecs-svc/0", "status": "ACTIVE", "taskDefinition": older, "desiredCount": 1,
        "runningCount": 1, "pendingCount": 0, "rolloutState": "COMPLETED", "createdAt": "2026-10-04T09:00:00+00:00"})
    current = {"taskDefinition": {"family": "checkout-api", "revision": 42, "containerDefinitions": [container(cpu=512)]}}
    previous = {"taskDefinition": {"family": "checkout-api", "revision": 39, "containerDefinitions": [container(cpu=256)]}}
    answers = healthy_answers(**{"ecs describe-services": svc})
    ctx, _, _ = make_context(config_data, tmp_path, answers, collector="ecs")
    fake = RevisionAws(answers, current, previous)
    fake.revisions["checkout-api:39"] = previous
    ctx.runner = fake
    COLLECTOR.run(ctx, dict(TARGETS))
    diff = next(f for f in ctx.evidence.facts if "between revision" in f.summary)
    assert "between revision 39 and 42" in diff.summary
    assert "container app cpu 256 -> 512" in diff.data["changes"]


def test_diff_summary_is_short_with_a_count_and_the_list_is_in_data(config_data, tmp_path):
    image_old = "111111111111.dkr.ecr.eu-west-1.amazonaws.com/" + "checkout-service/" * 8 + "app:1"
    image_new = image_old[:-1] + "2"
    old_env = {f"SETTING_{n}": f"old-{n}" for n in range(5)}
    new_env = {f"SETTING_{n}": f"new-{n}" for n in range(5)}
    current = {"taskDefinition": {"family": "checkout-api", "revision": 42, "containerDefinitions": [container(image=image_new, env=new_env)]}}
    previous = {"taskDefinition": {"family": "checkout-api", "revision": 41, "containerDefinitions": [container(image=image_old, env=old_env)]}}
    ctx, _, _ = make_context(config_data, tmp_path, healthy_answers(), collector="ecs")
    ctx.runner = RevisionAws(healthy_answers(), current, previous)
    COLLECTOR.run(ctx, dict(TARGETS))
    diff = next(f for f in ctx.evidence.facts if "between revision" in f.summary)
    assert diff.summary == "The task definition changed between revision 41 and 42: 6 changes (image, 5 environment values)"
    assert len(diff.data["changes"]) == 6
    assert "changes_omitted" not in diff.data


def test_diff_list_is_capped(config_data, tmp_path):
    old_env = {f"SETTING_{n}": "a" for n in range(60)}
    new_env = {f"SETTING_{n}": "b" for n in range(60)}
    current = {"taskDefinition": {"family": "checkout-api", "revision": 42, "containerDefinitions": [container(env=new_env)]}}
    previous = {"taskDefinition": {"family": "checkout-api", "revision": 41, "containerDefinitions": [container(env=old_env)]}}
    ctx, _, _ = make_context(config_data, tmp_path, healthy_answers(), collector="ecs")
    ctx.runner = RevisionAws(healthy_answers(), current, previous)
    COLLECTOR.run(ctx, dict(TARGETS))
    diff = next(f for f in ctx.evidence.facts if "between revision" in f.summary)
    assert len(diff.data["changes"]) == 50
    assert diff.data["changes_omitted"] == 10
    assert "60 changes" in diff.summary


def test_no_change_between_revisions(config_data, tmp_path):
    same = task_definition(41)
    ctx, _, _ = make_context(config_data, tmp_path, healthy_answers(), collector="ecs")
    ctx.runner = RevisionAws(healthy_answers(), same, same)
    COLLECTOR.run(ctx, dict(TARGETS))
    diff = next(f for f in ctx.evidence.facts if "between revision" in f.summary)
    assert diff.summary.startswith("The task definition did not change between revision 41 and 42")
    assert diff.data["changes"] == []


# Fix round 4

def _diff_for(config_data, tmp_path, old_container, new_container):
    current = {"taskDefinition": {"family": "checkout-api", "revision": 42, "containerDefinitions": [new_container]}}
    previous = {"taskDefinition": {"family": "checkout-api", "revision": 41, "containerDefinitions": [old_container]}}
    ctx, _, _ = make_context(config_data, tmp_path, healthy_answers(), collector="ecs")
    ctx.runner = RevisionAws(healthy_answers(), current, previous)
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, next(f for f in ctx.evidence.facts if "between revision" in f.summary)


def test_long_change_entry_ends_with_a_cut_marker(config_data, tmp_path):
    brokers = ",".join(f"b-{n}.kafka.example.com:9092" for n in range(1, 15))
    _, diff = _diff_for(config_data, tmp_path, container(env={"KAFKA_BROKERS": brokers}),
                        container(env={"KAFKA_BROKERS": brokers + ",b-99.kafka.example.com:9092"}))
    entry = next(change for change in diff.data["changes"] if "KAFKA_BROKERS" in change)
    assert len(entry) == 300 and entry.endswith("… [change cut]")


def test_digest_pinned_image_change_is_never_cut(config_data, tmp_path):
    repo = "111111111111.dkr.ecr.eu-west-1.amazonaws.com/checkout-service"
    old_image = f"{repo}:1.4.1@sha256:" + "a" * 64
    new_image = f"{repo}:1.4.2@sha256:" + "b" * 64
    _, diff = _diff_for(config_data, tmp_path, container(image=old_image), container(image=new_image))
    assert f"container app image {old_image} -> {new_image}" in diff.data["changes"]


def test_very_long_image_references_are_kept_whole(config_data, tmp_path):
    repo = "111111111111.dkr.ecr.eu-west-1.amazonaws.com/" + "checkout-service/" * 18 + "app"
    old_image = f"{repo}:1@sha256:" + "a" * 64
    new_image = f"{repo}:2@sha256:" + "b" * 64
    assert 400 < len(new_image) < 500
    _, diff = _diff_for(config_data, tmp_path, container(image=old_image), container(image=new_image))
    joined = "\n".join(diff.data["changes"])
    assert old_image in joined and new_image in joined
    assert "1 change (image)" in diff.summary


def test_c1_secret_never_reaches_the_document(config_data, tmp_path):
    secret = "sun" + "flower"
    ctx, diff = _diff_for(config_data, tmp_path, container(env={"DB_PASS1": secret}),
                          container(env={"DB_PASS1": secret + "Q"}))
    assert "container app: DB_PASS1 changed (values hidden)" in diff.data["changes"]
    current = next(f for f in ctx.evidence.facts if f.kind == "current" and "Task definition" in f.summary)
    assert current.data["environment"]["DB_PASS1"].startswith(("<hidden", "<SECRET"))
    assert secret not in ctx.evidence.to_json()



def test_an_image_reference_of_577_characters_is_recoverable_whole(config_data, tmp_path):
    repo = "111111111111.dkr.ecr.eu-west-1.amazonaws.com/" + "checkout-service/" * 26 + "app"
    repo += "x" * (577 - len(f"{repo}:2@sha256:" + "b" * 64))
    old_image = f"{repo}:1@sha256:" + "a" * 64
    new_image = f"{repo}:2@sha256:" + "b" * 64
    assert len(new_image) == 577
    _, diff = _diff_for(config_data, tmp_path, container(image=old_image), container(image=new_image))
    assert all(len(line) <= 500 for line in diff.data["changes"])
    was = [line for line in diff.data["changes"] if " image was" in line]
    now = [line for line in diff.data["changes"] if " image is now" in line]
    assert "".join(line.partition(": ")[2] for line in was) == old_image
    assert "".join(line.partition(": ")[2] for line in now) == new_image
    assert "part 1 of 2" in was[0] and "part 2 of 2" in was[1]
