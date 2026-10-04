import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.eks import COLLECTOR

CLUSTER = "platform-prod"
IN_WINDOW = "2026-10-04T10:42:10Z"
OUTSIDE = "2026-10-04T07:00:00Z"


def cluster_reply(status="ACTIVE", issues=()):
    return {"cluster": {
        "name": CLUSTER, "version": "1.30", "status": status,
        "resourcesVpcConfig": {"endpointPublicAccess": True, "endpointPrivateAccess": False},
        "health": {"issues": list(issues)}}}


def nodegroup_reply(status="ACTIVE", issues=()):
    return {"nodegroup": {
        "nodegroupName": "workers", "status": status,
        "scalingConfig": {"minSize": 2, "maxSize": 6, "desiredSize": 3},
        "health": {"issues": list(issues)}}}


def addon_reply(name="vpc-cni", status="ACTIVE", issues=()):
    return {"addon": {"addonName": name, "status": status, "health": {"issues": list(issues)}}}


def update_reply(created=IN_WINDOW, status="Failed", errors=()):
    return {"update": {"id": "u1", "status": status, "type": "VersionUpdate", "createdAt": created,
                       "errors": list(errors)}}


def aws_answers(**extra):
    base = {
        "eks describe-cluster": cluster_reply(),
        "eks list-nodegroups": {"nodegroups": ["workers"]},
        "eks describe-nodegroup": nodegroup_reply(),
        "eks list-addons": {"addons": ["vpc-cni"]},
        "eks describe-addon": addon_reply(),
        "eks list-updates": {"updateIds": []},
        "eks describe-update": update_reply(),
    }
    base.update(extra)
    return base


def pod(name="payments-api-abc", phase="Running", ready=True, restarts=0, waiting=None, terminated=None):
    state = {"running": {"startedAt": OUTSIDE}}
    if waiting:
        state = {"waiting": waiting}
    status = {"name": "app", "ready": ready, "restartCount": restarts, "state": state}
    if terminated:
        status["lastState"] = {"terminated": terminated}
    return {"metadata": {"name": name}, "status": {"phase": phase, "containerStatuses": [status]}}


def event(reason="BackOff", message="Back-off restarting failed container", when=IN_WINDOW, kind="Warning",
          obj="payments-api-abc"):
    return {"type": kind, "reason": reason, "message": message, "lastTimestamp": when, "count": 7,
            "involvedObject": {"kind": "Pod", "name": obj}}


def deployment(desired=3, ready=3, updated=3, conditions=()):
    return {"spec": {"replicas": desired}, "status": {
        "replicas": desired, "readyReplicas": ready, "updatedReplicas": updated, "conditions": list(conditions)}}


HISTORY = "deployment.apps/payments-api\nREVISION  CHANGE-CAUSE\n1         <none>\n2         <none>\n3         <none>\n"


def kube_answers(**extra):
    base = {"get pods": {"items": [pod()]}, "get events": {"items": []},
            "get deployment/payments-api": deployment(), "rollout history": HISTORY, "logs payments-api-abc": "line"}
    base.update(extra)
    return base


def run(config_data, tmp_path, aws=None, kube=None, targets=None):
    ctx, fake_aws, fake_kube = make_context(
        config_data, tmp_path, aws or aws_answers(), collector="eks", kube_answers=kube or kube_answers())
    COLLECTOR.run(ctx, {"cluster": CLUSTER, **(targets or {})})
    return ctx, fake_aws, fake_kube


def with_text(ctx, text):
    return [f for f in ctx.evidence.facts if text in f.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "eks"
    assert COLLECTOR.required == ("cluster",)
    assert COLLECTOR.optional == ("namespace", "workloads")


def test_healthy_cluster_aws_side_only(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path)
    cluster = ctx.evidence.facts[0]
    assert cluster.kind == "current" and cluster.resource == f"cluster/{CLUSTER}"
    for part in ("1.30", "ACTIVE", "public access true", "private access false", "no health issues"):
        assert part in cluster.summary
    group = with_text(ctx, "Nodegroup workers")[0]
    assert "min 2" in group.summary and "max 6" in group.summary and "desired 3" in group.summary
    assert with_text(ctx, "Add-on") == []
    assert kube.calls == []
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


def test_cluster_and_nodegroup_health_issues(config_data, tmp_path):
    issue = {"code": "NodeCreationFailure", "message": "Instances failed to join the cluster"}
    ctx, _, _ = run(config_data, tmp_path, aws_answers(**{
        "eks describe-cluster": cluster_reply(status="DEGRADED", issues=[{"code": "ConfigurationConflict", "message": "x"}]),
        "eks describe-nodegroup": nodegroup_reply(status="DEGRADED", issues=[issue]),
    }))
    assert "DEGRADED" in ctx.evidence.facts[0].summary and "ConfigurationConflict" in ctx.evidence.facts[0].summary
    group = with_text(ctx, "Nodegroup workers")[0]
    assert "NodeCreationFailure" in group.summary and "failed to join" in group.summary


def test_only_unhealthy_addons_are_reported(config_data, tmp_path):
    issue = {"code": "InsufficientNumberOfReplicas", "message": "replicas are not available"}
    ctx, aws, _ = run(config_data, tmp_path, aws_answers(**{
        "eks list-addons": {"addons": ["vpc-cni"]},
        "eks describe-addon": addon_reply(status="DEGRADED", issues=[issue])}))
    addon = with_text(ctx, "Add-on vpc-cni")[0]
    assert "DEGRADED" in addon.summary and "InsufficientNumberOfReplicas" in addon.summary


def test_updates_inside_the_window(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, aws_answers(**{
        "eks list-updates": {"updateIds": ["u1"]},
        "eks describe-update": update_reply(errors=[{"errorCode": "NodeCreationFailure", "errorMessage": "no capacity"}]),
    }))
    update = with_text(ctx, "Update u1")[0]
    assert update.kind == "incident_time" and update.time == IN_WINDOW
    assert "VersionUpdate" in update.summary and "Failed" in update.summary and "no capacity" in update.summary
    call = aws.called("eks", "list-updates")[0]
    assert call[call.index("--max-items") + 1] == "5"
    assert_read_only(ctx, aws, kube)


def test_update_outside_the_window_is_dropped(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, aws_answers(**{
        "eks list-updates": {"updateIds": ["u1"]}, "eks describe-update": update_reply(created=OUTSIDE)}))
    assert with_text(ctx, "Update u1") == []


def test_missing_cluster(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, aws_answers(**{
        "eks describe-cluster": (254, "An error occurred (ResourceNotFoundException) when calling: No cluster found")}),
        targets={"namespace": "web"})
    assert len(ctx.evidence.facts) == 1 and "not found" in ctx.evidence.facts[0].summary
    assert ctx.evidence.errors == []
    assert aws.called("eks", "list-nodegroups") == [] and kube.calls == []


def test_unknown_cluster_is_an_error_not_a_crash(config_data, tmp_path):
    ctx, fake_aws, fake_kube = make_context(config_data, tmp_path, aws_answers(), collector="eks")
    COLLECTOR.run(ctx, {"cluster": "no-such-cluster"})
    assert ctx.evidence.errors[0]["code"] == "UnknownCluster"
    assert fake_aws.calls == []


def test_account_mismatch_stops_the_run(config_data, tmp_path):
    ctx, fake_aws, fake_kube = make_context(config_data, tmp_path, aws_answers(), collector="eks", account="staging")
    COLLECTOR.run(ctx, {"cluster": CLUSTER, "namespace": "web"})
    assert ctx.evidence.errors[0]["code"] == "AccountMismatch"
    assert "prod-main" in ctx.evidence.errors[0]["message"] and "staging" in ctx.evidence.errors[0]["message"]
    assert fake_aws.calls == [] and fake_kube.calls == []


def test_the_cluster_region_is_used(config_data, tmp_path):
    config_data["eks_clusters"][CLUSTER]["region"] = "us-east-1"
    ctx, aws, _ = run(config_data, tmp_path)
    call = aws.called("eks", "describe-cluster")[0]
    assert call[call.index("--region") + 1] == "us-east-1"


def test_unhealthy_pods_with_reasons_and_logs(config_data, tmp_path):
    crashing = pod(restarts=5, ready=False, waiting={"reason": "CrashLoopBackOff", "message": "back-off 5m restarting"},
                   terminated={"reason": "OOMKilled", "exitCode": 137})
    kube = kube_answers(**{"get pods": {"items": [pod(name="healthy-1"), crashing, pod(name="done", phase="Succeeded", ready=False)]},
                           "logs payments-api-abc": "starting\nfatal: cannot connect to db"})
    ctx, aws, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    facts = with_text(ctx, "Pod payments-api-abc")
    assert len(facts) == 1 and facts[0].kind == "current"
    for part in ("Running", "5 restarts", "CrashLoopBackOff", "OOMKilled", "137"):
        assert part in facts[0].summary
    assert "back-off 5m restarting" in facts[0].excerpt
    assert with_text(ctx, "Pod healthy-1") == [] and with_text(ctx, "Pod done") == []
    logs = [f for f in ctx.evidence.facts if "fatal: cannot connect" in f.excerpt]
    assert len(logs) == 2 and any("previous" in f.summary for f in logs)
    log_calls = [c for c in fake_kube.calls if "logs" in c]
    assert len(log_calls) == 2
    for call in log_calls:
        assert call[call.index("--tail") + 1] == "50" and call[call.index("--since") + 1] == "120m"
    assert sum("--previous" in c for c in log_calls) == 1
    assert_read_only(ctx, aws, fake_kube)


def test_log_without_restarts_has_no_previous_call(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [pod(ready=False, phase="Pending")]}})
    ctx, _, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    assert not any("--previous" in c for c in fake_kube.calls)
    assert any("logs" in c for c in fake_kube.calls)


def test_warning_events_inside_the_window(config_data, tmp_path):
    events = {"items": [event(), event(reason="Old", when=OUTSIDE), event(reason="Pulled", kind="Normal")]}
    ctx, aws, fake_kube = run(config_data, tmp_path, kube=kube_answers(**{"get events": events}), targets={"namespace": "web"})
    found = [f for f in ctx.evidence.facts if f.kind == "incident_time" and "BackOff" in f.summary]
    assert len(found) == 1
    assert found[0].time == IN_WINDOW and "Pod/payments-api-abc" in found[0].summary and "7 times" in found[0].summary
    assert "Back-off restarting failed container" in found[0].excerpt
    assert with_text(ctx, "Old") == [] and with_text(ctx, "Pulled") == []
    call = next(c for c in fake_kube.calls if "events" in c)
    assert "--sort-by=.lastTimestamp" in call
    assert_read_only(ctx, aws, fake_kube)


def test_workload_status_and_rollout_history(config_data, tmp_path):
    kube = kube_answers(**{"get deployment/payments-api": deployment(desired=3, ready=1, updated=2, conditions=[
        {"type": "Available", "status": "False", "reason": "MinimumReplicasUnavailable"},
        {"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}])})
    ctx, aws, fake_kube = run(config_data, tmp_path, kube=kube,
                              targets={"namespace": "web", "workloads": "deployment/payments-api"})
    state = with_text(ctx, "deployment/payments-api")[0]
    for part in ("desired 3", "ready 1", "updated 2", "ProgressDeadlineExceeded"):
        assert part in state.summary
    history = with_text(ctx, "Rollout history")[0]
    assert "3 revisions" in history.summary and "latest revision 3" in history.summary
    assert_read_only(ctx, aws, fake_kube)


def test_bad_workload_names_are_skipped_with_an_error(config_data, tmp_path):
    ctx, _, fake_kube = run(config_data, tmp_path, targets={"namespace": "web", "workloads": "secret/db,deployment"})
    assert [e["code"] for e in ctx.evidence.errors] == ["InvalidTarget", "InvalidTarget"]
    assert not any("secret/db" in " ".join(c) for c in fake_kube.calls)


def test_kubectl_failure_is_one_error_and_the_rest_continues(config_data, tmp_path):
    kube = kube_answers(**{"get pods": (1, "forbidden: cannot list pods")})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    assert [e["code"] for e in ctx.evidence.errors] == ["KubectlError"]
    assert with_text(ctx, "Nodegroup workers")


def test_access_denied_on_one_aws_call_keeps_the_rest(config_data, tmp_path):
    ctx, aws, fake_kube = run(config_data, tmp_path, aws_answers(**{
        "eks list-nodegroups": access_denied("ListNodegroups")}), targets={"namespace": "web"})
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert ctx.evidence.facts[0].kind == "current" and "1.30" in ctx.evidence.facts[0].summary
    assert_read_only(ctx, aws, fake_kube)


def test_pod_log_secrets_never_reach_the_document(config_data, tmp_path):
    password = "pw" + "3" * 10
    key = "AKIA" + "D" * 16
    message = f"password={password} failed"
    crashing = pod(ready=False, restarts=1, waiting={"reason": "Error", "message": f"token={password}"})
    kube = kube_answers(**{"get pods": {"items": [crashing]}, "logs payments-api-abc": f"{message} key {key}",
                           "get events": {"items": [event(message=f"password={password}")]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    document = ctx.evidence.to_json()
    assert password not in document and key not in document
    assert "failed" in document


def test_log_excerpt_is_the_last_500_characters(config_data, tmp_path):
    log = "a" * 3000 + "THE-END"
    kube = kube_answers(**{"get pods": {"items": [pod(ready=False, phase="Pending")]}, "logs payments-api-abc": log})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    excerpt = next(f.excerpt for f in ctx.evidence.facts if f.excerpt.endswith("THE-END"))
    assert len(excerpt) <= 500


def test_pod_event_and_log_caps(config_data, tmp_path):
    pods = [pod(name=f"p-{n:02d}", ready=False, phase="Pending") for n in range(40)]
    events = [event(reason=f"Reason{n}", when=f"2026-10-04T10:{n % 60:02d}:00Z") for n in range(50)]
    kube = kube_answers(**{"get pods": {"items": pods}, "get events": {"items": events}})
    ctx, _, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    assert len(with_text(ctx, "Pod p-")) == 30
    assert len(with_text(ctx, "Warning event")) == 40
    assert len([c for c in fake_kube.calls if "logs" in c]) == 3
    assert with_text(ctx, "10 more pods")


def test_nodegroup_cap(config_data, tmp_path):
    names = [f"ng-{n}" for n in range(12)]
    ctx, aws, _ = run(config_data, tmp_path, aws_answers(**{"eks list-nodegroups": {"nodegroups": names}}))
    assert len(aws.called("eks", "describe-nodegroup")) == 10
    assert with_text(ctx, "12 nodegroups")
