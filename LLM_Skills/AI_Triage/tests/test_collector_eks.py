import json

from fakes import access_denied
from helpers import FakeKubectl, assert_read_only, make_context
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


def container(name="app", ready=True, restarts=0, state=None, last=None):
    body = {"name": name, "ready": ready, "restartCount": restarts, "state": state or {"running": {"startedAt": OUTSIDE}}}
    if last:
        body["lastState"] = {"terminated": last}
    return body


def pod(name="payments-api-abc", phase="Running", ready=True, restarts=0, waiting=None, terminated=None,
        containers=None):
    state = {"waiting": waiting} if waiting else None
    statuses = containers if containers is not None else [
        container(ready=ready, restarts=restarts, state=state, last=terminated)]
    return {"metadata": {"name": name}, "status": {"phase": phase, "containerStatuses": statuses}}


def event(reason="BackOff", message="Back-off restarting failed container", when=IN_WINDOW, kind="Warning",
          obj="payments-api-abc", first=None):
    return {"type": kind, "reason": reason, "message": message, "lastTimestamp": when, "count": 7,
            "firstTimestamp": first or when, "involvedObject": {"kind": "Pod", "name": obj}}


def deployment(desired=3, ready=3, updated=3, conditions=()):
    return {"spec": {"replicas": desired}, "status": {
        "replicas": desired, "readyReplicas": ready, "updatedReplicas": updated, "conditions": list(conditions)}}


HISTORY = "deployment.apps/payments-api\nREVISION  CHANGE-CAUSE\n1         <none>\n2         <none>\n3         <none>\n"


def kube_answers(**extra):
    base = {"get pods": {"items": [pod()]}, "get events": {"items": []},
            "get deployment/payments-api": deployment(), "rollout history": HISTORY}
    base.update(extra)
    return base


class LogKube(FakeKubectl):
    """Answers kubectl logs by (pod, container, previous); every other call as FakeKubectl does."""

    def __init__(self, answers, logs):
        super().__init__(answers)
        self.logs = logs

    def __call__(self, argv, timeout):
        if "logs" not in argv:
            return super().__call__(argv, timeout)
        self.calls.append(argv)
        pod_name = argv[argv.index("logs") + 1]
        container_name = argv[argv.index("-c") + 1] if "-c" in argv else None
        answer = self.logs.get((pod_name, container_name, "--previous" in argv), "")
        if isinstance(answer, tuple):
            return answer[0], "", answer[1]
        return 0, answer, ""


def run(config_data, tmp_path, aws=None, kube=None, targets=None, logs=None):
    ctx, fake_aws, _ = make_context(
        config_data, tmp_path, aws or aws_answers(), collector="eks", kube_answers=kube or kube_answers())
    fake_kube = LogKube(kube or kube_answers(), logs or {})
    ctx.kube_runner = fake_kube
    COLLECTOR.run(ctx, {"cluster": CLUSTER, **(targets or {})})
    return ctx, fake_aws, fake_kube


def log_calls(fake_kube):
    return [c for c in fake_kube.calls if "logs" in c]


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


def test_account_mismatch_is_a_fact_and_no_call_is_made(config_data, tmp_path):
    ctx, fake_aws, fake_kube = make_context(config_data, tmp_path, aws_answers(), collector="eks", account="staging")
    COLLECTOR.run(ctx, {"cluster": CLUSTER, "namespace": "web"})
    assert len(ctx.evidence.facts) == 1 and ctx.evidence.facts[0].kind == "derived"
    summary = ctx.evidence.facts[0].summary
    assert "prod-main" in summary and "staging" in summary and CLUSTER in summary
    assert fake_aws.calls == [] and fake_kube.calls == []

def test_the_cluster_region_is_used(config_data, tmp_path):
    config_data["eks_clusters"][CLUSTER]["region"] = "us-east-1"
    ctx, aws, _ = run(config_data, tmp_path)
    call = aws.called("eks", "describe-cluster")[0]
    assert call[call.index("--region") + 1] == "us-east-1"


IN_LOG = ["2026-10-04T10:30:00.123456789Z starting", "2026-10-04T11:00:00.5Z fatal: cannot connect to db"]
BEFORE_LOG = "2026-10-04T09:59:00.000000001Z before the incident"
AFTER_LOG = "2026-10-04T12:30:00.000000000Z after the incident"
LOG_TEXT = "\n".join([BEFORE_LOG, *IN_LOG, AFTER_LOG])


def crashing_pod():
    return pod(restarts=5, ready=False, waiting={"reason": "CrashLoopBackOff", "message": "back-off 5m restarting"},
               terminated={"reason": "OOMKilled", "exitCode": 137})


def test_unhealthy_pod_summary(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [pod(name="healthy-1"), crashing_pod(),
                                                   pod(name="done", phase="Succeeded", ready=False)]}})
    ctx, aws, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    facts = with_text(ctx, "Pod payments-api-abc is")
    assert len(facts) == 1 and facts[0].kind == "current"
    for part in ("Running", "5 restarts", "CrashLoopBackOff", "OOMKilled", "137"):
        assert part in facts[0].summary
    assert "back-off 5m restarting" in facts[0].excerpt
    assert with_text(ctx, "Pod healthy-1") == [] and with_text(ctx, "Pod done") == []
    assert_read_only(ctx, aws, fake_kube)


def test_logs_cover_the_incident_window_not_the_last_minutes(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    logs = {("payments-api-abc", "app", True): LOG_TEXT}
    ctx, aws, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"}, logs=logs)
    call = log_calls(fake_kube)[0]
    assert "--since-time=2026-10-04T10:00:00Z" in call
    assert "--timestamps" in call and "--since" not in call
    assert "--limit-bytes=200000" in call
    assert "--tail" not in call
    fact = next(f for f in ctx.evidence.facts if "fatal: cannot connect" in f.excerpt)
    assert "before the incident" not in fact.excerpt and "after the incident" not in fact.excerpt
    assert "2026-10-04T10:30:00Z" in fact.summary and "2026-10-04T11:00:00Z" in fact.summary
    assert "app" in fact.summary
    assert_read_only(ctx, aws, fake_kube)


def test_no_log_line_inside_the_window_is_a_derived_fact(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    logs = {("payments-api-abc", "app", True): "\n".join([BEFORE_LOG, AFTER_LOG])}
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"}, logs=logs)
    derived = [f for f in ctx.evidence.facts if f.kind == "derived" and "no log line" in f.summary.lower()]
    assert len(derived) == 1 and "app" in derived[0].summary
    assert not any("incident" in f.excerpt for f in ctx.evidence.facts)


def test_the_first_twenty_lines_and_the_error_lines_are_kept(config_data, tmp_path):
    lines = [f"2026-10-04T10:{n // 60:02d}:{n % 60:02d}.000000000Z line-{n:03d}" for n in range(80)]
    lines[40] = lines[40] + " ERROR something broke"
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "\n".join(lines)})
    fact = next(f for f in ctx.evidence.facts if "ERROR something broke" in f.excerpt)
    kept = fact.data["lines"]
    assert len(kept) == 21 and "line-000" in kept[0] and "line-019" in kept[19] and "ERROR something broke" in kept[20]
    assert "line-021" not in " ".join(kept)
    for part in ("80 lines read", "80 inside the window", "1 error-looking", "21 kept"):
        assert part in fact.summary
    assert "ERROR something broke" in fact.summary


def test_current_and_previous_logs_for_a_running_container_that_restarted(config_data, tmp_path):
    running = pod(containers=[container(ready=False, restarts=2)])
    kube = kube_answers(**{"get pods": {"items": [running]}})
    _, _, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    calls = log_calls(fake_kube)
    assert len(calls) == 2 and sum("--previous" in c for c in calls) == 1
    assert all(c[c.index("-c") + 1] == "app" for c in calls)


def test_logs_come_from_the_failing_container_not_the_sidecar(config_data, tmp_path):
    sidecar_first = pod(containers=[
        container(name="proxy"),
        container(name="app", ready=False, restarts=3, state={"waiting": {"reason": "CrashLoopBackOff"}},
                  last={"reason": "Error", "exitCode": 1}),
    ])
    kube = kube_answers(**{"get pods": {"items": [sidecar_first]}})
    ctx, aws, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    calls = log_calls(fake_kube)
    assert calls and all(c[c.index("-c") + 1] == "app" for c in calls)
    assert all("--previous" in c for c in calls)
    assert_read_only(ctx, aws, fake_kube)


def test_no_previous_logs_for_a_container_that_never_restarted(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [pod(containers=[container(ready=False, restarts=0)])]}})
    _, _, fake_kube = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"})
    assert len(log_calls(fake_kube)) == 1 and not any("--previous" in c for c in log_calls(fake_kube))


def test_no_logs_for_a_container_that_never_started(config_data, tmp_path):
    waiting = pod(phase="Pending", containers=[container(ready=False, state={"waiting": {"reason": "ImagePullBackOff"}})])
    ctx, _, fake_kube = run(config_data, tmp_path, kube=kube_answers(**{"get pods": {"items": [waiting]}}),
                            targets={"namespace": "web"})
    assert log_calls(fake_kube) == [] and ctx.evidence.errors == []
    assert with_text(ctx, "ImagePullBackOff")


def test_at_most_two_containers_per_pod_are_read(config_data, tmp_path):
    three = pod(containers=[container(name=n, ready=False) for n in ("a", "b", "c")])
    _, _, fake_kube = run(config_data, tmp_path, kube=kube_answers(**{"get pods": {"items": [three]}}),
                          targets={"namespace": "web"})
    assert {c[c.index("-c") + 1] for c in log_calls(fake_kube)} == {"a", "b"}



def test_warning_events_inside_the_window(config_data, tmp_path):
    events = {"items": [event(), event(reason="Old", when=OUTSIDE), event(reason="Pulled", kind="Normal")]}
    ctx, aws, fake_kube = run(config_data, tmp_path, kube=kube_answers(**{"get events": events}), targets={"namespace": "web"})
    found = [f for f in ctx.evidence.facts if f.kind == "incident_time" and "BackOff" in f.summary]
    assert len(found) == 1
    assert found[0].time == IN_WINDOW and "Pod/payments-api-abc" in found[0].summary and "7 times" in found[0].summary
    assert "Back-off restarting failed container" in found[0].excerpt
    assert with_text(ctx, "Old") == [] and with_text(ctx, "Pulled") == []
    assert_read_only(ctx, aws, fake_kube)


def events_found(config_data, tmp_path, *events):
    ctx, _, _ = run(config_data, tmp_path, kube=kube_answers(**{"get events": {"items": list(events)}}),
                    targets={"namespace": "web"})
    return [f for f in ctx.evidence.facts if "Warning event" in f.summary]


def test_recurring_event_that_began_in_the_window_and_still_fires_is_kept(config_data, tmp_path):
    found = events_found(config_data, tmp_path, event(first="2026-10-04T10:30:00Z", when="2026-10-04T13:00:00Z"))
    assert len(found) == 1 and found[0].time == "2026-10-04T10:30:00Z"
    assert "2026-10-04T10:30:00Z" in found[0].summary and "2026-10-04T13:00:00Z" in found[0].summary


def test_event_that_spans_the_whole_window_is_kept(config_data, tmp_path):
    assert len(events_found(config_data, tmp_path, event(first="2026-10-04T08:00:00Z", when="2026-10-04T13:00:00Z"))) == 1


def test_events_entirely_outside_the_window_are_dropped(config_data, tmp_path):
    assert events_found(config_data, tmp_path,
                        event(first="2026-10-04T07:00:00Z", when="2026-10-04T08:00:00Z"),
                        event(first="2026-10-04T13:00:00Z", when="2026-10-04T14:00:00Z")) == []

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
    crashing = pod(ready=False, restarts=1, waiting={"reason": "Error", "message": f"token={password}"})
    kube = kube_answers(**{"get pods": {"items": [crashing]},
                           "get events": {"items": [event(message=f"password={password}")]}})
    logs = {("payments-api-abc", "app", True): f"2026-10-04T10:30:00Z password={password} failed key {key}"}
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"}, logs=logs)
    document = ctx.evidence.to_json()
    assert password not in document and key not in document
    assert "failed" in document

def test_long_lines_are_cut_at_300_characters_with_a_marker(config_data, tmp_path):
    lines = [f"2026-10-04T10:30:{n:02d}.000000000Z {'a' * 400}" for n in range(3)]
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "\n".join(lines)})
    fact = next(f for f in ctx.evidence.facts if "lines" in f.data)
    assert all(len(line) <= 300 and line.endswith("…") for line in fact.data["lines"])
    assert fact.excerpt == fact.data["lines"][0].rstrip("…") or fact.excerpt.startswith("2026-10-04T10:30:00")


def test_updates_are_listed_twenty_at_a_time(config_data, tmp_path):
    _, aws, _ = run(config_data, tmp_path)
    call = aws.called("eks", "list-updates")[0]
    assert call[call.index("--max-items") + 1] == "20"


def test_only_updates_created_in_the_window_are_kept_among_many(config_data, tmp_path):
    ids = [f"u{n}" for n in range(20)]
    ctx, aws, _ = run(config_data, tmp_path, aws_answers(**{
        "eks list-updates": {"updateIds": ids}, "eks describe-update": update_reply()}))
    assert len(aws.called("eks", "describe-update")) == 20
    assert len(with_text(ctx, "Update u1")) == 20


def test_at_most_ten_workloads_are_read(config_data, tmp_path):
    names = ",".join(f"deployment/app-{n}" for n in range(12))
    ctx, _, fake_kube = run(config_data, tmp_path, targets={"namespace": "web", "workloads": names})
    reads = [c for c in fake_kube.calls if "get" in c and any(a.startswith("deployment/") for a in c)]
    assert len(reads) == 10
    derived = with_text(ctx, "12 workloads")
    assert len(derived) == 1 and derived[0].kind == "derived"


def test_access_denied_on_the_cluster_is_not_reported_as_not_found(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, aws_answers(**{"eks describe-cluster": access_denied("DescribeCluster")}))
    assert ctx.evidence.facts == [] and ctx.evidence.errors[0]["code"] == "AccessDeniedException"


def test_a_busy_pod_that_hits_the_byte_limit_is_reported_as_cut(config_data, tmp_path):
    first = "2026-10-04T10:00:01.000000000Z onset of the problem"
    filler = "2026-10-04T12:30:00.000000000Z " + "x" * 200000
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): first + "\n" + filler})
    assert any("onset of the problem" in f.excerpt for f in ctx.evidence.facts)
    cut = [f for f in ctx.evidence.facts if f.kind == "derived" and "200000 bytes" in f.summary]
    assert len(cut) == 1 and "later lines were not read" in cut[0].summary


def test_a_cut_log_with_nothing_inside_the_window_never_claims_it_is_empty(config_data, tmp_path):
    filler = "2026-10-04T12:30:00.000000000Z " + "x" * 200000
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): filler})
    assert not any("falls inside" in f.summary for f in ctx.evidence.facts)
    assert len([f for f in ctx.evidence.facts if "200000 bytes" in f.summary]) == 1


def test_a_quiet_pod_under_the_limit_may_say_no_line_falls_inside_the_window(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): AFTER_LOG})
    assert len([f for f in ctx.evidence.facts if "falls inside" in f.summary]) == 1
    assert not any("200000 bytes" in f.summary for f in ctx.evidence.facts)


def test_an_incident_that_ended_hours_ago_still_gets_its_lines(config_data, tmp_path):
    # The window is 10:00-12:00; the log also holds many hours of later lines, which are dropped in code.
    later = [f"2026-10-04T{h:02d}:00:00.000000000Z later-{h}" for h in range(13, 24)]
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "\n".join([*IN_LOG, *later])})
    fact = next(f for f in ctx.evidence.facts if "fatal: cannot connect" in f.excerpt)
    assert "later-" not in fact.excerpt


def test_event_count_is_never_one_times(config_data, tmp_path):
    single = event()
    single["count"] = 1
    series = event(reason="Unhealthy")
    series["count"] = None
    series["series"] = {"count": 12, "lastObservedTime": IN_WINDOW}
    ctx, _, _ = run(config_data, tmp_path, kube=kube_answers(**{"get events": {"items": [single, series]}}),
                    targets={"namespace": "web"})
    texts = [f.summary for f in ctx.evidence.facts if "Warning event" in f.summary]
    assert not any("1 times" in t for t in texts)
    assert any("BackOff" in t and "once" in t for t in texts)
    assert any("Unhealthy" in t and "12 times" in t for t in texts)


def test_an_early_error_in_a_cut_answer_is_kept(config_data, tmp_path):
    error = "2026-10-04T10:00:04.000000000Z ERROR db timeout"
    infos = [f"2026-10-04T10:{1 + n // 60:02d}:{n % 60:02d}.000000000Z info " + "x" * 180 for n in range(1100)]
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "\n".join(["2026-10-04T10:00:00.000000000Z start", error, *infos])})
    fact = next(f for f in ctx.evidence.facts if "lines" in f.data)
    assert fact.excerpt == error
    assert error in fact.data["lines"] and len(fact.data["lines"]) <= 50
    assert any("200000 bytes" in f.summary for f in ctx.evidence.facts)


def test_excerpt_is_the_first_in_window_line_when_nothing_looks_like_an_error(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "\n".join(["2026-10-04T10:30:00Z hello", "2026-10-04T10:31:00Z world"])})
    fact = next(f for f in ctx.evidence.facts if "lines" in f.data)
    assert fact.excerpt == "2026-10-04T10:30:00Z hello" and "0 error-looking" in fact.summary


def test_error_words_match_in_any_case_and_secrets_are_redacted_in_data(config_data, tmp_path):
    password = "pw" + "6" * 10
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    text = f"2026-10-04T10:30:00Z Connection refused password={password}"
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "2026-10-04T10:29:00Z ok\n" + text})
    fact = next(f for f in ctx.evidence.facts if "lines" in f.data)
    assert "1 error-looking" in fact.summary and "Connection refused" in fact.excerpt
    assert password not in ctx.evidence.to_json()


def test_an_answer_ending_in_a_replacement_character_keeps_the_last_line_as_text(config_data, tmp_path):
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    last = "2026-10-04T10:40:00Z cut mid-character \ufffd"
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "2026-10-04T10:30:00Z first\n" + last})
    fact = next(f for f in ctx.evidence.facts if "lines" in f.data)
    assert fact.data["lines"][-1] == last


def log_fact(config_data, tmp_path, lines):
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): "\n".join(lines) + "\n"})
    return ctx, next(f for f in ctx.evidence.facts if "lines" in f.data)


def stamp(n):
    return f"2026-10-04T10:{n // 60:02d}:{n % 60:02d}.000000000Z"


def test_repeated_warnings_count_once_and_never_crowd_out_a_fatal_line(config_data, tmp_path):
    lines = [f"{stamp(n)} info {n}" for n in range(20)]
    lines += [f"{stamp(20 + n)} WARN retrying attempt {n}" for n in range(45)]
    lines.append(f"{stamp(70)} FATAL out of memory")
    _, fact = log_fact(config_data, tmp_path, lines)
    kept = fact.data["lines"]
    assert any("FATAL out of memory" in line for line in kept)
    warns = [line for line in kept if "WARN retrying" in line]
    assert len(warns) == 1 and "repeated 45 times" in warns[0]
    assert "not kept" not in fact.summary
    assert "FATAL out of memory" in fact.excerpt


def test_strong_lines_come_before_soft_ones_and_the_summary_counts_what_was_left_out(config_data, tmp_path):
    words = [chr(ord("a") + n % 26) * (1 + n // 26) for n in range(40)]
    lines = [f"{stamp(n)} WARN slow call to {word}" for n, word in enumerate(words)]
    lines.append(f"{stamp(50)} panic: nil map")
    lines.append(f"{stamp(51)} Traceback (most recent call last)")
    _, fact = log_fact(config_data, tmp_path, lines)
    kept = fact.data["lines"]
    assert any("panic: nil map" in line for line in kept) and any("Traceback" in line for line in kept)
    assert "first 30 of 42 distinct error-looking lines; 12 not kept" in fact.summary
    times = [line.split()[0] for line in kept]
    assert times == sorted(times)
    # 2 strong groups and the first 28 soft ones fill the 30 places.
    assert f"slow call to {words[27]}" in kept[27] and not any(line.endswith(f"slow call to {words[28]}") for line in kept)
    assert len(kept) == 30


def test_replacement_characters_under_the_limit_are_not_reported_as_cut(config_data, tmp_path):
    # A Latin-1 log decoded with errors=replace: each invalid byte became one U+FFFD (3 bytes when re-encoded).
    line = "2026-10-04T10:30:00.000000000Z caf� " + "�" * 60
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    text = "\n".join([line] * 1500) + "\n"
    assert len(text.encode("utf-8")) > 200000 > len(text)
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): text})
    assert not any("200000 bytes" in f.summary for f in ctx.evidence.facts)


def test_a_cut_answer_with_crlf_line_ends_is_reported_as_cut(config_data, tmp_path):
    # The runner turned each CRLF into LF, so a 200000-byte cut answer arrives with one character per line fewer.
    body = "2026-10-04T10:30:00.000000000Z " + "y" * 66
    lines = 200000 // (len(body) + 2)
    text = "\r\n".join([body] * (lines + 1))[:200000].replace("\r\n", "\n")
    assert len(text) < 200000 and not text.endswith("\n")
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): text})
    assert len([f for f in ctx.evidence.facts if "200000 bytes" in f.summary]) == 1


def test_a_whole_answer_just_under_the_limit_is_not_reported_as_cut(config_data, tmp_path):
    body = "2026-10-04T10:30:00.000000000Z " + "z" * 67
    text = "\n".join([body] * 1990) + "\n"
    assert 195000 < len(text) < 200000
    kube = kube_answers(**{"get pods": {"items": [crashing_pod()]}})
    ctx, _, _ = run(config_data, tmp_path, kube=kube, targets={"namespace": "web"},
                    logs={("payments-api-abc", "app", True): text})
    assert not any("200000 bytes" in f.summary for f in ctx.evidence.facts)


def test_lines_differing_only_in_hex_ids_or_uuids_are_one_group_and_groups_are_counted_against_groups(config_data, tmp_path):
    letters = "abcdef"
    # Ids that differ in their letters, so normalising digits alone would not group them.
    hex_ids = ["deadbe" + letters[n % 6] + letters[n // 6] + "c0ffee" for n in range(10)]
    uuids = [f"a1b2c3{letters[n % 6]}{letters[n // 6]}-1b2c-4d3e-8f90-a1b2c3d4e5f6" for n in range(10)]
    lines = [f"{stamp(n)} info {n}" for n in range(20)]
    lines += [f"{stamp(20 + n)} ERROR request req={hex_ids[n]} failed" for n in range(10)]
    lines += [f"{stamp(30 + n)} ERROR trace {uuids[n]} lost" for n in range(10)]
    words = [chr(ord("a") + n % 26) * (1 + n // 26) for n in range(35)]
    lines += [f"{stamp(40 + n)} WARN slow call to {word}" for n, word in enumerate(words)]
    _, fact = log_fact(config_data, tmp_path, lines)
    kept = fact.data["lines"]
    assert len([line for line in kept if "req=" in line]) == 1 and any("repeated 10 times" in line and "req=" in line for line in kept)
    assert len([line for line in kept if "trace" in line]) == 1
    # 2 strong groups and 35 soft groups: 30 groups kept, 7 groups not kept.
    assert "first 30 of 37 distinct error-looking lines; 7 not kept" in fact.summary
    assert "55 error-looking" in fact.summary
