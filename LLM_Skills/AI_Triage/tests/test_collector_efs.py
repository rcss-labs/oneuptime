import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.efs import COLLECTOR

TARGETS = {"file_system": "fs-0abc123"}
NOT_FOUND = (254, "An error occurred (FileSystemNotFound) when calling the DescribeFileSystems operation: x")


def file_system(**overrides):
    body = {"FileSystemId": "fs-0abc123", "LifeCycleState": "available", "PerformanceMode": "generalPurpose",
            "ThroughputMode": "bursting", "SizeInBytes": {"Value": 5 * 1024**3}}
    body.update(overrides)
    return {"FileSystems": [body]}


def mount_target(identifier, state="available", zone="eu-west-1a", subnet="subnet-aaa", ip="10.0.1.10"):
    return {"MountTargetId": identifier, "AvailabilityZoneName": zone, "SubnetId": subnet, "LifeCycleState": state, "IpAddress": ip}


def group(identifier, protocol="tcp", low=2049, high=2049):
    return {"GroupId": identifier, "IpPermissions": [{"IpProtocol": protocol, "FromPort": low, "ToPort": high,
                                                       "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}]}


def healthy_answers(**extra):
    answers = {
        "efs describe-file-systems": file_system(),
        "efs describe-mount-targets": {"MountTargets": [mount_target("fsmt-1"), mount_target("fsmt-2", zone="eu-west-1b", subnet="subnet-bbb", ip="10.0.2.10")]},
        "efs describe-mount-target-security-groups": {"SecurityGroups": ["sg-nfs"]},
        "ec2 describe-security-groups": {"SecurityGroups": [group("sg-nfs")]},
        "efs describe-access-points": {"AccessPoints": []},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers):
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="efs")
    COLLECTOR.run(ctx, dict(TARGETS))
    return ctx, aws


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "efs"
    assert COLLECTOR.required == ("file_system",)
    assert COLLECTOR.optional == ()


def test_healthy_file_system(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers())
    state = ctx.evidence.facts[0]
    assert state.kind == "current" and state.id == "efs-0001"
    for word in ("fs-0abc123 is available", "generalPurpose", "throughput mode bursting", "5.00 GiB"):
        assert word in state.summary
    mounts = [f for f in ctx.evidence.facts if f.kind == "current" and "Mount target" in f.summary]
    assert len(mounts) == 2
    assert "fsmt-1" in mounts[0].summary and "eu-west-1a" in mounts[0].summary and "subnet-aaa" in mounts[0].summary
    assert "10.0.1.10" in mounts[0].summary and "available" in mounts[0].summary
    assert by_summary(ctx, "not available") == []
    nfs = next(f for f in ctx.evidence.facts if f.kind == "derived")
    assert "allow inbound TCP 2049" in nfs.summary and "sg-nfs" in nfs.summary
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws)


def test_provisioned_throughput_is_stated(config_data, tmp_path):
    answers = healthy_answers(**{"efs describe-file-systems": file_system(ThroughputMode="provisioned", ProvisionedThroughputInMibps=128.0)})
    ctx, _ = run(config_data, tmp_path, answers)
    assert "provisioned 128.0 MiB/s" in ctx.evidence.facts[0].summary


def test_unavailable_mount_target_gets_a_derived_fact(config_data, tmp_path):
    answers = healthy_answers(**{"efs describe-mount-targets": {"MountTargets": [mount_target("fsmt-1", state="creating")]}})
    ctx, _ = run(config_data, tmp_path, answers)
    fact = by_summary(ctx, "not available")[0]
    assert fact.kind == "derived" and "fsmt-1" in fact.summary and "creating" in fact.summary


def test_security_groups_that_block_nfs(config_data, tmp_path):
    answers = healthy_answers(**{"ec2 describe-security-groups": {"SecurityGroups": [group("sg-nfs", low=443, high=443)]}})
    ctx, aws = run(config_data, tmp_path, answers)
    fact = by_summary(ctx, "TCP 2049")[0]
    assert fact.kind == "derived" and fact.summary.startswith("No security group")
    call = aws.called("ec2", "describe-security-groups")[0]
    assert call[call.index("--group-ids") + 1:call.index("--group-ids") + 2] == ["sg-nfs"]
    assert len(aws.called("efs", "describe-mount-target-security-groups")) == 2


def test_all_traffic_rule_and_port_range_allow_nfs(config_data, tmp_path):
    for permission in (group("sg-nfs", protocol="-1", low=None, high=None), group("sg-nfs", low=2000, high=3000)):
        permission["IpPermissions"][0] = {k: v for k, v in permission["IpPermissions"][0].items() if v is not None}
        ctx, _ = run(config_data, tmp_path, healthy_answers(**{"ec2 describe-security-groups": {"SecurityGroups": [permission]}}))
        assert "allow inbound TCP 2049" in by_summary(ctx, "TCP 2049")[0].summary


def test_access_points_not_available(config_data, tmp_path):
    points = {"AccessPoints": [{"AccessPointId": "fsap-1", "LifeCycleState": "available"},
                               {"AccessPointId": "fsap-2", "LifeCycleState": "error", "Name": "uploads"}]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"efs describe-access-points": points}))
    facts = by_summary(ctx, "Access point")
    assert len(facts) == 1 and facts[0].kind == "current" and "fsap-2" in facts[0].summary and "error" in facts[0].summary
    call = aws.called("efs", "describe-access-points")[0]
    assert call[call.index("--max-items") + 1] == "20"


def test_no_mount_targets(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"efs describe-mount-targets": {"MountTargets": []}}))
    fact = by_summary(ctx, "no mount targets")[0]
    assert fact.kind == "derived"
    assert aws.called("ec2", "describe-security-groups") == []


def test_metrics(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [1000.0]}]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    assert by_summary(ctx, "BurstCreditBalance (Minimum): peak 1000.0")
    call = aws.called("cloudwatch", "get-metric-data")[0]
    queries = json.loads(call[call.index("--metric-data-queries") + 1])
    stats = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stats == {"BurstCreditBalance": "Minimum", "PercentIOLimit": "Maximum", "ClientConnections": "Sum",
                     "PermittedThroughput": "Minimum", "MeteredIOBytes": "Sum"}
    assert queries[0]["MetricStat"]["Metric"]["Namespace"] == "AWS/EFS"
    assert queries[0]["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "FileSystemId", "Value": "fs-0abc123"}]


def test_mount_targets_are_capped(config_data, tmp_path):
    targets = {"MountTargets": [mount_target(f"fsmt-{n}") for n in range(30)]}
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"efs describe-mount-targets": targets}))
    call = aws.called("efs", "describe-mount-targets")[0]
    assert call[call.index("--max-items") + 1] == "20"
    assert len(by_summary(ctx, "Mount target")) == 20


def test_missing_file_system(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"efs describe-file-systems": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert aws.called("efs", "describe-mount-targets") == []


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"ec2 describe-security-groups": access_denied("DescribeSecurityGroups")})
    ctx, aws = run(config_data, tmp_path, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert len(by_summary(ctx, "Mount target")) == 2
    assert aws.called("cloudwatch", "get-metric-data")
    assert by_summary(ctx, "TCP 2049") == []
    assert_read_only(ctx, aws)


def test_secret_in_access_point_name_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "6" * 10
    points = {"AccessPoints": [{"AccessPointId": "fsap-2", "LifeCycleState": "error", "Name": f"token={secret}"}]}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"efs describe-access-points": points}))
    assert secret not in ctx.evidence.to_json()
