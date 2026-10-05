import json

from fakes import FakeAws, access_denied
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


class PerMountTarget(FakeAws):
    """Answers the security group calls by mount target id and by the --group-ids given."""

    def __init__(self, answers, groups_of, group_replies):
        super().__init__(answers)
        self.groups_of, self.group_replies = groups_of, group_replies

    def __call__(self, argv, timeout):
        if argv[1:3] == ["efs", "describe-mount-target-security-groups"]:
            reply = self.groups_of[argv[argv.index("--mount-target-id") + 1]]
            self.answers["efs describe-mount-target-security-groups"] = reply
        if argv[1:3] == ["ec2", "describe-security-groups"]:
            ids = argv[argv.index("--group-ids") + 1:]
            ids = [i for i in ids if not i.startswith("--")][:1]
            self.answers["ec2 describe-security-groups"] = self.group_replies[ids[0]]
        return super().__call__(argv, timeout)


def run(config_data, tmp_path, answers, fake=None):
    ctx, aws, _ = make_context(config_data, tmp_path, answers, collector="efs")
    if fake is not None:
        ctx.runner, aws = fake, fake
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
    nfs = by_summary(ctx, "allows NFS")
    assert len(nfs) == 2 and all(f.kind == "derived" for f in nfs)
    assert nfs[0].summary == "Mount target fsmt-1 in eu-west-1a allows NFS from 10.0.0.0/16"
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


def rule(protocol="tcp", low=2049, high=2049, **sources):
    permission = {"IpProtocol": protocol, **{k: v for k, v in sources.items()}}
    if low is not None:
        permission.update(FromPort=low, ToPort=high)
    return permission


def test_nfs_is_judged_per_mount_target_with_sources(config_data, tmp_path):
    groups_of = {"fsmt-1": {"SecurityGroups": ["sg-a"]}, "fsmt-2": {"SecurityGroups": ["sg-b"]}}
    replies = {
        "sg-a": {"SecurityGroups": [{"GroupId": "sg-a", "IpPermissions": [rule(UserIdGroupPairs=[{"GroupId": "sg-unrelated"}], IpRanges=[{"CidrIp": "10.0.0.0/16"}])]}]},
        "sg-b": {"SecurityGroups": [{"GroupId": "sg-b", "IpPermissions": [rule(low=443, high=443, IpRanges=[{"CidrIp": "0.0.0.0/0"}])]}]},
    }
    fake = PerMountTarget(healthy_answers(), groups_of, replies)
    ctx, aws = run(config_data, tmp_path, healthy_answers(), fake=fake)
    allowed = by_summary(ctx, "Mount target fsmt-1 in eu-west-1a allows NFS")[0]
    assert allowed.summary == "Mount target fsmt-1 in eu-west-1a allows NFS from 10.0.0.0/16 and sg-unrelated"
    blocked = by_summary(ctx, "fsmt-2 in eu-west-1b")[-1]
    assert blocked.kind == "derived" and "nothing allows" in blocked.summary and "TCP 2049" in blocked.summary
    assert [c[c.index("--mount-target-id") + 1] for c in aws.called("efs", "describe-mount-target-security-groups")] == ["fsmt-1", "fsmt-2"]
    assert_read_only(ctx, aws)


def test_protocol_six_all_traffic_and_port_ranges_allow_nfs(config_data, tmp_path):
    for permission in (rule(protocol="6", IpRanges=[{"CidrIp": "10.1.0.0/16"}]),
                       rule(protocol="-1", low=None, PrefixListIds=[{"PrefixListId": "pl-123"}]),
                       rule(low=2000, high=3000, IpRanges=[{"CidrIp": "10.2.0.0/16"}])):
        answers = healthy_answers(**{"ec2 describe-security-groups": {"SecurityGroups": [{"GroupId": "sg-nfs", "IpPermissions": [permission]}]}})
        ctx, _ = run(config_data, tmp_path, answers)
        assert "allows NFS from" in by_summary(ctx, "fsmt-1 in eu-west-1a allows")[0].summary


def test_other_protocols_and_ports_do_not_allow_nfs(config_data, tmp_path):
    answers = healthy_answers(**{"ec2 describe-security-groups": {"SecurityGroups": [{"GroupId": "sg-nfs", "IpPermissions": [
        rule(protocol="udp", IpRanges=[{"CidrIp": "10.0.0.0/16"}]), rule(low=443, high=443, IpRanges=[{"CidrIp": "10.0.0.0/16"}])]}]}})
    ctx, _ = run(config_data, tmp_path, answers)
    assert by_summary(ctx, "allows NFS") == []
    assert len(by_summary(ctx, "nothing allows")) == 2


def test_failed_security_group_lookup_says_access_could_not_be_determined(config_data, tmp_path):
    answers = healthy_answers(**{"ec2 describe-security-groups": access_denied("DescribeSecurityGroups")})
    ctx, _ = run(config_data, tmp_path, answers)
    facts = by_summary(ctx, "could not be determined")
    assert len(facts) == 2 and all(f.kind == "derived" for f in facts)
    assert by_summary(ctx, "nothing allows") == [] and by_summary(ctx, "No security group") == []


def test_failed_mount_target_group_listing_says_access_could_not_be_determined(config_data, tmp_path):
    answers = healthy_answers(**{"efs describe-mount-target-security-groups": access_denied("DescribeMountTargetSecurityGroups")})
    ctx, aws = run(config_data, tmp_path, answers)
    assert len(by_summary(ctx, "could not be determined")) == 2
    assert aws.called("ec2", "describe-security-groups") == []
    assert by_summary(ctx, "nothing allows") == []


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
    assert [f.data["maximum"] for f in by_summary(ctx, "BurstCreditBalance (Minimum)")] == [1000]
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
    assert len([f for f in ctx.evidence.facts if f.kind == "current" and f.summary.startswith("Mount target")]) == 20


def test_missing_file_system(config_data, tmp_path):
    ctx, aws = run(config_data, tmp_path, healthy_answers(**{"efs describe-file-systems": NOT_FOUND}))
    assert len(ctx.evidence.facts) == 1
    assert ctx.evidence.facts[0].kind == "current" and "not found" in ctx.evidence.facts[0].summary
    assert ctx.evidence.facts[0].command
    assert ctx.evidence.errors == []
    assert aws.called("efs", "describe-mount-targets") == []


def test_denied_describe_file_systems_is_an_error_not_a_missing_file_system(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"efs describe-file-systems": access_denied("DescribeFileSystems")}))
    assert ctx.evidence.facts == []
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]


def test_access_denied_on_one_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"ec2 describe-security-groups": access_denied("DescribeSecurityGroups")})
    ctx, aws = run(config_data, tmp_path, answers)
    assert [e["code"] for e in ctx.evidence.errors] == ["AccessDeniedException"]
    assert len(by_summary(ctx, "Mount target fsmt-")) >= 2
    assert aws.called("cloudwatch", "get-metric-data")
    assert len(by_summary(ctx, "could not be determined")) == 2
    assert_read_only(ctx, aws)


def test_secret_in_access_point_name_never_reaches_the_document(config_data, tmp_path):
    secret = "pw" + "6" * 10
    points = {"AccessPoints": [{"AccessPointId": "fsap-2", "LifeCycleState": "error", "Name": f"token={secret}"}]}
    ctx, _ = run(config_data, tmp_path, healthy_answers(**{"efs describe-access-points": points}))
    assert secret not in ctx.evidence.to_json()


def test_state_facts_carry_the_arns_and_ids(config_data, tmp_path):
    fs_arn = "arn:aws:elasticfilesystem:eu-west-1:111111111111:file-system/fs-0abc123"
    ap_arn = "arn:aws:elasticfilesystem:eu-west-1:111111111111:access-point/fsap-2"
    answers = healthy_answers(**{
        "efs describe-file-systems": file_system(FileSystemArn=fs_arn),
        "efs describe-access-points": {"AccessPoints": [{"AccessPointId": "fsap-2", "AccessPointArn": ap_arn, "LifeCycleState": "error"}]},
    })
    ctx, _ = run(config_data, tmp_path, answers)
    assert ctx.evidence.facts[0].data["arn"] == fs_arn
    mounts = [f for f in ctx.evidence.facts if f.kind == "current" and f.summary.startswith("Mount target fsmt-")]
    assert [f.data["resource_id"] for f in mounts] == ["fsmt-1", "fsmt-2"]
    assert by_summary(ctx, "Access point fsap-2")[0].data["arn"] == ap_arn


def test_an_answer_without_arns_writes_no_arn_key(config_data, tmp_path):
    ctx, _ = run(config_data, tmp_path, healthy_answers())
    assert "arn" not in ctx.evidence.facts[0].data and ctx.evidence.errors == []
