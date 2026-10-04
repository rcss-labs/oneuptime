import json

from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.vpc import COLLECTOR

VPC = "vpc-0aaa1111"
SUBNET = "subnet-0aaa1111"
GROUP = "sg-0aaa1111"
TARGETS = {"security_group_ids": GROUP, "subnet_ids": SUBNET}


def permission(protocol="tcp", low=443, high=443, cidr=None, group=None):
    body = {"IpProtocol": protocol, "IpRanges": [], "UserIdGroupPairs": [], "Ipv6Ranges": [], "PrefixListIds": []}
    if protocol != "-1":
        body.update(FromPort=low, ToPort=high)
    if cidr:
        body["IpRanges"].append({"CidrIp": cidr})
    if group:
        body["UserIdGroupPairs"].append({"GroupId": group})
    return body


def security_group(group_id=GROUP, inbound=None, outbound=None):
    return {"GroupId": group_id, "GroupName": "web", "VpcId": VPC,
            "IpPermissions": inbound if inbound is not None else [
                permission(cidr="0.0.0.0/0"), permission(low=5432, high=5432, group="sg-0bbb2222")],
            "IpPermissionsEgress": outbound if outbound is not None else [permission("-1", cidr="0.0.0.0/0")]}


def healthy_answers(**extra):
    answers = {
        "ec2 describe-security-groups": {"SecurityGroups": [security_group()]},
        "ec2 describe-subnets": {"Subnets": [
            {"SubnetId": SUBNET, "VpcId": VPC, "AvailabilityZone": "eu-west-1a", "AvailableIpAddressCount": 200}]},
        "ec2 describe-route-tables": {"RouteTables": [{"RouteTableId": "rtb-0aaa", "Routes": [
            {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0aaa", "State": "active"}]}]},
        "ec2 describe-network-acls": {"NetworkAcls": [{"NetworkAclId": "acl-0aaa", "Entries": [
            {"RuleNumber": 100, "Egress": False, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"},
            {"RuleNumber": 32767, "Egress": False, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"}]}]},
        "ec2 describe-nat-gateways": {"NatGateways": [{"NatGatewayId": "nat-0aaa", "State": "available"}]},
        "ec2 describe-vpc-endpoints": {"VpcEndpoints": [
            {"VpcEndpointId": "vpce-0aaa", "ServiceName": "com.amazonaws.eu-west-1.s3", "State": "available"}]},
        "cloudwatch get-metric-data": {"MetricDataResults": []},
    }
    answers.update(extra)
    return answers


def run(config_data, tmp_path, answers, targets=None):
    ctx, aws, kube = make_context(config_data, tmp_path, answers, collector="vpc")
    COLLECTOR.run(ctx, dict(TARGETS if targets is None else targets))
    return ctx, aws, kube


def by_summary(ctx, text):
    return [fact for fact in ctx.evidence.facts if text in fact.summary]


def value_of(call, option):
    return call[call.index(option) + 1]


def test_declares_its_targets():
    assert COLLECTOR.name == "vpc"
    assert COLLECTOR.required == ()
    assert COLLECTOR.optional == ("security_group_ids", "subnet_ids", "vpc_id")


def test_healthy_network(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, healthy_answers())
    group = by_summary(ctx, "Security group sg-0aaa1111")[0]
    assert group.kind == "current"
    assert "2 inbound rules" in group.summary and "1 outbound rules" in group.summary
    assert "tcp 443 from anywhere (IPv4)" in group.summary and "tcp 5432 from sg-0bbb2222" in group.summary
    subnet = by_summary(ctx, "Subnet subnet-0aaa1111")[0]
    assert "eu-west-1a" in subnet.summary and "200 free addresses" in subnet.summary
    route = by_summary(ctx, "Route table rtb-0aaa")[0]
    assert "default route via nat-0aaa" in route.summary and "blackhole" not in route.summary
    acl = by_summary(ctx, "Network ACL acl-0aaa")[0]
    assert "no deny entries" in acl.summary
    nat = by_summary(ctx, "NAT gateway nat-0aaa")[0]
    assert "available" in nat.summary
    assert not [f for f in ctx.evidence.facts if f.kind == "derived" and "no data" not in f.summary]
    assert not by_summary(ctx, "VPC endpoint")
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


def test_call_arguments(config_data, tmp_path):
    targets = {"security_group_ids": "sg-0aaa1111,sg-0ccc3333", "subnet_ids": "subnet-0aaa1111,subnet-0bbb2222"}
    _, aws, _ = run(config_data, tmp_path, healthy_answers(), targets)
    group_call = aws.called("ec2", "describe-security-groups")[0]
    assert group_call[group_call.index("--group-ids") + 1:][:2] == ["sg-0aaa1111", "sg-0ccc3333"]
    subnet_call = aws.called("ec2", "describe-subnets")[0]
    assert subnet_call[subnet_call.index("--subnet-ids") + 1:][:2] == ["subnet-0aaa1111", "subnet-0bbb2222"]
    route_call = aws.called("ec2", "describe-route-tables")[0]
    assert value_of(route_call, "--filters") == "Name=association.subnet-id,Values=subnet-0aaa1111,subnet-0bbb2222"
    assert value_of(aws.called("ec2", "describe-network-acls")[0], "--filters").startswith("Name=association.subnet-id,")
    assert value_of(aws.called("ec2", "describe-nat-gateways")[0], "--filter") == f"Name=vpc-id,Values={VPC}"
    assert value_of(aws.called("ec2", "describe-vpc-endpoints")[0], "--filters") == f"Name=vpc-id,Values={VPC}"


def test_unhealthy_network(config_data, tmp_path):
    answers = healthy_answers(**{
        "ec2 describe-subnets": {"Subnets": [
            {"SubnetId": SUBNET, "VpcId": VPC, "AvailabilityZone": "eu-west-1a", "AvailableIpAddressCount": 4}]},
        "ec2 describe-route-tables": {"RouteTables": [{"RouteTableId": "rtb-0aaa", "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0dead", "State": "blackhole"}]}]},
        "ec2 describe-network-acls": {"NetworkAcls": [{"NetworkAclId": "acl-0aaa", "Entries": [
            {"RuleNumber": 90, "Egress": False, "RuleAction": "deny", "Protocol": "6",
             "CidrBlock": "10.9.0.0/16", "PortRange": {"From": 443, "To": 443}},
            {"RuleNumber": 32767, "Egress": False, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"}]}]},
        "ec2 describe-nat-gateways": {"NatGateways": [
            {"NatGatewayId": "nat-0aaa", "State": "failed", "FailureMessage": "Elastic IP address could not be attached"}]},
        "ec2 describe-vpc-endpoints": {"VpcEndpoints": [
            {"VpcEndpointId": "vpce-0bbb", "ServiceName": "com.amazonaws.eu-west-1.sqs", "State": "failed"}]},
    })
    ctx, _, _ = run(config_data, tmp_path, answers)
    derived = [f for f in ctx.evidence.facts if f.kind == "derived" and "free addresses" in f.summary][0]
    assert "subnet-0aaa1111" in derived.summary and "4" in derived.summary
    assert "blackhole" in by_summary(ctx, "Route table rtb-0aaa")[0].summary
    assert "nat-0dead" in by_summary(ctx, "Route table rtb-0aaa")[0].summary
    acl = by_summary(ctx, "Network ACL acl-0aaa")[0].summary
    assert "inbound rule 90 deny 6 port 443-443 from 10.9.0.0/16" in acl and "32767" not in acl
    nat = by_summary(ctx, "NAT gateway nat-0aaa")[0].summary
    assert "failed" in nat and "Elastic IP address could not be attached" in nat
    endpoint = by_summary(ctx, "VPC endpoint vpce-0bbb")[0].summary
    assert "failed" in endpoint and "com.amazonaws.eu-west-1.sqs" in endpoint


def test_neither_target_is_reported_clearly(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {}, {})
    assert ctx.evidence.errors[0]["code"] == "MissingTarget"
    assert "security_group_ids" in ctx.evidence.errors[0]["message"]
    assert aws.calls == []


def test_vpc_id_alone_reads_nat_gateways_and_endpoints(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, healthy_answers(), {"vpc_id": VPC})
    assert aws.called("ec2", "describe-security-groups") == []
    assert aws.called("ec2", "describe-subnets") == []
    assert aws.called("ec2", "describe-nat-gateways") and aws.called("ec2", "describe-vpc-endpoints")


def test_resources_that_do_not_exist(config_data, tmp_path):
    answers = healthy_answers(**{"ec2 describe-security-groups": {"SecurityGroups": []},
                                 "ec2 describe-subnets": {"Subnets": []}})
    ctx, aws, _ = run(config_data, tmp_path, answers)
    assert by_summary(ctx, "No security group was found")
    assert by_summary(ctx, "No subnet was found")
    assert aws.called("ec2", "describe-route-tables") == []


def test_denied_call_keeps_the_rest(config_data, tmp_path):
    answers = healthy_answers(**{"ec2 describe-route-tables": access_denied("DescribeRouteTables")})
    ctx, aws, kube = run(config_data, tmp_path, answers)
    assert len(ctx.evidence.errors) == 1 and ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert by_summary(ctx, "Security group sg-0aaa1111") and by_summary(ctx, "NAT gateway")
    assert_read_only(ctx, aws, kube)


def test_secret_in_a_failure_message_is_redacted(config_data, tmp_path):
    secret = "pw" + "6" * 10
    nat = {"NatGateways": [{"NatGatewayId": "nat-0aaa", "State": "failed", "FailureMessage": f"password={secret}"}]}
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**{"ec2 describe-nat-gateways": nat}))
    assert secret not in ctx.evidence.to_json()


def test_fact_count_is_bounded(config_data, tmp_path):
    groups = [security_group(f"sg-{n:08d}") for n in range(250)]
    ctx, _, _ = run(config_data, tmp_path, healthy_answers(**{"ec2 describe-security-groups": {"SecurityGroups": groups}}))
    assert len(ctx.evidence.facts) == 200 and ctx.evidence.truncated


def test_nat_gateway_metrics(config_data, tmp_path):
    results = {"MetricDataResults": [{"Id": "m0", "Timestamps": ["2026-10-04T10:41:00+00:00"], "Values": [37.0]}]}
    ctx, aws, _ = run(config_data, tmp_path, healthy_answers(**{"cloudwatch get-metric-data": results}))
    sent = json.loads(value_of(aws.called("cloudwatch", "get-metric-data")[0], "--metric-data-queries"))
    stats = {(q["MetricStat"]["Metric"]["MetricName"], q["MetricStat"]["Stat"]) for q in sent}
    assert stats == {("ErrorPortAllocation", "Sum"), ("PacketsDropCount", "Sum"), ("ActiveConnectionCount", "Maximum")}
    metric = sent[0]["MetricStat"]["Metric"]
    assert metric["Namespace"] == "AWS/NATGateway"
    assert metric["Dimensions"] == [{"Name": "NatGatewayId", "Value": "nat-0aaa"}]
    assert by_summary(ctx, "ErrorPortAllocation nat-0aaa (Sum): peak 37.0")
