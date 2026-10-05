# VPC playbook

## When to open

The target names security groups, subnets, or a VPC, or evidence shows a connection
that times out or is refused, a task or instance that cannot start for lack of an
address, or a NAT or endpoint problem.

## Collect

The plan already runs `vpc` for the ids it found. Add these when they apply; take the
account, region, window, and case folder from the plan's own lines.

| When | Command |
|---|---|
| The ids found are a service's groups and the subnets are not yet checked | `run collect vpc ... --target subnet_ids=<subnets of the service>` |
| Only a subnet is known and you need the NAT gateways and endpoints | `run collect vpc ... --target vpc_id=<vpc id>` |
| Another group is the source in a rule you read | `run collect vpc ... --target security_group_ids=<that group>` (use a `--suffix`) |
| A subnet ran out of addresses and tasks or pods are pending | `run collect ecs ... --target cluster=<cluster> --target service=<service>` or `run collect eks ... --target cluster=<cluster>` |
| A change to a group, route, or ACL is suspected | `run collect changes ... --target resource_names=<group, route table, or ACL id>` |

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Security group G (name) has N inbound rules, M of them open to anywhere, and K outbound rules" | `current`; the inbound rules are in `data["rules"]` (outbound rules are only counted) | each rule in the data; a rule from another group id names the group allowed in |
| the data has `rules_omitted` | more than 50 inbound rules; the rest were not listed | read the group with the command below |
| a needed port is absent from `data["rules"]` | the caller is not allowed in on that port or source | the caller's own group and its id |
| "Security group G was not found" | wrong id, wrong region, or deleted | `cloudtrail.md` for a delete |
| "Subnet S in <zone> has N free addresses" | `current` | the zone against where instances or tasks are placed |
| "Subnet S has only N free addresses (fewer than 10)" | new tasks, pods, or instances cannot get an address | which service scales into it |
| "Route table R has default route via igw-.../nat-..." | `current`; internet path of the subnet | a private subnet with an internet gateway, or a public one with a NAT, is misplaced |
| "Route table R ... has no default route" | no internet or NAT path | the endpoint facts: AWS APIs may need endpoints |
| "... blackhole routes: <destination> via <target>" | the target (gateway, peering, instance) was deleted | `cloudtrail.md` for the delete |
| "(the main route table of V, used by S implicitly ...)" | the subnet has no explicit table; a change to the main table affects it | the default route in that fact |
| "Network ACL A: inbound rule 90 deny tcp port 443-443 from <cidr>" | a deny entry that someone added; the default deny rules are left out | whether the cidr is the caller's |
| "Network ACL A: no deny entries besides the default rule" | explicit denies are ruled out; the allow rules are not shown | the ACL's allow rules, with a read below |
| "NAT gateway N is failed: <message>" or `deleted` | outbound traffic from private subnets stops | the failure message; `changes` |
| `ErrorPortAllocation` peak above zero, `PacketsDropCount` | a NAT gateway ran out of ports for one destination: many connections | `ActiveConnectionCount` and which service opens them |
| "VPC endpoint E (service) is pending/failed/..." | only endpoints that are not available are listed; calls to that service from the VPC fail | the endpoint's security group and the service name |

Security groups only allow, so a missing rule is the cause, not a deny. Network ACLs
are stateless and check both directions. All VPC facts are `current`, except the NAT
metric peaks, which carry times. The collector cannot show what a rule's source group
contains.

## Common causes

1. **A security group rule is missing or was removed.** Evidence: connection timeouts
   (not refusals) to a port, the port or source absent from `data["rules"]`, a change
   event on the group before the start. Rule out: the rule present and the same
   timeouts on a path the rule does not cover. Work order: the group id, port,
   protocol, and the source group or range; mitigation adds the rule, permanent fix
   fixes the source of the group definition.
2. **A subnet is out of addresses.** Evidence: the low-address fact and pending
   tasks, pods, or failed launches in the compute evidence. Work order: the subnet,
   its zone, free count, and the service growing into it.
3. **A route is wrong.** Evidence: a blackhole route, a missing default route, or a main
   route table change, with outbound calls timing out from that subnet. Work order:
   the route table, destination, and old and new target.
4. **A NAT gateway is failing or out of ports.** Evidence: `failed` state or an
   `ErrorPortAllocation` peak inside the window. Work order: the gateway id, the metric
   peak, and the connection source; the permanent fix is more gateways or connection reuse.
5. **A network ACL denies.** Evidence: a deny entry whose range and port cover the
   failing path. Work order: the ACL id, rule number, and the subnet it covers.
6. **A VPC endpoint is not available.** Evidence: the endpoint fact and timeouts to
   that AWS service only. Work order: the endpoint id and service name.

## Compare with

A subnet or group that serves the same role and works (same service in another zone,
or another environment), and the NAT metrics against one week earlier.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws ec2 describe-security-groups --group-ids <group id> --profile <triage profile> --region <region> --query 'SecurityGroups[].IpPermissions[].{proto:IpProtocol,from:FromPort,to:ToPort,groups:UserIdGroupPairs[].GroupId,cidrs:IpRanges[].CidrIp}' 2>/dev/null
aws ec2 describe-network-interfaces --filters Name=group-id,Values=<group id> --profile <triage profile> --region <region> --max-items 20 --query 'NetworkInterfaces[].{id:NetworkInterfaceId,subnet:SubnetId,status:Status,description:Description}' 2>/dev/null
aws ec2 describe-network-acls --filters Name=association.subnet-id,Values=<subnet id> --profile <triage profile> --region <region> --query 'NetworkAcls[].Entries[].{rule:RuleNumber,egress:Egress,action:RuleAction,protocol:Protocol,cidr:CidrBlock,ports:PortRange}' 2>/dev/null
aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=<vpc id> --profile <triage profile> --region <region> --query 'VpcEndpoints[].{id:VpcEndpointId,service:ServiceName,state:State,groups:Groups[].GroupId}' 2>/dev/null
```
