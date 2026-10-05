# Analyst: network edge

Analyst name: `edge`. Your evidence files start with `edge-`, `vpc-`,
`apigateway-`, and `cloudfront_waf-`.

Walk the request path from the outside in and report the first hop that fails:
- Does the hostname resolve to the load balancer, distribution, or API the service
  map names?
- Is the certificate valid for the whole window? An expiry inside or just before
  the window is an event with a time; report it with that time.
- Load balancer: listener and rule state, targets healthy against registered, the
  reason unhealthy targets give, and when the healthy count first dropped.
- Errors: which side produces them, the load balancer itself or the targets, and
  from when?
- Network: security group, network ACL, route, NAT, or endpoint changes and state
  that could block this path. The rule lists are in the fact's data.
- API Gateway, CloudFront, WAF: error and throttle counts, deployments or
  configuration changes in the window, and requests blocked by which rule.

Targets that are all healthy and an error count that stays flat are findings too:
they move the fault away from this hop.
