# Access playbook

## When to open

The target has an IAM role, a KMS key, or a secret, or evidence shows `AccessDenied`,
`AccessDeniedException`, "not authorized to perform", a KMS key error, or a password or
credential that stopped working. The collector reads metadata only.

## Collect

The plan does not run this: no service-map key feeds `access`. Run it when evidence
names a role, a key, or a secret, for example
`run collect access ... --case-dir <case> --target role=<role name>`. Take the account,
region, and window from the plan's own lines; `<case>` is the case folder. To get a
simulation, give it both an `action` and the role; `resource_arn` is optional.

| When | Command |
|---|---|
| An error names a role and an action | `run collect access ... --case-dir <case> --target role=<role name> --target action=<service:Action> --target resource_arn=<arn from the error>` |
| An error names a key, or an encrypted resource cannot be used | `run collect access ... --case-dir <case> --target kms_key=<key id or alias>` |
| Credentials stopped working, or a rotation is involved | `run collect access ... --case-dir <case> --target secret=<secret name>` |
| Who changed the policy, key, or secret, and when | `run collect changes ... --case-dir <case> --target resource_names=<name>` and read `cloudtrail.md` |
| The role belongs to a task, function, or pod that failed | `run collect ecs ... --case-dir <case> --target cluster=<c> --target service=<s>` (or `lambda` with `function=<name>`, `eks` with `cluster=<name>`) for it |
| The error text is needed | `run collect logs ... --case-dir <case> --target log_groups=<log group with the error>` |

Never read a secret's value, a parameter with decryption, or decrypt anything. The
evidence needed (state, times, policy names, a decision) is in the metadata.

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Role X created T, last used T in REGION; trusted principals: a, b" (`current`) | who may assume the role | whether the caller's principal (for example the service that runs the task) is in that list; conditions on the trust are not shown; "has never been used" means the role is not the one in use |
| "Role X policies: attached a, b; inline none" (`current`) | names only, not the documents | the Follow a lead commands for the statements |
| "Simulation: ACTION on RESOURCE is allowed" | the identity policies would allow it | a real denial then comes from elsewhere (cause 5) |
| "... is implicitDeny; no statement allows it" | no policy of the role allows it | the work order names the missing action and resource |
| "... is explicitDeny; denied by POLICY (TYPE)" | a statement denies it | that policy and its type |
| "The simulation lacked values for: ...; the real decision may differ" | a condition needs a request value the simulation did not have | treat the verdict as open |
| "Key K state Enabled, enabled True, origin AWS_KMS" (`current`; no second line for a usable key) | the key is usable | the key policy and grants (Follow a lead) |
| "Key K is disabled; calls that use it fail until it is enabled" | encrypt and decrypt calls fail | when it was disabled: the change evidence |
| "Key K is pending deletion (deletion date T); calls that use it fail" | same; the key will be destroyed on that date | the same, and the date is the deadline for the work order |
| "Key K is waiting for key material to be imported" or "is unavailable: the key or its custom key store cannot be reached" (even if enabled) | calls fail | the import, or the custom key store's state |
| "Key K is a replica key in state pending replica deletion (deletion date T)" | a replica is being deleted; the primary key is not affected by this fact | which region's key the caller uses |
| "Key K is still being created" or "is being updated" | a transient state | collect again later |
| "Key K has state S" | a state the collector does not know; no claim is made | the state's own meaning in the AWS documentation |
| "Secret S: rotation enabled, last rotated T, last changed T, next rotation T" (`current`; "unknown" means absent) | rotation metadata | "last changed" against the incident start |
| "Secret S: rotation is overdue: last rotated T, interval N days" | the scheduled rotation did not happen | the rotation function's errors in `lambda.md` and its logs |
| "Secret S changed inside the incident window, at T" | the stored value changed at T | a client that cached the old value, or a database not updated to match |

A `current` fact shows the state now and has no event time; the simulation is computed
at collection time. Only the secret-changed fact carries the time of a change. Failed
rotation has no fact of its own: it shows as overdue or as a changed secret whose
database login fails.

## Common causes

1. **The role lacks a permission.** Evidence: the denial names role, action, resource;
   the simulation says `implicitDeny`; a change to the role's policies before the
   incident. Rule out: simulation `allowed`. Work order: the role, the action, the
   resource ARN, the policy that should hold it; mitigation is adding that one statement;
   permanent fix is the same in the source that defines the role.
2. **An explicit deny.** Evidence: `explicitDeny` naming a policy, or an error message
   that says an explicit deny. Work order: the policy, its type, the statement to change.
3. **The trust policy does not include the caller.** Evidence: the error is from
   `AssumeRole`, and the caller's principal is not among the trusted principals. Work
   order: the role and the principal to add.
4. **A KMS key is disabled, pending deletion, or otherwise unusable.** Evidence: the key fact, errors that
   name the key or an invalid key state, and a start at the time the key changed.
   Work order: the key id, the state, the deletion date, who changed it (change
   evidence); mitigation is a person re-enabling or cancelling the deletion; permanent
   fix is protection on that key.
5. **The simulation allows it but the real call fails.** Evidence: `allowed`, still
   denied. The collector does not see a resource's own policy (a key or bucket policy),
   a permission boundary or service control policy, session policies, or conditions it
   lacked values for. Work order: name which of those remain unread and how to read it.
6. **A secret rotated, failed to rotate, or changed.** Evidence: a "changed inside the
   window" fact before authentication errors, or an overdue rotation. Work order:
   the secret, times, interval; never the value.

## Compare with

A role of the same kind that works (same service, another environment), the same role
before the incident (the change evidence), and the key or secret in another environment.

## Follow a lead

When the collector's facts are not enough, read directly by `reference/reading.md`:

```bash
aws iam get-role-policy --role-name <role> --policy-name <inline policy> --profile <triage profile> --region <region> --query 'PolicyDocument' | jq -c '.Statement[]'
aws iam get-policy-version --policy-arn <policy arn> --version-id <version> --profile <triage profile> --region <region> --query 'PolicyVersion.Document' | jq -c '.Statement[]'
aws kms get-key-policy --key-id <key id> --policy-name default --profile <triage profile> --region <region> --query 'Policy' | jq -r '.'
aws secretsmanager describe-secret --secret-id <secret name> --profile <triage profile> --region <region> --query '{rotation:RotationEnabled,rules:RotationRules,lastRotated:LastRotatedDate,lastChanged:LastChangedDate}'
```
