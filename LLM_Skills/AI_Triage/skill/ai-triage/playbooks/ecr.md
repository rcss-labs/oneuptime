# ECR playbook

## When to open

The target has an `ecr_repository`, or evidence names an image pull failure, an image
tag or digest, or a deployment that started the wrong image.

## Collect

The plan already runs `ecr` for the mapped repository. Add these when they apply; take
the account, region, and window from the plan's own lines; `<case>` is the case folder.

| When | Command |
|---|---|
| The image the workload runs is known by tag | `run collect ecr ... --case-dir <case> --target repository=<repository name> --target image_tag=<tag> --suffix tag` |
| The image is known by digest (from a task, pod, or function) | `run collect ecr ... --case-dir <case> --target repository=<repository name> --target image_digest=<sha256:...> --suffix digest` |
| The pull was denied rather than the image missing | `run collect access ... --case-dir <case> --target role=<execution or node role name>` |
| A deployment used the image | `run collect changes ... --case-dir <case> --target resource_names=<repository name> --target incident_start=<time>` |
| The workload runs on ECS | `run collect ecs ... --case-dir <case> --target cluster=<cluster> --target service=<service>`; see `ecs.md` |

Without `image_tag` or `image_digest` the collector lists only the five newest
images and runs no scan lookup.

## What the facts mean

| Fact | Usually means | Read next |
|---|---|---|
| "Image <tag> does not exist in repository R in <region>" | the tag was never pushed, was deleted, or the region or account is wrong | the five newest images; ask whether a lifecycle rule expires images (this skill cannot read the rule) |
| "Repository R was not found in <region>" | wrong name, region, or account | the region of the failing workload |
| "Repository R has no images" | nothing was pushed, or everything expired | ask whether a lifecycle rule expires images; a delete call in `changes` |
| "Image pushed: tags a, b, digest D, size S" with a time | an image exists; the time is the push time | the time against the incident start |
| "Image pushed (pushed inside the incident window)" | a push happened during the incident | whether its tag is the one the workload uses |
| the newest image is `untagged` and an older image holds the tag | the tag points at an older build than the latest push | the digests of both against the one the workload runs |
| "Only 1000 images were examined" | a newer push may not be listed | repeat with `image_tag` |
| "Scan of image X (COMPLETE): CRITICAL 2, HIGH 5" | counts of findings by severity at the scan time | whether the counts changed from the previous image |
| "Image X has no scan results" | scanning is off, or the image was not scanned yet | the repository's scan setting |

Every push fact carries the push time. The scan fact and the missing-image facts are
`current`: they describe now, not the incident start.

## Common causes

1. **The tag the deployment names does not exist.** Evidence: "does not exist" for the
   tag, and a pull error in the workload's evidence. Rule out: the tag exists with a
   push time before the failure. Work order: repository, expected tag, the tags that
   are there; mitigation is to deploy a tag that exists; permanent fix is a pipeline
   that pushes before it deploys.
2. **A mutable tag moved to a different build.** Evidence: a push inside the window
   with the same tag, and a digest that differs from the one the workload ran
   before. Work order: old and new digest, the push time, and the pusher from
   `changes`; mitigation is to deploy by the old digest; permanent fix is to deploy by
   digest or to make tags immutable (`imageTagMutability`).
3. **The image expired or was deleted.** Evidence: the digest the workload runs is
   missing, the repository has fewer images than expected, a delete call in `changes`
   or a lifecycle rule the engineer confirms (the skill cannot read it; put it in the open
   questions). Work order: the rule text the engineer supplies and the date the image
   would have expired.
4. **Pull denied, not missing.** Evidence: the image exists in the facts but the
   workload reports an authorization error. Work order: the role that pulls, the
   repository policy, and the account that owns the repository; read `access.md`.
5. **A new push brought a regression or a vulnerability.** Evidence: a push minutes
   before the incident, and scan counts higher than on the previous image. A scan
   count alone is not an outage cause; pair it with a behavior change. Work order:
   both digests and their scan counts.
6. **Pull is slow or fails on the network.** Evidence: the image and tag are fine
   and timeouts appear in the workload; read `vpc.md` (endpoints, NAT).

## Compare with

The previous image of the same repository (the collector lists five), and the image
a healthy environment runs, by digest.

## Follow a lead

```bash
aws ecr describe-images --repository-name <repository> --image-ids imageTag=<tag> --profile <triage profile> --region <region> --query 'imageDetails[].{digest:imageDigest,pushed:imagePushedAt,tags:imageTags}'
aws ecr describe-repositories --repository-names <repository> --profile <triage profile> --region <region> --query 'repositories[].{mutability:imageTagMutability,scanOnPush:imageScanningConfiguration.scanOnPush}'
aws ecr describe-image-scan-findings --repository-name <repository> --image-id imageTag=<tag> --max-items 20 --profile <triage profile> --region <region> --query 'imageScanFindings.findings[].{name:name,severity:severity}'
```
