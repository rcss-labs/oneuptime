"""ECR collector: when images were pushed, whether a tag exists, and scan findings."""
from __future__ import annotations

from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, DERIVED, INCIDENT_TIME

MAX_ITEMS = "1000"
MAX_RECENT_IMAGES = 5
IMAGE_NOT_FOUND = "ImageNotFoundException"
REPOSITORY_NOT_FOUND = "RepositoryNotFoundException"
SCAN_NOT_FOUND = "ScanNotFoundException"


def _image_id(targets: dict[str, str]) -> str | None:
    if targets.get("image_tag"):
        return f"imageTag={targets['image_tag']}"
    if targets.get("image_digest"):
        return f"imageDigest={targets['image_digest']}"
    return None


def _size_text(size: Any) -> str:
    return f"{size / (1024 * 1024):.1f} MiB" if isinstance(size, (int, float)) else "unknown size"


def _add_image(ctx: CollectContext, repository: str, image: dict) -> None:
    tags = image.get("imageTags") or []
    tag_text = f"tags {', '.join(tags)}" if tags else "untagged"
    inside = " (pushed inside the incident window)" if in_window(ctx.window, image.get("imagePushedAt")) else ""
    ctx.evidence.add(
        kind=INCIDENT_TIME, resource=f"repository/{repository}", time=image.get("imagePushedAt"),
        command=ctx.last_command,
        summary=(
            f"Image pushed{inside}: {tag_text}, digest {image.get('imageDigest')}, "
            f"size {_size_text(image.get('imageSizeInBytes'))}"
        ),
        data={
            "tags": tags, "digest": image.get("imageDigest"), "size_bytes": image.get("imageSizeInBytes"),
            # Neither describe call returns the repository ARN or URI, so only the name and registry id are stated.
            "resource_id": repository,
            **({"registry_id": image["registryId"]} if image.get("registryId") else {}),
        },
    )


def _add_scan_findings(ctx: CollectContext, repository: str, image_id: str) -> None:
    resource = f"repository/{repository}"
    # The severity counts are on the first page; later pages only list individual findings.
    reply = ctx.aws(
        "ecr", "describe-image-scan-findings",
        ["--repository-name", repository, "--image-id", image_id, "--max-items", "1"], not_found=(SCAN_NOT_FOUND,),
    )
    if was_not_found(ctx, (SCAN_NOT_FOUND,)):
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Image {image_id} has no scan results",
        )
        return
    if reply is None:
        return
    counts = (reply.get("imageScanFindings") or {}).get("findingSeverityCounts") or {}
    status = (reply.get("imageScanStatus") or {}).get("status")
    counts_text = ", ".join(f"{severity} {count}" for severity, count in sorted(counts.items())) or "no findings"
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=f"Scan of image {image_id} ({status}): {counts_text}",
        data={"severity_counts": counts},
    )


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    repository = targets["repository"]
    resource = f"repository/{repository}"
    image_id = _image_id(targets)
    args = ["--repository-name", repository]
    args += ["--image-ids", image_id] if image_id else ["--max-items", MAX_ITEMS]
    reply = ctx.aws("ecr", "describe-images", args, not_found=(IMAGE_NOT_FOUND, REPOSITORY_NOT_FOUND))
    if was_not_found(ctx, (REPOSITORY_NOT_FOUND,)):
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Repository {repository} was not found in {ctx.region}",
        )
        return
    images = (reply or {}).get("imageDetails", [])
    if was_not_found(ctx, (IMAGE_NOT_FOUND,)) or (reply is not None and not images):
        if image_id:
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=(
                    f"Image {image_id.split('=', 1)[1]} does not exist in repository {repository} in {ctx.region}; "
                    "a missing image is a common cause of failed deployments"
                ),
            )
        else:
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=f"Repository {repository} has no images",
            )
        return
    if reply is None:
        return
    epoch = parse_iso("1970-01-01T00:00:00Z")
    images.sort(key=lambda image: parse_iso(image.get("imagePushedAt")) or epoch, reverse=True)
    for image in images[: 1 if image_id else MAX_RECENT_IMAGES]:
        _add_image(ctx, repository, image)
    if not image_id and (reply or {}).get("NextToken"):
        ctx.evidence.add(
            kind=DERIVED, resource=resource,
            summary=(
                f"Only {MAX_ITEMS} images were examined and the repository holds more images than that; "
                "a newer push may exist that is not listed"
            ),
        )
    if image_id:
        _add_scan_findings(ctx, repository, image_id)


COLLECTOR = Collector(
    name="ecr",
    description="ECR image push times, whether a tag or digest exists, and image scan severity counts",
    required=("repository",),
    optional=("image_tag", "image_digest"),
    run=collect,
)
