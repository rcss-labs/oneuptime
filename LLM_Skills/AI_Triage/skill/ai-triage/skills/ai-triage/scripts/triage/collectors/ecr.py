"""ECR collector: when images were pushed, whether a tag exists, and scan findings."""
from __future__ import annotations

from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, parse_iso
from triage.context import CollectContext
from triage.evidence import CURRENT, INCIDENT_TIME

MAX_ITEMS = "50"
MAX_RECENT_IMAGES = 5
IMAGE_NOT_FOUND = "ImageNotFoundException"
REPOSITORY_NOT_FOUND = "RepositoryNotFoundException"
SCAN_NOT_FOUND = "ScanNotFoundException"


def _aws_expecting(ctx: CollectContext, args: list[str], operation: str, expected: set[str]) -> tuple[Any | None, str | None]:
    """Call ECR; an error code listed in expected is returned to the caller instead of staying an evidence error."""
    errors_before = len(ctx.evidence.errors)
    reply = ctx.aws("ecr", operation, args)
    if reply is None and len(ctx.evidence.errors) > errors_before:
        code = ctx.evidence.errors[-1]["code"]
        if code in expected:
            ctx.evidence.errors.pop()
            return None, code
    return reply, None


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
        data={"tags": tags, "digest": image.get("imageDigest"), "size_bytes": image.get("imageSizeInBytes")},
    )


def _add_scan_findings(ctx: CollectContext, repository: str, image_id: str) -> None:
    resource = f"repository/{repository}"
    reply, code = _aws_expecting(
        ctx, ["--repository-name", repository, "--image-id", image_id], "describe-image-scan-findings", {SCAN_NOT_FOUND},
    )
    if code:
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
    reply, code = _aws_expecting(ctx, args, "describe-images", {IMAGE_NOT_FOUND, REPOSITORY_NOT_FOUND})
    if code == REPOSITORY_NOT_FOUND:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command,
            summary=f"Repository {repository} was not found",
        )
        return
    images = (reply or {}).get("imageDetails", [])
    if code == IMAGE_NOT_FOUND or (reply is not None and not images):
        if image_id:
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=ctx.last_command,
                summary=(
                    f"Image {image_id.split('=', 1)[1]} does not exist in repository {repository}; "
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
    if image_id:
        _add_scan_findings(ctx, repository, image_id)


COLLECTOR = Collector(
    name="ecr",
    description="ECR image push times, whether a tag or digest exists, and image scan severity counts",
    required=("repository",),
    optional=("image_tag", "image_digest"),
    run=collect,
)
