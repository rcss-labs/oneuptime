from fakes import access_denied
from helpers import assert_read_only, make_context
from triage.collectors.ecr import COLLECTOR

IN_WINDOW = "2026-10-04T10:30:00+00:00"
OUTSIDE = "2026-10-01T09:00:00+00:00"
DIGEST = "sha256:" + "ab" * 32


def image(tags=("v42",), pushed=IN_WINDOW, digest=DIGEST, size=52428800):
    return {"registryId": "111111111111", "repositoryName": "checkout", "imageDigest": digest,
            "imageTags": list(tags), "imageSizeInBytes": size, "imagePushedAt": pushed}


def not_found(name):
    return 254, f"An error occurred ({name}) when calling the operation: not found"


def scan(counts):
    return {"imageScanStatus": {"status": "COMPLETE"}, "imageScanFindings": {"findingSeverityCounts": counts}}


def run(config_data, tmp_path, replies, **targets):
    ctx, aws, kube = make_context(config_data, tmp_path, replies, collector="ecr")
    COLLECTOR.run(ctx, {"repository": "checkout", **targets})
    return ctx, aws, kube


def with_text(ctx, text):
    return [f for f in ctx.evidence.facts if text in f.summary]


def test_declares_its_targets():
    assert COLLECTOR.name == "ecr"
    assert COLLECTOR.required == ("repository",)
    assert COLLECTOR.optional == ("image_tag", "image_digest")


def test_tagged_image_pushed_inside_the_window(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, {
        "ecr describe-images": {"imageDetails": [image()]},
        "ecr describe-image-scan-findings": scan({"CRITICAL": 2, "HIGH": 5}),
    }, image_tag="v42")
    pushed = ctx.evidence.facts[0]
    assert pushed.kind == "incident_time" and pushed.time == "2026-10-04T10:30:00Z"
    assert "v42" in pushed.summary and DIGEST in pushed.summary and "50.0 MiB" in pushed.summary
    assert "inside the incident window" in pushed.summary
    call = aws.called("ecr", "describe-images")[0]
    assert call[call.index("--image-ids") + 1] == "imageTag=v42"
    findings = with_text(ctx, "CRITICAL")[0]
    assert findings.kind == "current" and "CRITICAL 2" in findings.summary and "HIGH 5" in findings.summary
    assert ctx.evidence.errors == []
    assert_read_only(ctx, aws, kube)


def test_image_pushed_before_the_window_is_not_marked(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {
        "ecr describe-images": {"imageDetails": [image(pushed=OUTSIDE)]},
        "ecr describe-image-scan-findings": scan({}),
    }, image_tag="v42")
    assert "inside the incident window" not in ctx.evidence.facts[0].summary


def test_digest_target(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {
        "ecr describe-images": {"imageDetails": [image()]},
        "ecr describe-image-scan-findings": scan({"LOW": 1}),
    }, image_digest=DIGEST)
    call = aws.called("ecr", "describe-images")[0]
    assert call[call.index("--image-ids") + 1] == f"imageDigest={DIGEST}"
    scan_call = aws.called("ecr", "describe-image-scan-findings")[0]
    assert scan_call[scan_call.index("--image-id") + 1] == f"imageDigest={DIGEST}"


def test_missing_tag_is_a_fact_not_an_error(config_data, tmp_path):
    ctx, aws, _ = run(config_data, tmp_path, {
        "ecr describe-images": not_found("ImageNotFoundException")}, image_tag="v43")
    assert len(ctx.evidence.facts) == 1
    fact = ctx.evidence.facts[0]
    assert fact.kind == "current" and "does not exist" in fact.summary and "v43" in fact.summary
    assert "deployment" in fact.summary
    assert ctx.evidence.errors == []
    assert aws.called("ecr", "describe-image-scan-findings") == []


def test_empty_answer_for_a_tag_means_missing(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"ecr describe-images": {"imageDetails": []}}, image_tag="v43")
    assert "does not exist" in ctx.evidence.facts[0].summary


def test_missing_repository(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"ecr describe-images": not_found("RepositoryNotFoundException")})
    assert len(ctx.evidence.facts) == 1 and "not found" in ctx.evidence.facts[0].summary
    assert ctx.evidence.errors == []


def test_no_images_in_repository(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"ecr describe-images": {"imageDetails": []}})
    assert len(ctx.evidence.facts) == 1 and "no images" in ctx.evidence.facts[0].summary


def test_without_a_target_the_five_newest_are_listed(config_data, tmp_path):
    images = [image(tags=(f"v{n}",), pushed=f"2026-10-04T10:{n:02d}:00+00:00", digest="sha256:" + f"{n:02d}" * 32)
              for n in range(8)]
    ctx, aws, kube = run(config_data, tmp_path, {"ecr describe-images": {"imageDetails": images}})
    assert [f.summary.split("tags ")[1].split(",")[0] for f in ctx.evidence.facts] == ["v7", "v6", "v5", "v4", "v3"]
    call = aws.called("ecr", "describe-images")[0]
    assert call[call.index("--max-items") + 1] == "50"
    assert aws.called("ecr", "describe-image-scan-findings") == []
    assert_read_only(ctx, aws, kube)


def test_untagged_image(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {"ecr describe-images": {"imageDetails": [image(tags=())]}})
    assert "untagged" in ctx.evidence.facts[0].summary


def test_scan_not_available_is_a_fact(config_data, tmp_path):
    ctx, _, _ = run(config_data, tmp_path, {
        "ecr describe-images": {"imageDetails": [image()]},
        "ecr describe-image-scan-findings": not_found("ScanNotFoundException"),
    }, image_tag="v42")
    assert with_text(ctx, "no scan results")
    assert ctx.evidence.errors == []


def test_access_denied_on_scan_keeps_the_rest(config_data, tmp_path):
    ctx, aws, kube = run(config_data, tmp_path, {
        "ecr describe-images": {"imageDetails": [image()]},
        "ecr describe-image-scan-findings": access_denied("DescribeImageScanFindings"),
    }, image_tag="v42")
    assert len(ctx.evidence.errors) == 1 and ctx.evidence.errors[0]["code"] == "AccessDeniedException"
    assert with_text(ctx, "v42")
    assert_read_only(ctx, aws, kube)


def test_secret_looking_tag_never_reaches_the_document(config_data, tmp_path):
    secret = "AKIA" + "B" * 16
    ctx, _, _ = run(config_data, tmp_path, {"ecr describe-images": {"imageDetails": [image(tags=(secret,))]}})
    assert secret not in ctx.evidence.to_json()


def test_image_list_is_bounded_to_five_facts(config_data, tmp_path):
    images = [image(tags=(f"t{n}",), pushed=f"2026-10-04T10:{n:02d}:00+00:00") for n in range(50)]
    ctx, _, _ = run(config_data, tmp_path, {"ecr describe-images": {"imageDetails": images}})
    assert len(ctx.evidence.facts) == 5
