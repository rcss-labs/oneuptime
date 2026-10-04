"""API Gateway collector: stages, throttling, deployments, and request metrics for REST and HTTP APIs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from triage.collectors import Collector
from triage.collectors.common import in_window, newest_in_window, parse_iso, was_not_found
from triage.context import CollectContext
from triage.evidence import CURRENT, INCIDENT_TIME
from triage.metrics import MetricSpec, add_metric_facts
from triage.window import format_time

FETCH_DEPLOYMENTS = "50"
MAX_DEPLOYMENTS = 5
NOT_FOUND = ("NotFoundException",)
REST_ERRORS = ("5XXError", "4XXError")
HTTP_ERRORS = ("5xx", "4xx")


@dataclass(frozen=True)
class Stage:
    name: str
    deployment_id: str | None
    updated: str | None
    throttling: str
    cache: str


@dataclass(frozen=True)
class Deployment:
    id: str | None
    created: str | None
    note: str


def _rate_text(rate: Any, burst: Any) -> str:
    return f"rate {rate} burst {burst}"


def _rest_throttling(stage: dict) -> str:
    settings = stage.get("methodSettings") or {}
    parts = [
        f"{key} {_rate_text(value.get('throttlingRateLimit'), value.get('throttlingBurstLimit'))}"
        for key, value in settings.items() if "throttlingRateLimit" in value or "throttlingBurstLimit" in value
    ]
    return ", ".join(parts) or "no throttling settings"


def _rest_cache(stage: dict) -> str:
    if stage.get("cacheClusterEnabled"):
        return f"cache enabled ({stage.get('cacheClusterStatus')})"
    return "cache disabled"


def _rest_stage(raw: dict) -> Stage:
    return Stage(
        raw.get("stageName", ""), raw.get("deploymentId"), raw.get("lastUpdatedDate"),
        _rest_throttling(raw), _rest_cache(raw),
    )


def _http_stage(raw: dict) -> Stage:
    defaults = raw.get("DefaultRouteSettings") or {}
    if "ThrottlingRateLimit" in defaults or "ThrottlingBurstLimit" in defaults:
        throttling = "default " + _rate_text(defaults.get("ThrottlingRateLimit"), defaults.get("ThrottlingBurstLimit"))
    else:
        throttling = "no throttling settings"
    return Stage(
        raw.get("StageName", ""), raw.get("DeploymentId"), raw.get("LastUpdatedDate"), throttling, "no cache setting",
    )


def _rest_deployment(raw: dict) -> Deployment:
    return Deployment(raw.get("id"), raw.get("createdDate"), raw.get("description") or "")


def _http_deployment(raw: dict) -> Deployment:
    return Deployment(
        raw.get("DeploymentId"), raw.get("CreatedDate"),
        raw.get("DeploymentStatusMessage") or raw.get("DeploymentStatus") or "",
    )


def _get_api_name(ctx: CollectContext, api_id: str, http: bool) -> tuple[str | None, bool]:
    """Return the API name (None when it could not be read) and whether the API does not exist."""
    if http:
        reply = ctx.aws("apigatewayv2", "get-api", ["--api-id", api_id], not_found=NOT_FOUND)
        name = (reply or {}).get("Name")
    else:
        reply = ctx.aws("apigateway", "get-rest-api", ["--rest-api-id", api_id], not_found=NOT_FOUND)
        name = (reply or {}).get("name")
    return name, reply is None and was_not_found(ctx, NOT_FOUND)


def _add_stage(ctx: CollectContext, resource: str, stage: Stage) -> None:
    updated = parse_iso(stage.updated)
    when = f", last updated {format_time(updated)}" if updated else ""
    inside = " and was updated inside the window" if in_window(ctx.window, stage.updated) else ""
    ctx.evidence.add(
        kind=CURRENT, resource=resource, command=ctx.last_command,
        summary=(
            f"Stage {stage.name} runs deployment {stage.deployment_id}{when}{inside}; "
            f"throttling {stage.throttling}; {stage.cache}"
        ),
    )


def _add_deployments(ctx: CollectContext, resource: str, deployments: list[Deployment]) -> None:
    for deployment in newest_in_window(ctx.window, deployments, lambda d: d.created, MAX_DEPLOYMENTS):
        ctx.evidence.add(
            kind=INCIDENT_TIME, resource=resource, time=deployment.created, command=ctx.last_command,
            summary=f"Deployment {deployment.id} was created", excerpt=deployment.note,
        )


def _metric_specs(stage: str, dimensions: dict[str, str], error_names: tuple[str, str]) -> list[MetricSpec]:
    pairs = [(error_names[0], "Sum"), (error_names[1], "Sum"), ("Latency", "Maximum"),
             ("IntegrationLatency", "Maximum"), ("Count", "Sum")]
    return [
        MetricSpec(f"{metric} {stage}", "AWS/ApiGateway", metric, {**dimensions, "Stage": stage}, stat)
        for metric, stat in pairs
    ]


def collect(ctx: CollectContext, targets: dict[str, str]) -> None:
    api_id = targets["api_id"]
    http = targets.get("kind", "rest") == "http"
    resource = f"apigateway/{api_id}"
    name, missing = _get_api_name(ctx, api_id, http)
    if missing:
        ctx.evidence.add(
            kind=CURRENT, resource=resource, command=ctx.last_command, summary=f"API {api_id} was not found",
        )
        return
    if http:
        stages_reply = ctx.aws("apigatewayv2", "get-stages", ["--api-id", api_id])
        stages = [_http_stage(s) for s in (stages_reply or {}).get("Items", [])]
        stage_command = ctx.last_command
        deployments_reply = ctx.aws("apigatewayv2", "get-deployments", ["--api-id", api_id, "--max-items", FETCH_DEPLOYMENTS])
        deployments = [_http_deployment(d) for d in (deployments_reply or {}).get("Items", [])]
        dimensions, error_names = {"ApiId": api_id}, HTTP_ERRORS
    else:
        stages_reply = ctx.aws("apigateway", "get-stages", ["--rest-api-id", api_id])
        stages = [_rest_stage(s) for s in (stages_reply or {}).get("item", [])]
        stage_command = ctx.last_command
        deployments_reply = ctx.aws(
            "apigateway", "get-deployments", ["--rest-api-id", api_id, "--max-items", FETCH_DEPLOYMENTS],
        )
        deployments = [_rest_deployment(d) for d in (deployments_reply or {}).get("items", [])]
        dimensions, error_names = {"ApiName": name or ""}, REST_ERRORS
    deployments_command = ctx.last_command
    if targets.get("stage"):
        stages = [stage for stage in stages if stage.name == targets["stage"]]
        if not stages and stages_reply is not None:
            ctx.evidence.add(
                kind=CURRENT, resource=resource, command=stage_command,
                summary=f"Stage {targets['stage']} was not found on API {api_id}",
            )
    ctx.last_command = stage_command
    for stage in stages:
        _add_stage(ctx, resource, stage)
    ctx.last_command = deployments_command
    _add_deployments(ctx, resource, deployments)
    if name is None and not http:
        return
    specs = [spec for stage in stages for spec in _metric_specs(stage.name, dimensions, error_names)]
    if specs:
        add_metric_facts(ctx, resource, specs)


COLLECTOR = Collector(
    name="apigateway",
    description="API Gateway stages, throttling, recent deployments, errors, and latency for REST and HTTP APIs",
    required=("api_id",),
    optional=("stage", "kind"),
    run=collect,
)
