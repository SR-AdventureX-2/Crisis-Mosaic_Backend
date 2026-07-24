from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ..config import get_settings
from ..db import check_database
from ..observability import METRICS_REFRESH_FAILURES, refresh_database_metrics
from ..responses import success

router = APIRouter(tags=["运行状态"])
logger = logging.getLogger(__name__)


@router.get("/health/live")
async def live(request: Request) -> dict[str, object]:
    return success({"status": "ok"}, request)


@router.get("/health/ready")
async def ready(request: Request, response: Response) -> dict[str, object]:
    settings = get_settings()
    database = await check_database()
    core_ready = database
    if not core_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return success(
        {
            "status": "ready" if core_ready else "not_ready",
            "checks": {
                "database": "ok" if database else "failed",
                "ai": "configured" if settings.ai_configured else "degraded_not_configured",
            },
            "limitations": {
                "deployment": "single_process_sqlite",
                "workers": 1,
                "production_sla_claimed": False,
            },
        },
        request,
    )


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    responses={
        200: {"description": "Prometheus process, HTTP, realtime, job, AI, and business metrics"}
    },
)
async def metrics() -> Response:
    try:
        await refresh_database_metrics()
    except Exception:
        METRICS_REFRESH_FAILURES.inc()
        logger.exception("failed to refresh database-backed metrics")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
