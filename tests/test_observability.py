from __future__ import annotations

from prometheus_client import generate_latest

from crisis_mosaic.main import create_app
from crisis_mosaic.observability import (
    IDEMPOTENCY_OUTCOMES,
    MAP_VIEW_POINTS,
    OUTBOX_BACKLOG,
    REALTIME_CONNECTIONS,
    REPORTS,
    observe_http_request,
)


def test_metrics_openapi_declares_prometheus_text() -> None:
    operation = create_app().openapi()["paths"]["/api/v1/metrics"]["get"]
    content = operation["responses"]["200"]["content"]

    assert "text/plain" in content
    assert "application/json" not in content


def test_custom_operational_and_business_metrics_are_exported() -> None:
    observe_http_request("GET", "/api/v1/health/live", 200, 0.01)
    IDEMPOTENCY_OUTCOMES.labels(outcome="replayed").inc()
    REALTIME_CONNECTIONS.set(2)
    OUTBOX_BACKLOG.set(3)
    MAP_VIEW_POINTS.observe(4)
    REPORTS.labels(status="new", priority="high").set(1)

    try:
        payload = generate_latest().decode()

        assert 'crisis_mosaic_http_requests_total{method="GET"' in payload
        assert 'crisis_mosaic_idempotency_outcomes_total{outcome="replayed"}' in payload
        assert "crisis_mosaic_realtime_connections 2.0" in payload
        assert "crisis_mosaic_outbox_backlog 3.0" in payload
        assert "crisis_mosaic_map_view_points_count 1.0" in payload
        assert 'crisis_mosaic_reports{priority="high",status="new"} 1.0' in payload
    finally:
        REALTIME_CONNECTIONS.set(0)
        OUTBOX_BACKLOG.set(0)
        REPORTS.clear()
