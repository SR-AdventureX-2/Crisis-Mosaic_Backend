from __future__ import annotations

from datetime import datetime
from typing import Any

from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy import func, select

from .db import session_factory, write_lock
from .models import (
    AiAnalysis,
    BackgroundJob,
    BlindSpot,
    ConflictCase,
    DirectedAnswer,
    FactRecord,
    FactVersion,
    IdempotencyRecord,
    MapFeature,
    OutboxEvent,
    Report,
)
from .utils import as_utc, utcnow

HTTP_REQUESTS = Counter(
    "crisis_mosaic_http_requests_total",
    "HTTP requests handled by method, route template, and status.",
    ("method", "route", "status"),
)
HTTP_REQUEST_DURATION = Histogram(
    "crisis_mosaic_http_request_duration_seconds",
    "HTTP request duration by method and route template.",
    ("method", "route"),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 1.5, 2, 5, 10, 30),
)
BUSINESS_ERRORS = Counter(
    "crisis_mosaic_business_errors_total",
    "Structured API errors by stable error code.",
    ("code",),
)
IDEMPOTENCY_OUTCOMES = Counter(
    "crisis_mosaic_idempotency_outcomes_total",
    "Idempotency reservation and replay outcomes.",
    ("outcome",),
)

REALTIME_CONNECTIONS = Gauge(
    "crisis_mosaic_realtime_connections",
    "Current authenticated WebSocket connections.",
)
REALTIME_RECONNECTS = Counter(
    "crisis_mosaic_realtime_reconnects_total",
    "Authenticated WebSocket connections that supplied a replay cursor.",
)
REALTIME_REPLAY_EVENTS = Counter(
    "crisis_mosaic_realtime_replay_events_total",
    "Historical events replayed after WebSocket authentication.",
)
REALTIME_SLOW_CONSUMERS = Counter(
    "crisis_mosaic_realtime_slow_consumers_total",
    "WebSocket connections closed because their in-memory queue filled.",
)
OUTBOX_DELIVERIES = Counter(
    "crisis_mosaic_outbox_deliveries_total",
    "Outbox delivery attempts by outcome.",
    ("outcome",),
)
OUTBOX_DELIVERY_DELAY = Histogram(
    "crisis_mosaic_outbox_delivery_delay_seconds",
    "Delay from event creation to successful in-process delivery.",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300),
)
BACKGROUND_JOB_ATTEMPTS = Counter(
    "crisis_mosaic_background_job_attempts_total",
    "Persistent background job attempts by type and outcome.",
    ("job_type", "outcome"),
)
MAP_VIEW_POINTS = Histogram(
    "crisis_mosaic_map_view_points",
    "Number of exact map points returned per successful map-view request.",
    buckets=(0, 1, 5, 10, 25, 50, 100, 250, 500),
)
MAP_VIEW_REJECTIONS = Counter(
    "crisis_mosaic_map_view_rejections_total",
    "Map-view requests rejected by reason.",
    ("reason",),
)

REPORTS = Gauge(
    "crisis_mosaic_reports",
    "Current reports grouped by status and priority.",
    ("status", "priority"),
)
IDEMPOTENCY_RECORDS = Gauge(
    "crisis_mosaic_idempotency_records",
    "Current idempotency records grouped by completion state.",
    ("state",),
)
OUTBOX_BACKLOG = Gauge(
    "crisis_mosaic_outbox_backlog",
    "Unpublished outbox events.",
)
OUTBOX_OLDEST_AGE = Gauge(
    "crisis_mosaic_outbox_oldest_age_seconds",
    "Age of the oldest unpublished outbox event.",
)
BACKGROUND_JOBS = Gauge(
    "crisis_mosaic_background_jobs",
    "Persistent background jobs grouped by type and status.",
    ("job_type", "status"),
)
AI_ANALYSES = Gauge(
    "crisis_mosaic_ai_analyses",
    "Stored AI analyses grouped by type and status.",
    ("analysis_type", "status"),
)
AI_AVERAGE_LATENCY = Gauge(
    "crisis_mosaic_ai_average_latency_seconds",
    "Average completed model latency grouped by analysis type.",
    ("analysis_type",),
)
CONFLICTS = Gauge(
    "crisis_mosaic_conflicts",
    "Current conflict cases grouped by status.",
    ("status",),
)
CONFLICT_RESOLUTION_AVERAGE = Gauge(
    "crisis_mosaic_conflict_resolution_average_seconds",
    "Average elapsed time from conflict detection to resolution.",
)
BLIND_SPOTS = Gauge(
    "crisis_mosaic_blind_spots",
    "Current blind spots grouped by status.",
    ("status",),
)
BLIND_SPOT_FIRST_ANSWER_AVERAGE = Gauge(
    "crisis_mosaic_blind_spot_first_answer_average_seconds",
    "Average elapsed time from question publication to its first answer.",
)
MAP_FEATURES = Gauge(
    "crisis_mosaic_map_features",
    "Current non-deleted map features grouped by kind.",
    ("kind",),
)
MAP_AGGREGATION_RATIO = Gauge(
    "crisis_mosaic_map_aggregation_ratio",
    "Ratio of aggregated map results; the exact-point P0 intentionally remains zero.",
)
FACT_RECORDS = Gauge(
    "crisis_mosaic_fact_records",
    "Current fact records grouped by status.",
    ("status",),
)
FACT_VERSIONS = Gauge(
    "crisis_mosaic_fact_versions",
    "Stored append-only fact versions.",
)
SQLITE_WRITE_LOCK_HELD = Gauge(
    "crisis_mosaic_sqlite_write_lock_held",
    "Whether the single-process application write lock is currently held.",
)
METRICS_REFRESH_FAILURES = Counter(
    "crisis_mosaic_metrics_refresh_failures_total",
    "Failures while refreshing database-backed metrics.",
)


def observe_http_request(method: str, route: str, status_code: int, elapsed: float) -> None:
    HTTP_REQUESTS.labels(method=method, route=route, status=str(status_code)).inc()
    HTTP_REQUEST_DURATION.labels(method=method, route=route).observe(elapsed)


def observe_outbox_delivery(envelope: dict[str, Any]) -> None:
    OUTBOX_DELIVERIES.labels(outcome="succeeded").inc()
    occurred_at = envelope.get("occurred_at")
    if not isinstance(occurred_at, str):
        return
    try:
        occurred = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    except ValueError:
        return
    delay = max(0.0, (utcnow() - as_utc(occurred)).total_seconds())
    OUTBOX_DELIVERY_DELAY.observe(delay)


def _set_grouped(metric: Gauge, rows: list[tuple[Any, ...]]) -> None:
    metric.clear()
    for row in rows:
        *labels, value = row
        metric.labels(*(str(label) for label in labels)).set(float(value))


async def refresh_database_metrics() -> None:
    """Refresh low-cardinality gauges from the durable SQLite state."""

    async with session_factory()() as session:
        report_rows = list(
            (
                await session.execute(
                    select(Report.status, Report.priority, func.count(Report.id))
                    .where(Report.deleted_at.is_(None))
                    .group_by(Report.status, Report.priority)
                )
            ).tuples()
        )
        idempotency_rows = list(
            (
                await session.execute(
                    select(
                        func.count(IdempotencyRecord.id).filter(
                            IdempotencyRecord.response_body.is_not(None)
                        ),
                        func.count(IdempotencyRecord.id).filter(
                            IdempotencyRecord.response_body.is_(None)
                        ),
                    )
                )
            ).one()
        )
        outbox_count, oldest_outbox = (
            await session.execute(
                select(func.count(OutboxEvent.id), func.min(OutboxEvent.occurred_at)).where(
                    OutboxEvent.published_at.is_(None)
                )
            )
        ).one()
        job_rows = list(
            (
                await session.execute(
                    select(
                        BackgroundJob.job_type,
                        BackgroundJob.status,
                        func.count(BackgroundJob.id),
                    ).group_by(BackgroundJob.job_type, BackgroundJob.status)
                )
            ).tuples()
        )
        ai_rows = list(
            (
                await session.execute(
                    select(
                        AiAnalysis.analysis_type,
                        AiAnalysis.status,
                        func.count(AiAnalysis.id),
                    ).group_by(AiAnalysis.analysis_type, AiAnalysis.status)
                )
            ).tuples()
        )
        ai_latency_rows = list(
            (
                await session.execute(
                    select(
                        AiAnalysis.analysis_type,
                        func.avg(AiAnalysis.latency_ms),
                    )
                    .where(AiAnalysis.latency_ms.is_not(None))
                    .group_by(AiAnalysis.analysis_type)
                )
            ).tuples()
        )
        conflict_rows = list(
            (
                await session.execute(
                    select(ConflictCase.status, func.count(ConflictCase.id)).group_by(
                        ConflictCase.status
                    )
                )
            ).tuples()
        )
        resolved_conflicts = list(
            (
                await session.execute(
                    select(ConflictCase.detected_at, ConflictCase.resolved_at).where(
                        ConflictCase.resolved_at.is_not(None)
                    )
                )
            ).tuples()
        )
        blind_spot_rows = list(
            (
                await session.execute(
                    select(BlindSpot.status, func.count(BlindSpot.id)).group_by(BlindSpot.status)
                )
            ).tuples()
        )
        published_questions = list(
            (
                await session.execute(
                    select(OutboxEvent.resource_id, func.min(OutboxEvent.occurred_at))
                    .where(
                        OutboxEvent.event_type == "question.published",
                        OutboxEvent.resource_id.is_not(None),
                    )
                    .group_by(OutboxEvent.resource_id)
                )
            ).tuples()
        )
        first_answers = list(
            (
                await session.execute(
                    select(
                        DirectedAnswer.question_id,
                        func.min(DirectedAnswer.created_at),
                    ).group_by(DirectedAnswer.question_id)
                )
            ).tuples()
        )
        map_rows = list(
            (
                await session.execute(
                    select(MapFeature.kind, func.count(MapFeature.id))
                    .where(MapFeature.is_deleted.is_(False))
                    .group_by(MapFeature.kind)
                )
            ).tuples()
        )
        fact_rows = list(
            (
                await session.execute(
                    select(FactRecord.status, func.count(FactRecord.id)).group_by(FactRecord.status)
                )
            ).tuples()
        )
        fact_version_count = int(await session.scalar(select(func.count(FactVersion.id))) or 0)

    _set_grouped(REPORTS, report_rows)
    IDEMPOTENCY_RECORDS.labels(state="completed").set(float(idempotency_rows[0] or 0))
    IDEMPOTENCY_RECORDS.labels(state="in_progress").set(float(idempotency_rows[1] or 0))
    OUTBOX_BACKLOG.set(float(outbox_count or 0))
    if oldest_outbox is None:
        OUTBOX_OLDEST_AGE.set(0)
    else:
        OUTBOX_OLDEST_AGE.set(max(0.0, (utcnow() - as_utc(oldest_outbox)).total_seconds()))
    _set_grouped(BACKGROUND_JOBS, job_rows)
    _set_grouped(AI_ANALYSES, ai_rows)
    AI_AVERAGE_LATENCY.clear()
    for analysis_type, latency_ms in ai_latency_rows:
        AI_AVERAGE_LATENCY.labels(analysis_type=str(analysis_type)).set(
            float(latency_ms or 0) / 1000
        )
    _set_grouped(CONFLICTS, conflict_rows)
    conflict_durations = [
        max(0.0, (as_utc(resolved) - as_utc(detected)).total_seconds())
        for detected, resolved in resolved_conflicts
        if resolved is not None
    ]
    CONFLICT_RESOLUTION_AVERAGE.set(
        sum(conflict_durations) / len(conflict_durations) if conflict_durations else 0
    )
    _set_grouped(BLIND_SPOTS, blind_spot_rows)
    published_by_question = {
        str(question_id): as_utc(published_at)
        for question_id, published_at in published_questions
        if question_id is not None and published_at is not None
    }
    first_answer_durations = [
        max(
            0.0,
            (as_utc(answered_at) - published_by_question[str(question_id)]).total_seconds(),
        )
        for question_id, answered_at in first_answers
        if answered_at is not None and str(question_id) in published_by_question
    ]
    BLIND_SPOT_FIRST_ANSWER_AVERAGE.set(
        sum(first_answer_durations) / len(first_answer_durations) if first_answer_durations else 0
    )
    _set_grouped(MAP_FEATURES, map_rows)
    MAP_AGGREGATION_RATIO.set(0)
    _set_grouped(FACT_RECORDS, fact_rows)
    FACT_VERSIONS.set(fact_version_count)
    SQLITE_WRITE_LOCK_HELD.set(1 if write_lock.locked() else 0)
