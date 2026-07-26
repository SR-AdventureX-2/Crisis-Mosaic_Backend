from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..domain.coordinates import haversine_m, normalize
from ..models import (
    BackgroundJob,
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    FactRecord,
    FactVersion,
    Incident,
    InformationFragment,
    Report,
)
from ..security import Actor
from ..utils import as_utc, isoformat, utcnow
from .conflicts import (
    detect_structured_fragment_conflict,
    fragment_snapshot,
    mark_analyses_stale,
    mark_fact_under_review,
)
from .events import emit_event, record_audit
from .map_features import (
    hide_blind_spot_map_feature,
    hide_conflict_map_feature,
    upsert_blind_spot_map_feature,
    upsert_conflict_map_feature,
    upsert_fragment_map_feature,
)

_ROAD_BLOCKED = re.compile(
    r"(?:\u65e0\u6cd5|\u4e0d\u80fd|\u4e0d\u53ef|\u7981\u6b62|\u4e2d\u65ad).{0,8}\u901a\u884c"
    r"|(?:\u9053\u8def|\u6865\u6881).{0,8}(?:\u5c01\u95ed|\u4e2d\u65ad)"
    r"|\u5c01\u8def|\b(?:blocked|closed|impassable)\b",
    re.IGNORECASE,
)
_ROAD_PASSABLE = re.compile(
    r"(?:(?<!\u4e0d)\u53ef|\u53ef\u4ee5|\u80fd\u591f|\u4ecd\u53ef|\u5c1a\u53ef|\u6062\u590d|\u6b63\u5e38|\u7f13\u6162).{0,8}\u901a\u884c"
    r"|(?:\u9053\u8def|\u6865\u6881).{0,8}(?:\u7545\u901a|\u5f00\u653e)"
    r"|\b(?:passable|open to traffic)\b",
    re.IGNORECASE,
)
_ROAD_RISK = re.compile(
    r"\u79ef\u6c34|\u584c\u65b9|\u843d\u77f3|\u8def\u9762.{0,6}(?:\u635f\u574f|\u584c\u9677|\u5f00\u88c2)"
    r"|(?:\u9053\u8def|\u6865\u6881).{0,6}(?:\u635f\u574f|\u5371\u9669|\u5f02\u5e38)"
    r"|\b(?:flood(?:ed|ing)?|landslide|road damage|bridge damage)\b",
    re.IGNORECASE,
)
_ROAD_FLOOD_ABSENT = re.compile(
    r"(?:\u6ca1\u6709|\u65e0|\u672a\u89c1|\u672a\u53d1\u73b0|\u5e76\u672a|\u5c1a\u672a|"
    r"\u4e0d\u5b58\u5728|\u5e76\u65e0).{0,4}\u79ef\u6c34"
    r"|\u79ef\u6c34.{0,6}(?:\u5df2\u9000|\u6d88\u9000|\u9000\u53bb|\u5df2\u6392\u9664)",
    re.IGNORECASE,
)
_ROAD_FLOOD_UNCERTAIN = re.compile(
    r"(?:\u662f\u5426|\u6709\u65e0|\u6709\u6ca1\u6709|\u4e0d\u786e\u5b9a|"
    r"\u4e0d\u77e5\u9053|\u672a\u77e5|\u5f85\u786e\u8ba4).{0,10}\u79ef\u6c34"
    r"|\u79ef\u6c34.{0,10}(?:\u662f\u5426|\u6709\u65e0|\u4e0d\u786e\u5b9a|"
    r"\u4e0d\u77e5\u9053|\u672a\u77e5|\u5f85\u786e\u8ba4|\u60c5\u51b5\u4e0d\u660e)",
    re.IGNORECASE,
)
_ROAD_FLOOD_PRESENT = re.compile(r"\u79ef\u6c34", re.IGNORECASE)
_ROAD_UNCERTAIN = re.compile(
    r"\u662f\u5426|\u80fd\u5426|\u80fd\u4e0d\u80fd|\u4e0d\u786e\u5b9a|\u4e0d\u77e5\u9053|\u672a\u77e5|\u5f85\u786e\u8ba4"
    r"|[\u5417\uff1f?]|\b(?:unknown|unclear|uncertain|not sure|whether)\b",
    re.IGNORECASE,
)
_ROAD_TOPIC = re.compile(
    r"\u901a\u884c|\u9053\u8def|\u6865\u6881|\u8def\u51b5|\b(?:road|bridge|passab)\w*\b",
    re.IGNORECASE,
)

_CATEGORY_LABELS = {
    "rescue": "\u6551\u63f4",
    "medical": "\u533b\u7597",
    "water": "\u996e\u6c34",
    "food": "\u98df\u7269",
    "shelter": "\u5b89\u7f6e",
    "road": "\u9053\u8def",
}


@dataclass(frozen=True)
class StructuredClaim:
    topic: str
    key: str
    value: str


def extract_structured_claim(report: Report) -> StructuredClaim | None:
    """Extract only narrow, explicit facts that are safe to compare automatically."""

    if report.category != "road":
        return None
    text = f"{report.content_original}\n{report.content_display}"
    if _ROAD_FLOOD_UNCERTAIN.search(text):
        return StructuredClaim(
            topic="road_flooding",
            key=_road_flooding_fact_key(report.location_text),
            value="unknown",
        )
    if _ROAD_UNCERTAIN.search(text) and _ROAD_TOPIC.search(text):
        return StructuredClaim(
            topic="road_passability",
            key=_road_fact_key(report.location_text),
            value="unknown",
        )
    blocked = bool(_ROAD_BLOCKED.search(text))
    passable = bool(_ROAD_PASSABLE.search(text))
    if blocked != passable:
        return StructuredClaim(
            topic="road_passability",
            key=_road_fact_key(report.location_text),
            value="blocked" if blocked else "passable",
        )
    flood_absent = bool(_ROAD_FLOOD_ABSENT.search(text))
    flood_present = bool(
        _ROAD_FLOOD_PRESENT.search(_ROAD_FLOOD_ABSENT.sub("", text))
    )
    if flood_absent != flood_present:
        return StructuredClaim(
            topic="road_flooding",
            key=_road_flooding_fact_key(report.location_text),
            value="absent" if flood_absent else "present",
        )
    if flood_absent or flood_present:
        return StructuredClaim(
            topic="road_flooding",
            key=_road_flooding_fact_key(report.location_text),
            value="unknown",
        )
    if blocked or passable or _ROAD_RISK.search(text):
        return StructuredClaim(
            topic="road_passability",
            key=_road_fact_key(report.location_text),
            value="unknown",
        )
    return None


def _normalized_location(value: str) -> str:
    return "".join(value.split()).casefold()


def _road_fact_key(location_text: str) -> str:
    location_hash = hashlib.sha256(_normalized_location(location_text).encode()).hexdigest()[:20]
    return f"road.passability:{location_hash}"


def _road_flooding_fact_key(location_text: str) -> str:
    location_hash = hashlib.sha256(_normalized_location(location_text).encode()).hexdigest()[:20]
    return f"road.flooding:{location_hash}"


def _same_location(
    *,
    first_latitude: float | None,
    first_longitude: float | None,
    first_coordinate_system: str | None,
    first_location_text: str,
    second_latitude: float | None,
    second_longitude: float | None,
    second_coordinate_system: str | None,
    second_location_text: str,
    radius_m: float,
) -> bool:
    first_has_position = (
        first_latitude is not None
        and first_longitude is not None
        and first_coordinate_system is not None
    )
    second_has_position = (
        second_latitude is not None
        and second_longitude is not None
        and second_coordinate_system is not None
    )
    if first_has_position and second_has_position:
        assert first_latitude is not None
        assert first_longitude is not None
        assert first_coordinate_system is not None
        assert second_latitude is not None
        assert second_longitude is not None
        assert second_coordinate_system is not None
        first = normalize(first_latitude, first_longitude, first_coordinate_system)
        second = normalize(second_latitude, second_longitude, second_coordinate_system)
        return (
            haversine_m(
                first.wgs84_latitude,
                first.wgs84_longitude,
                second.wgs84_latitude,
                second.wgs84_longitude,
            )
            <= radius_m
        )
    first_text = _normalized_location(first_location_text)
    return bool(first_text) and first_text == _normalized_location(second_location_text)


def _fragment_data(fragment: InformationFragment) -> dict[str, Any]:
    data = fragment_snapshot(fragment)
    data.update(
        {
            "incident_id": fragment.incident_id,
            "status": fragment.status,
            "received_at": isoformat(fragment.received_at),
            "created_at": isoformat(fragment.created_at),
            "updated_at": isoformat(fragment.updated_at),
        }
    )
    return data


def _blind_spot_data(blind_spot: BlindSpot) -> dict[str, Any]:
    return {
        "id": blind_spot.id,
        "incident_id": blind_spot.incident_id,
        "claim_key": blind_spot.claim_key,
        "title": blind_spot.title,
        "location_text": blind_spot.location_text,
        "latitude": blind_spot.latitude,
        "longitude": blind_spot.longitude,
        "coordinate_system": blind_spot.coordinate_system,
        "scope_type": blind_spot.scope_type,
        "scope_data": blind_spot.scope_data,
        "severity": blind_spot.severity,
        "route_impact_count": blind_spot.route_impact_count,
        "min_valid_answers": blind_spot.min_valid_answers,
        "status": blind_spot.status,
        "resolution_value": blind_spot.resolution_value,
        "revision": blind_spot.revision,
        "created_at": isoformat(blind_spot.created_at),
        "updated_at": isoformat(blind_spot.updated_at),
    }


async def _upsert_report_fragment(
    session: AsyncSession,
    report: Report,
    settings: Settings,
) -> tuple[InformationFragment, bool, bool]:
    claim = extract_structured_claim(report)
    observed_at = report.location_observed_at or report.updated_at or report.created_at
    received_at = report.updated_at or report.created_at
    values: dict[str, Any] = {
        "incident_id": report.incident_id,
        "source_type": "resident_report",
        "source_ref_id": report.id,
        "source_cluster_id": hmac.new(
            settings.installation_id_pepper.encode(),
            report.reporter_device_id.encode(),
            hashlib.sha256,
        ).hexdigest()[:36],
        "topic": claim.topic if claim else report.category,
        "claim_key": claim.key if claim else None,
        "claim_value": claim.value if claim else None,
        "label": (
            f"{_CATEGORY_LABELS.get(report.category, report.category)} · "
            f"{report.location_text}"
        )[:120],
        "description": report.content_display,
        "location_text": report.location_text,
        "latitude": report.latitude,
        "longitude": report.longitude,
        "coordinate_system": report.coordinate_system,
        "confidence": 0.7 if claim and claim.value != "unknown" else 0.3,
        "observed_at": observed_at,
        "received_at": received_at,
    }
    fragment = await session.scalar(
        select(InformationFragment).where(
            InformationFragment.incident_id == report.incident_id,
            InformationFragment.source_type == "resident_report",
            InformationFragment.source_ref_id == report.id,
        )
    )
    if fragment is None:
        fragment = InformationFragment(**values, status="normal")
        session.add(fragment)
        await session.flush()
        return fragment, True, True

    changed_fields = [name for name, value in values.items() if getattr(fragment, name) != value]
    reactivating = fragment.status == "withdrawn"
    if not changed_fields and not reactivating:
        return fragment, False, False
    if reactivating or set(changed_fields) & {
        "claim_key",
        "claim_value",
        "location_text",
        "latitude",
        "longitude",
        "coordinate_system",
        "observed_at",
    }:
        fragment.status = "normal"
    for name, value in values.items():
        setattr(fragment, name, value)
    fragment.revision += 1
    await session.flush()
    return fragment, False, True


def _grace_minutes(
    incident: Incident,
    settings: Settings,
    *,
    fragment: InformationFragment | None = None,
) -> int:
    if fragment is not None and _is_explicitly_uncertain(fragment):
        return 0
    override = (incident.feature_flags or {}).get("blind_spot_report_grace_minutes")
    if isinstance(override, int) and not isinstance(override, bool) and override >= 0:
        return override
    return settings.blind_spot_report_grace_minutes


def _is_explicitly_uncertain(fragment: InformationFragment) -> bool:
    text = fragment.description
    return bool(
        (fragment.topic == "road_flooding" and _ROAD_FLOOD_UNCERTAIN.search(text))
        or (
            fragment.topic == "road_passability"
            and _ROAD_UNCERTAIN.search(text)
            and _ROAD_TOPIC.search(text)
        )
    )


async def _ensure_blind_spot_job(
    session: AsyncSession,
    *,
    incident: Incident,
    fragment: InformationFragment,
    settings: Settings,
) -> None:
    if fragment.claim_value != "unknown":
        return
    jobs = list(
        (
            await session.scalars(
                select(BackgroundJob).where(
                    BackgroundJob.job_type == "blind_spot.detect",
                    BackgroundJob.payload["fragment_id"].as_string() == fragment.id,
                )
            )
        ).all()
    )
    if any(job.payload.get("fragment_revision") == fragment.revision for job in jobs):
        return
    grace_minutes = _grace_minutes(incident, settings, fragment=fragment)
    due_at = as_utc(fragment.received_at) + timedelta(minutes=grace_minutes)
    session.add(
        BackgroundJob(
            job_type="blind_spot.detect",
            status="queued",
            payload={
                "incident_id": incident.id,
                "fragment_id": fragment.id,
                "fragment_revision": fragment.revision,
                "grace_minutes": grace_minutes,
                "due_at": isoformat(due_at),
            },
            max_attempts=settings.job_max_attempts,
            run_after=due_at,
        )
    )


async def _cancel_blind_spot_jobs(
    session: AsyncSession,
    *,
    fragment: InformationFragment,
    keep_revision: int | None = None,
) -> None:
    jobs = list(
        (
            await session.scalars(
                select(BackgroundJob).where(
                    BackgroundJob.job_type == "blind_spot.detect",
                    BackgroundJob.payload["fragment_id"].as_string() == fragment.id,
                    BackgroundJob.status.in_(("queued", "retry", "running")),
                )
            )
        ).all()
    )
    for job in jobs:
        if keep_revision is not None and job.payload.get("fragment_revision") == keep_revision:
            continue
        job.status = "canceled"
        job.lease_expires_at = None
        job.last_error = "canceled because the source report observation changed"
        job.updated_at = utcnow()


async def _invalidate_fragment_evidence(
    session: AsyncSession,
    fragment: InformationFragment,
) -> tuple[list[ConflictCase], dict[str, set[str]]]:
    evidence = list(
        (
            await session.scalars(
                select(ConflictEvidence).where(
                    ConflictEvidence.kind == "fragment",
                    ConflictEvidence.source_id == fragment.id,
                    ConflictEvidence.is_current.is_(True),
                )
            )
        ).all()
    )
    if not evidence:
        return [], {}
    for item in evidence:
        item.is_current = False
    case_ids = {item.conflict_id for item in evidence}
    cases = list(
        (await session.scalars(select(ConflictCase).where(ConflictCase.id.in_(case_ids)))).all()
    )
    return cases, {
        case_id: {item.id for item in evidence if item.conflict_id == case_id}
        for case_id in case_ids
    }


def _evidence_source_identity(item: ConflictEvidence) -> tuple[str, str]:
    if item.source_cluster_id:
        return "cluster", item.source_cluster_id
    source_type = item.snapshot.get("source_type")
    source_ref_id = item.snapshot.get("source_ref_id")
    if isinstance(source_type, str) and isinstance(source_ref_id, str):
        return source_type, source_ref_id
    return item.kind, item.source_id


def _has_cross_source_contradiction(evidence: list[ConflictEvidence]) -> bool:
    comparable = [
        (item, item.snapshot.get("claim_value"))
        for item in evidence
        if item.kind == "fragment"
        and isinstance(item.snapshot.get("claim_value"), str)
        and str(item.snapshot["claim_value"]).casefold() != "unknown"
    ]
    return any(
        _evidence_source_identity(first) != _evidence_source_identity(second)
        and first_value != second_value
        for index, (first, first_value) in enumerate(comparable)
        for second, second_value in comparable[index + 1 :]
    )


async def _reconcile_conflicts(
    session: AsyncSession,
    *,
    incident: Incident,
    cases: list[ConflictCase],
    actor: Actor | None,
    request_id: str | None,
    withdrawn_evidence_by_case: dict[str, set[str]],
    revisions_before_withdrawal: dict[str, int],
) -> None:
    seen: set[str] = set()
    for case in cases:
        if case.id in seen:
            continue
        seen.add(case.id)
        withdrawn_ids = withdrawn_evidence_by_case.get(case.id, set())
        if withdrawn_ids:
            previous_revision = revisions_before_withdrawal.get(case.id, case.revision)
            if case.revision == previous_revision:
                case.revision += 1
            await mark_analyses_stale(session, case, "evidence_withdrawn")
            await record_audit(
                session,
                actor=actor,
                incident_id=incident.id,
                action="conflict.evidence_withdrawn",
                resource_type="conflict",
                resource_id=case.id,
                request_id=request_id,
                before={"revision": previous_revision},
                after={
                    "revision": case.revision,
                    "withdrawn_evidence_ids": sorted(withdrawn_ids),
                },
            )
            await emit_event(
                session,
                incident=incident,
                event_type="conflict.updated",
                resource_type="conflict",
                resource_id=case.id,
                resource_revision=case.revision,
                payload={
                    "conflict_id": case.id,
                    "reason": "evidence_withdrawn",
                    "withdrawn_evidence_ids": sorted(withdrawn_ids),
                },
                request_id=request_id,
            )
            fact = await session.scalar(
                select(FactRecord).where(
                    FactRecord.incident_id == case.incident_id,
                    FactRecord.fact_key == case.fact_key,
                )
            )
            version = (
                await session.get(FactVersion, fact.current_version_id)
                if fact is not None and fact.current_version_id
                else None
            )
            if (
                fact is not None
                and fact.status != "under_review"
                and version is not None
                and withdrawn_ids.intersection(version.accepted_evidence_ids)
            ):
                await mark_fact_under_review(
                    session,
                    case,
                    reason="accepted_evidence_withdrawn",
                )
                await record_audit(
                    session,
                    actor=actor,
                    incident_id=incident.id,
                    action="fact_record.under_review",
                    resource_type="fact",
                    resource_id=fact.id,
                    request_id=request_id,
                    after={"status": fact.status, "revision": fact.current_revision},
                )
                await emit_event(
                    session,
                    incident=incident,
                    event_type="fact_record.updated",
                    resource_type="fact",
                    resource_id=fact.id,
                    resource_revision=fact.current_revision,
                    payload={
                        "fact_record_id": fact.id,
                        "status": "under_review",
                        "reason": "accepted_evidence_withdrawn",
                    },
                    request_id=request_id,
                )
        current = list(
            (
                await session.scalars(
                    select(ConflictEvidence).where(
                        ConflictEvidence.conflict_id == case.id,
                        ConflictEvidence.is_current.is_(True),
                    )
                )
            ).all()
        )
        if any(item.kind != "fragment" for item in current):
            await upsert_conflict_map_feature(session, case)
            continue
        if _has_cross_source_contradiction(current):
            await upsert_conflict_map_feature(session, case)
            continue
        if case.status in {"resolved", "closed"}:
            await hide_conflict_map_feature(session, case)
            continue

        previous_status = case.status
        case.status = "resolved"
        case.resolved_at = utcnow()
        case.resolved_by = None
        case.resolution = {
            "reason": "insufficient_current_conflicting_sources",
            "automatic": True,
        }
        if not withdrawn_ids:
            case.revision += 1
            await mark_analyses_stale(
                session,
                case,
                "current_conflicting_evidence_withdrawn",
            )
        await hide_conflict_map_feature(session, case)

        source_ids = list(
            (
                await session.scalars(
                    select(ConflictEvidence.source_id).where(
                        ConflictEvidence.conflict_id == case.id,
                        ConflictEvidence.kind == "fragment",
                    )
                )
            ).all()
        )
        if source_ids:
            fragments = list(
                (
                    await session.scalars(
                        select(InformationFragment).where(InformationFragment.id.in_(source_ids))
                    )
                ).all()
            )
            for related in fragments:
                active_reference = await session.scalar(
                    select(ConflictEvidence.id)
                    .join(ConflictCase, ConflictCase.id == ConflictEvidence.conflict_id)
                    .where(
                        ConflictEvidence.kind == "fragment",
                        ConflictEvidence.source_id == related.id,
                        ConflictEvidence.is_current.is_(True),
                        ConflictCase.status.not_in(("resolved", "closed")),
                    )
                    .limit(1)
                )
                if active_reference is None and related.status == "conflict":
                    related.status = "normal"
                    related.revision += 1
                    await upsert_fragment_map_feature(session, related)

        await record_audit(
            session,
            actor=actor,
            incident_id=incident.id,
            action="conflict.auto_resolved",
            resource_type="conflict",
            resource_id=case.id,
            request_id=request_id,
            before={"status": previous_status},
            after={"status": case.status, "revision": case.revision},
        )
        await emit_event(
            session,
            incident=incident,
            event_type="conflict.resolved",
            resource_type="conflict",
            resource_id=case.id,
            resource_revision=case.revision,
            payload={
                "conflict_id": case.id,
                "reason": "insufficient_current_conflicting_sources",
            },
            request_id=request_id,
        )


async def _resolve_automatic_blind_spots(
    session: AsyncSession,
    *,
    incident: Incident,
    fragment: InformationFragment,
    conflict_case: ConflictCase | None,
    actor: Actor | None,
    request_id: str | None,
    settings: Settings,
) -> None:
    if not fragment.claim_key or fragment.claim_value in {None, "unknown"}:
        return
    blind_spots = list(
        (
            await session.scalars(
                select(BlindSpot).where(
                    BlindSpot.incident_id == incident.id,
                    BlindSpot.claim_key == fragment.claim_key,
                    BlindSpot.status.in_(("open", "reopened")),
                )
            )
        ).all()
    )
    for blind_spot in blind_spots:
        scope = blind_spot.scope_data or {}
        if scope.get("source") != "resident_report_gap" or not _same_location(
            first_latitude=fragment.latitude,
            first_longitude=fragment.longitude,
            first_coordinate_system=fragment.coordinate_system,
            first_location_text=fragment.location_text,
            second_latitude=blind_spot.latitude,
            second_longitude=blind_spot.longitude,
            second_coordinate_system=blind_spot.coordinate_system,
            second_location_text=blind_spot.location_text,
            radius_m=settings.conflict_radius_m,
        ):
            continue
        blind_spot.status = "resolved"
        blind_spot.resolution_value = (
            "conflicting_evidence" if conflict_case is not None else fragment.claim_value
        )
        blind_spot.scope_data = {
            **scope,
            "resolution_fragment_id": fragment.id,
        }
        blind_spot.revision += 1
        await upsert_blind_spot_map_feature(session, blind_spot)
        data = _blind_spot_data(blind_spot)
        await record_audit(
            session,
            actor=actor,
            incident_id=incident.id,
            action="blind_spot.resolved",
            resource_type="blind_spot",
            resource_id=blind_spot.id,
            request_id=request_id,
            after=data,
        )
        await emit_event(
            session,
            incident=incident,
            event_type="blind_spot.resolved",
            resource_type="blind_spot",
            resource_id=blind_spot.id,
            resource_revision=blind_spot.revision,
            payload=data,
            request_id=request_id,
        )


async def _report_fragment_is_active(
    session: AsyncSession,
    fragment: InformationFragment,
) -> bool:
    if fragment.status not in {"normal", "conflict", "resolved"}:
        return False
    if fragment.source_type != "resident_report":
        return True
    report = await session.get(Report, fragment.source_ref_id or "")
    return report is not None and report.deleted_at is None and report.status != "invalid"


async def _deactivate_automatic_blind_spots(
    session: AsyncSession,
    *,
    incident: Incident,
    fragment: InformationFragment,
    actor: Actor | None,
    request_id: str | None,
    reason: str,
    settings: Settings,
) -> None:
    blind_spots = list(
        (
            await session.scalars(
                select(BlindSpot).where(
                    BlindSpot.incident_id == incident.id,
                    BlindSpot.status.in_(("open", "reopened", "resolved")),
                )
            )
        ).all()
    )
    for blind_spot in blind_spots:
        scope = blind_spot.scope_data or {}
        if scope.get("source") != "resident_report_gap":
            continue
        is_origin = scope.get("origin_fragment_id") == fragment.id
        is_resolver = scope.get("resolution_fragment_id") == fragment.id
        if not is_origin and not is_resolver:
            continue

        resolver_still_equivalent = (
            is_resolver
            and blind_spot.status == "resolved"
            and fragment.claim_key == blind_spot.claim_key
            and fragment.claim_value == blind_spot.resolution_value
            and await _report_fragment_is_active(session, fragment)
            and _same_location(
                first_latitude=blind_spot.latitude,
                first_longitude=blind_spot.longitude,
                first_coordinate_system=blind_spot.coordinate_system,
                first_location_text=blind_spot.location_text,
                second_latitude=fragment.latitude,
                second_longitude=fragment.longitude,
                second_coordinate_system=fragment.coordinate_system,
                second_location_text=fragment.location_text,
                radius_m=settings.conflict_radius_m,
            )
        )
        if resolver_still_equivalent:
            continue

        possible_fragments = list(
            (
                await session.scalars(
                    select(InformationFragment).where(
                        InformationFragment.incident_id == incident.id,
                        InformationFragment.id != fragment.id,
                        InformationFragment.claim_key == blind_spot.claim_key,
                    )
                )
            ).all()
        )
        active_nearby: list[InformationFragment] = []
        for candidate in possible_fragments:
            if await _report_fragment_is_active(session, candidate) and _same_location(
                first_latitude=blind_spot.latitude,
                first_longitude=blind_spot.longitude,
                first_coordinate_system=blind_spot.coordinate_system,
                first_location_text=blind_spot.location_text,
                second_latitude=candidate.latitude,
                second_longitude=candidate.longitude,
                second_coordinate_system=candidate.coordinate_system,
                second_location_text=candidate.location_text,
                radius_m=settings.conflict_radius_m,
            ):
                active_nearby.append(candidate)

        if is_resolver and blind_spot.status == "resolved":
            concrete_replacement = next(
                (
                    candidate
                    for candidate in active_nearby
                    if candidate.claim_value not in {None, "unknown"}
                ),
                None,
            )
            if concrete_replacement is not None:
                blind_spot.resolution_value = concrete_replacement.claim_value
                blind_spot.scope_data = {
                    **scope,
                    "resolution_fragment_id": concrete_replacement.id,
                }
                blind_spot.revision += 1
                await upsert_blind_spot_map_feature(session, blind_spot)
                continue
            origin = await session.get(
                InformationFragment,
                str(scope.get("origin_fragment_id") or ""),
            )
            if (
                origin is not None
                and origin.claim_value == "unknown"
                and await _report_fragment_is_active(session, origin)
            ):
                blind_spot.status = "reopened"
                blind_spot.resolution_value = None
                blind_spot.scope_data = {
                    key: value
                    for key, value in scope.items()
                    if key != "resolution_fragment_id"
                }
                blind_spot.revision += 1
                await upsert_blind_spot_map_feature(session, blind_spot)
                await emit_event(
                    session,
                    incident=incident,
                    event_type="blind_spot.reopened",
                    resource_type="blind_spot",
                    resource_id=blind_spot.id,
                    resource_revision=blind_spot.revision,
                    payload={"blind_spot_id": blind_spot.id, "reason": reason},
                    request_id=request_id,
                )
                continue

        if not is_origin or blind_spot.status not in {"open", "reopened"}:
            continue
        fragment_still_unknown_here = (
            fragment.claim_key == blind_spot.claim_key
            and fragment.claim_value == "unknown"
            and await _report_fragment_is_active(session, fragment)
            and _same_location(
                first_latitude=blind_spot.latitude,
                first_longitude=blind_spot.longitude,
                first_coordinate_system=blind_spot.coordinate_system,
                first_location_text=blind_spot.location_text,
                second_latitude=fragment.latitude,
                second_longitude=fragment.longitude,
                second_coordinate_system=fragment.coordinate_system,
                second_location_text=fragment.location_text,
                radius_m=settings.conflict_radius_m,
            )
        )
        if fragment_still_unknown_here:
            continue
        if (
            fragment.claim_key == blind_spot.claim_key
            and fragment.claim_value not in {None, "unknown"}
            and await _report_fragment_is_active(session, fragment)
        ):
            blind_spot.status = "resolved"
            blind_spot.resolution_value = fragment.claim_value
            blind_spot.scope_data = {
                **scope,
                "resolution_fragment_id": fragment.id,
            }
            blind_spot.revision += 1
            await upsert_blind_spot_map_feature(session, blind_spot)
            continue

        unknown_replacement = next(
            (candidate for candidate in active_nearby if candidate.claim_value == "unknown"),
            None,
        )
        if unknown_replacement is not None:
            blind_spot.scope_data = {
                **scope,
                "origin_fragment_id": unknown_replacement.id,
            }
            blind_spot.revision += 1
            await upsert_blind_spot_map_feature(session, blind_spot)
            continue

        blind_spot.status = "resolved"
        blind_spot.resolution_value = reason
        blind_spot.revision += 1
        await hide_blind_spot_map_feature(session, blind_spot)
        data = _blind_spot_data(blind_spot)
        await record_audit(
            session,
            actor=actor,
            incident_id=incident.id,
            action="blind_spot.auto_resolved",
            resource_type="blind_spot",
            resource_id=blind_spot.id,
            request_id=request_id,
            after=data,
        )
        await emit_event(
            session,
            incident=incident,
            event_type="blind_spot.resolved",
            resource_type="blind_spot",
            resource_id=blind_spot.id,
            resource_revision=blind_spot.revision,
            payload={"blind_spot_id": blind_spot.id, "reason": reason},
            request_id=request_id,
        )


async def process_report_observation(
    session: AsyncSession,
    *,
    incident: Incident,
    report: Report,
    actor: Actor,
    request_id: str | None,
    settings: Settings | None = None,
) -> InformationFragment:
    settings = settings or get_settings()
    fragment, created, changed = await _upsert_report_fragment(session, report, settings)
    affected_cases: list[ConflictCase] = []
    withdrawn_evidence_by_case: dict[str, set[str]] = {}
    revisions_before_withdrawal: dict[str, int] = {}
    if changed and not created:
        affected_cases, withdrawn_evidence_by_case = await _invalidate_fragment_evidence(
            session,
            fragment,
        )
        revisions_before_withdrawal = {
            case.id: case.revision for case in affected_cases
        }
        await _deactivate_automatic_blind_spots(
            session,
            incident=incident,
            fragment=fragment,
            actor=actor,
            request_id=request_id,
            reason="source_report_updated",
            settings=settings,
        )
    if fragment.claim_value == "unknown":
        await _cancel_blind_spot_jobs(
            session,
            fragment=fragment,
            keep_revision=fragment.revision,
        )
        if _is_explicitly_uncertain(fragment):
            await run_report_blind_spot_detection(
                session,
                incident_id=incident.id,
                fragment_id=fragment.id,
                fragment_revision=fragment.revision,
                due_at=fragment.received_at,
                grace_minutes=0,
                settings=settings,
            )
        else:
            await _ensure_blind_spot_job(
                session,
                incident=incident,
                fragment=fragment,
                settings=settings,
            )
    else:
        await _cancel_blind_spot_jobs(session, fragment=fragment)
    if not changed:
        return fragment

    conflict_result = await detect_structured_fragment_conflict(session, fragment, settings)
    conflict_case = conflict_result[0] if conflict_result else None
    await upsert_fragment_map_feature(session, fragment)
    data = _fragment_data(fragment)
    await record_audit(
        session,
        actor=actor,
        incident_id=incident.id,
        action="fragment.created" if created else "fragment.updated",
        resource_type="fragment",
        resource_id=fragment.id,
        request_id=request_id,
        after=data,
    )
    await emit_event(
        session,
        incident=incident,
        event_type="fragment.created" if created else "fragment.updated",
        resource_type="fragment",
        resource_id=fragment.id,
        resource_revision=fragment.revision,
        payload=data,
        request_id=request_id,
    )
    if conflict_result is not None:
        conflict_case, opened = conflict_result
        affected_cases.append(conflict_case)
        await upsert_conflict_map_feature(session, conflict_case)
        source_ids = list(
            (
                await session.scalars(
                    select(ConflictEvidence.source_id).where(
                        ConflictEvidence.conflict_id == conflict_case.id,
                        ConflictEvidence.kind == "fragment",
                        ConflictEvidence.is_current.is_(True),
                    )
                )
            ).all()
        )
        if source_ids:
            conflict_fragments = list(
                (
                    await session.scalars(
                        select(InformationFragment).where(InformationFragment.id.in_(source_ids))
                    )
                ).all()
            )
            for conflict_fragment in conflict_fragments:
                await upsert_fragment_map_feature(session, conflict_fragment)
        if opened or conflict_case.id not in withdrawn_evidence_by_case:
            await emit_event(
                session,
                incident=incident,
                event_type="conflict.opened" if opened else "conflict.updated",
                resource_type="conflict",
                resource_id=conflict_case.id,
                resource_revision=conflict_case.revision,
                payload={
                    "conflict_id": conflict_case.id,
                    "fact_key": conflict_case.fact_key,
                    "source": "resident_reports",
                },
                request_id=request_id,
            )
    await _reconcile_conflicts(
        session,
        incident=incident,
        cases=affected_cases,
        actor=actor,
        request_id=request_id,
        withdrawn_evidence_by_case=withdrawn_evidence_by_case,
        revisions_before_withdrawal=revisions_before_withdrawal,
    )
    await _resolve_automatic_blind_spots(
        session,
        incident=incident,
        fragment=fragment,
        conflict_case=conflict_case,
        actor=actor,
        request_id=request_id,
        settings=settings,
    )
    return fragment


async def deactivate_report_observation(
    session: AsyncSession,
    *,
    incident: Incident,
    report: Report,
    actor: Actor,
    request_id: str | None,
    reason: str,
    settings: Settings | None = None,
) -> InformationFragment | None:
    settings = settings or get_settings()
    fragment = await session.scalar(
        select(InformationFragment).where(
            InformationFragment.incident_id == incident.id,
            InformationFragment.source_type == "resident_report",
            InformationFragment.source_ref_id == report.id,
        )
    )
    if fragment is None:
        return None
    affected_cases, withdrawn_evidence_by_case = await _invalidate_fragment_evidence(
        session,
        fragment,
    )
    revisions_before_withdrawal = {
        case.id: case.revision for case in affected_cases
    }
    await _cancel_blind_spot_jobs(session, fragment=fragment)
    if fragment.status != "withdrawn":
        fragment.status = "withdrawn"
        fragment.revision += 1
    await upsert_fragment_map_feature(session, fragment)
    await _deactivate_automatic_blind_spots(
        session,
        incident=incident,
        fragment=fragment,
        actor=actor,
        request_id=request_id,
        reason=reason,
        settings=settings,
    )
    await _reconcile_conflicts(
        session,
        incident=incident,
        cases=affected_cases,
        actor=actor,
        request_id=request_id,
        withdrawn_evidence_by_case=withdrawn_evidence_by_case,
        revisions_before_withdrawal=revisions_before_withdrawal,
    )
    data = _fragment_data(fragment)
    await record_audit(
        session,
        actor=actor,
        incident_id=incident.id,
        action="fragment.withdrawn",
        resource_type="fragment",
        resource_id=fragment.id,
        request_id=request_id,
        after={"reason": reason, "fragment": data},
    )
    await emit_event(
        session,
        incident=incident,
        event_type="fragment.withdrawn",
        resource_type="fragment",
        resource_id=fragment.id,
        resource_revision=fragment.revision,
        payload={"fragment_id": fragment.id, "reason": reason},
        request_id=request_id,
    )
    return fragment


async def run_report_blind_spot_detection(
    session: AsyncSession,
    *,
    incident_id: str,
    fragment_id: str,
    fragment_revision: int,
    due_at: datetime | None = None,
    grace_minutes: int | None = None,
    settings: Settings | None = None,
) -> BlindSpot | None:
    settings = settings or get_settings()
    incident = await session.get(Incident, incident_id)
    fragment = await session.get(InformationFragment, fragment_id)
    if (
        incident is None
        or incident.status != "active"
        or fragment is None
        or fragment.incident_id != incident.id
        or fragment.source_type != "resident_report"
        or fragment.revision != fragment_revision
        or not fragment.claim_key
        or fragment.claim_value != "unknown"
        or fragment.status not in {"normal", "conflict"}
    ):
        return None
    report = await session.get(Report, fragment.source_ref_id or "")
    if report is None or report.deleted_at is not None or report.status == "invalid":
        return None
    effective_grace_minutes = (
        grace_minutes
        if grace_minutes is not None
        else _grace_minutes(incident, settings, fragment=fragment)
    )
    effective_due_at = (
        as_utc(due_at)
        if due_at is not None
        else as_utc(fragment.received_at) + timedelta(minutes=effective_grace_minutes)
    )
    if utcnow() < effective_due_at:
        return None

    valid_fragments = list(
        (
            await session.scalars(
                select(InformationFragment).where(
                    InformationFragment.incident_id == incident.id,
                    InformationFragment.id != fragment.id,
                    InformationFragment.claim_key == fragment.claim_key,
                    InformationFragment.claim_value.is_not(None),
                    InformationFragment.claim_value != "unknown",
                    InformationFragment.status.in_(("normal", "conflict", "resolved")),
                    InformationFragment.received_at >= fragment.received_at,
                )
            )
        ).all()
    )
    for candidate in valid_fragments:
        if not await _report_fragment_is_active(session, candidate):
            continue
        if _same_location(
            first_latitude=fragment.latitude,
            first_longitude=fragment.longitude,
            first_coordinate_system=fragment.coordinate_system,
            first_location_text=fragment.location_text,
            second_latitude=candidate.latitude,
            second_longitude=candidate.longitude,
            second_coordinate_system=candidate.coordinate_system,
            second_location_text=candidate.location_text,
            radius_m=settings.conflict_radius_m,
        ):
            return None

    candidates = list(
        (
            await session.scalars(
                select(BlindSpot).where(
                    BlindSpot.incident_id == incident.id,
                    BlindSpot.claim_key == fragment.claim_key,
                )
            )
        ).all()
    )
    matching = next(
        (
            item
            for item in candidates
            if _same_location(
                first_latitude=fragment.latitude,
                first_longitude=fragment.longitude,
                first_coordinate_system=fragment.coordinate_system,
                first_location_text=fragment.location_text,
                second_latitude=item.latitude,
                second_longitude=item.longitude,
                second_coordinate_system=item.coordinate_system,
                second_location_text=item.location_text,
                radius_m=settings.conflict_radius_m,
            )
        ),
        None,
    )
    if matching is not None:
        if (matching.scope_data or {}).get("source") != "resident_report_gap":
            return None
        if matching.status in {"open", "reopened"}:
            return None
        matching.status = "reopened"
        matching.resolution_value = None
        matching.scope_data = {
            **(matching.scope_data or {}),
            "origin_fragment_id": fragment.id,
            "grace_minutes": effective_grace_minutes,
            "due_at": isoformat(effective_due_at),
        }
        matching.revision += 1
        blind_spot = matching
        event_type = "blind_spot.reopened"
    else:
        blind_spot = BlindSpot(
            incident_id=incident.id,
            claim_key=fragment.claim_key,
            title=f"{fragment.location_text} \u9053\u8def\u901a\u884c\u4fe1\u606f\u76f2\u533a",
            location_text=fragment.location_text,
            latitude=fragment.latitude,
            longitude=fragment.longitude,
            coordinate_system=fragment.coordinate_system,
            scope_type=("radius" if fragment.latitude is not None else "incident"),
            scope_data={
                "source": "resident_report_gap",
                "origin_fragment_id": fragment.id,
                "grace_minutes": effective_grace_minutes,
                "due_at": isoformat(effective_due_at),
                "radius_m": settings.conflict_radius_m,
            },
            severity="high" if report.is_urgent or report.priority == "high" else "medium",
            min_valid_answers=settings.directed_min_valid_answers,
            status="open",
        )
        session.add(blind_spot)
        await session.flush()
        event_type = "blind_spot.created"

    await upsert_blind_spot_map_feature(session, blind_spot)
    data = _blind_spot_data(blind_spot)
    await record_audit(
        session,
        actor=None,
        incident_id=incident.id,
        action=event_type,
        resource_type="blind_spot",
        resource_id=blind_spot.id,
        after=data,
    )
    await emit_event(
        session,
        incident=incident,
        event_type=event_type,
        resource_type="blind_spot",
        resource_id=blind_spot.id,
        resource_revision=blind_spot.revision,
        payload=data,
    )
    return blind_spot
