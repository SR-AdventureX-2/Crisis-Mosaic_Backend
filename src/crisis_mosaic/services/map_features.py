from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..domain.coordinates import normalize
from ..models import (
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    InformationFragment,
    MapFeature,
)


async def upsert_map_feature(
    session: AsyncSession,
    *,
    incident_id: str,
    kind: str,
    source_ref: str,
    title: str,
    status: str,
    severity: str,
    latitude: float | None,
    longitude: float | None,
    coordinate_system: str | None,
    revision: int,
    public_data: dict[str, Any],
    private_data: dict[str, Any] | None = None,
) -> MapFeature:
    feature = await session.scalar(
        select(MapFeature).where(
            MapFeature.incident_id == incident_id,
            MapFeature.kind == kind,
            MapFeature.source_ref == source_ref,
        )
    )
    if feature is None:
        feature = MapFeature(
            incident_id=incident_id,
            kind=kind,
            source_ref=source_ref,
            title=title,
            status=status,
            severity=severity,
        )
        session.add(feature)
    position = (
        normalize(latitude, longitude, coordinate_system)
        if latitude is not None and longitude is not None and coordinate_system is not None
        else None
    )
    feature.title = title
    feature.status = status
    feature.severity = severity
    feature.latitude_wgs84 = position.wgs84_latitude if position else None
    feature.longitude_wgs84 = position.wgs84_longitude if position else None
    feature.latitude_gcj02 = position.gcj02_latitude if position else None
    feature.longitude_gcj02 = position.gcj02_longitude if position else None
    feature.revision = revision
    feature.is_deleted = position is None
    feature.public_data = public_data
    feature.private_data = private_data or public_data
    return feature


async def hide_map_feature(
    session: AsyncSession,
    *,
    incident_id: str,
    kind: str,
    source_ref: str,
    revision: int,
    status: str,
) -> MapFeature | None:
    feature = await session.scalar(
        select(MapFeature).where(
            MapFeature.incident_id == incident_id,
            MapFeature.kind == kind,
            MapFeature.source_ref == source_ref,
        )
    )
    if feature is None:
        return None
    feature.status = status
    feature.revision = revision
    feature.is_deleted = True
    return feature


async def upsert_fragment_map_feature(
    session: AsyncSession, fragment: InformationFragment
) -> MapFeature | None:
    if fragment.source_type == "resident_report":
        return await hide_map_feature(
            session,
            incident_id=fragment.incident_id,
            kind="fragment",
            source_ref=fragment.id,
            revision=fragment.revision,
            status=fragment.status,
        )
    return await upsert_map_feature(
        session,
        incident_id=fragment.incident_id,
        kind="fragment",
        source_ref=fragment.id,
        title=fragment.label,
        status=fragment.status,
        severity="high" if fragment.status == "conflict" else "medium",
        latitude=fragment.latitude,
        longitude=fragment.longitude,
        coordinate_system=fragment.coordinate_system,
        revision=fragment.revision,
        public_data={
            "topic": fragment.topic,
            "confidence": fragment.confidence,
            "location_text": fragment.location_text,
        },
    )


async def hide_conflict_map_feature(
    session: AsyncSession,
    conflict: ConflictCase,
) -> MapFeature | None:
    return await hide_map_feature(
        session,
        incident_id=conflict.incident_id,
        kind="conflict",
        source_ref=conflict.id,
        revision=conflict.revision,
        status=conflict.status,
    )


async def hide_blind_spot_map_feature(
    session: AsyncSession,
    blind_spot: BlindSpot,
) -> MapFeature | None:
    return await hide_map_feature(
        session,
        incident_id=blind_spot.incident_id,
        kind="blind_spot",
        source_ref=blind_spot.id,
        revision=blind_spot.revision,
        status=blind_spot.status,
    )


async def upsert_blind_spot_map_feature(session: AsyncSession, blind_spot: BlindSpot) -> MapFeature:
    resident_report_derived = (
        (blind_spot.scope_data or {}).get("source") == "resident_report_gap"
    )
    return await upsert_map_feature(
        session,
        incident_id=blind_spot.incident_id,
        kind="blind_spot",
        source_ref=blind_spot.id,
        title=blind_spot.title,
        status=blind_spot.status,
        severity=blind_spot.severity,
        latitude=blind_spot.latitude,
        longitude=blind_spot.longitude,
        coordinate_system=blind_spot.coordinate_system,
        revision=blind_spot.revision,
        public_data={
            "fact_key": blind_spot.claim_key,
            "route_impact_count": blind_spot.route_impact_count,
            "location_text": blind_spot.location_text,
        },
        private_data={
            "fact_key": blind_spot.claim_key,
            "route_impact_count": blind_spot.route_impact_count,
            "location_text": blind_spot.location_text,
            "resident_report_derived": resident_report_derived,
        },
    )


async def upsert_conflict_map_feature(session: AsyncSession, conflict: ConflictCase) -> MapFeature:
    resident_report_evidence_id = await session.scalar(
        select(ConflictEvidence.id)
        .join(
            InformationFragment,
            InformationFragment.id == ConflictEvidence.source_id,
        )
        .where(
            ConflictEvidence.conflict_id == conflict.id,
            ConflictEvidence.kind == "fragment",
            InformationFragment.source_type == "resident_report",
        )
        .limit(1)
    )
    return await upsert_map_feature(
        session,
        incident_id=conflict.incident_id,
        kind="conflict",
        source_ref=conflict.id,
        title=conflict.title,
        status=conflict.status,
        severity=conflict.severity,
        latitude=conflict.latitude,
        longitude=conflict.longitude,
        coordinate_system=conflict.coordinate_system,
        revision=conflict.revision,
        public_data={
            "fact_key": conflict.fact_key,
            "topic": conflict.topic,
            "location_text": conflict.location_text,
        },
        private_data={
            "fact_key": conflict.fact_key,
            "topic": conflict.topic,
            "location_text": conflict.location_text,
            "resident_report_derived": resident_report_evidence_id is not None,
        },
    )
