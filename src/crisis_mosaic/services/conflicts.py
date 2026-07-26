from __future__ import annotations

import re
from collections import Counter
from datetime import timedelta
from difflib import SequenceMatcher
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..domain.coordinates import haversine_m, normalize
from ..errors import ApiError, conflict, not_found
from ..models import (
    AiAnalysis,
    Attachment,
    ConflictCase,
    ConflictDecision,
    ConflictEvidence,
    DirectedAnswer,
    DirectedQuestion,
    FactRecord,
    FactVersion,
    InformationFragment,
    MapFeature,
    Report,
)
from ..schemas.conflicts import (
    ConflictDecisionRequest,
    EvidenceReference,
)
from ..security import Actor
from ..services.events import emit_event, record_audit
from ..services.map_features import (
    upsert_conflict_map_feature,
    upsert_fragment_map_feature,
)
from ..utils import as_utc, canonical_json, isoformat, sha256_text, utcnow

_NO_TEXT_VISION_PREFIX = "[vision_policy:no_text_v1]\n"
_ADDRESS_NOISE = re.compile(r"靠近|附近|周边|旁边|临近|位于")
_ADDRESS_NUMBERS = re.compile(r"\d+")


def _normalize_address(value: str) -> str:
    without_noise = _ADDRESS_NOISE.sub("", value.casefold())
    return "".join(character for character in without_noise if character.isalnum())


def _addresses_likely_same(first: str, second: str) -> bool:
    first_normalized = _normalize_address(first)
    second_normalized = _normalize_address(second)
    if not first_normalized or not second_normalized:
        return False
    if first_normalized == second_normalized:
        return True

    first_numbers = set(_ADDRESS_NUMBERS.findall(first_normalized))
    second_numbers = set(_ADDRESS_NUMBERS.findall(second_normalized))
    if first_numbers and second_numbers and first_numbers.isdisjoint(second_numbers):
        return False

    shorter, longer = sorted(
        (first_normalized, second_normalized),
        key=len,
    )
    if len(shorter) >= 6 and shorter in longer:
        return True
    return SequenceMatcher(
        None,
        first_normalized,
        second_normalized,
        autojunk=False,
    ).ratio() >= 0.72


def fragment_snapshot(fragment: InformationFragment) -> dict[str, Any]:
    return {
        "id": fragment.id,
        "revision": fragment.revision,
        "source_type": fragment.source_type,
        "source_ref_id": fragment.source_ref_id,
        "topic": fragment.topic,
        "claim_key": fragment.claim_key,
        "claim_value": fragment.claim_value,
        "label": fragment.label,
        "description": fragment.description,
        "location_text": fragment.location_text,
        "latitude": fragment.latitude,
        "longitude": fragment.longitude,
        "coordinate_system": fragment.coordinate_system,
        "confidence": fragment.confidence,
        "observed_at": isoformat(fragment.observed_at),
        "received_at": isoformat(fragment.received_at),
    }


def fragments_share_source(
    first: InformationFragment,
    second: InformationFragment,
) -> bool:
    if first.source_cluster_id and second.source_cluster_id:
        return first.source_cluster_id == second.source_cluster_id
    return (
        first.source_type == second.source_type
        and first.source_ref_id is not None
        and first.source_ref_id == second.source_ref_id
    )


async def evidence_snapshot(
    session: AsyncSession,
    reference: EvidenceReference,
    *,
    incident_id: str,
) -> tuple[int, str | None, dict[str, Any]]:
    model: type[InformationFragment | Report | Attachment | DirectedAnswer]
    if reference.kind == "fragment":
        model = InformationFragment
    elif reference.kind == "report":
        model = Report
    elif reference.kind == "attachment":
        model = Attachment
    else:
        model = DirectedAnswer
    row = await session.get(model, reference.source_id)
    if row is None:
        raise not_found("evidence source")
    if reference.kind == "fragment":
        fragment = row
        assert isinstance(fragment, InformationFragment)
        if fragment.incident_id != incident_id:
            raise ApiError(422, "CROSS_INCIDENT_EVIDENCE", "证据不属于当前事件")
        snapshot = fragment_snapshot(fragment)
        revision = fragment.revision
        cluster_id = fragment.source_cluster_id
    elif reference.kind == "report":
        report = row
        assert isinstance(report, Report)
        if report.incident_id != incident_id:
            raise ApiError(422, "CROSS_INCIDENT_EVIDENCE", "证据不属于当前事件")
        snapshot = {
            "id": report.id,
            "revision": report.revision,
            "category": report.category,
            "content_original": report.content_original,
            "content_display": report.content_display,
            "location_text": report.location_text,
            "latitude": report.latitude,
            "longitude": report.longitude,
            "coordinate_system": report.coordinate_system,
            "created_at": isoformat(report.created_at),
        }
        revision = report.revision
        cluster_id = None
    elif reference.kind == "attachment":
        attachment = row
        assert isinstance(attachment, Attachment)
        if attachment.incident_id != incident_id:
            raise ApiError(422, "CROSS_INCIDENT_EVIDENCE", "证据不属于当前事件")
        if attachment.metadata_status != "ready" or attachment.malware_scan_status not in {
            "clean",
            "fake_clean",
        }:
            raise ApiError(422, "ATTACHMENT_NOT_READY", "图片证据尚未通过安全处理")
        snapshot = {
            "id": attachment.id,
            "revision": 1,
            "report_id": attachment.report_id,
            "mime_type": attachment.mime_type,
            "sha256": attachment.sha256,
            "perceptual_hash": attachment.perceptual_hash,
            "vision_summary": (
                attachment.vision_summary.removeprefix(_NO_TEXT_VISION_PREFIX)
                if attachment.vision_summary
                and attachment.vision_summary.startswith(_NO_TEXT_VISION_PREFIX)
                else None
            ),
            "malware_scan_status": attachment.malware_scan_status,
            "created_at": isoformat(attachment.created_at),
        }
        revision = 1
        cluster_id = attachment.source_cluster_id
    else:
        answer = row
        assert isinstance(answer, DirectedAnswer)
        question = await session.get(DirectedQuestion, answer.question_id)
        if question is None or question.incident_id != incident_id:
            raise ApiError(422, "CROSS_INCIDENT_EVIDENCE", "证据不属于当前事件")
        snapshot = {
            "id": answer.id,
            "revision": answer.revision,
            "question_id": answer.question_id,
            "semantic_value": answer.semantic_value,
            "answer_text": answer.answer_text,
            "observed_latitude": answer.observed_latitude,
            "observed_longitude": answer.observed_longitude,
            "observed_coordinate_system": answer.observed_coordinate_system,
            "updated_at": isoformat(answer.updated_at),
        }
        revision = answer.revision
        cluster_id = None
    if reference.source_revision is not None and reference.source_revision != revision:
        raise conflict(
            "EVIDENCE_REVISION_CONFLICT",
            "evidence source revision is no longer current",
            {"current_revision": revision, "source_id": reference.source_id},
        )
    return revision, cluster_id, snapshot


async def add_evidence(
    session: AsyncSession,
    case: ConflictCase,
    references: list[EvidenceReference],
) -> list[ConflictEvidence]:
    added: list[ConflictEvidence] = []
    for reference in references:
        revision, cluster_id, snapshot = await evidence_snapshot(
            session,
            reference,
            incident_id=case.incident_id,
        )
        existing = await session.scalar(
            select(ConflictEvidence).where(
                ConflictEvidence.conflict_id == case.id,
                ConflictEvidence.kind == reference.kind,
                ConflictEvidence.source_id == reference.source_id,
                ConflictEvidence.source_revision == revision,
            )
        )
        if existing is not None:
            existing.is_current = True
            added.append(existing)
            continue
        previous = (
            await session.scalars(
                select(ConflictEvidence).where(
                    ConflictEvidence.conflict_id == case.id,
                    ConflictEvidence.kind == reference.kind,
                    ConflictEvidence.source_id == reference.source_id,
                    ConflictEvidence.is_current.is_(True),
                )
            )
        ).all()
        for old in previous:
            old.is_current = False
        item = ConflictEvidence(
            conflict_id=case.id,
            kind=reference.kind,
            source_id=reference.source_id,
            source_revision=revision,
            source_cluster_id=cluster_id,
            snapshot=snapshot,
            snapshot_sha256=sha256_text(canonical_json(snapshot)),
            is_current=True,
        )
        session.add(item)
        added.append(item)
    await session.flush()
    return added


async def mark_analyses_stale(session: AsyncSession, case: ConflictCase, reason: str) -> None:
    analyses = (
        await session.scalars(
            select(AiAnalysis).where(
                AiAnalysis.analysis_type == "conflict_analysis",
                AiAnalysis.incident_id == case.incident_id,
                AiAnalysis.is_stale.is_(False),
                AiAnalysis.input_snapshot["conflict_id"].as_string() == case.id,
            )
        )
    ).all()
    now = utcnow()
    for analysis in analyses:
        analysis.is_stale = True
        analysis.stale_at = now
        analysis.stale_reason = reason


async def find_or_open_structured_conflict(
    session: AsyncSession,
    *,
    incident_id: str,
    fact_key: str,
    title: str,
    topic: str,
    location_text: str,
    latitude: float | None,
    longitude: float | None,
    coordinate_system: str | None,
    fragments: list[InformationFragment],
) -> tuple[ConflictCase, bool]:
    settings = get_settings()
    candidate_fact_keys = {
        item.claim_key for item in fragments if item.claim_key is not None
    }
    candidate_fact_keys.add(fact_key)
    cases = list(
        (
            await session.scalars(
                select(ConflictCase)
                .where(
                    ConflictCase.incident_id == incident_id,
                    ConflictCase.fact_key.in_(candidate_fact_keys),
                )
                .order_by(ConflictCase.created_at.desc())
            )
        ).all()
    )
    case: ConflictCase | None = None
    for candidate in cases:
        if (
            latitude is not None
            and longitude is not None
            and coordinate_system is not None
            and candidate.latitude is not None
            and candidate.longitude is not None
            and candidate.coordinate_system is not None
        ):
            current = normalize(latitude, longitude, coordinate_system)
            previous = normalize(
                candidate.latitude,
                candidate.longitude,
                candidate.coordinate_system,
            )
            if (
                haversine_m(
                    current.wgs84_latitude,
                    current.wgs84_longitude,
                    previous.wgs84_latitude,
                    previous.wgs84_longitude,
                )
                > settings.conflict_radius_m
                and not _addresses_likely_same(candidate.location_text, location_text)
            ):
                continue
        elif not _addresses_likely_same(candidate.location_text, location_text):
            continue
        if utcnow() - as_utc(candidate.detected_at) > timedelta(
            hours=settings.conflict_window_hours
        ):
            continue
        case = candidate
        break
    opened = False
    existed = case is not None
    if case is None:
        case = ConflictCase(
            incident_id=incident_id,
            fact_key=fact_key,
            title=title,
            topic=topic,
            location_text=location_text,
            latitude=latitude,
            longitude=longitude,
            coordinate_system=coordinate_system,
            status="open",
            severity="high",
        )
        session.add(case)
        await session.flush()
        opened = True
    elif case.status == "resolved":
        case.status = "reopened"
        case.resolved_at = None
        case.resolved_by = None
        case.resolution = None
        case.revision += 1
        opened = True
        await mark_analyses_stale(session, case, "conflict_reopened_with_new_evidence")
        await mark_fact_under_review(session, case)
    references = [
        EvidenceReference(
            kind="fragment",
            source_id=item.id,
            source_revision=item.revision,
        )
        for item in fragments
    ]
    existing_rows = (
        await session.execute(
            select(
                ConflictEvidence.kind,
                ConflictEvidence.source_id,
                ConflictEvidence.source_revision,
            ).where(ConflictEvidence.conflict_id == case.id)
        )
    ).all()
    existing_versions = {
        (str(kind), str(source_id), int(source_revision))
        for kind, source_id, source_revision in existing_rows
    }
    await add_evidence(session, case, references)
    has_new_snapshot = any(
        ("fragment", item.id, item.revision) not in existing_versions for item in fragments
    )
    if existed and has_new_snapshot and not opened:
        case.revision += 1
        await mark_analyses_stale(session, case, "evidence_updated")
    for item in fragments:
        item.status = "conflict"
    return case, opened


async def detect_structured_fragment_conflict(
    session: AsyncSession,
    fragment: InformationFragment,
    settings: Settings | None = None,
) -> tuple[ConflictCase, bool] | None:
    """Detect contradictory structured claims within the configured time/radius window."""

    settings = settings or get_settings()
    fragment_location = _normalize_address(fragment.location_text)
    fragment_has_position = (
        fragment.latitude is not None
        and fragment.longitude is not None
        and fragment.coordinate_system is not None
    )
    if (
        not fragment.claim_key
        or not fragment.claim_value
        or fragment.claim_value.strip().lower() == "unknown"
        or (not fragment_has_position and not fragment_location)
    ):
        return None
    candidates = list(
        (
            await session.scalars(
                select(InformationFragment).where(
                    InformationFragment.incident_id == fragment.incident_id,
                    InformationFragment.id != fragment.id,
                    InformationFragment.topic == fragment.topic,
                    InformationFragment.claim_value.is_not(None),
                    InformationFragment.claim_value != fragment.claim_value,
                    InformationFragment.status.in_(("normal", "conflict")),
                )
            )
        ).all()
    )
    current_time = as_utc(fragment.observed_at or fragment.received_at)
    current = None
    if fragment_has_position:
        assert fragment.latitude is not None
        assert fragment.longitude is not None
        assert fragment.coordinate_system is not None
        current = normalize(
            fragment.latitude,
            fragment.longitude,
            fragment.coordinate_system,
        )
    matching: list[InformationFragment] = []
    for candidate in candidates:
        if fragments_share_source(fragment, candidate):
            continue
        if not candidate.claim_value or candidate.claim_value.strip().lower() == "unknown":
            continue
        candidate_time = as_utc(candidate.observed_at or candidate.received_at)
        if abs(current_time - candidate_time) > timedelta(hours=settings.conflict_window_hours):
            continue
        candidate_has_position = (
            candidate.latitude is not None
            and candidate.longitude is not None
            and candidate.coordinate_system is not None
        )
        if current is not None and candidate_has_position:
            assert candidate.latitude is not None
            assert candidate.longitude is not None
            assert candidate.coordinate_system is not None
            previous = normalize(
                candidate.latitude,
                candidate.longitude,
                candidate.coordinate_system,
            )
            if (
                haversine_m(
                    current.wgs84_latitude,
                    current.wgs84_longitude,
                    previous.wgs84_latitude,
                    previous.wgs84_longitude,
                )
                > settings.conflict_radius_m
                and not _addresses_likely_same(
                    candidate.location_text,
                    fragment.location_text,
                )
            ):
                continue
        elif not _addresses_likely_same(candidate.location_text, fragment.location_text):
            continue
        matching.append(candidate)
    if not matching:
        return None
    return await find_or_open_structured_conflict(
        session,
        incident_id=fragment.incident_id,
        fact_key=fragment.claim_key,
        title=f"{fragment.label} 信息冲突",
        topic=fragment.topic,
        location_text=fragment.location_text,
        latitude=fragment.latitude,
        longitude=fragment.longitude,
        coordinate_system=fragment.coordinate_system,
        fragments=[*matching, fragment],
    )


async def mark_fact_under_review(
    session: AsyncSession,
    case: ConflictCase,
    reason: str = "conflict_reopened",
) -> FactRecord | None:
    fact = await session.scalar(
        select(FactRecord).where(
            FactRecord.incident_id == case.incident_id,
            FactRecord.fact_key == case.fact_key,
        )
    )
    if fact is None or fact.status == "under_review":
        return fact
    previous = (
        await session.scalar(select(FactVersion).where(FactVersion.id == fact.current_version_id))
        if fact.current_version_id
        else None
    )
    if previous is not None:
        previous.valid_to = utcnow()
    version = FactVersion(
        fact_record_id=fact.id,
        previous_version_id=fact.current_version_id,
        revision=fact.current_revision + 1,
        status="under_review",
        statement=previous.statement if previous else "New evidence requires review",
        confidence=previous.confidence if previous else None,
        source_conflict_id=case.id,
        source_analysis_id=None,
        context_snapshot={"reason": reason, "conflict_revision": case.revision},
        accepted_evidence_ids=[],
        decision_snapshot={"automatic_transition": "under_review"},
        decided_by="system",
    )
    session.add(version)
    await session.flush()
    fact.status = "under_review"
    fact.is_public = False
    fact.current_revision = version.revision
    fact.current_version_id = version.id
    feature = await session.scalar(
        select(MapFeature).where(
            MapFeature.incident_id == case.incident_id,
            MapFeature.kind == "fact",
            MapFeature.source_ref == fact.id,
        )
    )
    if feature is not None:
        feature.status = "under_review"
        feature.revision = version.revision
        feature.public_data = {}
        feature.private_data = {
            **(feature.private_data or {}),
            "fact_revision": version.revision,
        }
    return fact


async def valid_answer_consensus(
    session: AsyncSession, question_id: str
) -> tuple[str | None, int, set[str]]:
    answers = (
        await session.scalars(
            select(DirectedAnswer).where(DirectedAnswer.question_id == question_id)
        )
    ).all()
    values = [
        item.semantic_value for item in answers if item.semantic_value.strip().lower() != "unknown"
    ]
    counts = Counter(values)
    if not counts:
        return None, 0, set()
    value, count = counts.most_common(1)[0]
    return value, count, set(counts)


async def decide_conflict(
    session: AsyncSession,
    *,
    case: ConflictCase,
    payload: ConflictDecisionRequest,
    actor: Actor,
    request_id: str | None,
) -> tuple[ConflictDecision, FactRecord, FactVersion, list[str]]:
    if case.revision != payload.revision:
        raise conflict(
            "REVISION_CONFLICT",
            "conflict revision does not match",
            {"current_revision": case.revision},
        )
    if case.status == "resolved":
        raise conflict("CONFLICT_ALREADY_RESOLVED", "conflict is already resolved")
    evidence = (
        await session.scalars(
            select(ConflictEvidence).where(
                ConflictEvidence.conflict_id == case.id,
                ConflictEvidence.is_current.is_(True),
            )
        )
    ).all()
    evidence_ids = {item.id for item in evidence}
    submitted_ids = {item.evidence_id for item in payload.evidence_decisions}
    if submitted_ids != evidence_ids:
        raise ApiError(
            422,
            "INCOMPLETE_EVIDENCE_DISPOSITION",
            "every current evidence item must be explicitly disposed",
            details={
                "missing_evidence_ids": sorted(evidence_ids - submitted_ids),
                "unknown_evidence_ids": sorted(submitted_ids - evidence_ids),
            },
        )
    analysis: AiAnalysis | None = None
    if payload.analysis_id:
        analysis = await session.get(AiAnalysis, payload.analysis_id)
        if (
            analysis is None
            or analysis.incident_id != case.incident_id
            or analysis.analysis_type != "conflict_analysis"
            or analysis.status != "succeeded"
            or str(analysis.input_snapshot.get("conflict_id", "")) != case.id
        ):
            raise ApiError(422, "INVALID_AI_ANALYSIS", "AI analysis is not usable")
        if analysis.is_stale or analysis.input_version != case.revision:
            raise conflict("AI_ANALYSIS_STALE", "AI analysis is stale")
    accepted_ids = [
        item.evidence_id for item in payload.evidence_decisions if item.disposition == "accepted"
    ]
    decision = ConflictDecision(
        conflict_id=case.id,
        conflict_revision=case.revision,
        analysis_id=analysis.id if analysis else None,
        evidence_decisions=[item.model_dump(mode="json") for item in payload.evidence_decisions],
        conclusion=payload.conclusion,
        note=payload.note,
        decided_by=actor.subject_id,
    )
    session.add(decision)
    fact = await session.scalar(
        select(FactRecord).where(
            FactRecord.incident_id == case.incident_id,
            FactRecord.fact_key == case.fact_key,
        )
    )
    created = fact is None
    if fact is None:
        if payload.expected_fact_revision != 0:
            raise conflict(
                "FACT_REVISION_CONFLICT",
                "fact record does not exist",
                {"current_revision": 0},
            )
        fact = FactRecord(
            incident_id=case.incident_id,
            fact_key=case.fact_key,
            topic=case.topic,
            location_text=case.location_text,
            latitude=case.latitude,
            longitude=case.longitude,
            coordinate_system=case.coordinate_system,
            current_revision=0,
            status=payload.fact_status,
            is_public=payload.is_public,
        )
        session.add(fact)
        await session.flush()
    elif fact.current_revision != payload.expected_fact_revision:
        raise conflict(
            "FACT_REVISION_CONFLICT",
            "fact revision does not match",
            {"current_revision": fact.current_revision},
        )
    previous = (
        await session.get(FactVersion, fact.current_version_id) if fact.current_version_id else None
    )
    if previous is not None:
        previous.valid_to = utcnow()
    version = FactVersion(
        fact_record_id=fact.id,
        previous_version_id=fact.current_version_id,
        revision=fact.current_revision + 1,
        status=payload.fact_status,
        statement=payload.conclusion,
        confidence=payload.confidence,
        source_conflict_id=case.id,
        source_analysis_id=analysis.id if analysis else None,
        context_snapshot=analysis.context_package if analysis else None,
        accepted_evidence_ids=accepted_ids,
        decision_snapshot=payload.model_dump(mode="json"),
        decided_by=actor.subject_id,
    )
    session.add(version)
    await session.flush()
    fact.current_version_id = version.id
    fact.current_revision = version.revision
    fact.status = payload.fact_status
    fact.is_public = payload.is_public
    case.status = "resolved"
    case.resolved_at = utcnow()
    case.resolved_by = actor.subject_id
    case.resolution = {
        "decision_id": decision.id,
        "conclusion": payload.conclusion,
        "accepted_evidence_ids": accepted_ids,
        "analysis_id": analysis.id if analysis else None,
    }
    case.revision += 1
    await upsert_conflict_map_feature(session, case)
    dispositions = {item.evidence_id: item.disposition for item in payload.evidence_decisions}
    for item in evidence:
        if item.kind != "fragment":
            continue
        fragment = await session.get(InformationFragment, item.source_id)
        if fragment is None:
            continue
        fragment.status = "resolved" if dispositions[item.id] == "accepted" else "normal"
        fragment.revision += 1
        await upsert_fragment_map_feature(session, fragment)
    feature = await session.scalar(
        select(MapFeature).where(
            MapFeature.incident_id == case.incident_id,
            MapFeature.kind == "fact",
            MapFeature.source_ref == fact.id,
        )
    )
    feature_data = {
        "fact_record_id": fact.id,
        "fact_key": fact.fact_key,
        "statement": payload.conclusion,
        "fact_revision": version.revision,
        "source_conflict_id": case.id,
    }
    normalized = (
        normalize(case.latitude, case.longitude, case.coordinate_system)
        if case.latitude is not None
        and case.longitude is not None
        and case.coordinate_system is not None
        else None
    )
    if feature is None:
        feature = MapFeature(
            incident_id=case.incident_id,
            kind="fact",
            source_ref=fact.id,
            title=case.title,
            status=payload.fact_status,
            severity=case.severity,
            latitude_wgs84=normalized.wgs84_latitude if normalized else None,
            longitude_wgs84=normalized.wgs84_longitude if normalized else None,
            latitude_gcj02=normalized.gcj02_latitude if normalized else None,
            longitude_gcj02=normalized.gcj02_longitude if normalized else None,
            revision=version.revision,
            is_deleted=False,
            public_data=feature_data if payload.is_public else {},
            private_data=feature_data,
        )
        session.add(feature)
    else:
        feature.title = case.title
        feature.status = payload.fact_status
        feature.latitude_wgs84 = normalized.wgs84_latitude if normalized else None
        feature.longitude_wgs84 = normalized.wgs84_longitude if normalized else None
        feature.latitude_gcj02 = normalized.gcj02_latitude if normalized else None
        feature.longitude_gcj02 = normalized.gcj02_longitude if normalized else None
        feature.revision = version.revision
        feature.is_deleted = False
        feature.public_data = feature_data if payload.is_public else {}
        feature.private_data = feature_data
    await record_audit(
        session,
        actor=actor,
        incident_id=case.incident_id,
        action="conflict.decided",
        resource_type="conflict",
        resource_id=case.id,
        request_id=request_id,
        before={"revision": payload.revision, "status": "open"},
        after={
            "revision": case.revision,
            "status": case.status,
            "fact_record_id": fact.id,
            "fact_revision": version.revision,
        },
        metadata={"decision_id": decision.id, "analysis_id": payload.analysis_id},
    )
    from ..models import Incident

    incident = await session.get(Incident, case.incident_id)
    if incident is None:
        raise not_found("incident")
    event_ids: list[str] = []
    resolved_event = await emit_event(
        session,
        incident=incident,
        event_type="conflict.resolved",
        resource_type="conflict",
        resource_id=case.id,
        resource_revision=case.revision,
        payload={
            "conflict_id": case.id,
            "fact_record_id": fact.id,
            "fact_record_revision": version.revision,
        },
        visibility="public" if payload.is_public else "operators",
    )
    fact_event = await emit_event(
        session,
        incident=incident,
        event_type="fact_record.created" if created else "fact_record.updated",
        resource_type="fact",
        resource_id=fact.id,
        resource_revision=version.revision,
        payload=feature_data,
        visibility="public" if payload.is_public else "operators",
    )
    await session.flush()
    event_ids.extend([resolved_event.id, fact_event.id])
    return decision, fact, version, event_ids
