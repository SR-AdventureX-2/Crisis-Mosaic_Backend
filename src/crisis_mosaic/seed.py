from __future__ import annotations

from sqlalchemy import select

from .config import get_settings
from .db import configure_database, session_factory, write_lock
from .models import (
    BlindSpot,
    ConflictCase,
    ConflictEvidence,
    DirectedQuestion,
    Incident,
    IncidentMembership,
    InformationFragment,
    LocalAccount,
    MapFeature,
)
from .security import hash_password
from .utils import canonical_json, sha256_text


async def seed_demo() -> dict[str, str]:
    settings = get_settings()
    configure_database(settings)
    async with write_lock, session_factory()() as session:
        incident = await session.scalar(
            select(Incident).where(Incident.alias == "demo-hangzhou-flood")
        )
        if incident is None:
            active_exists = await session.scalar(
                select(Incident.id).where(Incident.status == "active")
            )
            incident = Incident(
                alias="demo-hangzhou-flood",
                name="杭州洪灾",
                type="flood",
                status="preparing" if active_exists else "active",
                center_latitude=settings.map_default_latitude,
                center_longitude=settings.map_default_longitude,
                map_coordinate_system="gcj02",
                map_default_zoom=settings.map_default_zoom,
                timezone="Asia/Shanghai",
                feature_flags={
                    "ai_report_refinement": True,
                    "ai_command_brief": True,
                    "directed_questions": True,
                    "amap_map": True,
                    "foreground_location": True,
                },
            )
            session.add(incident)
            await session.flush()

        account_ids: dict[str, str] = {}
        account_specs = [
            (
                settings.bootstrap_admin_username,
                settings.bootstrap_admin_password,
                "admin",
            ),
            (
                settings.bootstrap_operator_username,
                settings.bootstrap_operator_password,
                "operator",
            ),
        ]
        for username, password, role in account_specs:
            account = await session.scalar(
                select(LocalAccount).where(LocalAccount.username == username)
            )
            if account is None:
                account = LocalAccount(
                    username=username,
                    password_hash=hash_password(password),
                    role=role,
                    is_active=True,
                )
                session.add(account)
                await session.flush()
            membership = await session.scalar(
                select(IncidentMembership).where(
                    IncidentMembership.account_id == account.id,
                    IncidentMembership.incident_id == incident.id,
                )
            )
            if membership is None:
                session.add(
                    IncidentMembership(
                        account_id=account.id,
                        incident_id=incident.id,
                        role=role,
                    )
                )
            account_ids[role] = account.id

        blind_spot = await session.scalar(
            select(BlindSpot).where(
                BlindSpot.incident_id == incident.id,
                BlindSpot.claim_key == "daguan_bridge.passability",
            )
        )
        if blind_spot is None:
            blind_spot = BlindSpot(
                incident_id=incident.id,
                claim_key="daguan_bridge.passability",
                title="大关桥通行情况盲区",
                location_text="大关桥",
                latitude=30.3132,
                longitude=120.1558,
                coordinate_system="gcj02",
                scope_type="radius",
                scope_data={"radius_m": 500},
                severity="high",
                route_impact_count=2,
                min_valid_answers=1,
                status="open",
            )
            session.add(blind_spot)
            await session.flush()
        question = await session.scalar(
            select(DirectedQuestion).where(DirectedQuestion.blind_spot_id == blind_spot.id)
        )
        if question is None:
            question = DirectedQuestion(
                incident_id=incident.id,
                blind_spot_id=blind_spot.id,
                title="大关桥现在可以通行吗？",
                location_text="大关桥",
                target_geometry={
                    "type": "Point",
                    "coordinates": [120.1558, 30.3132],
                    "radius_m": 500,
                    "coordinate_system": "gcj02",
                },
                route_impact_count=2,
                options=[
                    {
                        "id": "passable",
                        "label": "可以通行",
                        "semantic_value": "passable",
                        "is_informative": True,
                    },
                    {
                        "id": "pedestrian_only",
                        "label": "仅步行可通行",
                        "semantic_value": "pedestrian_only",
                        "is_informative": True,
                    },
                    {
                        "id": "blocked",
                        "label": "无法通行",
                        "semantic_value": "blocked",
                        "is_informative": True,
                    },
                    {
                        "id": "unknown",
                        "label": "不清楚",
                        "semantic_value": "unknown",
                        "is_informative": False,
                    },
                ],
                status="published",
                created_by=account_ids["operator"],
            )
            session.add(question)

        conflict = await session.scalar(
            select(ConflictCase).where(ConflictCase.alias == "along-river-road-passability")
        )
        if conflict is None:
            conflict = ConflictCase(
                incident_id=incident.id,
                alias="along-river-road-passability",
                fact_key="along_river_road.passability",
                title="沿江路通行情况冲突",
                topic="road_passability",
                location_text="沿江路",
                latitude=30.2475,
                longitude=120.1810,
                coordinate_system="gcj02",
                status="open",
                severity="high",
            )
            session.add(conflict)
            await session.flush()
            evidence_specs = [
                (
                    "passable",
                    "现场居民称沿江路小型车辆仍可缓慢通行。",
                    0.72,
                ),
                (
                    "blocked",
                    "巡查人员称沿江路积水较深，机动车无法通行。",
                    0.88,
                ),
            ]
            for value, description, confidence in evidence_specs:
                fragment = InformationFragment(
                    incident_id=incident.id,
                    source_type="seed",
                    source_ref_id=None,
                    topic="road_passability",
                    claim_key="along_river_road.passability",
                    claim_value=value,
                    label="沿江路通行证据",
                    description=description,
                    location_text="沿江路",
                    latitude=30.2475,
                    longitude=120.1810,
                    coordinate_system="gcj02",
                    status="conflict",
                    confidence=confidence,
                )
                session.add(fragment)
                await session.flush()
                snapshot = {
                    "id": fragment.id,
                    "modality": "text",
                    "source": "seed",
                    "statement": description,
                    "location": "沿江路",
                    "claim_key": fragment.claim_key,
                    "claim_value": value,
                    "confidence": confidence,
                }
                session.add(
                    ConflictEvidence(
                        conflict_id=conflict.id,
                        kind="fragment",
                        source_id=fragment.id,
                        source_revision=fragment.revision,
                        source_cluster_id=fragment.source_cluster_id,
                        snapshot=snapshot,
                        snapshot_sha256=sha256_text(canonical_json(snapshot)),
                    )
                )
            gcj_lat, gcj_lon = 30.2475, 120.1810
            # The seed source is GCJ-02; retain a normalized WGS84 projection.
            from .domain.coordinates import gcj02_to_wgs84

            wgs_lat, wgs_lon = gcj02_to_wgs84(gcj_lat, gcj_lon)
            session.add(
                MapFeature(
                    incident_id=incident.id,
                    kind="conflict",
                    source_ref=conflict.id,
                    title=conflict.title,
                    status=conflict.status,
                    severity=conflict.severity,
                    latitude_wgs84=wgs_lat,
                    longitude_wgs84=wgs_lon,
                    latitude_gcj02=gcj_lat,
                    longitude_gcj02=gcj_lon,
                    revision=conflict.revision,
                    public_data={
                        "topic": conflict.topic,
                        "location_text": conflict.location_text,
                    },
                    private_data={},
                )
            )

        await session.commit()
        return {
            "incident_id": incident.id,
            "admin_id": account_ids["admin"],
            "operator_id": account_ids["operator"],
            "blind_spot_id": blind_spot.id,
            "conflict_id": conflict.id,
        }
