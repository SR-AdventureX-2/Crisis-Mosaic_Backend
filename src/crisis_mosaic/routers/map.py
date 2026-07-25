from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from pydantic import ValidationError
from sqlalchemy import and_, select

from ..config import get_settings
from ..dependencies import ActorDep, IncidentHeader, SessionDep
from ..domain.coordinates import normalize
from ..errors import ApiError
from ..models import MapFeature
from ..observability import MAP_VIEW_POINTS, MAP_VIEW_REJECTIONS
from ..responses import success
from ..schemas.incidents import BoundingBox, MapLayer
from ..services.reports import assert_incident_access, get_incident
from ..utils import as_utc, utcnow

router = APIRouter(tags=["Map"])

_LAYER_KIND: dict[str, str] = {
    "reports": "report",
    "fragments": "fragment",
    "conflicts": "conflict",
    "blind_spots": "blind_spot",
    "facts": "fact",
}
_PUBLIC_MAP_FIELDS = {
    "category",
    "is_urgent",
    "priority",
    "location_text",
    "topic",
    "confidence",
    "count",
    "dominant_status",
    "statement",
    "fact_key",
    "route_impact_count",
}


def _parse_bbox(value: str | None) -> BoundingBox | None:
    if value is None:
        return None
    try:
        parts = [float(item.strip()) for item in value.split(",")]
        if len(parts) != 4:
            raise ValueError
        return BoundingBox(
            min_longitude=parts[0],
            min_latitude=parts[1],
            max_longitude=parts[2],
            max_latitude=parts[3],
        )
    except (ValueError, ValidationError) as exc:
        raise ApiError(
            422,
            "INVALID_BBOX",
            "bbox must be min_longitude,min_latitude,max_longitude,max_latitude",
        ) from exc


def _parse_layers(value: str | None) -> set[MapLayer]:
    if value is None:
        return {"reports", "fragments", "conflicts", "blind_spots", "facts"}
    requested = {item.strip() for item in value.split(",") if item.strip()}
    invalid = requested - set(_LAYER_KIND)
    if invalid or not requested:
        raise ApiError(
            422,
            "INVALID_MAP_LAYERS",
            "layers contains unsupported values",
            details={"invalid": sorted(invalid)},
        )
    return requested  # type: ignore[return-value]


def _position(feature: MapFeature, coordinate_system: str) -> tuple[float, float]:
    if coordinate_system == "wgs84":
        assert feature.latitude_wgs84 is not None
        assert feature.longitude_wgs84 is not None
        return feature.latitude_wgs84, feature.longitude_wgs84
    assert feature.latitude_gcj02 is not None
    assert feature.longitude_gcj02 is not None
    return feature.latitude_gcj02, feature.longitude_gcj02


def _is_owner_report(feature: MapFeature, actor: Any) -> bool:
    private_data = feature.private_data or {}
    return (
        actor.is_resident
        and feature.kind == "report"
        and private_data.get("owner_device_id") == actor.subject_id
    )


def _is_resident_report_derived(feature: MapFeature) -> bool:
    return (
        feature.kind in {"conflict", "blind_spot"}
        and (feature.private_data or {}).get("resident_report_derived") is True
    )


def _resident_position(
    feature: MapFeature,
    actor: Any,
    coordinate_system: str,
) -> tuple[float, float, str]:
    latitude, longitude = _position(feature, coordinate_system)
    if not actor.is_resident:
        return latitude, longitude, "exact"
    if feature.kind == "report" and _is_owner_report(feature, actor):
        return latitude, longitude, "exact"
    if feature.kind != "report" and not _is_resident_report_derived(feature):
        return latitude, longitude, "exact"
    return round(latitude, 3), round(longitude, 3), "fuzzy_100m"


@router.get("/incidents/{incident_id}/map-view")
async def map_view(
    incident_id: str,
    request: Request,
    session: SessionDep,
    actor: ActorDep,
    incident_header: IncidentHeader,
    bbox: str | None = None,
    coordinate_system: str = "gcj02",
    zoom: float | None = None,
    layers: str | None = None,
    updated_after: datetime | None = None,
) -> dict[str, Any]:
    if coordinate_system not in {"wgs84", "gcj02"}:
        raise ApiError(
            422,
            "UNSUPPORTED_COORDINATE_SYSTEM",
            "coordinate_system must be wgs84 or gcj02",
        )
    if zoom is not None and not 1 <= zoom <= 22:
        raise ApiError(422, "INVALID_ZOOM", "zoom must be between 1 and 22")
    parsed_bbox = _parse_bbox(bbox)
    parsed_layers = _parse_layers(layers)
    incident = await get_incident(session, incident_id)
    assert_incident_access(actor, incident, incident_header)
    settings = get_settings()
    if parsed_bbox is not None:
        bbox_area = (parsed_bbox.max_longitude - parsed_bbox.min_longitude) * (
            parsed_bbox.max_latitude - parsed_bbox.min_latitude
        )
        if bbox_area > settings.map_max_bbox_area_degrees:
            MAP_VIEW_REJECTIONS.labels(reason="bbox_area").inc()
            raise ApiError(
                422,
                "MAP_VIEW_TOO_LARGE",
                "map view bbox is too large; narrow the requested area",
                details={
                    "bbox_area_degrees": bbox_area,
                    "max_bbox_area_degrees": settings.map_max_bbox_area_degrees,
                },
            )

    latitude_column = (
        MapFeature.latitude_wgs84 if coordinate_system == "wgs84" else MapFeature.latitude_gcj02
    )
    longitude_column = (
        MapFeature.longitude_wgs84 if coordinate_system == "wgs84" else MapFeature.longitude_gcj02
    )
    filters: list[Any] = [
        MapFeature.incident_id == incident.id,
        MapFeature.kind.in_({_LAYER_KIND[layer] for layer in parsed_layers}),
        MapFeature.is_deleted.is_(False),
        latitude_column.is_not(None),
        longitude_column.is_not(None),
    ]
    if parsed_bbox is not None:
        filters.append(
            and_(
                longitude_column >= parsed_bbox.min_longitude,
                longitude_column <= parsed_bbox.max_longitude,
                latitude_column >= parsed_bbox.min_latitude,
                latitude_column <= parsed_bbox.max_latitude,
            )
        )
    if updated_after is not None:
        filters.append(MapFeature.updated_at > as_utc(updated_after).replace(tzinfo=None))
    if "facts" in parsed_layers:
        filters.append(
            (MapFeature.kind != "fact") | MapFeature.status.in_({"current", "under_review"})
        )
    if actor.is_resident:
        filters.append((MapFeature.kind != "fact") | (MapFeature.public_data != {}))

    limit = min(settings.map_max_points, 500)
    features = list(
        (
            await session.scalars(
                select(MapFeature)
                .where(*filters)
                .order_by(MapFeature.updated_at.desc(), MapFeature.id.desc())
                .limit(limit + 1)
            )
        ).all()
    )
    if len(features) > limit:
        MAP_VIEW_REJECTIONS.labels(reason="point_count").inc()
        raise ApiError(
            422,
            "MAP_VIEW_TOO_LARGE",
            f"map view contains more than {limit} exact points; narrow the bbox or layers",
            details={"max_points": limit},
        )

    center_latitude = (
        incident.center_latitude
        if incident.center_latitude is not None
        else settings.map_default_latitude
    )
    center_longitude = (
        incident.center_longitude
        if incident.center_longitude is not None
        else settings.map_default_longitude
    )
    source_system = incident.map_coordinate_system or "gcj02"
    center = normalize(center_latitude, center_longitude, source_system)
    if coordinate_system == "wgs84":
        center_position = {
            "latitude": center.wgs84_latitude,
            "longitude": center.wgs84_longitude,
        }
    else:
        center_position = {
            "latitude": center.gcj02_latitude,
            "longitude": center.gcj02_longitude,
        }
    items: list[dict[str, Any]] = []
    for feature in features:
        latitude, longitude, precision = _resident_position(feature, actor, coordinate_system)
        visible_data = (
            feature.public_data or {}
            if actor.is_resident
            else {**(feature.public_data or {}), **(feature.private_data or {})}
        )
        if actor.is_resident and precision != "exact":
            visible_data = {
                key: value
                for key, value in visible_data.items()
                if key != "location_text"
            }
        public_data = {
            key: value for key, value in visible_data.items() if key in _PUBLIC_MAP_FIELDS
        }
        title = feature.title
        if actor.is_resident and feature.kind == "report" and precision != "exact":
            title = "现场上报位置已模糊化"
        elif actor.is_resident and _is_resident_report_derived(feature):
            title = "现场信息冲突" if feature.kind == "conflict" else "现场信息盲区"
        items.append(
            {
                "id": f"{feature.kind}:{feature.source_ref}",
                "kind": feature.kind,
                "position": {"latitude": latitude, "longitude": longitude},
                "position_precision": precision,
                "title": title,
                "status": feature.status,
                "severity": feature.severity,
                "source_ref": feature.source_ref,
                "revision": feature.revision,
                "updated_at": feature.updated_at,
                **public_data,
            }
        )
    MAP_VIEW_POINTS.observe(len(items))
    return success(
        {
            "incident_id": incident.id,
            "coordinate_system": coordinate_system,
            "revision": incident.map_revision,
            "viewport": {
                "center": center_position,
                "zoom": zoom or incident.map_default_zoom,
            },
            "items": items,
            "as_of": utcnow().isoformat(),
        },
        request,
    )
