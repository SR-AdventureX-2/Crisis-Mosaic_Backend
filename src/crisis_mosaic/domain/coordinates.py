from __future__ import annotations

import math
from dataclasses import dataclass

from ..errors import ApiError

_PI = math.pi
_A = 6378245.0
_EE = 0.006693421622965943


@dataclass(frozen=True, slots=True)
class NormalizedCoordinates:
    raw_latitude: float
    raw_longitude: float
    coordinate_system: str
    wgs84_latitude: float
    wgs84_longitude: float
    gcj02_latitude: float
    gcj02_longitude: float
    algorithm_version: str = "gcj02-v1"


def validate_coordinates(latitude: float, longitude: float) -> None:
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ApiError(422, "INVALID_COORDINATES", "经纬度超出合法范围")


def _outside_china(latitude: float, longitude: float) -> bool:
    return not (72.004 <= longitude <= 137.8347 and 0.8293 <= latitude <= 55.8271)


def _transform_latitude(x: float, y: float) -> float:
    result = -100 + 2 * x + 3 * y + 0.2 * y * y + 0.1 * x * y
    result += 0.2 * math.sqrt(abs(x))
    result += (20 * math.sin(6 * x * _PI) + 20 * math.sin(2 * x * _PI)) * 2 / 3
    result += (20 * math.sin(y * _PI) + 40 * math.sin(y / 3 * _PI)) * 2 / 3
    result += (160 * math.sin(y / 12 * _PI) + 320 * math.sin(y * _PI / 30)) * 2 / 3
    return result


def _transform_longitude(x: float, y: float) -> float:
    result = 300 + x + 2 * y + 0.1 * x * x + 0.1 * x * y
    result += 0.1 * math.sqrt(abs(x))
    result += (20 * math.sin(6 * x * _PI) + 20 * math.sin(2 * x * _PI)) * 2 / 3
    result += (20 * math.sin(x * _PI) + 40 * math.sin(x / 3 * _PI)) * 2 / 3
    result += (150 * math.sin(x / 12 * _PI) + 300 * math.sin(x / 30 * _PI)) * 2 / 3
    return result


def wgs84_to_gcj02(latitude: float, longitude: float) -> tuple[float, float]:
    validate_coordinates(latitude, longitude)
    if _outside_china(latitude, longitude):
        return latitude, longitude
    delta_lat = _transform_latitude(longitude - 105, latitude - 35)
    delta_lon = _transform_longitude(longitude - 105, latitude - 35)
    rad_lat = latitude / 180 * _PI
    magic = math.sin(rad_lat)
    magic = 1 - _EE * magic * magic
    sqrt_magic = math.sqrt(magic)
    delta_lat = delta_lat * 180 / ((_A * (1 - _EE)) / (magic * sqrt_magic) * _PI)
    delta_lon = delta_lon * 180 / (_A / sqrt_magic * math.cos(rad_lat) * _PI)
    return latitude + delta_lat, longitude + delta_lon


def gcj02_to_wgs84(latitude: float, longitude: float) -> tuple[float, float]:
    validate_coordinates(latitude, longitude)
    if _outside_china(latitude, longitude):
        return latitude, longitude
    gcj_lat, gcj_lon = wgs84_to_gcj02(latitude, longitude)
    return latitude * 2 - gcj_lat, longitude * 2 - gcj_lon


def normalize(
    latitude: float,
    longitude: float,
    coordinate_system: str,
) -> NormalizedCoordinates:
    validate_coordinates(latitude, longitude)
    coordinate_system = coordinate_system.lower()
    if coordinate_system == "wgs84":
        wgs_lat, wgs_lon = latitude, longitude
        gcj_lat, gcj_lon = wgs84_to_gcj02(latitude, longitude)
    elif coordinate_system == "gcj02":
        gcj_lat, gcj_lon = latitude, longitude
        wgs_lat, wgs_lon = gcj02_to_wgs84(latitude, longitude)
    else:
        raise ApiError(
            422,
            "UNSUPPORTED_COORDINATE_SYSTEM",
            "coordinate_system 仅支持 wgs84 或 gcj02",
        )
    return NormalizedCoordinates(
        raw_latitude=latitude,
        raw_longitude=longitude,
        coordinate_system=coordinate_system,
        wgs84_latitude=wgs_lat,
        wgs84_longitude=wgs_lon,
        gcj02_latitude=gcj_lat,
        gcj02_longitude=gcj_lon,
    )


def haversine_m(
    latitude_a: float,
    longitude_a: float,
    latitude_b: float,
    longitude_b: float,
) -> float:
    radius = 6_371_000.0
    lat_a, lat_b = math.radians(latitude_a), math.radians(latitude_b)
    delta_lat = lat_b - lat_a
    delta_lon = math.radians(longitude_b - longitude_a)
    value = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat_a) * math.cos(lat_b) * math.sin(delta_lon / 2) ** 2
    )
    return 2 * radius * math.asin(math.sqrt(value))
