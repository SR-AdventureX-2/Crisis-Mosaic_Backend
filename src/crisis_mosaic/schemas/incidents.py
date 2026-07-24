from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CoordinateSystem = Literal["wgs84", "gcj02"]
MapLayer = Literal["reports", "fragments", "conflicts", "blind_spots", "facts"]


def _default_map_layers() -> set[MapLayer]:
    return {"reports", "fragments", "conflicts", "blind_spots", "facts"}


class BoundingBox(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_longitude: float = Field(ge=-180, le=180)
    min_latitude: float = Field(ge=-90, le=90)
    max_longitude: float = Field(ge=-180, le=180)
    max_latitude: float = Field(ge=-90, le=90)

    @model_validator(mode="after")
    def validate_order(self) -> BoundingBox:
        if self.min_longitude >= self.max_longitude:
            raise ValueError("min_longitude must be smaller than max_longitude")
        if self.min_latitude >= self.max_latitude:
            raise ValueError("min_latitude must be smaller than max_latitude")
        return self


class MapViewQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bbox: BoundingBox | None = None
    coordinate_system: CoordinateSystem = "gcj02"
    zoom: float | None = Field(default=None, ge=1, le=22)
    layers: set[MapLayer] = Field(default_factory=_default_map_layers)
    updated_after: datetime | None = None
