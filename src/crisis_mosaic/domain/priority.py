from __future__ import annotations

from typing import Literal

Priority = Literal["low", "medium", "high"]
_DEFAULTS: dict[str, Priority] = {
    "rescue": "high",
    "medical": "high",
    "water": "medium",
    "food": "medium",
    "shelter": "medium",
    "road": "medium",
}


def effective_priority(
    category: str,
    *,
    is_urgent: bool,
    manual_priority: Priority | None = None,
    ai_priority: Priority | None = None,
) -> tuple[Priority, str]:
    if is_urgent:
        return "high", "urgent_flag"
    if manual_priority is not None:
        return manual_priority, "manual"
    if ai_priority is not None:
        return ai_priority, "ai"
    return _DEFAULTS.get(category, "medium"), "category_default"
