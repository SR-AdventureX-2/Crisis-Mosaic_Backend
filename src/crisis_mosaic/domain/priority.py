from __future__ import annotations

from typing import Literal

Priority = Literal["low", "medium", "high"]


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
    # A category describes the report topic, not whether the submitted facts are urgent.
    # Residents and AI can still raise priority explicitly through the branches above.
    return "low", "category_default"
