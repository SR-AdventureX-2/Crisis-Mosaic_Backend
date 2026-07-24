from __future__ import annotations

from pathlib import Path

import pytest

from crisis_mosaic.runtime_guard import SingleProcessGuard


def test_single_process_guard_rejects_a_second_runtime(tmp_path: Path) -> None:
    lock_path = tmp_path / "runtime.lock"
    first = SingleProcessGuard(lock_path)
    second = SingleProcessGuard(lock_path)

    first.acquire()
    try:
        with pytest.raises(RuntimeError, match="exactly one Uvicorn worker"):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    assert second.acquired is True
    second.release()
    assert second.acquired is False
