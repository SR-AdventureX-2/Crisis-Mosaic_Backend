from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

if os.name == "nt":
    import msvcrt
else:  # pragma: no cover - exercised on Unix deployments
    import fcntl


class SingleProcessGuard:
    """Hold an operating-system file lock for the lifetime of the API process."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: BinaryIO | None = None

    @property
    def acquired(self) -> bool:
        return self._handle is not None

    def acquire(self) -> None:
        if self._handle is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - exercised on Unix deployments
                fcntl.flock(  # type: ignore[attr-defined]
                    handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
        except OSError as exc:
            handle.close()
            raise RuntimeError(
                "Crisis Mosaic SQLite P0 already has an active API process; "
                "run exactly one Uvicorn worker"
            ) from exc
        self._handle = handle

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:  # pragma: no cover - exercised on Unix deployments
                fcntl.flock(  # type: ignore[attr-defined]
                    handle.fileno(),
                    fcntl.LOCK_UN,  # type: ignore[attr-defined]
                )
        finally:
            handle.close()
            self._handle = None

    def __enter__(self) -> SingleProcessGuard:
        self.acquire()
        return self

    def __exit__(self, *_: object) -> None:
        self.release()
