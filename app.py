"""Compatibility entry point for direct execution and ASGI-aware tooling."""

import sys
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

from fastapi import FastAPI


class _RuntimeSettings(Protocol):
    app_host: str
    app_port: int
    app_log_level: str


def _load_application() -> FastAPI:
    try:
        module = import_module("crisis_mosaic.main")
    except ModuleNotFoundError as exc:
        if exc.name != "crisis_mosaic":
            raise
        source_root = str(Path(__file__).resolve().parent / "src")
        if source_root not in sys.path:
            sys.path.insert(0, source_root)
        module = import_module("crisis_mosaic.main")
    return cast(FastAPI, module.app)


app = _load_application()

__all__ = ["app", "run"]


def run() -> None:
    import uvicorn

    settings_module = import_module("crisis_mosaic.config")
    get_settings = cast(
        Callable[[], _RuntimeSettings],
        settings_module.get_settings,
    )
    settings = get_settings()
    uvicorn.run(
        app,
        host=settings.app_host,
        port=settings.app_port,
        workers=1,
        log_level=settings.app_log_level.lower(),
    )


if __name__ == "__main__":
    run()
