from __future__ import annotations

import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest
import uvicorn

import app as entrypoint


def test_entrypoint_imports_from_src_without_editable_install() -> None:
    project_root = Path(__file__).resolve().parents[1]
    purelib = Path(sysconfig.get_paths()["purelib"])
    script = (
        "import sys; "
        f"sys.path[:0] = [{str(project_root)!r}, {str(purelib)!r}]; "
        "import app; "
        "print(app.app.title)"
    )

    result = subprocess.run(
        [sys.executable, "-S", "-c", script],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "Crisis Mosaic API"


def test_entrypoint_run_uses_configured_single_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(application: object, **kwargs: object) -> None:
        captured["application"] = application
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)

    entrypoint.run()

    assert captured["application"] is entrypoint.app
    assert captured["workers"] == 1
    assert "reload" not in captured
