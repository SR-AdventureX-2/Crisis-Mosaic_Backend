from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import pytest
import respx
from PIL import Image

from crisis_mosaic.config import Settings, get_settings
from crisis_mosaic.errors import ApiError
from crisis_mosaic.main import create_app
from crisis_mosaic.middleware import redact
from crisis_mosaic.schemas.ai import ReportRefinementOutput
from crisis_mosaic.services.ai import _invoke_structured
from crisis_mosaic.services.ai_prompts import REPORT_REFINEMENT_PROMPT_VERSION, get_prompt_spec
from crisis_mosaic.services.uploads import _sanitize_image, _scan_file


def _openai_settings() -> Settings:
    return Settings(
        app_env="test",
        ai_provider="openai_compatible",
        ai_api_key="test-only-api-key",
        ai_base_url="https://ai.invalid/v1",
    )


def _png_bytes(size: tuple[int, int]) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", size, color=(20, 80, 140)).save(output, format="PNG")
    return output.getvalue()


def test_prompt_specs_render_task_specific_placeholders() -> None:
    payload = '{"incident_id":"incident","value":1}'
    for purpose in (
        "report_refinement",
        "attachment_enrichment",
        "conflict_analysis",
        "command_brief",
    ):
        rendered = get_prompt_spec(purpose).render_user_prompt(payload)
        assert payload in rendered
        assert "{{" not in rendered


@pytest.mark.asyncio
async def test_fake_scanner_detects_eicar_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "eicar.txt"
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _path: b"EICAR-" + b"STANDARD-ANTIVIRUS test marker",
    )
    settings = Settings(app_env="test", malware_scanner="fake")

    with pytest.raises(ApiError) as error:
        await _scan_file(sample, settings)

    assert error.value.status_code == 422
    assert error.value.code == "MALWARE_DETECTED"


def test_image_sanitizer_rejects_pixel_bomb_before_writing_derivatives(
    tmp_path: Path,
) -> None:
    source = tmp_path / "oversized.png"
    source.write_bytes(_png_bytes((64, 64)))
    settings = Settings(
        app_env="test",
        data_dir=tmp_path,
        storage_root=tmp_path / "uploads",
        max_image_pixels=1_000,
        malware_scanner="fake",
    )
    settings.ensure_directories()
    previous_limit = Image.MAX_IMAGE_PIXELS

    try:
        with pytest.raises(ApiError) as error:
            _sanitize_image(source, "01900000-0000-7000-8000-000000000301", settings)
    finally:
        Image.MAX_IMAGE_PIXELS = previous_limit

    assert error.value.status_code == 422
    assert error.value.code == "IMAGE_PIXEL_LIMIT_EXCEEDED"
    assert not any((settings.storage_root / "sanitized").iterdir())
    assert not any((settings.storage_root / "thumbnails").iterdir())


@pytest.mark.asyncio
async def test_openai_compatible_uses_versioned_prompt_schema_and_records_usage() -> None:
    settings = _openai_settings()
    payload = {
        "request_context": {"incident_id": "incident", "language": "zh-CN"},
        "report": {
            "category": "rescue",
            "content": "water rising",
            "location_text": "bridge",
        },
    }
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(settings.ai_endpoint).mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "refined_content": (
                                            "【需要救援】water rising.\n【位置】bridge"
                                        ),
                                        "risk_hint": "仅整理了表达，请居民核对后提交。",
                                        "suggest_urgent": False,
                                        "detected_risk_tags": [],
                                        "confidence": 0.7,
                                    }
                                )
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 123, "completion_tokens": 45},
                },
            )
        )

        result = await _invoke_structured(
            purpose="report_refinement",
            payload=payload,
            output_model=ReportRefinementOutput,
            model="test-model",
            timeout_seconds=1,
            settings=settings,
        )

    request_body = json.loads(route.calls[0].request.content)
    assert request_body["temperature"] == 0.1
    assert "Crisis Mosaic 灾害现场信息辅助分析引擎" in request_body["messages"][0]["content"]
    assert "【当前任务：居民上报整理】" in request_body["messages"][0]["content"]
    assert "TASK_INPUT_JSON" in request_body["messages"][1]["content"]
    assert request_body["response_format"]["type"] == "json_schema"
    assert result.prompt_version == REPORT_REFINEMENT_PROMPT_VERSION
    assert len(result.prompt_sha256) == 64
    assert result.input_tokens == 123
    assert result.output_tokens == 45
    assert result.schema_valid is True
    assert result.output.confidence == 0.7


@pytest.mark.asyncio
async def test_openai_compatible_timeout_maps_to_stable_api_error() -> None:
    settings = _openai_settings()
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(settings.ai_endpoint).mock(
            side_effect=httpx.ReadTimeout("test deadline exceeded")
        )

        with pytest.raises(ApiError) as error:
            await _invoke_structured(
                purpose="report_refinement",
                payload={
                    "content": "water rising",
                    "location_text": "bridge",
                },
                output_model=ReportRefinementOutput,
                model="test-model",
                timeout_seconds=0.01,
                settings=settings,
            )

    assert route.called
    assert error.value.status_code == 504
    assert error.value.code == "AI_MODEL_TIMEOUT"


@pytest.mark.asyncio
async def test_openai_compatible_invalid_schema_is_rejected() -> None:
    settings = _openai_settings()
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(settings.ai_endpoint).mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "refined_content": "missing required fields",
                                        "confidence": "high",
                                    }
                                )
                            }
                        }
                    ]
                },
            )
        )

        with pytest.raises(ApiError) as error:
            await _invoke_structured(
                purpose="report_refinement",
                payload={
                    "content": "water rising",
                    "location_text": "bridge",
                },
                output_model=ReportRefinementOutput,
                model="test-model",
                timeout_seconds=1,
                settings=settings,
            )

    request = route.calls[0].request
    assert request.headers["authorization"] == "Bearer test-only-api-key"
    assert error.value.status_code == 502
    assert error.value.code == "AI_OUTPUT_SCHEMA_INVALID"
    assert error.value.details


@pytest.mark.asyncio
async def test_openai_compatible_http_error_is_fail_closed() -> None:
    settings = _openai_settings()
    with respx.mock(assert_all_called=True) as mock:
        mock.post(settings.ai_endpoint).mock(
            return_value=httpx.Response(429, json={"error": {"message": "rate limited"}})
        )

        with pytest.raises(ApiError) as error:
            await _invoke_structured(
                purpose="report_refinement",
                payload={
                    "content": "water rising",
                    "location_text": "bridge",
                },
                output_model=ReportRefinementOutput,
                model="test-model",
                timeout_seconds=1,
                settings=settings,
            )

    assert error.value.status_code == 503
    assert error.value.code == "AI_SERVICE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_cors_preflight_allows_configured_origin_and_denies_other_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("CORS_ORIGINS", '["https://allowed.example"]')
    get_settings.cache_clear()
    try:
        app = create_app()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            allowed = await client.options(
                "/api/v1/health/live",
                headers={
                    "Origin": "https://allowed.example",
                    "Access-Control-Request-Method": "GET",
                },
            )
            denied = await client.options(
                "/api/v1/health/live",
                headers={
                    "Origin": "https://denied.example",
                    "Access-Control-Request-Method": "GET",
                },
            )
    finally:
        get_settings.cache_clear()

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://allowed.example"
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_redact_masks_deep_sensitive_keys_without_mutating_input() -> None:
    original = {
        "authorization": "Bearer top-secret",
        "nested": {
            "refresh_token": "refresh-secret",
            "items": [
                {"api-key": "provider-secret", "safe": "visible"},
                {"Password": "hunter2"},
            ],
        },
        "safe": "still-visible",
    }

    result = redact(original)

    assert result == {
        "authorization": "***",
        "nested": {
            "refresh_token": "***",
            "items": [
                {"api-key": "***", "safe": "visible"},
                {"Password": "***"},
            ],
        },
        "safe": "still-visible",
    }
    assert original["authorization"] == "Bearer top-secret"
    assert original["nested"]["refresh_token"] == "refresh-secret"
