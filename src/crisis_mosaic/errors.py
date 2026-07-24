from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .observability import BUSINESS_ERRORS


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers


def error_body(request: Request, code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", None),
            "details": details,
        }
    }


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
        BUSINESS_ERRORS.labels(code=exc.code).inc()
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(request, exc.code, exc.message, exc.details),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        BUSINESS_ERRORS.labels(code="VALIDATION_ERROR").inc()
        return JSONResponse(
            status_code=422,
            content=error_body(
                request,
                "VALIDATION_ERROR",
                "请求数据校验失败",
                exc.errors(),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "请求失败"
        BUSINESS_ERRORS.labels(code=f"HTTP_{exc.status_code}").inc()
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(request, f"HTTP_{exc.status_code}", detail),
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        BUSINESS_ERRORS.labels(code="INTERNAL_ERROR").inc()
        return JSONResponse(
            status_code=500,
            content=error_body(
                request,
                "INTERNAL_ERROR",
                "服务器处理请求时发生内部错误",
            ),
        )


def not_found(resource: str = "资源") -> ApiError:
    return ApiError(404, "NOT_FOUND", f"{resource}不存在")


def conflict(code: str, message: str, details: Any = None) -> ApiError:
    return ApiError(409, code, message, details=details)


def add_error_openapi_responses(schema: dict[str, Any]) -> None:
    components = schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas["ErrorEnvelope"] = {
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message", "request_id", "details"],
                "properties": {
                    "code": {"type": "string", "example": "VALIDATION_ERROR"},
                    "message": {"type": "string", "example": "请求数据校验失败"},
                    "request_id": {"type": ["string", "null"]},
                    "details": {},
                },
            }
        },
    }
    descriptions = {
        "401": "Authentication failed",
        "403": "Access denied",
        "404": "Requested resource was not found",
        "409": "Revision, idempotency, or state conflict",
        "422": "Request or content validation failed",
        "429": "Rate limit exceeded",
        "500": "Unexpected server error",
        "503": "Configured dependency is unavailable",
    }
    response_template = {
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorEnvelope"}}}
    }
    for path_item in schema.get("paths", {}).values():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"} or not isinstance(
                operation, dict
            ):
                continue
            responses = operation.setdefault("responses", {})
            responses["422"] = {
                "description": descriptions["422"],
                **response_template,
            }
            responses.setdefault(
                "500",
                {"description": descriptions["500"], **response_template},
            )
            responses.setdefault(
                "404",
                {"description": descriptions["404"], **response_template},
            )
            if operation.get("security"):
                for status_code in ("401", "403"):
                    responses.setdefault(
                        status_code,
                        {
                            "description": descriptions[status_code],
                            **response_template,
                        },
                    )
            if method in {"post", "put", "patch", "delete"}:
                for status_code in ("409", "429", "503"):
                    responses.setdefault(
                        status_code,
                        {
                            "description": descriptions[status_code],
                            **response_template,
                        },
                    )
