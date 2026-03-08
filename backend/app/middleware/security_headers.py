"""
Commit 59: Security Headers Middleware
=========================================
FastAPI middleware that injects security headers into every HTTP response.
Implements best-practice browser and API security headers.

Headers applied:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
  - Cache-Control (for API responses)
  - X-Request-ID (unique per request for traceability)
  - X-Response-Time (server processing time in ms)
  - X-Neuro-Sentry-Version (platform identifier)

Also implements:
  - Server header suppression (hide framework identity)
  - Request ID generation and propagation
  - Response time logging
  - Per-path header overrides (e.g. relax CSP for /docs)
"""

import logging
import time
import uuid
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# ── Version tag ────────────────────────────────────────────────────────────────
NS_VERSION = "3.0-defense"

# ── Default security headers ───────────────────────────────────────────────────
_DEFAULT_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), "
        "gyroscope=(), magnetometer=(), microphone=(), "
        "payment=(), usb=()"
    ),
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "X-Neuro-Sentry-Version": NS_VERSION,
}

# ── Path-specific header overrides ─────────────────────────────────────────────
# FastAPI docs UI needs relaxed CSP to load Swagger assets
_PATH_OVERRIDES: dict[str, dict[str, str]] = {
    "/docs": {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "font-src 'self' https://fonts.googleapis.com;"
        ),
        "Cache-Control": "public, max-age=3600",
    },
    "/openapi.json": {
        "Cache-Control": "public, max-age=3600",
    },
    "/redoc": {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data:;"
        ),
    },
}

# ── Headers to strip (hide server identity) ────────────────────────────────────
_HEADERS_TO_REMOVE = {"server", "x-powered-by", "x-runtime"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that injects security headers into every API response.
    Also adds X-Request-ID and X-Response-Time for observability.
    """

    def __init__(self, app: ASGIApp, extra_headers: Optional[dict[str, str]] = None) -> None:  # type: ignore[name-defined]
        super().__init__(app)
        self._extra = extra_headers or {}
        self._request_count = 0
        self._total_response_time_ms = 0.0
        logger.info("🔒 SecurityHeadersMiddleware loaded (%d default headers)", len(_DEFAULT_HEADERS))

    async def dispatch(self, request: Request, call_next: Callable) -> StarletteResponse:
        start = time.perf_counter()
        request_id = str(uuid.uuid4())

        # Attach request ID to request state for downstream use
        request.state.request_id = request_id

        response: StarletteResponse = await call_next(request)

        elapsed_ms = (time.perf_counter() - start) * 1000

        # ── Determine which headers to apply ───────────────────────────────
        path = request.url.path
        headers = dict(_DEFAULT_HEADERS)

        # Apply any path-specific overrides
        for path_prefix, overrides in _PATH_OVERRIDES.items():
            if path.startswith(path_prefix):
                headers.update(overrides)
                break

        # Apply extra headers from constructor
        headers.update(self._extra)

        # ── Observability headers (always applied) ─────────────────────────
        headers["X-Request-ID"] = request_id
        headers["X-Response-Time"] = f"{elapsed_ms:.2f}ms"

        # ── Apply headers to response ──────────────────────────────────────
        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value

        # ── Strip identifying headers ──────────────────────────────────────
        for h in _HEADERS_TO_REMOVE:
            if h in response.headers:
                del response.headers[h]

        # ── Override Server header with a neutral value ───────────────────
        response.headers["Server"] = "Neuro-Sentry"

        # ── Stats ──────────────────────────────────────────────────────────
        self._request_count += 1
        self._total_response_time_ms += elapsed_ms

        if response.status_code >= 500:
            logger.error(
                "🔒 [%s] %s %s → %d  (%.1fms)",
                request_id[:8], request.method, path, response.status_code, elapsed_ms
            )
        elif elapsed_ms > 5000:
            logger.warning(
                "🔒 [%s] Slow response: %s %s → %.0fms",
                request_id[:8], request.method, path, elapsed_ms
            )

        return response

    def get_stats(self) -> dict:
        avg_ms = (
            self._total_response_time_ms / self._request_count
            if self._request_count > 0 else 0.0
        )
        return {
            "total_requests": self._request_count,
            "avg_response_time_ms": round(float(avg_ms), 1),  # type: ignore[call-overload]
            "headers_applied": len(_DEFAULT_HEADERS),
            "path_overrides": len(_PATH_OVERRIDES),
        }

