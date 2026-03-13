"""
Commit 2: feat: add prompt length validation and rate limiting
Simple in-memory per-IP rate limiter as ASGI middleware.
"""

import time
import logging
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.config.settings import settings

logger = logging.getLogger(__name__)

# Store: ip -> list of request timestamps
_request_log: dict[str, list[float]] = defaultdict(list)
_WINDOW = 60.0  # seconds


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window per-IP rate limiter.
    Configured via RATE_LIMIT_PER_MINUTE environment variable.
    """

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean old entries outside the window
        _request_log[ip] = [t for t in _request_log[ip] if now - t < _WINDOW]

        if len(_request_log[ip]) >= settings.RATE_LIMIT_PER_MINUTE:
            logger.warning(f"🚫 Rate limit exceeded for IP: {ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        f"Rate limit exceeded: max {settings.RATE_LIMIT_PER_MINUTE} "
                        f"requests per minute."
                    )
                },
            )

        _request_log[ip].append(now)
        response = await call_next(request)
        return response
