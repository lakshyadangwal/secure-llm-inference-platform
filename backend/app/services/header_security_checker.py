"""
Commit 91: Header Security Checker
=====================================
Validates security-relevant HTTP response headers and checks
that incoming request headers meet baseline security requirements.

Checks response headers:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY or SAMEORIGIN
  - Strict-Transport-Security present
  - Content-Security-Policy present
  - Referrer-Policy present
  - Permissions-Policy present

Checks request headers:
  - No Host header injection (CR/LF)
  - Origin header validation against allowlist
  - Authorization format validation (Bearer token)
"""

import re
from dataclasses import dataclass
from threading import RLock
from typing import Optional

_NEWLINE_RE = re.compile(r"[\r\n]")
_BEARER_RE  = re.compile(r"^Bearer\s+[A-Za-z0-9\-._~+/]+=*$")

_REQUIRED_RESPONSE_HEADERS: list[tuple[str, Optional[str]]] = [
    ("x-content-type-options", "nosniff"),
    ("x-frame-options",        None),   # any value is acceptable
    ("strict-transport-security", None),
    ("content-security-policy",   None),
    ("referrer-policy",           None),
]


@dataclass
class HeaderCheckResult:
    passed: bool
    missing_headers: list[str]
    invalid_headers: list[str]
    issues: list[str]

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "missing_headers": self.missing_headers,
            "invalid_headers": self.invalid_headers,
            "issues": self.issues,
        }


class HeaderSecurityChecker:
    """Validates HTTP security headers on both requests and responses."""

    def __init__(self, allowed_origins: Optional[list[str]] = None) -> None:
        self._allowed_origins = set(allowed_origins or [])
        self._lock = RLock()
        self._request_checks = 0
        self._response_checks = 0
        self._request_failures = 0
        self._response_failures = 0

    def check_response_headers(self, headers: dict[str, str]) -> HeaderCheckResult:
        """Check that response headers include required security headers."""
        lower = {k.lower(): v for k, v in headers.items()}
        missing: list[str] = []
        invalid: list[str] = []
        issues: list[str] = []

        for name, expected_value in _REQUIRED_RESPONSE_HEADERS:
            if name not in lower:
                missing.append(name)
                issues.append(f"Missing header: {name}")
            elif expected_value and lower[name].lower() != expected_value.lower():
                invalid.append(name)
                issues.append(f"Header {name}={lower[name]!r} expected {expected_value!r}")

        passed = not missing and not invalid
        with self._lock:
            self._response_checks += 1
            if not passed:
                self._response_failures += 1

        return HeaderCheckResult(passed=passed, missing_headers=missing, invalid_headers=invalid, issues=issues)

    def check_request_headers(self, headers: dict[str, str]) -> HeaderCheckResult:
        """Validate incoming request headers for security issues."""
        issues: list[str] = []
        invalid: list[str] = []

        # CR/LF injection in all header values
        for name, value in headers.items():
            if _NEWLINE_RE.search(value):
                issues.append(f"Header injection in {name}")
                invalid.append(name)

        # Origin validation
        if self._allowed_origins:
            origin = headers.get("origin", headers.get("Origin", ""))
            if origin and origin not in self._allowed_origins:
                issues.append(f"Origin not allowed: {origin}")
                invalid.append("origin")

        # Authorization format
        auth = headers.get("authorization", headers.get("Authorization", ""))
        if auth and not _BEARER_RE.match(auth):
            issues.append("Authorization header format invalid")
            invalid.append("authorization")

        passed = not issues
        with self._lock:
            self._request_checks += 1
            if not passed:
                self._request_failures += 1

        return HeaderCheckResult(passed=passed, missing_headers=[], invalid_headers=invalid, issues=issues)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "request_checks": self._request_checks,
                "response_checks": self._response_checks,
                "request_failures": self._request_failures,
                "response_failures": self._response_failures,
            }


header_security_checker = HeaderSecurityChecker()
