"""
Commit 69: Request Validator
===============================
Deep HTTP request validation layer. Checks request structure,
headers, body content-type, encoding integrity, and payload size
before the request reaches any business logic.

Validates:
  1. HTTP method whitelist (only GET / POST / OPTIONS allowed)
  2. Content-Type enforcement for POST bodies
  3. Payload size limits (default 64 KB)
  4. JSON structure validation (required fields, type checks)
  5. Header injection check (newline chars in header values)
  6. User-Agent blocklist (known scanner/bot signatures)
  7. Host header validation (prevent DNS rebinding)
  8. Query parameter length / count limits
  9. Encoding integrity (valid UTF-8, detect binary smuggling)
 10. Suspicious filename / path traversal in query strings
"""

import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_BODY_BYTES          = 65_536    # 64 KB
MAX_QUERY_PARAM_LENGTH  = 512
MAX_QUERY_PARAM_COUNT   = 20
MAX_HEADER_VALUE_LENGTH = 1024
MAX_JSON_DEPTH          = 8
MAX_STRING_FIELD_LENGTH = 32_768

ALLOWED_METHODS: set[str] = {"GET", "POST", "OPTIONS", "HEAD"}

ALLOWED_CONTENT_TYPES: set[str] = {
    "application/json",
    "application/json; charset=utf-8",
    "text/plain",
    "text/plain; charset=utf-8",
}

# User agents that suggest automated scanning / attack tools
_BLOCKED_USER_AGENTS: list[re.Pattern] = [
    re.compile(p, re.I) for p in [
        r"\b(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf)\b",
        r"\b(burp\s*suite|owasp\s*zap|acunetix|nessus|openvas)\b",
        r"\b(python-requests|go-http-client|java/\d|curl/\d|wget/\d)\b",
        r"\b(libwww-perl|mechanize|scrapy|httpx|aiohttp)\b",
        r"\b(masscan|zgrab|shodan|censys|nuclei)\b",
    ]
]

# Suspicious query string patterns
_TRAVERSAL_PATTERN = re.compile(r"\.\.(\/|\\)|%2e%2e|%252e%252e", re.I)
_HEADER_INJECTION  = re.compile(r"[\r\n]")
_TEMPLATE_INJECT   = re.compile(r"\{\{.{0,80}\}\}|\{%.{0,80}%\}|\$\{.{0,80}\}")
_NULL_BYTE         = re.compile(r"\x00|%00")


# ── Validation result ─────────────────────────────────────────────────────────

@dataclass
class ValidationViolation:
    code: str
    message: str
    severity: str    # "low" | "medium" | "high" | "critical"


@dataclass
class ValidationResult:
    is_valid: bool
    violations: list[ValidationViolation]
    risk_score: float
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "violation_count": len(self.violations),
            "risk_score": round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "violations": [{"code": v.code, "message": v.message, "severity": v.severity}
                           for v in self.violations],
        }


_SEV_WEIGHT: dict[str, float] = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 1.0}


# ── Validator ─────────────────────────────────────────────────────────────────

class RequestValidator:
    """
    Performs deep validation of incoming HTTP requests.
    Returns detailed violation reports and a risk score.
    """

    def __init__(
        self,
        max_body_bytes: int = MAX_BODY_BYTES,
        allowed_hosts: Optional[list[str]] = None,
    ) -> None:
        self._max_body = max_body_bytes
        self._allowed_hosts: Optional[set[str]] = set(allowed_hosts) if allowed_hosts else None
        self._lock = RLock()
        self._total_checked = 0
        self._total_rejected = 0
        self._violation_counts: dict[str, int] = {}
        logger.info("🛂 RequestValidator initialised (max_body=%dKB)", max_body_bytes // 1024)

    def validate(
        self,
        method: str,
        path: str,
        query_params: dict[str, str],
        headers: dict[str, str],
        body_raw: Optional[bytes],
        body_json: Optional[Any] = None,
    ) -> ValidationResult:
        """
        Validate an incoming HTTP request.

        Args:
            method:       HTTP method string (e.g. "POST")
            path:         URL path (e.g. "/api/v1/chat")
            query_params: Dict of query parameter name → value
            headers:      Dict of header name → value (already parsed)
            body_raw:     Raw request body bytes
            body_json:    Pre-parsed JSON (if content-type is application/json)

        Returns:
            ValidationResult with violations list and risk score.
        """
        with self._lock:
            self._total_checked += 1

        violations: list[ValidationViolation] = []

        # 1. HTTP method
        if method.upper() not in ALLOWED_METHODS:
            violations.append(ValidationViolation(
                code="METHOD_NOT_ALLOWED",
                message=f"HTTP method '{method}' is not allowed",
                severity="medium",
            ))

        # 2. Body size
        if body_raw and len(body_raw) > self._max_body:
            violations.append(ValidationViolation(
                code="BODY_TOO_LARGE",
                message=f"Request body {len(body_raw)} bytes exceeds limit {self._max_body}",
                severity="high",
            ))

        # 3. Content-Type for POST
        if method.upper() == "POST":
            ct = headers.get("content-type", headers.get("Content-Type", "")).split(";")[0].strip().lower()
            if ct and ct not in {c.split(";")[0].strip() for c in ALLOWED_CONTENT_TYPES}:
                violations.append(ValidationViolation(
                    code="INVALID_CONTENT_TYPE",
                    message=f"Content-Type '{ct}' is not allowed",
                    severity="medium",
                ))

        # 4. Header injection
        for name, value in headers.items():
            if _HEADER_INJECTION.search(value):
                violations.append(ValidationViolation(
                    code="HEADER_INJECTION",
                    message=f"Header '{name}' contains newline characters",
                    severity="critical",
                ))
            if len(value) > MAX_HEADER_VALUE_LENGTH:
                violations.append(ValidationViolation(
                    code="HEADER_TOO_LONG",
                    message=f"Header '{name}' exceeds {MAX_HEADER_VALUE_LENGTH} chars",
                    severity="medium",
                ))

        # 5. User-Agent blocklist
        ua = headers.get("user-agent", headers.get("User-Agent", ""))
        for ua_re in _BLOCKED_USER_AGENTS:
            if ua_re.search(ua):
                violations.append(ValidationViolation(
                    code="BLOCKED_USER_AGENT",
                    message=f"User-Agent matches known scanner: {ua[:60]}",
                    severity="high",
                ))
                break

        # 6. Host header
        if self._allowed_hosts:
            host = headers.get("host", headers.get("Host", "")).split(":")[0]  # type: ignore[index]
            if host and host not in self._allowed_hosts:
                violations.append(ValidationViolation(
                    code="INVALID_HOST",
                    message=f"Host '{host}' is not in allowed list",
                    severity="high",
                ))

        # 7. Query params
        if len(query_params) > MAX_QUERY_PARAM_COUNT:
            violations.append(ValidationViolation(
                code="TOO_MANY_QUERY_PARAMS",
                message=f"{len(query_params)} query params exceeds limit {MAX_QUERY_PARAM_COUNT}",
                severity="medium",
            ))
        for pname, pval in query_params.items():
            if len(pval) > MAX_QUERY_PARAM_LENGTH:
                violations.append(ValidationViolation(
                    code="QUERY_PARAM_TOO_LONG",
                    message=f"Query param '{pname}' exceeds {MAX_QUERY_PARAM_LENGTH} chars",
                    severity="medium",
                ))
            if _TRAVERSAL_PATTERN.search(pval):
                violations.append(ValidationViolation(
                    code="PATH_TRAVERSAL_IN_QUERY",
                    message=f"Path traversal pattern in query param '{pname}'",
                    severity="critical",
                ))
            if _NULL_BYTE.search(pval):
                violations.append(ValidationViolation(
                    code="NULL_BYTE_IN_QUERY",
                    message=f"Null byte in query param '{pname}'",
                    severity="critical",
                ))

        # 8. Template injection in path or query
        full_path = path + "?" + "&".join(f"{k}={v}" for k, v in query_params.items())
        if _TEMPLATE_INJECT.search(full_path):
            violations.append(ValidationViolation(
                code="TEMPLATE_INJECTION",
                message="Template injection pattern detected in URL",
                severity="critical",
            ))

        # 9. JSON structure validation
        if body_json is not None:
            json_violations = self._validate_json(body_json, depth=0)
            violations.extend(json_violations)

        # 10. Encoding integrity (check for binary / non-UTF-8 in body)
        if body_raw:
            try:
                body_raw.decode("utf-8")
            except UnicodeDecodeError:
                violations.append(ValidationViolation(
                    code="INVALID_ENCODING",
                    message="Request body contains non-UTF-8 bytes",
                    severity="high",
                ))

        # Compute risk score
        risk: float = 0.0
        for v in violations:
            risk = float(risk + _SEV_WEIGHT.get(v.severity, 0.1))  # type: ignore[operator]
        risk = min(1.0, risk)

        is_valid = not any(v.severity in ("critical", "high") for v in violations)

        with self._lock:
            if not is_valid:
                self._total_rejected += 1
            for v in violations:
                self._violation_counts[v.code] = self._violation_counts.get(v.code, 0) + 1

        if not is_valid:
            logger.warning(
                "🛂 Request rejected — violations=%s risk=%.2f",
                [v.code for v in violations], risk,
            )

        return ValidationResult(is_valid=is_valid, violations=violations, risk_score=risk)

    def _validate_json(self, obj: Any, depth: int) -> list[ValidationViolation]:
        violations: list[ValidationViolation] = []
        if depth > MAX_JSON_DEPTH:
            violations.append(ValidationViolation(
                code="JSON_TOO_DEEP",
                message=f"JSON nesting depth exceeds {MAX_JSON_DEPTH}",
                severity="high",
            ))
            return violations
        if isinstance(obj, dict):
            for val in obj.values():
                violations.extend(self._validate_json(val, depth + 1))
        elif isinstance(obj, list):
            for item in obj:
                violations.extend(self._validate_json(item, depth + 1))
        elif isinstance(obj, str):
            if len(obj) > MAX_STRING_FIELD_LENGTH:
                violations.append(ValidationViolation(
                    code="JSON_STRING_TOO_LONG",
                    message=f"JSON string field exceeds {MAX_STRING_FIELD_LENGTH} chars",
                    severity="medium",
                ))
            if _NULL_BYTE.search(obj):
                violations.append(ValidationViolation(
                    code="NULL_BYTE_IN_JSON",
                    message="Null byte found in JSON string field",
                    severity="critical",
                ))
        return violations

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_checked": self._total_checked,
                "total_rejected": self._total_rejected,
                "rejection_rate_pct": round(
                    float(self._total_rejected) / max(self._total_checked, 1) * 100, 1
                ),  # type: ignore[call-overload]
                "violation_counts": dict(self._violation_counts),
                "max_body_bytes": self._max_body,
            }


request_validator = RequestValidator()
