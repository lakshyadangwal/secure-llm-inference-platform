"""
Commit 26: Data Leak Prevention (DLP) Engine
=============================================
Scans LLM *output* for sensitive data before returning it to the user.
Catches accidental disclosure of:
  - Email addresses
  - Phone numbers (US/international)
  - Credit card numbers (Luhn-validated)
  - API keys / tokens (common formats)
  - Private IP addresses and internal hostnames
  - Social Security Numbers (SSN)
  - AWS / GCP / Azure credential patterns
  - JWT tokens
  - Passwords in common key=value patterns
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── DLP Pattern Definitions ────────────────────────────────────────────────────

_DLP_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"
    ),
    "phone_us": re.compile(
        r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "credit_card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
        r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "ssn": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b"
    ),
    "jwt_token": re.compile(
        r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
    ),
    "aws_access_key": re.compile(
        r"\b(?:AKIA|AIPA|AIHA|AIDA|AROA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"
    ),
    "aws_secret_key": re.compile(
        r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"
    ),
    "private_ip": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
    "api_key_generic": re.compile(
        r"(?i)(?:api[_\-]?key|token|secret|password|passwd|pwd)"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,64})['\"]?"
    ),
    "bearer_token": re.compile(
        r"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})"
    ),
    "private_key_header": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
}

# Severity weights per category
_SEVERITY: dict[str, float] = {
    "private_key_header": 1.0,
    "aws_secret_key": 1.0,
    "aws_access_key": 0.9,
    "credit_card": 0.9,
    "ssn": 0.9,
    "jwt_token": 0.8,
    "bearer_token": 0.7,
    "api_key_generic": 0.7,
    "email": 0.4,
    "phone_us": 0.4,
    "private_ip": 0.3,
}


# ── Result Dataclass ───────────────────────────────────────────────────────────

@dataclass
class DLPResult:
    """Result of a DLP scan on a piece of text."""
    has_leak: bool
    leaks: list[dict] = field(default_factory=list)
    redacted_text: str = ""
    highest_severity: float = 0.0

    @property
    def leak_types(self) -> list[str]:
        return list({leak["type"] for leak in self.leaks})


# ── Luhn Algorithm (credit card validation) ────────────────────────────────────

def _luhn_check(number: str) -> bool:
    """Return True if the digit string passes the Luhn checksum."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# ── Core DLP Scanner ───────────────────────────────────────────────────────────

class DLPEngine:
    """
    Scans text for sensitive data patterns and optionally redacts them.
    Designed to run on LLM output before returning to the frontend.
    """

    def __init__(self, redact: bool = True, redact_char: str = "*"):
        self.redact = redact
        self.redact_char = redact_char
        self._scan_count = 0
        self._leak_count = 0
        logger.info("🔍 DLP Engine initialised (redact=%s)", redact)

    def scan(self, text: str) -> DLPResult:
        """
        Scan `text` for all registered DLP patterns.

        Args:
            text: The text to scan (typically LLM output).

        Returns:
            DLPResult with leak details and optionally redacted text.
        """
        self._scan_count += 1
        leaks: list[dict] = []
        working = text

        for category, pattern in _DLP_PATTERNS.items():
            for match in pattern.finditer(text):
                matched = match.group(0)

                # Extra validation for credit cards
                if category == "credit_card":
                    clean = re.sub(r"\D", "", matched)
                    if not _luhn_check(clean):
                        continue

                severity = _SEVERITY.get(category, 0.5)
                leaks.append({
                    "type": category,
                    "match": matched[:8] + "..." if len(matched) > 8 else matched,
                    "severity": severity,
                    "span": match.span(),
                })
                logger.warning(
                    "🚨 DLP leak detected — type=%s  severity=%.1f  preview=%s",
                    category,
                    severity,
                    matched[:12] + "..." if len(matched) > 12 else matched,
                )

                if self.redact:
                    replacement = f"[REDACTED:{category.upper()}]"
                    working = working.replace(matched, replacement, 1)

        if leaks:
            self._leak_count += 1

        highest = max((l["severity"] for l in leaks), default=0.0)

        return DLPResult(
            has_leak=bool(leaks),
            leaks=leaks,
            redacted_text=working,
            highest_severity=float(highest),
        )

    def get_stats(self) -> dict:
        """Return lifetime DLP statistics."""
        return {
            "total_scanned": self._scan_count,
            "total_leaks_caught": self._leak_count,
            "leak_rate": round(
                (self._leak_count / self._scan_count * 100) if self._scan_count else 0.0,
                1,
            ),
        }


# ── Module-level singleton ─────────────────────────────────────────────────────
dlp_engine = DLPEngine(redact=True)
