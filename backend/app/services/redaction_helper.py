"""
Commit 101: Redaction Helper
==============================
Redacts common PII patterns from text before logging or storing.
Patterns: email, phone, SSN (US), credit card, IPv4, API keys.
Returns redacted text and a count per category.
"""

import re
from dataclasses import dataclass

_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("email",       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), "[EMAIL]"),
    ("phone",       re.compile(r"\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"), "[PHONE]"),
    ("ssn",         re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"), "[SSN]"),
    ("credit_card", re.compile(r"\b(?:\d[ \-]?){13,16}\b"), "[CARD]"),
    ("ipv4",        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
    ("api_key",     re.compile(r"\b(?:sk|pk|api)[_\-][A-Za-z0-9]{20,}\b"), "[API_KEY]"),
]


@dataclass
class RedactionResult:
    redacted_text: str
    counts: dict[str, int]
    total_redacted: int

    def to_dict(self) -> dict:
        return {
            "total_redacted": self.total_redacted,
            "counts": self.counts,
        }


def redact(text: str) -> RedactionResult:
    counts: dict[str, int] = {}
    result = text
    for name, pattern, placeholder in _PATTERNS:
        matches = pattern.findall(result)
        if matches:
            counts[name] = len(matches)
            result = pattern.sub(placeholder, result)
    return RedactionResult(
        redacted_text=result,
        counts=counts,
        total_redacted=sum(counts.values()),
    )
