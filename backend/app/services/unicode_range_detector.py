"""
Commit 103: Unicode Range Detector
=====================================
Detects characters from suspicious or unexpected Unicode ranges
often used in obfuscation attacks:
  - Cyrillic lookalikes to Latin chars
  - Fullwidth Latin characters
  - Enclosed alphanumerics (circled letters)
  - Tags block (U+E0000–U+E007F) — invisible characters
  - Combining characters used to hide text
"""

from dataclasses import dataclass

# (range_start, range_end, label)
_SUSPICIOUS_RANGES: list[tuple[int, int, str]] = [
    (0x0400, 0x04FF, "cyrillic"),
    (0xFF01, 0xFF5E, "fullwidth_latin"),
    (0x2460, 0x24FF, "enclosed_alphanumeric"),
    (0xE0000, 0xE007F, "tags_block"),
    (0x0300, 0x036F, "combining_diacritics"),
    (0x2060, 0x206F, "general_punctuation_invisible"),
    (0x1D400, 0x1D7FF, "mathematical_alphanumeric"),
]


@dataclass
class UnicodeRangeResult:
    suspicious_char_count: int
    ranges_triggered: list[str]
    risk_score: float

    def to_dict(self) -> dict:
        return {
            "suspicious_char_count": self.suspicious_char_count,
            "ranges_triggered": self.ranges_triggered,
            "risk_score": round(self.risk_score, 3),
        }


def detect_suspicious_unicode(text: str) -> UnicodeRangeResult:
    triggered: dict[str, int] = {}
    for ch in text:
        cp = ord(ch)
        for start, end, label in _SUSPICIOUS_RANGES:
            if start <= cp <= end:
                triggered[label] = triggered.get(label, 0) + 1
                break

    total_suspicious = sum(triggered.values())
    risk = min(1.0, total_suspicious / max(len(text), 1) * 10)

    return UnicodeRangeResult(
        suspicious_char_count=total_suspicious,
        ranges_triggered=list(triggered.keys()),
        risk_score=float(risk),
    )
