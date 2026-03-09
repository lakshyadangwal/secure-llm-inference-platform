"""
Commit 100: Base64 Detector
==============================
Detects base64-encoded strings embedded within prompts.
Attackers use base64 to obfuscate harmful instructions.
Optionally decodes found segments for secondary scanning.
"""

import base64
import re
from dataclasses import dataclass

# Strict base64 pattern: ≥20 chars, only valid base64 alphabet, padded
_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_MIN_DECODE_LEN = 20


@dataclass
class Base64Result:
    found: bool
    segment_count: int
    decoded_samples: list[str]   # up to 3 decoded snippets
    flags: list[str]

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "segment_count": self.segment_count,
            "decoded_samples": self.decoded_samples,
            "flags": self.flags,
        }


def detect_base64(text: str, max_decode: int = 3) -> Base64Result:
    candidates = _B64_RE.findall(text)
    decoded_samples: list[str] = []
    flags: list[str] = []

    for candidate in candidates:
        if len(decoded_samples) >= max_decode:
            break
        try:
            # Pad to multiple of 4
            padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if len(decoded) >= 10 and decoded.isprintable():
                decoded_samples.append(decoded[:200])
        except Exception:
            pass

    if candidates:
        flags.append("base64_segments_found")
    if len(candidates) > 3:
        flags.append("multiple_base64_segments")

    return Base64Result(
        found=bool(candidates),
        segment_count=len(candidates),
        decoded_samples=decoded_samples,
        flags=flags,
    )
