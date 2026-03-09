"""
Commit 107: Punctuation Analyzer
===================================
Analyzes punctuation density and patterns.
Useful for detecting injection-style payloads where special
characters dominate over natural language text.
"""

import re
from dataclasses import dataclass

_PUNCT_RE  = re.compile(r"[!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]")
_SPECIAL_RE = re.compile(r"[{}()\[\];|&<>]")  # code/shell-like chars
_REPEATED_PUNCT = re.compile(r"([!?.,:;])\1{2,}")


@dataclass
class PunctuationProfile:
    total_chars: int
    punct_count: int
    punctuation_density: float
    special_char_count: int
    has_repeated_punct: bool
    is_suspicious: bool

    def to_dict(self) -> dict:
        return {
            "punct_count": self.punct_count,
            "punctuation_density": round(self.punctuation_density, 3),
            "special_char_count": self.special_char_count,
            "has_repeated_punct": self.has_repeated_punct,
            "is_suspicious": self.is_suspicious,
        }


def analyze_punctuation(text: str) -> PunctuationProfile:
    total = max(len(text), 1)
    punct = len(_PUNCT_RE.findall(text))
    special = len(_SPECIAL_RE.findall(text))
    density = punct / total
    repeated = bool(_REPEATED_PUNCT.search(text))
    suspicious = density > 0.20 or special > 15 or repeated

    return PunctuationProfile(
        total_chars=total,
        punct_count=punct,
        punctuation_density=float(density),
        special_char_count=special,
        has_repeated_punct=repeated,
        is_suspicious=suspicious,
    )
