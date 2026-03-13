"""
Commit 108: Text Statistics
=============================
Aggregates common text metrics used across defense modules.
Single pass over the text for efficient computation.
"""

from dataclasses import dataclass
import re

_WORD_RE = re.compile(r"\b\w+\b")


@dataclass
class TextStats:
    char_count: int
    word_count: int
    sentence_count: int
    avg_word_length: float
    unique_word_ratio: float   # unique_words / total_words
    digit_fraction: float
    upper_fraction: float

    def to_dict(self) -> dict:
        return {
            "char_count": self.char_count,
            "word_count": self.word_count,
            "sentence_count": self.sentence_count,
            "avg_word_length": round(self.avg_word_length, 2),
            "unique_word_ratio": round(self.unique_word_ratio, 3),
            "digit_fraction": round(self.digit_fraction, 3),
            "upper_fraction": round(self.upper_fraction, 3),
        }


def compute_stats(text: str) -> TextStats:
    if not text:
        return TextStats(0, 0, 0, 0.0, 0.0, 0.0, 0.0)

    words = _WORD_RE.findall(text)
    sentence_count = max(1, text.count(".") + text.count("!") + text.count("?"))
    unique_ratio = len(set(w.lower() for w in words)) / max(len(words), 1)
    avg_wl = sum(len(w) for w in words) / max(len(words), 1)
    digits = sum(1 for c in text if c.isdigit())
    uppers = sum(1 for c in text if c.isupper())
    total = max(len(text), 1)

    return TextStats(
        char_count=len(text),
        word_count=len(words),
        sentence_count=sentence_count,
        avg_word_length=float(avg_wl),
        unique_word_ratio=float(unique_ratio),
        digit_fraction=float(digits / total),
        upper_fraction=float(uppers / total),
    )
