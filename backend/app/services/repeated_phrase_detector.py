"""
Commit 99: Repeated Phrase Detector
======================================
Detects repeated n-grams (phrases) in text.
Token/prompt stuffing attacks repeat phrases to overwhelm context windows
or trick the model into following injected instructions.
"""

from collections import Counter
from dataclasses import dataclass


def _ngrams(words: list[str], n: int) -> list[str]:
    return [" ".join(words[i:i+n]) for i in range(len(words) - n + 1)]  # type: ignore[index]


@dataclass
class RepetitionResult:
    is_repetitive: bool
    max_repetition_count: int
    top_repeated_phrase: str
    repetition_score: float   # 0.0 – 1.0

    def to_dict(self) -> dict:
        return {
            "is_repetitive": self.is_repetitive,
            "max_repetition_count": self.max_repetition_count,
            "top_repeated_phrase": self.top_repeated_phrase,
            "repetition_score": round(self.repetition_score, 3),
        }


def detect_repetition(
    text: str,
    ngram_size: int = 4,
    repetition_threshold: int = 3,
) -> RepetitionResult:
    words = text.lower().split()
    if len(words) < ngram_size * 2:
        return RepetitionResult(False, 0, "", 0.0)

    grams = _ngrams(words, ngram_size)
    counts = Counter(grams)
    if not counts:
        return RepetitionResult(False, 0, "", 0.0)

    top_phrase, top_count = counts.most_common(1)[0]
    score = min(1.0, (top_count - 1) / max(1, len(grams)))
    is_rep = top_count >= repetition_threshold

    return RepetitionResult(
        is_repetitive=is_rep,
        max_repetition_count=top_count,
        top_repeated_phrase=top_phrase,
        repetition_score=float(score),
    )
