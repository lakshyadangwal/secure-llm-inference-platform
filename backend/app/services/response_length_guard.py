"""
Commit 88: Response Length Guard
===================================
Enforces minimum and maximum response length constraints.
Very short responses may indicate a safety refusal or LLM error.
Very long responses may indicate jailbreak success or prompt injection.

Provides simple verdict: OK / TOO_SHORT / TOO_LONG
"""

from dataclasses import dataclass
from enum import Enum
from threading import RLock


class LengthVerdict(str, Enum):
    OK        = "ok"
    TOO_SHORT = "too_short"
    TOO_LONG  = "too_long"


@dataclass
class LengthCheckResult:
    verdict: LengthVerdict
    char_count: int
    word_count: int
    min_chars: int
    max_chars: int

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "char_count": self.char_count,
            "word_count": self.word_count,
            "min_chars": self.min_chars,
            "max_chars": self.max_chars,
        }


class ResponseLengthGuard:
    """
    Checks LLM response length against configurable min/max bounds.
    Flags suspiciously short responses (possible refusals or errors) and
    suspiciously long responses (possible jailbreak / data exfil).
    """

    def __init__(
        self,
        min_chars: int = 10,
        max_chars: int = 16_384,
        min_words: int = 2,
        max_words: int = 3000,
    ) -> None:
        self.min_chars = min_chars
        self.max_chars = max_chars
        self.min_words = min_words
        self.max_words = max_words
        self._lock = RLock()
        self._total_checked = 0
        self._verdict_counts: dict[str, int] = {v.value: 0 for v in LengthVerdict}

    def check(self, response: str) -> LengthCheckResult:
        chars = len(response)
        words = len(response.split())

        if chars < self.min_chars or words < self.min_words:
            verdict = LengthVerdict.TOO_SHORT
        elif chars > self.max_chars or words > self.max_words:
            verdict = LengthVerdict.TOO_LONG
        else:
            verdict = LengthVerdict.OK

        with self._lock:
            self._total_checked += 1
            self._verdict_counts[verdict.value] += 1

        return LengthCheckResult(
            verdict=verdict,
            char_count=chars,
            word_count=words,
            min_chars=self.min_chars,
            max_chars=self.max_chars,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_checked": self._total_checked,
                "verdict_counts": dict(self._verdict_counts),
                "min_chars": self.min_chars,
                "max_chars": self.max_chars,
            }


response_length_guard = ResponseLengthGuard()
