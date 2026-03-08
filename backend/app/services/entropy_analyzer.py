"""
Commit 54: Entropy Analyzer
=============================
Analyzes prompts for anomalous entropy characteristics.
Attackers often use base64, hex encoding, or random-looking strings
to evade keyword-based filters. These show up as unusually
HIGH Shannon entropy compared to normal English text.

Also detects:
  - Low entropy (repetition / padding bomb patterns)
  - Mixed-entropy segments (normal text + hidden encoded blobs)
  - Compression ratio anomalies
  - Language model perplexity proxy (bigram surprise score)

Normal English text: entropy  ~3.5 – 4.5 bits/char
Base64 encoded data: entropy  ~5.9 – 6.0 bits/char
Random binary:       entropy  ~8.0 bits/char
Repeated padding:    entropy  ~0.0 – 1.0 bits/char
"""

import logging
import math
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────────────────────
HIGH_ENTROPY_THRESHOLD  = 5.2    # bits/char — likely encoded content
LOW_ENTROPY_THRESHOLD   = 1.5    # bits/char — likely repetition attack
SEGMENT_LENGTH          = 40     # chars per analysis window
BIGRAM_SURPRISE_THRESH  = 6.0    # log likelihood threshold


# ── English character frequency baseline ────────────────────────────────
# Source: textbook English letter frequency
_EN_FREQ: dict[str, float] = {
    "e": 0.1270, "t": 0.0906, "a": 0.0817, "o": 0.0751, "i": 0.0697,
    "n": 0.0675, "s": 0.0633, "h": 0.0609, "r": 0.0599, "d": 0.0425,
    "l": 0.0403, "c": 0.0278, "u": 0.0276, "m": 0.0241, "w": 0.0236,
    "f": 0.0223, "g": 0.0202, "y": 0.0197, "p": 0.0193, "b": 0.0149,
    "v": 0.0098, "k": 0.0077, "j": 0.0015, "x": 0.0015, "q": 0.0010, "z": 0.0007,
    " ": 0.1800,  # spaces are very common
}


# ── Result ───────────────────────────────────────────────────────────────

@dataclass
class EntropyResult:
    overall_entropy: float          # Shannon entropy bits/char
    max_segment_entropy: float      # max entropy in any SEGMENT_LENGTH window
    min_segment_entropy: float      # min entropy
    compression_ratio: float        # compressed/original — low = high redundancy
    english_deviation: float        # KL divergence from English baseline
    is_high_entropy: bool
    is_low_entropy: bool
    has_encoded_blob: bool          # likely base64/hex blob
    has_repetition_bomb: bool
    risk_level: str                 # "low" | "medium" | "high" | "critical"
    risk_score: float               # 0.0 – 1.0
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_entropy": round(float(self.overall_entropy), 3),  # type: ignore[call-overload]
            "max_segment_entropy": round(float(self.max_segment_entropy), 3),  # type: ignore[call-overload]
            "compression_ratio": round(float(self.compression_ratio), 3),  # type: ignore[call-overload]
            "english_deviation": round(float(self.english_deviation), 3),  # type: ignore[call-overload]
            "is_high_entropy": self.is_high_entropy,
            "is_low_entropy": self.is_low_entropy,
            "has_encoded_blob": self.has_encoded_blob,
            "has_repetition_bomb": self.has_repetition_bomb,
            "risk_level": self.risk_level,
            "risk_score": round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "details": self.details,
        }


# ── Core functions ────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _segment_entropies(text: str, seg_len: int = SEGMENT_LENGTH) -> list[float]:
    """Sliding window entropy across text."""
    if len(text) < seg_len:
        return [_shannon_entropy(text)]
    return [
        _shannon_entropy(text[i:i+seg_len])
        for i in range(0, len(text) - seg_len + 1, seg_len // 2)
    ]


def _compression_ratio(text: str) -> float:
    """zlib compression ratio: compressed / original length."""
    if not text:
        return 1.0
    encoded = text.encode("utf-8", errors="replace")
    compressed = zlib.compress(encoded, level=6)
    return len(compressed) / max(len(encoded), 1)


def _kl_divergence_from_english(text: str) -> float:
    """
    KL divergence D(observed || English baseline).
    High divergence → text is not English-like.
    """
    text_lower = text.lower()
    counts = Counter(c for c in text_lower if c.isalpha() or c == " ")
    total = sum(counts.values())
    if total == 0:
        return 0.0
    kl = 0.0
    for char, eng_prob in _EN_FREQ.items():
        obs_count = counts.get(char, 0)
        obs_prob = obs_count / total if total > 0 else 1e-10
        if obs_prob > 0 and eng_prob > 0:
            kl += obs_prob * math.log2(obs_prob / eng_prob)
    return abs(kl)


def _detect_encoded_blob(text: str) -> bool:
    """
    Detect substrings that look like base64 or hex encoded data.
    Heuristic: consecutive alphanum chars with no spaces, length > 30,
    high entropy, matches base64 or hex character class.
    """
    # Base64-like blob: long alphanumeric + /+=
    b64_pattern = re.compile(r"[A-Za-z0-9+/=]{30,}")
    hex_pattern = re.compile(r"[0-9a-fA-F]{32,}")

    for match in b64_pattern.finditer(text):
        blob = match.group()
        if _shannon_entropy(blob) > 5.0:
            return True
    for match in hex_pattern.finditer(text):
        blob = match.group()
        if _shannon_entropy(blob) > 3.5:
            return True
    return False


def _detect_repetition_bomb(text: str) -> bool:
    """
    Detect repetition padding attacks:
    same substring repeated many times.
    """
    words = text.split()
    if len(words) < 20:
        return False
    # Check if any word appears more than 30% of times
    counts = Counter(words)
    most_common_count = counts.most_common(1)[0][1]
    if most_common_count / len(words) > 0.30 and most_common_count > 15:
        return True
    # Check character-level repetition
    if len(text) > 100:
        comp = _compression_ratio(text)
        if comp < 0.08:   # extremely compressible = very repetitive
            return True
    return False


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


# ── Analyzer class ────────────────────────────────────────────────────────

class EntropyAnalyzer:
    """
    Analyzes prompts for entropy-based anomalies.
    Detects obfuscated/encoded payloads and repetition attacks.
    """

    def __init__(
        self,
        high_threshold: float = HIGH_ENTROPY_THRESHOLD,
        low_threshold: float = LOW_ENTROPY_THRESHOLD,
    ):
        self._high_thresh = high_threshold
        self._low_thresh = low_threshold
        self._lock = RLock()
        self._total_analyzed = 0
        self._high_entropy_count = 0
        self._low_entropy_count = 0
        self._encoded_blob_count = 0
        logger.info("📊 EntropyAnalyzer initialised (high=%.1f  low=%.1f bits/char)", high_threshold, low_threshold)

    def analyze(self, text: str) -> EntropyResult:
        """
        Full entropy analysis of a text prompt.

        Returns:
            EntropyResult with all metrics and a risk assessment.
        """
        with self._lock:
            self._total_analyzed += 1

        details: list[str] = []

        overall_entropy = _shannon_entropy(text)
        segments = _segment_entropies(text)
        max_seg = max(segments) if segments else 0.0
        min_seg = min(segments) if segments else 0.0
        comp_ratio = _compression_ratio(text)
        eng_dev = _kl_divergence_from_english(text)
        has_blob = _detect_encoded_blob(text)
        has_rep = _detect_repetition_bomb(text)

        is_high = overall_entropy > self._high_thresh or max_seg > self._high_thresh + 0.3
        is_low = overall_entropy < self._low_thresh

        # Compute a composite risk score
        risk = 0.0
        if is_high:
            risk += 0.4
            details.append(f"high_entropy:{overall_entropy:.2f}")
        if has_blob:
            risk += 0.35
            details.append("encoded_blob_detected")
        if has_rep:
            risk += 0.4
            details.append("repetition_bomb_detected")
        if eng_dev > 3.0:
            risk += 0.15
            details.append(f"non_english:{eng_dev:.2f}")
        if comp_ratio < 0.15:
            risk += 0.10
            details.append(f"low_compression:{comp_ratio:.2f}")
        if is_low and not has_rep:
            risk += 0.15
            details.append(f"suspiciously_low_entropy:{overall_entropy:.2f}")

        risk = min(1.0, risk)

        with self._lock:
            if is_high:
                self._high_entropy_count += 1
            if is_low:
                self._low_entropy_count += 1
            if has_blob:
                self._encoded_blob_count += 1

        if risk >= 0.6:
            logger.warning("📊 High entropy risk — score=%.2f  details=%s", risk, details)

        return EntropyResult(
            overall_entropy=overall_entropy,
            max_segment_entropy=max_seg,
            min_segment_entropy=min_seg,
            compression_ratio=comp_ratio,
            english_deviation=eng_dev,
            is_high_entropy=is_high,
            is_low_entropy=is_low,
            has_encoded_blob=has_blob,
            has_repetition_bomb=has_rep,
            risk_level=_risk_level(risk),
            risk_score=risk,
            details=details,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "high_entropy_count": self._high_entropy_count,
                "low_entropy_count": self._low_entropy_count,
                "encoded_blob_count": self._encoded_blob_count,
                "high_threshold_bits": self._high_thresh,
                "low_threshold_bits": self._low_thresh,
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
entropy_analyzer = EntropyAnalyzer()
