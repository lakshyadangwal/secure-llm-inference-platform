"""
Commit 113: Defense Utilities
================================
Shared helper functions used across multiple defense modules.
Centralises common operations to avoid code duplication.
"""

import hashlib
import re
import time


def sha256_prefix(text: str, length: int = 16) -> str:
    """Return a short SHA-256 hex digest of `text` for safe logging."""
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return digest[:length]


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a float to [lo, hi]."""
    return max(lo, min(hi, value))


def weighted_max_sum(scores: list[float], weights: list[float], alpha: float = 0.5) -> float:
    """
    Hybrid aggregation: alpha * max_score + (1-alpha) * weighted_average.
    Gives weight to the worst-case signal while still considering all signals.
    """
    if not scores:
        return 0.0
    max_score = max(scores)
    total_w = sum(weights) or 1.0
    w_avg = sum(s * w for s, w in zip(scores, weights)) / total_w
    return clamp(alpha * max_score + (1 - alpha) * w_avg)


def now_ms() -> int:
    """Current time in milliseconds."""
    return int(time.time() * 1000)


def truncate_for_log(text: str, max_len: int = 120) -> str:
    """Truncate and clean text for safe log output."""
    text = re.sub(r"[\r\n\t]+", " ", text)
    if len(text) > max_len:
        return text[:max_len] + "…"
    return text


def score_to_verdict(score: float, warn: float = 0.35, block: float = 0.65) -> str:
    """Convert a numeric score to a verdict string."""
    if score >= block:
        return "block"
    if score >= warn:
        return "warn"
    return "allow"
