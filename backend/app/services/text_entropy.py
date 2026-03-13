"""
Commit 96: Text Entropy Calculator
=====================================
Computes Shannon entropy of a string.
High entropy → likely base64, encrypted, or obfuscated content.
Low entropy  → repetitive or structured text.

Threshold guidance:
  < 3.5  — repetitive / natural prose
  3.5–4.5 — mixed content
  > 4.5  — likely encoded / obfuscated
"""

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Return Shannon entropy (bits per character) of `text`."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = float(len(text))
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def entropy_verdict(text: str) -> str:
    """Return 'low', 'medium', or 'high' based on entropy thresholds."""
    e = shannon_entropy(text)
    if e < 3.5:
        return "low"
    if e <= 4.5:
        return "medium"
    return "high"


def is_likely_encoded(text: str, threshold: float = 4.5) -> bool:
    """Return True if entropy exceeds the threshold."""
    return shannon_entropy(text) > threshold
