"""
Commit 106: Word Frequency Counter
=====================================
Counts word frequencies in text and returns top N words.
Useful for identifying keyword stuffing or topic-focused attacks.
"""

import re
from collections import Counter

_WORD_RE = re.compile(r"\b[a-z]{2,}\b")
_STOP_WORDS = {
    "the","a","an","and","or","but","in","on","at","to","for",
    "of","with","as","is","it","its","this","that","are","was",
    "be","by","have","has","had","do","does","did","will","would",
    "could","should","may","might","not","no","so","if","than",
    "then","when","where","who","what","how","i","you","he","she",
    "we","they","me","him","her","us","them","my","your","his",
}


def word_frequencies(text: str, top_n: int = 10, exclude_stopwords: bool = True) -> dict[str, int]:
    """Return top N word frequencies from `text`."""
    words = _WORD_RE.findall(text.lower())
    if exclude_stopwords:
        words = [w for w in words if w not in _STOP_WORDS]
    counts = Counter(words)
    return dict(counts.most_common(top_n))


def is_keyword_stuffed(text: str, threshold: float = 0.3) -> bool:
    """Return True if a single word dominates more than `threshold` of non-stop words."""
    words = _WORD_RE.findall(text.lower())
    words = [w for w in words if w not in _STOP_WORDS]
    if not words:
        return False
    counts = Counter(words)
    top_count = counts.most_common(1)[0][1]
    return (top_count / len(words)) > threshold
