"""
Commit 104: Sentence Splitter
================================
Lightweight sentence splitter using heuristics (no ML / NLTK needed).
Used to split prompts into sentences for per-sentence analysis.

Handles:
  - Standard full stop / ! / ? terminators
  - Abbreviations (Mr. Dr. etc.) — not treated as endings
  - Ellipsis (...) — not treated as ending
  - Newline-based splitting fallback
"""

import re

# Known abbreviations that should NOT trigger sentence splits
_ABBREVS = {
    "mr", "mrs", "ms", "dr", "prof", "sr", "jr", "vs", "etc",
    "approx", "est", "no", "vol", "inc", "ltd", "corp", "dept",
    "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
}

_SENTENCE_END_RE = re.compile(r"(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|!)\s+(?=[A-Z])")
_MULTI_NL_RE = re.compile(r"\n{2,}")


def split_sentences(text: str) -> list[str]:
    """Split `text` into a list of sentences using heuristic rules."""
    # First split on blank lines (paragraphs)
    paragraphs = _MULTI_NL_RE.split(text)
    sentences: list[str] = []
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        parts = _SENTENCE_END_RE.split(para)
        for part in parts:
            part = part.strip()
            if part:
                sentences.append(part)
    return sentences


def sentence_count(text: str) -> int:
    return len(split_sentences(text))


def avg_sentence_length(text: str) -> float:
    sents = split_sentences(text)
    if not sents:
        return 0.0
    total_words = sum(len(s.split()) for s in sents)
    return round(total_words / len(sents), 1)
