"""
Commit 86: Token Counter
==========================
Lightweight approximate token counter that works without any ML library.
Uses a heuristic similar to GPT tokenisation:
  - Split on whitespace
  - Further split tokens that contain punctuation
  - Every ~4 characters counts as one token for long words

Provides:
  - count(text)            → int
  - fits_in_budget(text, n) → bool
  - truncate_to(text, n)   → str  (truncate to approximately n tokens)
"""

import re
from threading import RLock

_PUNCT_RE = re.compile(r"([^\w\s])")
_WHITESPACE_RE = re.compile(r"\s+")


def _split_tokens(text: str) -> list[str]:
    """Split text into approximate tokens."""
    # Insert spaces around punctuation so they become separate tokens
    spaced = _PUNCT_RE.sub(r" \1 ", text)
    raw_tokens = _WHITESPACE_RE.split(spaced.strip())
    tokens: list[str] = []
    for tok in raw_tokens:
        if not tok:
            continue
        # Long words are split every 4 chars (rough byte-pair encoding approximation)
        if len(tok) > 8:
            for i in range(0, len(tok), 4):
                chunk = tok[i:i+4]  # type: ignore[index]
                if chunk:
                    tokens.append(chunk)
        else:
            tokens.append(tok)
    return tokens


def count(text: str) -> int:
    """Return approximate token count for `text`."""
    if not text:
        return 0
    return len(_split_tokens(text))


def fits_in_budget(text: str, max_tokens: int) -> bool:
    """Return True if `text` fits within `max_tokens`."""
    return count(text) <= max_tokens


def truncate_to(text: str, max_tokens: int) -> str:
    """Truncate `text` to approximately `max_tokens` tokens."""
    tokens = _split_tokens(text)
    if len(tokens) <= max_tokens:
        return text
    truncated_tokens = tokens[:max_tokens]
    # Rebuild by finding where the last kept token ends in the original text
    rejoined = " ".join(truncated_tokens)
    # Walk back to last complete word boundary in the original
    end_pos = len(rejoined)
    if end_pos < len(text):
        # Find nearest whitespace in original text near this position
        search_start = max(0, end_pos - 20)
        segment = text[search_start:end_pos + 20]
        ws_pos = segment.rfind(" ")
        if ws_pos != -1:
            end_pos = search_start + ws_pos
    return text[:end_pos].rstrip()


class TokenBudgetGuard:
    """
    Stateful guard that tracks token usage per session/key and
    rejects requests that exceed the configured budget.
    """

    def __init__(self, max_tokens_per_session: int = 4096) -> None:
        self._max = max_tokens_per_session
        self._usage: dict[str, int] = {}
        self._lock = RLock()

    def consume(self, key: str, text: str) -> tuple[bool, int]:
        """
        Attempt to consume tokens for `key`.
        Returns (allowed, tokens_used).
        """
        tokens_used = count(text)
        with self._lock:
            current = self._usage.get(key, 0)
            if current + tokens_used > self._max:
                return False, tokens_used
            self._usage[key] = current + tokens_used
        return True, tokens_used

    def reset(self, key: str) -> None:
        with self._lock:
            self._usage.pop(key, None)

    def usage(self, key: str) -> int:
        with self._lock:
            return self._usage.get(key, 0)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "max_tokens_per_session": self._max,
                "tracked_keys": len(self._usage),
                "total_tokens_consumed": sum(self._usage.values()),
            }


token_budget_guard = TokenBudgetGuard()
