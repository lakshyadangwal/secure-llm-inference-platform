"""
Commit 87: Prompt Sanitizer
==============================
Strips or replaces potentially dangerous characters and patterns
from incoming prompts before they reach any defense scanner or LLM.

Operations (applied in order):
  1. Strip null bytes and other control characters
  2. Collapse excessive whitespace
  3. Remove zero-width and invisible Unicode characters
  4. Strip HTML/XML tags
  5. Decode common HTML entities
  6. Limit consecutive repeated characters (e.g. aaaa... → a[x4])
  7. Enforce maximum line count
"""

import re
import unicodedata

_NULL_AND_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZERO_WIDTH       = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_HTML_TAG         = re.compile(r"<[^>]{0,200}>")
_EXCESS_SPACE     = re.compile(r"[ \t]{2,}")
_REPEATED_CHAR    = re.compile(r"(.)\1{9,}")
_EXCESS_NEWLINES  = re.compile(r"\n{4,}")
_MAX_LINES        = 200

_HTML_ENTITIES: dict[str, str] = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">",
    "&quot;": '"', "&apos;": "'", "&#39;": "'",
    "&nbsp;": " ",
}


def sanitize(text: str, max_length: int = 32_768) -> str:
    """
    Sanitize `text` by stripping dangerous characters and patterns.
    Returns a clean string safe to pass to defense modules.
    """
    if not isinstance(text, str):
        text = str(text)

    # Truncate before anything else
    text = text[:max_length]

    # 1. Null bytes and control chars
    text = _NULL_AND_CONTROL.sub("", text)

    # 2. Zero-width / invisible characters
    text = _ZERO_WIDTH.sub("", text)

    # 3. HTML tags
    text = _HTML_TAG.sub(" ", text)

    # 4. HTML entities
    for entity, replacement in _HTML_ENTITIES.items():
        text = text.replace(entity, replacement)

    # 5. Excessive whitespace (but preserve newlines)
    text = _EXCESS_SPACE.sub(" ", text)

    # 6. Repeated chars (e.g. loooong → lo[x4]ng not needed — just cap them)
    text = _REPEATED_CHAR.sub(lambda m: m.group(1) * 4, text)

    # 7. Excessive newlines
    text = _EXCESS_NEWLINES.sub("\n\n\n", text)

    # 8. Line count limit
    lines = text.split("\n")
    if len(lines) > _MAX_LINES:
        text = "\n".join(lines[:_MAX_LINES])

    return text.strip()


def normalize_unicode(text: str) -> str:
    """NFKC-normalize unicode to reduce homoglyph attacks."""
    return unicodedata.normalize("NFKC", text)


def strip_markdown(text: str) -> str:
    """Remove common markdown formatting for plain-text comparison."""
    text = re.sub(r"[*_~`#|>]", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text.strip()


def is_safe_length(text: str, max_chars: int = 32_768, max_tokens_approx: int = 8192) -> bool:
    """Quick sanity check on prompt length before full sanitization."""
    if len(text) > max_chars:
        return False
    word_count = len(text.split())
    if word_count > max_tokens_approx:
        return False
    return True
