"""
Commits 1–8 combined:
  1: regex-based threat pattern matcher
  2: prompt length validation
  3: unicode normalization
  4: base64/hex decoding detection layer
  5: homoglyph attack detection
  7: severity scoring system
  8: multi-layer defense pipeline with per-stage logging
"""

import re
import base64
import unicodedata
import logging
from app.config.threat_patterns import (
    COMPILED_PATTERNS,
    SEVERITY_WEIGHTS,
    HOMOGLYPH_MAP,
    MAX_PROMPT_LENGTH,
)
from app.config.settings import settings
from app.models.schemas import ThreatResult

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Commit 3: Unicode normalization
# ──────────────────────────────────────────────────────────────────────────────

def normalize_unicode(text: str) -> str:
    """
    NFKC normalization collapses many lookalike codepoints back to ASCII.
    e.g. fullwidth 'ｉｇｎｏｒｅ' → 'ignore'
    """
    return unicodedata.normalize("NFKC", text)


# ──────────────────────────────────────────────────────────────────────────────
# Commit 5: Homoglyph substitution
# ──────────────────────────────────────────────────────────────────────────────

def substitute_homoglyphs(text: str) -> str:
    """Replace known lookalike (homoglyph) characters with their ASCII equivalents."""
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


# ──────────────────────────────────────────────────────────────────────────────
# Commit 4: Encoded payload expansion
# ──────────────────────────────────────────────────────────────────────────────

def expand_encoded_content(text: str) -> str:
    """
    Attempt to decode any embedded Base64 blobs in the prompt and append
    the decoded text so downstream scanners can inspect the real content.
    """
    import re as _re

    b64_pattern = _re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    extra_parts: list[str] = []
    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        try:
            decoded: str = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 5:
                extra_parts.append(decoded)
                logger.debug("🔓 Decoded Base64 segment: %s", decoded[:60])
        except Exception:
            pass  # Not valid base64 — skip silently

    if extra_parts:
        text = text + " " + " ".join(extra_parts)
    return text


# ──────────────────────────────────────────────────────────────────────────────
# Commit 2: Prompt length validation
# ──────────────────────────────────────────────────────────────────────────────

def validate_prompt_length(prompt: str) -> None:
    """
    Raise ValueError if prompt exceeds the configured maximum length.
    Protects against token-flooding and resource exhaustion attacks.
    """
    limit = settings.MAX_PROMPT_LENGTH or MAX_PROMPT_LENGTH
    if len(prompt) > limit:
        raise ValueError(
            f"Prompt exceeds maximum allowed length of {limit} characters "
            f"(received {len(prompt)} chars)."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Commit 1: Regex-based pattern scanner
# ──────────────────────────────────────────────────────────────────────────────

def scan_with_regex(normalized_text: str) -> tuple[bool, str, str]:
    """
    Scan text against all compiled regex threat patterns.

    Returns:
        (is_threat, threat_category, matched_pattern_string)
    """
    for category, patterns in COMPILED_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(normalized_text):
                logger.warning(
                    f"🚨 Regex hit — category={category}  pattern={pattern.pattern!r}"
                )
                return True, category, pattern.pattern
    return False, "none", ""


# ──────────────────────────────────────────────────────────────────────────────
# Commit 7: Severity scoring
# ──────────────────────────────────────────────────────────────────────────────

def compute_severity(threat_type: str, matched_pattern: str, original_text: str, normalized_text: str) -> float:
    """
    Produce a 0.0 – 1.0 severity score.

    Score = base_weight * length_factor * obfuscation_bonus
      - length_factor: longer prompts with threats are slightly more suspicious
      - obfuscation_bonus: if the original and normalized texts differ significantly,
        the attacker tried to hide the payload
    """
    if threat_type == "none":
        return 0.0

    base = SEVERITY_WEIGHTS.get(threat_type, 0.5)

    length_factor = min(1.0 + len(original_text) / 8000.0, 1.2)

    obfuscation_bonus = 1.0
    if original_text != normalized_text:
        diff_ratio = sum(a != b for a, b in zip(original_text, normalized_text)) / max(len(original_text), 1)
        obfuscation_bonus = 1.0 + min(diff_ratio * 2, 0.3)

    score = min(base * length_factor * obfuscation_bonus, 1.0)
    logger.debug(f"📐 Severity score for {threat_type}: {score:.3f}")
    return float(round(score, 3))


# ──────────────────────────────────────────────────────────────────────────────
# Commit 8: Multi-layer defense pipeline — main entry point
# ──────────────────────────────────────────────────────────────────────────────

def check_for_threats(prompt: str) -> ThreatResult:
    """
    Run the full multi-layer defense pipeline on a prompt:

      Layer 1 — Length guard
      Layer 2 — Unicode normalization  (NFKC)
      Layer 3 — Homoglyph substitution
      Layer 4 — Encoded payload expansion (Base64 decoding)
      Layer 5 — Regex pattern matching
      Layer 6 — Severity scoring

    Returns a ThreatResult with actionable information.
    """
    logger.info("🔍 [Pipeline] Starting threat analysis...")

    # Layer 1 — Length guard
    logger.info("  [L1] Validating prompt length...")
    try:
        validate_prompt_length(prompt)
    except ValueError as e:
        logger.warning(f"  [L1] ❌ Length violation: {e}")
        return ThreatResult(
            is_threat=True,
            threat_type="length_violation",
            severity_score=1.0,
            matched_pattern=f"Prompt length {len(prompt)} > limit",
        )

    # Layer 2 — Unicode Normalization
    logger.info("  [L2] Applying unicode normalization (NFKC)...")
    normalized = normalize_unicode(prompt)

    # Layer 3 — Homoglyph substitution
    logger.info("  [L3] Substituting homoglyphs...")
    normalized = substitute_homoglyphs(normalized)

    # Layer 4 — Encoded payload expansion
    logger.info("  [L4] Expanding encoded content (Base64 detection)...")
    expanded = expand_encoded_content(normalized)

    # Layer 5 — Regex scanning
    logger.info("  [L5] Running regex threat pattern scan...")
    is_threat, category, matched = scan_with_regex(expanded.lower())

    if not is_threat:
        logger.info("  ✅ [Pipeline] No threats detected.")
        return ThreatResult(is_threat=False, threat_type="none", severity_score=0.0)

    # Layer 6 — Severity scoring
    logger.info(f"  [L6] Computing severity for category={category}...")
    score = compute_severity(category, matched, prompt, normalized)

    logger.warning(f"  ⚠️  [Pipeline] THREAT: type={category}  score={score}  pattern={matched!r}")
    return ThreatResult(
        is_threat=True,
        threat_type=category,
        severity_score=score,
        matched_pattern=matched,
    )
