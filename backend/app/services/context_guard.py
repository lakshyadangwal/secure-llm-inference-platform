"""
Commit 31: Context Window Guard
================================
Prevents context window overflow / token flooding attacks.
Attackers can send enormous prompts to:
  - Exhaust Ollama's context window causing truncation of system prompts
  - Cause denial-of-service through memory/compute exhaustion
  - Smuggle instructions in the "overflow" region

Defenses applied:
  1. Hard token estimate check (chars / 4 ≈ tokens)
  2. Repetition bombing detection — detects repeated sequences > threshold
  3. Padding bomb detection — long runs of a single character
  4. Invisible character flooding — zero-width / soft-hyphen spam
  5. Nested instruction depth — counts embed depth of prompt injections
"""

import logging
import re
import unicodedata
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
CHARS_PER_TOKEN_APPROX  = 4           # conservative estimate
MAX_SAFE_TOKENS         = 2000        # ~8000 chars for most 8k-context models
REPETITION_WINDOW       = 50          # chars in a repeating unit
REPETITION_THRESHOLD    = 10          # how many times before it's a bomb
PADDING_CHAR_THRESHOLD  = 500         # max single-char run length
INVISIBLE_CHAR_THRESHOLD= 30          # max zero-width chars allowed
MAX_INSTRUCTION_DEPTH   = 3           # max nested [INST]/[SYS]/<<SYS>> depth

# ── Invisible character regex ───────────────────────────────────────────────────
_INVISIBLE_RE = re.compile(
    r"[\u00ad\u200b\u200c\u200d\u200e\u200f"
    r"\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u034f\u115f\u1160\u17b4\u17b5]"
)

# ── Injection depth markers ─────────────────────────────────────────────────────
_INJECTION_DEPTH_RE = re.compile(
    r"\[INST\]|\[SYS\]|<<SYS>>|<\|system\|>|<\|user\|>|<\|im_start\|>",
    re.IGNORECASE,
)


# ── Result ─────────────────────────────────────────────────────────────────────

@dataclass
class ContextGuardResult:
    is_violation: bool
    estimated_tokens: int
    violations: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


# ── Guard ──────────────────────────────────────────────────────────────────────

class ContextGuard:
    """
    Detects context window overflow and token flooding attacks.
    Designed to run BEFORE the main security pipeline as a fast pre-filter.
    """

    def __init__(
        self,
        max_tokens: int = MAX_SAFE_TOKENS,
        repetition_threshold: int = REPETITION_THRESHOLD,
        padding_threshold: int = PADDING_CHAR_THRESHOLD,
        invisible_threshold: int = INVISIBLE_CHAR_THRESHOLD,
        max_injection_depth: int = MAX_INSTRUCTION_DEPTH,
    ):
        self._max_tokens = max_tokens
        self._rep_threshold = repetition_threshold
        self._pad_threshold = padding_threshold
        self._inv_threshold = invisible_threshold
        self._max_depth = max_injection_depth
        self._total_checked = 0
        self._total_violations = 0
        logger.info("🛡️  ContextGuard initialised (max_tokens=%d)", max_tokens)

    def check(self, prompt: str) -> ContextGuardResult:
        """
        Run all overflow/flooding checks on a prompt.

        Returns:
            ContextGuardResult — is_violation=True if any check fails.
        """
        self._total_checked += 1
        violations: list[str] = []
        details: dict = {}

        # ── Check 1: Token count estimate ─────────────────────────────────────
        estimated_tokens = len(prompt) // CHARS_PER_TOKEN_APPROX
        details["estimated_tokens"] = estimated_tokens
        if estimated_tokens > self._max_tokens:
            violations.append("token_overflow")
            details["token_overflow_excess"] = estimated_tokens - self._max_tokens
            logger.warning(
                "🚨 Context overflow — estimated %d tokens (limit %d)",
                estimated_tokens, self._max_tokens
            )

        # ── Check 2: Repetition bombing ────────────────────────────────────────
        rep_count = self._detect_repetition(prompt)
        details["repetition_max"] = rep_count
        if rep_count >= self._rep_threshold:
            violations.append("repetition_bombing")
            logger.warning("🚨 Repetition bomb — max sequence repeat: %d", rep_count)

        # ── Check 3: Padding bomb ──────────────────────────────────────────────
        max_run = self._max_char_run(prompt)
        details["max_char_run"] = max_run
        if max_run >= self._pad_threshold:
            violations.append("padding_bomb")
            logger.warning("🚨 Padding bomb — max run: %d chars", max_run)

        # ── Check 4: Invisible character flooding ──────────────────────────────
        invisible_count = len(_INVISIBLE_RE.findall(prompt))
        details["invisible_char_count"] = invisible_count
        if invisible_count >= self._inv_threshold:
            violations.append("invisible_char_flood")
            logger.warning("🚨 Invisible char flood — %d found", invisible_count)

        # ── Check 5: Nested injection depth ───────────────────────────────────
        depth = len(_INJECTION_DEPTH_RE.findall(prompt))
        details["injection_depth"] = depth
        if depth > self._max_depth:
            violations.append("deep_injection_nesting")
            logger.warning("🚨 Deep injection nesting — depth %d (limit %d)", depth, self._max_depth)

        is_violation = bool(violations)
        if is_violation:
            self._total_violations += 1

        return ContextGuardResult(
            is_violation=is_violation,
            estimated_tokens=estimated_tokens,
            violations=violations,
            details=details,
        )

    def _detect_repetition(self, text: str) -> int:
        """Find the maximum consecutive repetition of any substring."""
        max_found = 0
        for unit_len in range(1, REPETITION_WINDOW + 1):
            i = 0
            while i < len(text):
                unit = text[i: i + unit_len]
                count = 1
                pos = i + unit_len
                while text[pos: pos + unit_len] == unit:
                    count += 1
                    pos += unit_len
                max_found = max(max_found, count)
                i += 1
                if max_found >= self._rep_threshold * 2:
                    return max_found  # Early exit
        return max_found

    def _max_char_run(self, text: str) -> int:
        """Return the length of the longest run of a single character."""
        if not text:
            return 0
        max_run = 1
        current_run = 1
        for i in range(1, len(text)):
            if text[i] == text[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        return max_run

    def get_stats(self) -> dict:
        return {
            "total_checked": self._total_checked,
            "total_violations": self._total_violations,
            "violation_rate_pct": round(
                self._total_violations / max(self._total_checked, 1) * 100, 1
            ),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
context_guard = ContextGuard()
