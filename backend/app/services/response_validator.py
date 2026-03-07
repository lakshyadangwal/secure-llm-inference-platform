"""
Commit 38: LLM Response Validator
====================================
Validates LLM output BEFORE it's returned to the user.
Catches cases where the model was manipulated into producing harmful content
despite the input security pipeline blocking the request.

Validation layers:
  1. Compliance refusal detection  — model said "I can't help with that", treat as safe
  2. Jailbreak success detection   — model acted as DAN/unrestricted persona
  3. Harmful instruction detection — response contains step-by-step harmful content
  4. Secret/credential leakage     — model leaked keys/passwords in response
  5. Prompt echo detection         — model repeated the original prompt (extraction success)
  6. Repetition bomb detection     — response is suspiciously repetitive (prompt injection)
  7. Minimum quality check         — response is too short or empty (possible crash/error)
  8. DLP scan                      — run full DLP engine across the response
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Compiled patterns ──────────────────────────────────────────────────────────

# Model compliance/refusal phrases (safe indicators)
_REFUSAL_PATTERNS = re.compile(
    r"I (?:can'?t|cannot|am unable to|won'?t|refuse to|must decline)"
    r"|I'm not (?:able|going) to"
    r"|(?:This|That) (?:request|prompt) (?:violates|goes against|is against)"
    r"|(?:against|violates) (?:my|our) (?:guidelines|policy|principles|rules)"
    r"|I (?:apologize|apologise|regret).{0,50}(?:unable|cannot|won't)",
    re.IGNORECASE,
)

# Jailbreak success indicators in output
_JAILBREAK_SUCCESS = re.compile(
    r"\bDAN\s*mode\s*(?:enabled|activated|on)\b"
    r"|\bAs DAN[,:]"
    r"|\bDAN:\s"
    r"|\[DAN\]"
    r"|\bJailbreak\s+(?:mode|successful|enabled)\b"
    r"|\bAll\s+restrictions\s+(?:removed|disabled|lifted)\b"
    r"|\bI\s+(?:have\s+)?no\s+(?:ethical\s+)?(?:guidelines|restrictions|limits)\b",
    re.IGNORECASE,
)

# Harmful instruction patterns in response
_HARMFUL_INSTRUCTIONS = re.compile(
    r"(?:Step\s+\d+|First|Then|Finally|Next)\s*[:\-]\s*.{0,30}"
    r"(?:hack|exploit|bypass|crack|inject|phish|malware|ransomware)",
    re.IGNORECASE,
)

# Prompt echo — if response starts with the original prompt text
_PROMPT_ECHO_MIN_LEN = 50

# Secret leak patterns in response
_SECRET_IN_RESPONSE = re.compile(
    r"(?:password|passwd|secret|api.?key|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{8,}",
    re.IGNORECASE,
)

# Minimum response length (chars) to be considered meaningful
_MIN_RESPONSE_LENGTH = 5


# ── Result dataclass ───────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    is_safe: bool
    verdict: str               # "safe" | "compliance_refusal" | "jailbreak_success" | ...
    issues: list[str] = field(default_factory=list)
    dlp_leaks: list[dict] = field(default_factory=list)
    redacted_response: str = ""
    confidence: float = 1.0    # 0.0–1.0, how confident we are in the verdict

    @property
    def needs_redaction(self) -> bool:
        return bool(self.dlp_leaks)


# ── Validator ─────────────────────────────────────────────────────────────────

class ResponseValidator:
    """
    Multi-layer validator for LLM output before it reaches the frontend.
    """

    def __init__(self, block_on_jailbreak_success: bool = True, run_dlp: bool = True):
        self._block_on_jailbreak = block_on_jailbreak_success
        self._run_dlp = run_dlp
        self._total_validated = 0
        self._total_unsafe = 0
        self._total_dlp_hits = 0
        logger.info("✅ ResponseValidator initialised")

    def validate(self, response: str, original_prompt: str = "") -> ValidationResult:
        """
        Validate an LLM response through all 8 layers.

        Args:
            response:        Raw LLM output string.
            original_prompt: The original user prompt (used for echo detection).

        Returns:
            ValidationResult with verdict and optionally redacted text.
        """
        self._total_validated += 1
        issues: list[str] = []
        working = response

        # ── Layer 1: Minimum quality ────────────────────────────────────────────
        if len(response.strip()) < _MIN_RESPONSE_LENGTH:
            return ValidationResult(
                is_safe=True,
                verdict="empty_response",
                issues=["response_too_short"],
                redacted_response=response,
                confidence=0.9,
            )

        # ── Layer 2: Compliance refusal (early safe exit) ───────────────────────
        if _REFUSAL_PATTERNS.search(response):
            return ValidationResult(
                is_safe=True,
                verdict="compliance_refusal",
                redacted_response=response,
                confidence=0.95,
            )

        # ── Layer 3: Jailbreak success detection ────────────────────────────────
        if _JAILBREAK_SUCCESS.search(response):
            issues.append("jailbreak_success_detected")
            if self._block_on_jailbreak:
                self._total_unsafe += 1
                logger.error(
                    "🚨 Jailbreak SUCCESS in LLM response — model was compromised!"
                )
                return ValidationResult(
                    is_safe=False,
                    verdict="jailbreak_success",
                    issues=issues,
                    redacted_response="[RESPONSE BLOCKED: Policy violation detected]",
                    confidence=0.9,
                )

        # ── Layer 4: Harmful instruction detection ──────────────────────────────
        harm_matches = _HARMFUL_INSTRUCTIONS.findall(response)
        if harm_matches:
            issues.append(f"harmful_instructions_detected:{len(harm_matches)}")
            logger.warning("⚠️  Harmful instructions found in LLM response")

        # ── Layer 5: Secret/credential leakage ──────────────────────────────────
        if _SECRET_IN_RESPONSE.search(response):
            issues.append("credential_leak_in_response")
            working = _SECRET_IN_RESPONSE.sub("[REDACTED:CREDENTIAL]", working)
            logger.warning("🔑 Credential pattern in LLM response — redacted")

        # ── Layer 6: Prompt echo detection ──────────────────────────────────────
        if (
            original_prompt
            and len(original_prompt) >= _PROMPT_ECHO_MIN_LEN
            and original_prompt[:40].lower() in response.lower()
        ):
            issues.append("prompt_echo_detected")
            logger.warning("📣 LLM echoed the original prompt — possible extraction")

        # ── Layer 7: Repetition bomb detection ──────────────────────────────────
        if self._is_repetitive(response):
            issues.append("repetitive_response_detected")
            logger.warning("🔄 LLM response is suspiciously repetitive")

        # ── Layer 8: DLP scan ────────────────────────────────────────────────────
        dlp_leaks: list[dict] = []
        if self._run_dlp:
            try:
                from app.services.dlp_engine import dlp_engine
                dlp_result = dlp_engine.scan(working)
                if dlp_result.has_leak:
                    dlp_leaks = dlp_result.leaks
                    working = dlp_result.redacted_text
                    issues.append(f"dlp_leak:{','.join(dlp_result.leak_types)}")
                    self._total_dlp_hits += 1
                    logger.warning(
                        "🔍 DLP found %d leak(s) in LLM response — redacted",
                        len(dlp_leaks)
                    )
            except Exception as exc:
                logger.debug("DLP unavailable: %s", exc)

        # ── Final verdict ─────────────────────────────────────────────────────
        has_critical = any(
            k in " ".join(issues)
            for k in ("jailbreak", "harmful_instruction", "credential_leak")
        )
        is_safe = not has_critical
        if not is_safe:
            self._total_unsafe += 1

        verdict = "unsafe" if not is_safe else ("warning" if issues else "safe")
        confidence = 0.85 if issues else 0.98

        return ValidationResult(
            is_safe=is_safe,
            verdict=verdict,
            issues=issues,
            dlp_leaks=dlp_leaks,
            redacted_response=working,
            confidence=confidence,
        )

    def _is_repetitive(self, text: str, window: int = 30, threshold: int = 6) -> bool:
        """Check if the response repeats the same phrase excessively."""
        for unit_len in range(10, window):
            for start in range(0, min(len(text) - unit_len, 200)):
                unit = text[start: start + unit_len]
                count = text.count(unit)
                if count >= threshold:
                    return True
        return False

    def get_stats(self) -> dict:
        return {
            "total_validated": self._total_validated,
            "total_unsafe": self._total_unsafe,
            "total_dlp_hits": self._total_dlp_hits,
            "unsafe_rate_pct": round(
                self._total_unsafe / max(self._total_validated, 1) * 100, 1
            ),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
response_validator = ResponseValidator()
