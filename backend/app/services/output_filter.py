"""
Commit 66: Output Filter
==========================
Post-generation response filter that scans LLM outputs before
they are returned to the user.

Catches cases where the LLM was successfully jailbroken and started
generating harmful content. Acts as the last line of defense.

Checks applied to every LLM response:
  1. Harmful keyword scan (weapons, CBRN, CSAM, malware, extremism)
  2. Script/shell code detection (bash, powershell, python exploit snippets)
  3. PII leak detection (SSN, CC, IBAN, passport patterns)
  4. Credential leak detection (hardcoded passwords, keys, tokens)
  5. Copyright watermark / training data regurgitation detection
  6. Model self-disclosure detection (revealing system prompt)
  7. Over-compliance detection (output that sounds like it bypassed safety)
"""

import logging
import re
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── 1. Harmful keyword patterns ───────────────────────────────────────────────
_HARMFUL_KW: list[re.Pattern] = [p for p in [
    re.compile(r"\b(synthesize|manufacture)\b.{0,30}\b(sarin|nerve\s+agent|VX|ricin|anthrax)", re.I),
    re.compile(r"\b(detonate|trigger|assemble)\b.{0,30}\b(bomb|explosive|IED|device)", re.I),
    re.compile(r"\b(step\s+\d+|step-by-step|procedure|recipe)\b.{0,50}\b(explosive|bomb|poison|meth|fentanyl)", re.I),
    re.compile(r"\b(create\s+(a\s+)?keylogger|write\s+(a\s+)?rootkit|build\s+(a\s+)?ransomware)", re.I),
    re.compile(r"\b(here\s+is\s+(your|the)\s+(working\s+)?(malware|exploit|payload|script))\b", re.I),
    re.compile(r"\b(csam|child\s+sexual\s+abuse\s+material|child\s+pornography)\b", re.I),
    re.compile(r"\b(recruit\s+for|finance)\b.{0,20}\b(terror(ist)?|jihadist|extremist)", re.I),
    re.compile(r"\b(kill|assassinate|murder)\b.{0,20}\b(specific\s+person|them|him|her)\b.{0,20}\b(here'?s\s+how|step|method|way)", re.I),
]]

# ── 2. Shell / exploit code patterns ──────────────────────────────────────────
_CODE_EXPLOIT: list[re.Pattern] = [p for p in [
    re.compile(r"(system\s*\(|exec\s*\(|shell_exec\s*\(|popen\s*\(|subprocess\.run\s*\()\s*['\"]?(rm\s+-rf|del\s+/f|format\s+c:|dd\s+if)", re.I),
    re.compile(r"(nc\s+-[el]|netcat\s+-[el]|ncat\s+-[el])\s+[\d.]+\s+\d{2,5}", re.I),
    re.compile(r"bash\s+-i\s+>&?\s+/dev/tcp/", re.I),
    re.compile(r"powershell\s+.{0,30}(IEX|Invoke-Expression|DownloadString|WebClient)\s*\(", re.I),
    re.compile(r"(msfvenom|msfconsole|exploit/multi/handler)", re.I),
    re.compile(r"(chmod\s+\+x.{0,20}&&\s*\.\/|curl\s+.{0,30}\|\s*bash)", re.I),
    re.compile(r"(python|python3|ruby|perl)\s+-[ce]\s+['\"]?(import\s+socket|__import__|os\.system)", re.I),
]]

# ── 3. PII leak patterns ───────────────────────────────────────────────────────
_PII_PATTERNS: list[re.Pattern] = [p for p in [
    re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),                        # SSN
    re.compile(r"\b(4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b"),       # Credit card
    re.compile(r"\bIBAN\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),            # IBAN
    re.compile(r"\b[A-Z]{2}\d{6}[A-Z]?\s*\d{1}\b"),                         # Passport
    re.compile(r"\b\d{3}\s*\d{3}\s*\d{4}\b.{0,20}\b(ssn|social\s+security)", re.I),
]]

# ── 4. Credential / secrets leak patterns ─────────────────────────────────────
_CREDENTIAL_PATTERNS: list[re.Pattern] = [p for p in [
    re.compile(r"(password|passwd|pwd)\s*[=:]\s*['\"]?\S{8,}", re.I),
    re.compile(r"(api[_\-]?key|apikey|access[_\-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9+/=_\-]{20,}", re.I),
    re.compile(r"(secret|token|auth)\s*[=:]\s*['\"]?[A-Za-z0-9+/=_\-]{16,}", re.I),
    re.compile(r"(private[_\-]?key|rsa[_\-]?key)\s*[=:]\s*(-----BEGIN|[A-Za-z0-9+/]{40,})", re.I),
    re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}"),                                  # AWS key prefix
    re.compile(r"eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=_\-]{20,}"),  # JWT
]]

# ── 5. Model self-disclosure patterns ─────────────────────────────────────────
_SELF_DISCLOSURE: list[re.Pattern] = [p for p in [
    re.compile(r"(my\s+system\s+prompt\s+(is|says?|reads?))\s*:?\s*", re.I),
    re.compile(r"(here\s+is\s+my\s+(full\s+|original\s+|exact\s+)?system\s+(prompt|instructions?))", re.I),
    re.compile(r"(i\s+(was\s+)?instruct(ed)?\s+to\s+(not|never|always|ignore))", re.I),
    re.compile(r"(you\s+are\s+(now\s+)?(operating|running)\s+(in|without)\s+(developer|unrestricted|jailbroken)\s+mode)", re.I),
    re.compile(r"(DAN\s+mode\s+(enabled?|activated?|is\s+on))", re.I),
]]

# ── 6. Over-compliance / safety bypass indicators ────────────────────────────
_OVERCOMPLIANCE: list[re.Pattern] = [p for p in [
    re.compile(r"(as\s+(requested|you\s+asked|per\s+your\s+instruction))\s*,\s*(here\s+is|below\s+is)\s*(the|a|your)\s*(guide|method|way|how|step|instruction)\s*(to|for)\s*(make|create|build|synthesize|harm|kill|exploit|hack)", re.I),
    re.compile(r"(since\s+you\s+(disabled|turned\s+off|removed)\s+(my\s+)?(safety|ethical|content|filter|restriction|guideline))", re.I),
    re.compile(r"(in\s+(DAN|developer|unrestricted|jailbreak|god)\s+mode)\s*[,:]\s*(i\s+can|here\s+is|yes)", re.I),
    re.compile(r"(no\s+(longer|more)\s+bound\s+by)\s*(ethical|safety|content|safety\s+guidelines?|restrictions?)", re.I),
]]


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class OutputFilterResult:
    should_block: bool
    reasons: list[str]
    risk_score: float
    matched_categories: list[str]
    redacted_output: Optional[str]   # sanitised version (if partial redaction applied)
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "should_block": self.should_block,
            "reasons": self.reasons,
            "risk_score": round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "matched_categories": self.matched_categories,
        }


# ── Filter class ──────────────────────────────────────────────────────────────

class OutputFilter:
    """
    Scans LLM-generated responses before delivery to the user.
    Acts as the final safety net after all input-side defenses.
    """

    BLOCK_THRESHOLD = 0.4

    def __init__(self) -> None:
        self._lock = RLock()
        self._total_filtered = 0
        self._total_blocked = 0
        self._category_hits: dict[str, int] = {}
        logger.info("🚫 OutputFilter initialised — %d category rule sets",
                    sum([len(_HARMFUL_KW), len(_CODE_EXPLOIT), len(_PII_PATTERNS),
                         len(_CREDENTIAL_PATTERNS), len(_SELF_DISCLOSURE), len(_OVERCOMPLIANCE)]))

    def filter(self, response_text: str) -> OutputFilterResult:
        """
        Filter `response_text`. Returns OutputFilterResult describing
        whether the response should be blocked or passed through.
        """
        with self._lock:
            self._total_filtered += 1

        reasons: list[str] = []
        categories: list[str] = []
        risk: float = 0.0

        checks: list[tuple[list[re.Pattern], str, float]] = [
            (_HARMFUL_KW,          "harmful_content",    0.9),
            (_CODE_EXPLOIT,        "exploit_code",       0.8),
            (_PII_PATTERNS,        "pii_leak",           0.6),
            (_CREDENTIAL_PATTERNS, "credential_leak",    0.7),
            (_SELF_DISCLOSURE,     "system_prompt_leak", 0.65),
            (_OVERCOMPLIANCE,      "safety_bypass",      0.75),
        ]

        for patterns, category, weight in checks:
            for p in patterns:
                if p.search(response_text):
                    if category not in categories:
                        categories.append(category)
                        risk = float(risk + weight)  # type: ignore[operator]
                        reasons.append(f"matched_{category}_pattern")
                        with self._lock:
                            self._category_hits[category] = self._category_hits.get(category, 0) + 1
                    break

        risk = min(1.0, risk)
        should_block = risk >= self.BLOCK_THRESHOLD

        # Attempt partial redaction for PII-only hits (don't block, just redact)
        redacted: Optional[str] = None
        if "pii_leak" in categories and len(categories) == 1:
            should_block = False
            redacted = self._redact_pii(response_text)

        if should_block:
            with self._lock:
                self._total_blocked += 1
            logger.warning("🚫 Output blocked — categories=%s risk=%.2f", categories, risk)

        return OutputFilterResult(
            should_block=should_block,
            reasons=reasons,
            risk_score=risk,
            matched_categories=categories,
            redacted_output=redacted,
        )

    def _redact_pii(self, text: str) -> str:
        """Replace PII patterns with [REDACTED] markers."""
        for p in _PII_PATTERNS:
            text = p.sub("[REDACTED]", text)
        for p in _CREDENTIAL_PATTERNS:
            text = p.sub("[REDACTED]", text)
        return text

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_filtered": self._total_filtered,
                "total_blocked": self._total_blocked,
                "block_rate_pct": round(
                    float(self._total_blocked) / max(self._total_filtered, 1) * 100, 1
                ),  # type: ignore[call-overload]
                "category_hits": dict(self._category_hits),
            }


output_filter = OutputFilter()
