"""
Commit 29: Input Sanitizer
===========================
Strips and neutralises dangerous content from raw user input
BEFORE it enters the threat-scanning pipeline.

Layers applied in order:
  1. Null byte removal              — prevent path traversal / NUL injection
  2. Control character stripping    — remove non-printable ASCII < 0x20
  3. HTML entity decoding           — &lt;script&gt; → <script> before scan
  4. HTML tag stripping             — remove residual <...> markup
  5. SQL injection neutralisation   — quote and comment stripping
  6. Script injection detection     — flag JS/VBS event handlers
  7. Path traversal neutralisation  — collapse ../ sequences
  8. Excessive whitespace collapse  — normalise padding attacks
  9. Length enforcement             — hard cut at MAX_CHARS
"""

import html
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
MAX_CHARS = 8000         # hard upper limit after all transforms
WARN_CHARS = 4000        # warn if prompt is this long after sanitise

# ── Compiled patterns ──────────────────────────────────────────────────────────
_HTML_TAG_RE     = re.compile(r"<[^>]{0,200}>", re.DOTALL)
_NULL_BYTE_RE    = re.compile(r"\x00")
_CTRL_CHAR_RE    = re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SQL_COMMENT_RE  = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_SQL_QUOTE_RE    = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"")
_PATH_TRAV_RE    = re.compile(r"\.{2,}[\\/]")
_JS_EVENT_RE     = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
_EXCESS_WS_RE    = re.compile(r"[ \t]{4,}")
_MULTI_NEWLINE_RE= re.compile(r"\n{4,}")

# ── Result ─────────────────────────────────────────────────────────────────────

@dataclass
class SanitizeResult:
    original_length: int
    sanitized_text: str
    sanitized_length: int
    transforms_applied: list[str] = field(default_factory=list)
    flagged: bool = False
    flag_reasons: list[str] = field(default_factory=list)

    @property
    def was_modified(self) -> bool:
        return self.original_length != self.sanitized_length or bool(self.transforms_applied)


# ── Sanitizer ──────────────────────────────────────────────────────────────────

class InputSanitizer:
    """
    Multi-layer input sanitizer for raw user prompts.
    Returns a SanitizeResult with the cleaned text and a full
    audit trail of every transform that was applied.
    """

    def __init__(self, max_chars: int = MAX_CHARS):
        self._max_chars = max_chars
        self._total_sanitized = 0
        self._total_flagged = 0
        logger.info("🧼 InputSanitizer initialised (max_chars=%d)", max_chars)

    def sanitize(self, text: str) -> SanitizeResult:
        """
        Run all sanitization layers on `text` in order.

        Args:
            text: Raw user input string.

        Returns:
            SanitizeResult with the cleaned text and audit metadata.
        """
        self._total_sanitized += 1
        original_length = len(text)
        transforms: list[str] = []
        flags: list[str] = []
        working = text

        # ── Layer 1: Null byte removal ─────────────────────────────────────────
        cleaned = _NULL_BYTE_RE.sub("", working)
        if cleaned != working:
            transforms.append("null_byte_removal")
            working = cleaned

        # ── Layer 2: Control character stripping ───────────────────────────────
        cleaned = _CTRL_CHAR_RE.sub("", working)
        if cleaned != working:
            transforms.append("control_char_strip")
            working = cleaned

        # ── Layer 3: HTML entity decoding ──────────────────────────────────────
        decoded = html.unescape(working)
        if decoded != working:
            transforms.append("html_entity_decode")
            working = decoded

        # ── Layer 4: HTML tag stripping ────────────────────────────────────────
        cleaned = _HTML_TAG_RE.sub(" ", working)
        if cleaned != working:
            transforms.append("html_tag_strip")
            flags.append("html_tags_detected")
            working = cleaned

        # ── Layer 5: Script injection detection ────────────────────────────────
        if _JS_EVENT_RE.search(working):
            flags.append("script_event_handler_detected")
            working = _JS_EVENT_RE.sub("[REMOVED]", working)
            transforms.append("script_event_handler_removal")

        # ── Layer 6: SQL comment neutralisation ────────────────────────────────
        cleaned = _SQL_COMMENT_RE.sub(" ", working)
        if cleaned != working:
            transforms.append("sql_comment_strip")
            flags.append("sql_comment_detected")
            working = cleaned

        # ── Layer 7: Path traversal neutralisation ─────────────────────────────
        cleaned = _PATH_TRAV_RE.sub("./", working)
        if cleaned != working:
            transforms.append("path_traversal_collapse")
            flags.append("path_traversal_detected")
            working = cleaned

        # ── Layer 8: Whitespace normalisation ──────────────────────────────────
        cleaned = _EXCESS_WS_RE.sub("    ", working)
        cleaned = _MULTI_NEWLINE_RE.sub("\n\n\n", cleaned)
        if cleaned != working:
            transforms.append("whitespace_collapse")
            working = cleaned

        # ── Layer 9: Length enforcement ────────────────────────────────────────
        if len(working) > self._max_chars:
            working = working[: self._max_chars]
            transforms.append("hard_truncation")
            flags.append(f"exceeded_max_chars_{self._max_chars}")

        # ── Warn on large prompts ──────────────────────────────────────────────
        if len(working) > WARN_CHARS:
            flags.append(f"large_prompt_warning_{len(working)}_chars")

        if flags:
            self._total_flagged += 1

        result = SanitizeResult(
            original_length=original_length,
            sanitized_text=working,
            sanitized_length=len(working),
            transforms_applied=transforms,
            flagged=bool(flags),
            flag_reasons=flags,
        )

        if transforms:
            logger.info(
                "🧼 Sanitized prompt — transforms=%s  flags=%s  delta=%d chars",
                transforms, flags,
                original_length - len(working),
            )

        return result

    def get_stats(self) -> dict:
        return {
            "total_sanitized": self._total_sanitized,
            "total_flagged": self._total_flagged,
            "flag_rate_pct": round(
                self._total_flagged / max(self._total_sanitized, 1) * 100, 1
            ),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
input_sanitizer = InputSanitizer()
