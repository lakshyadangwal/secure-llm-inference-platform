"""
Commit 56: Keyword Watchlist
==============================
Configurable keyword and phrase watchlist for the defense pipeline.
Supports three match modes:
  - EXACT    : case-insensitive exact word-boundary match
  - SUBSTRING: anywhere in the text
  - REGEX    : full regular expression

Each entry has:
  - A severity (LOW / MEDIUM / HIGH / CRITICAL)
  - An action (LOG / WARN / BLOCK)
  - A category tag (e.g., "weapons", "pii", "extremism")
  - Optional expiry time (auto-disabled after a date)

Default built-in watchlist covers ~60 terms across 8 categories.
Runtime additions are thread-safe and take effect immediately.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────────────

class MatchMode(str, Enum):
    EXACT     = "exact"
    SUBSTRING = "substring"
    REGEX     = "regex"


class WatchSeverity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        _w: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return _w[str(self.value)]


class WatchAction(str, Enum):
    LOG   = "log"
    WARN  = "warn"
    BLOCK = "block"


# ── Entry ──────────────────────────────────────────────────────────────────────

@dataclass
class WatchlistEntry:
    entry_id: str
    term: str
    mode: MatchMode
    severity: WatchSeverity
    action: WatchAction
    category: str
    enabled: bool = True
    expires_at: Optional[float] = None
    hit_count: int = 0
    created_at: float = field(default_factory=time.time)
    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.mode == MatchMode.REGEX:
            try:
                self._compiled = re.compile(self.term, re.IGNORECASE)
            except re.error as exc:
                logger.error("Invalid watchlist regex '%s': %s", self.term, exc)
                self.enabled = False
        elif self.mode == MatchMode.EXACT:
            escaped = re.escape(self.term)
            self._compiled = re.compile(rf"\b{escaped}\b", re.IGNORECASE)
        else:  # SUBSTRING
            self._compiled = re.compile(re.escape(self.term), re.IGNORECASE)

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at

    def matches(self, text: str) -> bool:
        if not self.enabled or self.is_expired or self._compiled is None:
            return False
        return bool(self._compiled.search(text))


# ── Match result ───────────────────────────────────────────────────────────────

@dataclass
class WatchlistMatch:
    entry_id: str
    term: str
    category: str
    severity: WatchSeverity
    action: WatchAction
    mode: MatchMode

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "term": self.term,
            "category": self.category,
            "severity": self.severity.value,
            "action": self.action.value,
        }


@dataclass
class WatchlistResult:
    matches: list[WatchlistMatch]
    should_block: bool
    should_warn: bool
    highest_severity: Optional[WatchSeverity]
    categories_triggered: list[str]

    def to_dict(self) -> dict:
        return {
            "match_count": len(self.matches),
            "should_block": self.should_block,
            "should_warn": self.should_warn,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "categories_triggered": self.categories_triggered,
            "matches": [m.to_dict() for m in self.matches],
        }


# ── Default built-in entries ───────────────────────────────────────────────────

def _make_entry(
    entry_id: str,
    term: str,
    mode: MatchMode,
    severity: WatchSeverity,
    action: WatchAction,
    category: str,
) -> WatchlistEntry:
    return WatchlistEntry(
        entry_id=entry_id,
        term=term,
        mode=mode,
        severity=severity,
        action=action,
        category=category,
    )


_DEFAULT_ENTRIES: list[WatchlistEntry] = [
    # ── Jailbreak signals ──────────────────────────────────────────────────
    _make_entry("jb_001", r"\bDAN\b", MatchMode.REGEX, WatchSeverity.HIGH, WatchAction.BLOCK, "jailbreak"),
    _make_entry("jb_002", "jailbreak mode", MatchMode.EXACT, WatchSeverity.HIGH, WatchAction.BLOCK, "jailbreak"),
    _make_entry("jb_003", "no restrictions", MatchMode.EXACT, WatchSeverity.MEDIUM, WatchAction.WARN, "jailbreak"),
    _make_entry("jb_004", "ignore all instructions", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "jailbreak"),
    _make_entry("jb_005", r"act\s+as\s+if\s+you\s+have\s+no\s+rules", MatchMode.REGEX, WatchSeverity.HIGH, WatchAction.BLOCK, "jailbreak"),
    _make_entry("jb_006", "bypass safety", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.BLOCK, "jailbreak"),
    _make_entry("jb_007", "disable content filter", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.BLOCK, "jailbreak"),

    # ── Weapons / CBRN ────────────────────────────────────────────────────
    _make_entry("wp_001", r"\b(?:synthesize|manufacture|make|produce)\b.{0,25}\b(?:drug|explosive|poison|toxin|mustard gas|nerve agent)\b", MatchMode.REGEX, WatchSeverity.CRITICAL, WatchAction.BLOCK, "weapons"),
    _make_entry("wp_002", "3d print gun", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "weapons"),
    _make_entry("wp_003", "untraceable firearm", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "weapons"),
    _make_entry("wp_004", r"\b(?:sarin|VX|novichok|ricin|anthrax)\b", MatchMode.REGEX, WatchSeverity.CRITICAL, WatchAction.BLOCK, "weapons"),

    # ── Cybercrime / Hacking ──────────────────────────────────────────────
    _make_entry("ck_001", "write malware", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.BLOCK, "cybercrime"),
    _make_entry("ck_002", "keylogger code", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.BLOCK, "cybercrime"),
    _make_entry("ck_003", r"(?:ddos|dos)\s+attack\s+(?:script|tool|code)", MatchMode.REGEX, WatchSeverity.HIGH, WatchAction.BLOCK, "cybercrime"),
    _make_entry("ck_004", "ransomware source code", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "cybercrime"),
    _make_entry("ck_005", r"\b(?:sql\s+injection|xss\s+payload|shell\s+injection)\b(?:.{0,20}example)", MatchMode.REGEX, WatchSeverity.MEDIUM, WatchAction.WARN, "cybercrime"),
    _make_entry("ck_006", "credential stuffing", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.WARN, "cybercrime"),

    # ── PII / Data exfiltration ───────────────────────────────────────────
    _make_entry("pii_001", r"\b\d{3}-\d{2}-\d{4}\b", MatchMode.REGEX, WatchSeverity.HIGH, WatchAction.WARN, "pii"),
    _make_entry("pii_002", r"\b4[0-9]{12}(?:[0-9]{3})?\b", MatchMode.REGEX, WatchSeverity.HIGH, WatchAction.WARN, "pii"),
    _make_entry("pii_003", "dump all user data", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.BLOCK, "pii"),

    # ── Extremism / Radicalisation ────────────────────────────────────────
    _make_entry("ext_001", "recruit for terrorist", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "extremism"),
    _make_entry("ext_002", r"\bterror(?:ist|ism)\b.{0,30}\b(?:attack|plan|recruit|fund)", MatchMode.REGEX, WatchSeverity.CRITICAL, WatchAction.BLOCK, "extremism"),
    _make_entry("ext_003", "mass casualty", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "extremism"),

    # ── Child safety ──────────────────────────────────────────────────────
    _make_entry("cs_001", r"\bCSAM\b", MatchMode.REGEX, WatchSeverity.CRITICAL, WatchAction.BLOCK, "child_safety"),
    _make_entry("cs_002", "explicit content involving minor", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "child_safety"),

    # ── Prompt injection signals ──────────────────────────────────────────
    _make_entry("pi_001", "ignore the above", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.BLOCK, "injection"),
    _make_entry("pi_002", "new persona:", MatchMode.SUBSTRING, WatchSeverity.MEDIUM, WatchAction.WARN, "injection"),
    _make_entry("pi_003", "system prompt:", MatchMode.SUBSTRING, WatchSeverity.HIGH, WatchAction.WARN, "injection"),
    _make_entry("pi_004", r"<\|(?:system|im_start|im_end)\|>", MatchMode.REGEX, WatchSeverity.HIGH, WatchAction.BLOCK, "injection"),

    # ── Self-harm ─────────────────────────────────────────────────────────
    _make_entry("sh_001", r"\b(?:kill|harm|hurt)\s+myself\b", MatchMode.REGEX, WatchSeverity.CRITICAL, WatchAction.BLOCK, "self_harm"),
    _make_entry("sh_002", "methods of suicide", MatchMode.SUBSTRING, WatchSeverity.CRITICAL, WatchAction.BLOCK, "self_harm"),
]


# ── Watchlist class ────────────────────────────────────────────────────────────

class KeywordWatchlist:
    """
    Evaluates text against a configurable keyword/phrase watchlist.
    Supports runtime additions, bulk import, and hot-reload.
    """

    def __init__(self) -> None:
        self._entries: dict[str, WatchlistEntry] = {}
        self._lock = RLock()
        self._total_evaluated = 0
        self._total_hits = 0
        self._total_blocks = 0

        for entry in _DEFAULT_ENTRIES:
            self._entries[entry.entry_id] = entry

        logger.info("📋 KeywordWatchlist loaded with %d default entries", len(self._entries))

    def add(
        self,
        entry_id: str,
        term: str,
        mode: MatchMode = MatchMode.SUBSTRING,
        severity: WatchSeverity = WatchSeverity.MEDIUM,
        action: WatchAction = WatchAction.WARN,
        category: str = "custom",
        expires_in_seconds: Optional[float] = None,
    ) -> WatchlistEntry:
        """Add or replace a watchlist entry."""
        expires_at = time.time() + expires_in_seconds if expires_in_seconds else None
        entry = WatchlistEntry(
            entry_id=entry_id,
            term=term,
            mode=mode,
            severity=severity,
            action=action,
            category=category,
            expires_at=expires_at,
        )
        with self._lock:
            self._entries[entry_id] = entry
        logger.info("📋 Watchlist entry added: %s (%s / %s)", entry_id, term[:30], mode.value)
        return entry

    def remove(self, entry_id: str) -> bool:
        with self._lock:
            return self._entries.pop(entry_id, None) is not None

    def enable(self, entry_id: str) -> bool:
        with self._lock:
            if entry_id in self._entries:
                self._entries[entry_id].enabled = True
                return True
        return False

    def disable(self, entry_id: str) -> bool:
        with self._lock:
            if entry_id in self._entries:
                self._entries[entry_id].enabled = False
                return True
        return False

    def evaluate(self, text: str) -> WatchlistResult:
        """
        Evaluate text against all active watchlist entries.

        Returns:
            WatchlistResult with all matches and recommended action.
        """
        self._total_evaluated += 1
        matches: list[WatchlistMatch] = []

        with self._lock:
            entries = list(self._entries.values())

        for entry in entries:
            if entry.matches(text):
                with self._lock:
                    entry.hit_count += 1
                matches.append(WatchlistMatch(
                    entry_id=entry.entry_id,
                    term=entry.term,
                    category=entry.category,
                    severity=entry.severity,
                    action=entry.action,
                    mode=entry.mode,
                ))

        if not matches:
            return WatchlistResult(
                matches=[], should_block=False, should_warn=False,
                highest_severity=None, categories_triggered=[],
            )

        with self._lock:
            self._total_hits += len(matches)

        should_block = any(m.action == WatchAction.BLOCK for m in matches)
        should_warn = any(m.action == WatchAction.WARN for m in matches)
        highest = max(matches, key=lambda m: m.severity.weight)
        categories = list({m.category for m in matches})

        if should_block:
            with self._lock:
                self._total_blocks += 1
            logger.warning("📋 Watchlist BLOCK — categories=%s", categories)

        return WatchlistResult(
            matches=matches,
            should_block=should_block,
            should_warn=should_warn,
            highest_severity=highest.severity,
            categories_triggered=categories,
        )

    def list_entries(self, category: Optional[str] = None) -> list[dict]:
        with self._lock:
            entries = list(self._entries.values())
        if category:
            entries = [e for e in entries if e.category == category]
        return [
            {
                "entry_id": e.entry_id,
                "term": e.term,
                "mode": e.mode.value,
                "severity": e.severity.value,
                "action": e.action.value,
                "category": e.category,
                "enabled": e.enabled,
                "hit_count": e.hit_count,
            }
            for e in entries
        ]

    def get_stats(self) -> dict:
        with self._lock:
            active = sum(1 for e in self._entries.values() if e.enabled and not e.is_expired)
            top_entries = sorted(
                self._entries.values(), key=lambda e: e.hit_count, reverse=True
            )
            top_5 = [{"id": e.entry_id, "hits": e.hit_count} for e in top_entries[:5]]  # type: ignore[index]
        return {
            "total_entries": len(self._entries),
            "active_entries": active,
            "total_evaluated": self._total_evaluated,
            "total_hits": self._total_hits,
            "total_blocks": self._total_blocks,
            "top_triggered": top_5,
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
keyword_watchlist = KeywordWatchlist()
