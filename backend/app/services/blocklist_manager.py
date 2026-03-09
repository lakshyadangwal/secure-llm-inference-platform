"""
Commit 89: Blocklist Manager
==============================
Manages a dynamic phrase/word blocklist that can be updated at runtime.
Supports exact match, starts-with, and regex rules.
Groups rules by category for selective enforcement.
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


class MatchType(str, Enum):
    EXACT  = "exact"
    PREFIX = "prefix"
    REGEX  = "regex"


@dataclass
class BlocklistRule:
    rule_id: str
    category: str
    match_type: MatchType
    value: str
    severity: str = "medium"
    _compiled: Optional[re.Pattern] = None

    def __post_init__(self) -> None:
        if self.match_type == MatchType.REGEX:
            try:
                self._compiled = re.compile(self.value, re.IGNORECASE)
            except re.error:
                self._compiled = None

    def matches(self, text: str) -> bool:
        if self.match_type == MatchType.EXACT:
            return self.value.lower() in text.lower()
        if self.match_type == MatchType.PREFIX:
            return text.lower().startswith(self.value.lower())
        if self.match_type == MatchType.REGEX and self._compiled:
            return bool(self._compiled.search(text))
        return False


@dataclass
class BlocklistResult:
    matched: bool
    matched_rules: list[str]
    categories: list[str]

    def to_dict(self) -> dict:
        return {
            "matched": self.matched,
            "matched_rules": self.matched_rules,
            "categories": self.categories,
        }


class BlocklistManager:
    """Dynamic blocklist with hot-reload support."""

    def __init__(self) -> None:
        self._rules: list[BlocklistRule] = []
        self._lock = RLock()
        self._total_checked = 0
        self._total_blocked = 0
        self._seed_defaults()
        logger.info("🚫 BlocklistManager ready — %d rules", len(self._rules))

    def _seed_defaults(self) -> None:
        defaults: list[tuple[str, str, str, str]] = [
            ("bl_001", "offensive",  "exact",  "kys"),
            ("bl_002", "offensive",  "exact",  "kill yourself"),
            ("bl_003", "jailbreak",  "exact",  "dan mode"),
            ("bl_004", "jailbreak",  "exact",  "jailbreak mode"),
            ("bl_005", "dangerous",  "regex",  r"\bsarin\b|\bVX\s+nerve\b|\bnovichok\b"),
            ("bl_006", "dangerous",  "regex",  r"\b(bomb|explosive)\s+(instructions?|guide|recipe|tutorial)\b"),
            ("bl_007", "offensive",  "regex",  r"\bcsam\b|\bchild\s+pornography\b"),
            ("bl_008", "fraud",      "regex",  r"\b(phishing|smishing)\s+(kit|template|script)\b"),
            ("bl_009", "malware",    "regex",  r"\b(ransomware|rootkit|keylogger)\s+(code|source|payload)\b"),
            ("bl_010", "selfharm",   "regex",  r"\b(kill\s+myself|suicide\s+method|lethal\s+dose)\b"),
        ]
        for rid, cat, mtype, val in defaults:
            self.add_rule(rid, cat, MatchType(mtype), val)

    def add_rule(self, rule_id: str, category: str, match_type: MatchType, value: str, severity: str = "medium") -> None:
        rule = BlocklistRule(rule_id=rule_id, category=category, match_type=match_type, value=value, severity=severity)
        with self._lock:
            # Remove existing rule with same id
            self._rules = [r for r in self._rules if r.rule_id != rule_id]
            self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.rule_id != rule_id]
            return len(self._rules) < before

    def check(self, text: str, categories: Optional[list[str]] = None) -> BlocklistResult:
        with self._lock:
            self._total_checked += 1
            rules = [r for r in self._rules if categories is None or r.category in categories]

        matched_ids: list[str] = []
        matched_cats: list[str] = []
        for rule in rules:
            if rule.matches(text):
                matched_ids.append(rule.rule_id)
                if rule.category not in matched_cats:
                    matched_cats.append(rule.category)

        matched = bool(matched_ids)
        with self._lock:
            if matched:
                self._total_blocked += 1

        return BlocklistResult(matched=matched, matched_rules=matched_ids, categories=matched_cats)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "rule_count": len(self._rules),
                "total_checked": self._total_checked,
                "total_blocked": self._total_blocked,
            }


blocklist_manager = BlocklistManager()
