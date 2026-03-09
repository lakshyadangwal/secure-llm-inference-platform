"""
Commit 94: Allowlist Guard
============================
Complements the blocklist by providing an explicit allowlist for
trusted prompts, user patterns, and API key prefixes.

When a request matches an allowlist entry it can bypass certain
defense checks (e.g., rate limiting or lightweight pattern checks)
to reduce latency for known-safe traffic.

Allowlist types:
  - EXACT_PROMPT   — exact prompt string is pre-approved
  - REGEX_PROMPT   — prompt matches a safe pattern
  - API_KEY_PREFIX — API keys starting with a prefix are trusted
  - USER_ID        — specific user IDs are pre-approved
"""

import re
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Optional


class AllowlistType(str, Enum):
    EXACT_PROMPT   = "exact_prompt"
    REGEX_PROMPT   = "regex_prompt"
    API_KEY_PREFIX = "api_key_prefix"
    USER_ID        = "user_id"


@dataclass
class AllowlistEntry:
    entry_id: str
    entry_type: AllowlistType
    value: str
    reason: str = ""
    _compiled: Optional[re.Pattern] = None

    def __post_init__(self) -> None:
        if self.entry_type == AllowlistType.REGEX_PROMPT:
            try:
                self._compiled = re.compile(self.value, re.IGNORECASE)
            except re.error:
                self._compiled = None


@dataclass
class AllowlistResult:
    allowed: bool
    matched_entry: Optional[str]
    entry_type: Optional[str]
    reason: Optional[str]

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "matched_entry": self.matched_entry,
            "entry_type": self.entry_type,
            "reason": self.reason,
        }


class AllowlistGuard:
    """
    Maintains allowlists for prompts, users, and API keys.
    Matched entries can bypass lightweight defense checks.
    """

    def __init__(self) -> None:
        self._entries: list[AllowlistEntry] = []
        self._lock = RLock()
        self._total_checked = 0
        self._total_allowed = 0

    def add(self, entry_id: str, entry_type: AllowlistType, value: str, reason: str = "") -> None:
        entry = AllowlistEntry(entry_id=entry_id, entry_type=entry_type, value=value, reason=reason)
        with self._lock:
            self._entries = [e for e in self._entries if e.entry_id != entry_id]
            self._entries.append(entry)

    def remove(self, entry_id: str) -> bool:
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.entry_id != entry_id]
            return len(self._entries) < before

    def check_prompt(self, prompt: str) -> AllowlistResult:
        with self._lock:
            self._total_checked += 1
            entries = list(self._entries)

        for entry in entries:
            if entry.entry_type == AllowlistType.EXACT_PROMPT:
                if entry.value.lower() == prompt.lower():
                    return self._hit(entry)
            elif entry.entry_type == AllowlistType.REGEX_PROMPT and entry._compiled:
                if entry._compiled.search(prompt):
                    return self._hit(entry)

        return AllowlistResult(allowed=False, matched_entry=None, entry_type=None, reason=None)

    def check_user(self, user_id: str) -> AllowlistResult:
        with self._lock:
            entries = list(self._entries)
        for entry in entries:
            if entry.entry_type == AllowlistType.USER_ID and entry.value == user_id:
                return self._hit(entry)
        return AllowlistResult(allowed=False, matched_entry=None, entry_type=None, reason=None)

    def check_api_key(self, api_key: str) -> AllowlistResult:
        with self._lock:
            entries = list(self._entries)
        for entry in entries:
            if entry.entry_type == AllowlistType.API_KEY_PREFIX and api_key.startswith(entry.value):
                return self._hit(entry)
        return AllowlistResult(allowed=False, matched_entry=None, entry_type=None, reason=None)

    def _hit(self, entry: AllowlistEntry) -> AllowlistResult:
        with self._lock:
            self._total_allowed += 1
        return AllowlistResult(
            allowed=True,
            matched_entry=entry.entry_id,
            entry_type=entry.entry_type.value,
            reason=entry.reason,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "entry_count": len(self._entries),
                "total_checked": self._total_checked,
                "total_allowed": self._total_allowed,
            }


allowlist_guard = AllowlistGuard()
