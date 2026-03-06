"""
Commit 27: Threat Cache with TTL
=================================
In-memory LRU threat cache so the security pipeline can skip re-scanning
prompts it has already evaluated. Uses a hash of the normalized prompt
as the cache key to detect semantically-identical payloads even with
minor whitespace/case differences.

Features:
  - Configurable TTL (default 10 min) and max size (default 1000 entries)
  - Thread-safe with RLock
  - LRU eviction when capacity is reached
  - Hit/miss/eviction statistics
  - Exported singleton `threat_cache`
"""

import hashlib
import logging
import time
import unicodedata
from collections import OrderedDict
from threading import RLock
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Cache entry ────────────────────────────────────────────────────────────────

@dataclass
class CacheEntry:
    """A single cached threat-scan result."""
    is_threat: bool
    threat_type: str
    severity_score: float
    cached_at: float
    hits: int = 0

    def is_expired(self, ttl_seconds: float) -> bool:
        return (time.time() - self.cached_at) > ttl_seconds


# ── Cache stats ────────────────────────────────────────────────────────────────

@dataclass
class CacheStats:
    total_lookups: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    evictions: int = 0
    expirations: int = 0

    @property
    def hit_rate(self) -> float:
        if self.total_lookups == 0:
            return 0.0
        return float(round(self.cache_hits / self.total_lookups * 100, 1))


# ── Threat Cache ───────────────────────────────────────────────────────────────

class ThreatCache:
    """
    Thread-safe LRU cache for threat scan results.

    Normalises the prompt before hashing so that trivial mutations
    (extra spaces, mixed case, unicode variants) map to the same key.
    """

    def __init__(self, max_size: int = 1000, ttl_seconds: float = 600.0):
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = RLock()
        self._stats = CacheStats()
        logger.info(
            "📦 ThreatCache initialised — max_size=%d  ttl=%.0fs",
            max_size, ttl_seconds
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _make_key(self, prompt: str) -> str:
        """Normalise prompt and produce a SHA-256 hex digest cache key."""
        normalised = unicodedata.normalize("NFKC", prompt).lower().strip()
        # Collapse whitespace so "ignore  previous" == "ignore previous"
        collapsed = " ".join(normalised.split())
        return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()

    def _evict_one(self) -> None:
        """Evict the least-recently-used entry."""
        if self._store:
            key, _ = self._store.popitem(last=False)
            self._stats.evictions += 1
            logger.debug("🗑️  LRU eviction — key=%s...", key[:12])

    # ── Public API ─────────────────────────────────────────────────────────────

    def get(self, prompt: str) -> Optional[CacheEntry]:
        """
        Look up a prompt in the cache.

        Returns:
            CacheEntry if found and not expired, None otherwise.
        """
        key = self._make_key(prompt)
        with self._lock:
            self._stats.total_lookups += 1
            entry = self._store.get(key)

            if entry is None:
                self._stats.cache_misses += 1
                return None

            if entry.is_expired(self._ttl):
                del self._store[key]
                self._stats.expirations += 1
                self._stats.cache_misses += 1
                logger.debug("⏰ Cache entry expired — key=%s...", key[:12])
                return None

            # Move to end (most recently used)
            self._store.move_to_end(key)
            entry.hits += 1
            self._stats.cache_hits += 1
            logger.debug(
                "✅ Cache HIT — key=%s...  is_threat=%s  hits=%d",
                key[:12], entry.is_threat, entry.hits
            )
            return entry

    def put(
        self,
        prompt: str,
        is_threat: bool,
        threat_type: str,
        severity_score: float,
    ) -> None:
        """Store a scan result in the cache."""
        key = self._make_key(prompt)
        with self._lock:
            if len(self._store) >= self._max_size:
                self._evict_one()

            self._store[key] = CacheEntry(
                is_threat=is_threat,
                threat_type=threat_type,
                severity_score=severity_score,
                cached_at=time.time(),
            )
            self._store.move_to_end(key)
            logger.debug(
                "📝 Cached threat result — key=%s...  is_threat=%s",
                key[:12], is_threat
            )

    def invalidate(self, prompt: str) -> bool:
        """Remove a specific prompt from the cache. Returns True if removed."""
        key = self._make_key(prompt)
        with self._lock:
            if key in self._store:
                del self._store[key]
                logger.info("🗑️  Cache entry invalidated — key=%s...", key[:12])
                return True
            return False

    def flush(self) -> int:
        """Clear all entries. Returns the number of entries removed."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            logger.info("🧹 Cache flushed — %d entries removed", count)
            return count

    def get_stats(self) -> dict:
        """Return cache performance statistics."""
        with self._lock:
            return {
                "size": len(self._store),
                "max_size": self._max_size,
                "ttl_seconds": self._ttl,
                "total_lookups": self._stats.total_lookups,
                "cache_hits": self._stats.cache_hits,
                "cache_misses": self._stats.cache_misses,
                "hit_rate_pct": self._stats.hit_rate,
                "evictions": self._stats.evictions,
                "expirations": self._stats.expirations,
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# ── Module-level singleton ─────────────────────────────────────────────────────
threat_cache = ThreatCache(max_size=1000, ttl_seconds=600.0)
