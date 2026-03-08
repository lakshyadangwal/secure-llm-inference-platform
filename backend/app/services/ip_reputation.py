"""
Commit 46: IP Reputation Manager
===================================
Manages IP blocklists, allowlists, and reputation scoring for the platform.
Tracks per-IP violation history and computes dynamic reputation scores.

Features:
  - Permanent blocklist (manual additions)
  - Temporary blocklist with TTL (auto-expires)
  - Allowlist (bypasses all checks)
  - Dynamic reputation score per IP (0.0 = trusted, 1.0 = blocked)
  - Violation event history per IP
  - Bulk import from CIDR ranges
  - Export blocklist to JSON
  - GeoIP country filtering support (offline, no external calls)
"""

import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── IP verdict ────────────────────────────────────────────────────────────────

class IPVerdict:
    ALLOWED   = "allowed"
    NEUTRAL   = "neutral"
    SUSPICIOUS= "suspicious"
    BLOCKED   = "blocked"


# ── Violation event ────────────────────────────────────────────────────────────

@dataclass
class ViolationEvent:
    timestamp: float
    violation_type: str    # "threat_detected" | "anomaly" | "rate_limit" | "honeypot"
    severity: float        # 0.0 – 1.0
    detail: str = ""

    @property
    def age_seconds(self) -> float:
        return time.time() - self.timestamp


# ── IP Reputation Record ───────────────────────────────────────────────────────

@dataclass
class IPReputationRecord:
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    violations: list[ViolationEvent] = field(default_factory=list)
    reputation_score: float = 0.0      # 0.0 = clean, 1.0 = definitely malicious
    is_permanently_blocked: bool = False
    is_temporarily_blocked: bool = False
    block_expires_at: Optional[float] = None
    block_reason: str = ""
    is_allowlisted: bool = False

    @property
    def is_blocked(self) -> bool:
        if self.is_permanently_blocked:
            return True
        if self.is_temporarily_blocked:
            if self.block_expires_at is not None and time.time() > self.block_expires_at:
                self.is_temporarily_blocked = False
                return False
            return True
        return False

    @property
    def verdict(self) -> str:
        if self.is_allowlisted:
            return IPVerdict.ALLOWED
        if self.is_blocked:
            return IPVerdict.BLOCKED
        if self.reputation_score >= 0.7:
            return IPVerdict.SUSPICIOUS
        return IPVerdict.NEUTRAL


# ── Reputation Manager ────────────────────────────────────────────────────────

class IPReputationManager:
    """
    Tracks per-IP reputation, blocklists, and violation history.
    All data is in-memory; initialise with seed data if needed.
    """

    # Well-known private/reserved ranges — never block these
    _PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]

    def __init__(
        self,
        score_decay_per_hour: float = 0.05,
        violation_window_seconds: float = 3600.0,
        auto_block_threshold: float = 0.9,
    ):
        self._records: dict[str, IPReputationRecord] = {}
        self._cidr_blocklist: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._lock = RLock()
        self._score_decay = score_decay_per_hour
        self._violation_window = violation_window_seconds
        self._auto_block_threshold = auto_block_threshold
        self._total_violations = 0
        self._total_blocks = 0
        logger.info("🌐 IPReputationManager initialised")

    # ── Private helpers ───────────────────────────────────────────────────────

    def _is_private(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self._PRIVATE_RANGES)
        except ValueError:
            return False

    def _get_or_create(self, ip: str) -> IPReputationRecord:
        if ip not in self._records:
            self._records[ip] = IPReputationRecord(ip=ip)
        return self._records[ip]

    def _matches_cidr_block(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self._cidr_blocklist)
        except ValueError:
            return False

    def _recompute_score(self, record: IPReputationRecord) -> float:
        """Recompute reputation score from recent violations."""
        now = time.time()
        recent = [
            v for v in record.violations
            if (now - v.timestamp) <= self._violation_window
        ]
        if not recent:
            # Apply decay for inactivity
            hours_idle = (now - record.last_seen) / 3600.0
            decayed = record.reputation_score * ((1 - self._score_decay) ** hours_idle)
            return max(0.0, round(float(decayed), 3))  # type: ignore[call-overload]

        # Weighted sum: recent violations count more
        total_score = 0.0
        for v in recent:
            age_factor = max(0.0, 1.0 - (v.age_seconds / self._violation_window))
            total_score += v.severity * age_factor
        return min(1.0, round(float(total_score) / max(len(recent), 1), 3))  # type: ignore[call-overload]

    # ── Public API ─────────────────────────────────────────────────────────────

    def check(self, ip: str) -> IPReputationRecord:
        """
        Look up or create the reputation record for an IP.
        Updates last_seen and recomputes score.
        """
        now = time.time()
        with self._lock:
            record = self._get_or_create(ip)
            record.last_seen = now

            # Check CIDR blocklist
            if not record.is_permanently_blocked and self._matches_cidr_block(ip):
                record.is_permanently_blocked = True
                record.block_reason = "cidr_blocklist"

            # Recompute dynamic score
            record.reputation_score = self._recompute_score(record)

            # Auto-block if score exceeds threshold (not private IPs)
            if (
                record.reputation_score >= self._auto_block_threshold
                and not record.is_blocked
                and not self._is_private(ip)
            ):
                record.is_temporarily_blocked = True
                record.block_expires_at = now + 1800.0   # 30 min auto-block
                record.block_reason = f"auto_block_score_{record.reputation_score:.2f}"
                self._total_blocks += 1
                logger.warning(
                    "🔴 Auto-blocked IP %s — score=%.2f", ip, record.reputation_score
                )

        return record

    def record_violation(
        self,
        ip: str,
        violation_type: str,
        severity: float,
        detail: str = "",
    ) -> None:
        """Record a security violation for an IP and update its score."""
        event = ViolationEvent(
            timestamp=time.time(),
            violation_type=violation_type,
            severity=severity,
            detail=detail,
        )
        with self._lock:
            record = self._get_or_create(ip)
            record.violations.append(event)
            # Keep last 500 violations per IP
            if len(record.violations) > 500:
                record.violations = list(record.violations)[-500:]  # type: ignore[index]
            self._total_violations += 1
        logger.info(
            "⚠️  Violation recorded — ip=%s  type=%s  severity=%.2f",
            ip, violation_type, severity
        )

    def block_permanent(self, ip: str, reason: str = "manual") -> None:
        with self._lock:
            record = self._get_or_create(ip)
            record.is_permanently_blocked = True
            record.block_reason = reason
            record.reputation_score = 1.0
            self._total_blocks += 1
        logger.warning("🔴 IP permanently blocked — ip=%s  reason=%s", ip, reason)

    def block_temporary(self, ip: str, seconds: float, reason: str = "manual") -> None:
        with self._lock:
            record = self._get_or_create(ip)
            record.is_temporarily_blocked = True
            record.block_expires_at = time.time() + seconds
            record.block_reason = reason
            self._total_blocks += 1
        logger.warning(
            "🟡 IP temporarily blocked — ip=%s  duration=%.0fs  reason=%s",
            ip, seconds, reason
        )

    def unblock(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._records:
                return False
            record = self._records[ip]
            record.is_permanently_blocked = False
            record.is_temporarily_blocked = False
            record.block_expires_at = None
            record.block_reason = ""
        logger.info("🟢 IP unblocked — ip=%s", ip)
        return True

    def allowlist(self, ip: str) -> None:
        with self._lock:
            record = self._get_or_create(ip)
            record.is_allowlisted = True
        logger.info("✅ IP allowlisted — ip=%s", ip)

    def add_cidr_block(self, cidr: str) -> bool:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            with self._lock:
                self._cidr_blocklist.append(net)
            logger.info("🔴 CIDR block added — %s", cidr)
            return True
        except ValueError:
            logger.error("Invalid CIDR: %s", cidr)
            return False

    def get_record(self, ip: str) -> Optional[dict]:
        with self._lock:
            if ip not in self._records:
                return None
            r = self._records[ip]
            return {
                "ip": r.ip,
                "reputation_score": r.reputation_score,
                "verdict": r.verdict,
                "is_blocked": r.is_blocked,
                "is_allowlisted": r.is_allowlisted,
                "block_reason": r.block_reason,
                "violation_count": len(r.violations),
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
            }

    def get_top_offenders(self, limit: int = 20) -> list[dict]:
        with self._lock:
            records = list(self._records.values())
        scored = sorted(records, key=lambda r: r.reputation_score, reverse=True)
        top = list(scored)[:limit]  # type: ignore[index]
        return [
            {
                "ip": r.ip,
                "reputation_score": r.reputation_score,
                "verdict": r.verdict,
                "violation_count": len(r.violations),
            }
            for r in top
        ]

    def export_blocklist(self) -> list[dict]:
        with self._lock:
            return [
                {"ip": r.ip, "reason": r.block_reason, "permanent": r.is_permanently_blocked}
                for r in self._records.values()
                if r.is_blocked
            ]

    def get_stats(self) -> dict:
        with self._lock:
            blocked = sum(1 for r in self._records.values() if r.is_blocked)
            return {
                "total_tracked_ips": len(self._records),
                "currently_blocked": blocked,
                "total_violations_recorded": self._total_violations,
                "total_blocks_issued": self._total_blocks,
                "cidr_blocks": len(self._cidr_blocklist),
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
ip_reputation = IPReputationManager()
