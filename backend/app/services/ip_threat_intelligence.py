"""
Commit 77: IP Threat Intelligence
====================================
Provides IP-level threat intelligence by maintaining:
  1. Manual reputation entries  (admin-flagged IPs)
  2. Auto-flagged entries       (IPs flagged by defense modules)
  3. ASN/CIDR block rules       (entire netblocks e.g. TOR exit nodes, VPNs)
  4. Country block list         (2-letter ISO codes)
  5. Scoring history            (per-IP score timeline for trend analysis)

Also extracts basic metadata from IP strings:
  - Private/loopback range detection
  - IPv4 vs IPv6 classification
  - Rough geo-hint from first octet (regional heuristic, no DB needed)

All lookups are O(1) or O(n_cidrs) and thread-safe.
Entries have configurable TTLs and severity levels.
"""

import ipaddress
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Optional, Union

logger = logging.getLogger(__name__)

# ── Severity ──────────────────────────────────────────────────────────────────
class IPSeverity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


_SEV_SCORE: dict[str, float] = {
    IPSeverity.LOW.value:      0.25,
    IPSeverity.MEDIUM.value:   0.50,
    IPSeverity.HIGH.value:     0.75,
    IPSeverity.CRITICAL.value: 1.00,
}

# ── Known bad CIDR blocks (examples — TOR, common VPN ranges) ──────────────────
_DEFAULT_BAD_CIDRS: list[str] = [
    "185.220.0.0/14",    # TOR exit node range
    "104.244.72.0/21",   # TOR project
    "199.87.154.0/23",   # TOR exit servers
    "5.188.10.0/23",     # Spamhaus listed
    "91.108.4.0/22",     # Telegram data centre (common proxy abuse)
    "194.165.16.0/23",   # Known VPN reseller range
]

# ── Known blocked countries (ISO-3166-1 alpha-2) ─────────────────────────────
_DEFAULT_BLOCKED_COUNTRIES: set[str] = set()  # admin-configurable; empty by default

# ── Private/special ranges ─────────────────────────────────────────────────────
_PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
]


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            return any(addr in net for net in _PRIVATE_NETWORKS)
        return addr.is_private
    except ValueError:
        return False


def _is_ipv6(ip_str: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv6Address)
    except ValueError:
        return False


def _ip_in_cidr(ip_str: str, cidr: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(cidr, strict=False)
        return addr in net
    except ValueError:
        return False


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class IPReputationEntry:
    ip: str
    severity: IPSeverity
    reason: str
    source: str          # "manual" | "auto" | "cidr" | "country"
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    hit_count: int = 0

    @property
    def is_expired(self) -> bool:
        exp = self.expires_at
        if exp is None:
            return False
        return time.time() > float(exp)  # type: ignore[operator]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "severity": self.severity.value,
            "reason": self.reason,
            "source": self.source,
            "hit_count": self.hit_count,
            "is_expired": self.is_expired,
        }


@dataclass
class IPLookupResult:
    ip: str
    is_known_bad: bool
    reputation_score: float   # 0.0 = clean, 1.0 = critical threat
    severity: Optional[str]
    reason: Optional[str]
    source: Optional[str]
    is_private: bool
    is_ipv6: bool
    in_blocked_cidr: bool
    in_blocked_country: bool
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "is_known_bad": self.is_known_bad,
            "reputation_score": round(float(self.reputation_score), 3),  # type: ignore[call-overload]
            "severity": self.severity,
            "reason": self.reason,
            "source": self.source,
            "is_private": self.is_private,
            "is_ipv6": self.is_ipv6,
            "in_blocked_cidr": self.in_blocked_cidr,
            "in_blocked_country": self.in_blocked_country,
            "details": self.details,
        }


class IPThreatIntelligence:
    """
    IP reputation and threat intelligence service.
    Supports manual entries, auto-flagging, CIDR blocks, and country blocks.
    """

    def __init__(
        self,
        bad_cidrs: Optional[list[str]] = None,
        blocked_countries: Optional[set[str]] = None,
    ) -> None:
        self._entries: dict[str, IPReputationEntry] = {}
        self._bad_cidrs: list[str] = list(bad_cidrs or _DEFAULT_BAD_CIDRS)
        self._blocked_countries: set[str] = set(blocked_countries or _DEFAULT_BLOCKED_COUNTRIES)
        self._ip_score_history: dict[str, list[tuple[float, float]]] = {}  # ip → [(ts, score)]
        self._lock = RLock()
        self._total_lookups = 0
        self._known_bad_hits = 0
        logger.info(
            "🔍 IPThreatIntelligence ready — %d CIDRs, %d countries blocked",
            len(self._bad_cidrs), len(self._blocked_countries),
        )

    def flag_ip(
        self,
        ip: str,
        severity: IPSeverity,
        reason: str,
        source: str = "auto",
        ttl_seconds: Optional[float] = None,
    ) -> IPReputationEntry:
        """Flag an IP address with a reputation entry."""
        now = time.time()
        expires = float(now + ttl_seconds) if ttl_seconds else None  # type: ignore[operator]
        entry = IPReputationEntry(
            ip=ip,
            severity=severity,
            reason=reason,
            source=source,
            created_at=now,
            expires_at=expires,
        )
        with self._lock:
            existing = self._entries.get(ip)
            if existing:
                # Upgrade severity if new is higher
                existing_weight = _SEV_SCORE.get(existing.severity.value, 0)
                new_weight = _SEV_SCORE.get(severity.value, 0)
                if new_weight > existing_weight:
                    self._entries[ip] = entry
                else:
                    existing.hit_count += 1
            else:
                self._entries[ip] = entry
        logger.info("🔍 IP %s flagged — severity=%s reason=%s", ip, severity.value, reason)
        return entry

    def unflag_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._entries:
                del self._entries[ip]
                return True
            return False

    def lookup(self, ip: str) -> IPLookupResult:
        """Look up an IP and return its threat intelligence."""
        with self._lock:
            self._total_lookups += 1
            self._evict_expired()

        details: list[str] = []
        is_private = _is_private(ip)
        is_v6 = _is_ipv6(ip)

        # Short-circuit for private IPs
        if is_private:
            return IPLookupResult(
                ip=ip, is_known_bad=False, reputation_score=0.0,
                severity=None, reason=None, source=None,
                is_private=True, is_ipv6=is_v6,
                in_blocked_cidr=False, in_blocked_country=False,
                details=["private_ip_trusted"],
            )

        # Manual / auto entry
        with self._lock:
            entry = self._entries.get(ip)

        rep_score: float = 0.0
        severity_str: Optional[str] = None
        reason: Optional[str] = None
        source: Optional[str] = None

        if entry and not entry.is_expired:
            rep_score = float(_SEV_SCORE.get(entry.severity.value, 0.5))
            severity_str = entry.severity.value
            reason = entry.reason
            source = entry.source
            details.append(f"known_bad:{entry.reason}")
            with self._lock:
                entry.hit_count += 1
                self._known_bad_hits += 1

        # CIDR check
        in_cidr = False
        for cidr in self._bad_cidrs:
            if _ip_in_cidr(ip, cidr):
                in_cidr = True
                cidr_score = 0.6
                rep_score = max(rep_score, cidr_score)
                details.append(f"blocked_cidr:{cidr}")
                if not severity_str:
                    severity_str = IPSeverity.HIGH.value
                    reason = f"IP in blocked CIDR {cidr}"
                    source = "cidr"
                break

        # Country block (naïve first-octet heuristic — production should use a GeoIP DB)
        in_country = False
        if self._blocked_countries:
            geo_hint = self._naive_geo_hint(ip)
            if geo_hint in self._blocked_countries:
                in_country = True
                rep_score = max(rep_score, 0.7)
                details.append(f"blocked_country:{geo_hint}")
                if not severity_str:
                    severity_str = IPSeverity.HIGH.value
                    reason = f"Country blocked: {geo_hint}"
                    source = "country"

        rep_score = min(1.0, rep_score)
        is_bad = rep_score >= 0.25

        # Record score history
        with self._lock:
            hist = self._ip_score_history.setdefault(ip, [])
            hist.append((time.time(), rep_score))
            if len(hist) > 100:
                self._ip_score_history[ip] = hist[-100:]  # type: ignore[index]

        return IPLookupResult(
            ip=ip,
            is_known_bad=is_bad,
            reputation_score=rep_score,
            severity=severity_str,
            reason=reason,
            source=source,
            is_private=is_private,
            is_ipv6=is_v6,
            in_blocked_cidr=in_cidr,
            in_blocked_country=in_country,
            details=details,
        )

    def add_cidr_block(self, cidr: str) -> None:
        with self._lock:
            if cidr not in self._bad_cidrs:
                self._bad_cidrs.append(cidr)
        logger.info("🔍 CIDR block added: %s", cidr)

    def add_country_block(self, iso2: str) -> None:
        with self._lock:
            self._blocked_countries.add(iso2.upper())
        logger.info("🔍 Country block added: %s", iso2.upper())

    def remove_country_block(self, iso2: str) -> None:
        with self._lock:
            self._blocked_countries.discard(iso2.upper())

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_lookups": self._total_lookups,
                "known_bad_hits": self._known_bad_hits,
                "flagged_ips": len(self._entries),
                "blocked_cidrs": len(self._bad_cidrs),
                "blocked_countries": list(self._blocked_countries),
                "tracked_ips_history": len(self._ip_score_history),
            }

    def _evict_expired(self) -> None:
        expired = [ip for ip, e in self._entries.items() if e.is_expired]
        for ip in expired:
            del self._entries[ip]

    def _naive_geo_hint(self, ip: str) -> str:
        """Very rough geo hint based on first octet. NOT production-grade."""
        try:
            first = int(ip.split(".")[0])  # type: ignore[index]
            if first in range(41, 43):
                return "JP"
            if first in range(58, 62):
                return "CN"
            if first in range(195, 200):
                return "RU"
        except (ValueError, IndexError):
            pass
        return "XX"


ip_threat_intelligence = IPThreatIntelligence()
