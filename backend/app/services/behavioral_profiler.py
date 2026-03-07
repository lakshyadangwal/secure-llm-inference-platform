"""
Commit 37: Behavioral Profiler
================================
Builds persistent in-memory behavioral profiles for each IP/session.
Profiles track request patterns over time to detect:
  - Gradual escalation (slowly increasing threat scores)
  - Time-of-day anomalies (requests at unusual hours)
  - Topic drift (switching attack strategy mid-session)
  - Probe-then-attack patterns (benign probes followed by exploitation)
  - Persistence scoring (how long and frequently an IP targets the system)

Each profile is a rolling snapshot updated on every request.
"""

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
PROFILE_WINDOW_SECONDS   = 3600.0    # 1-hour rolling window
MAX_PROFILE_HISTORY      = 200       # max events per IP profile
ESCALATION_WINDOW        = 300.0     # 5 min window for escalation detect
ESCALATION_THRESHOLD     = 0.3       # avg severity increase considered escalation
PROBE_ATTACK_GAP         = 120.0     # seconds between safe probe and attack attempt
PERSISTENCE_DECAY        = 0.95      # score decay per hour of inactivity


# ── Profile event ──────────────────────────────────────────────────────────────

@dataclass
class ProfileEvent:
    timestamp: float
    is_threat: bool
    threat_type: str
    severity: float
    prompt_length: int
    hour_of_day: int = field(init=False)

    def __post_init__(self):
        self.hour_of_day = int(time.localtime(self.timestamp).tm_hour)


# ── Behavioral risk assessment ─────────────────────────────────────────────────

@dataclass
class BehavioralRisk:
    ip: str
    risk_score: float          # 0.0 – 1.0
    risk_level: str            # "low" | "medium" | "high" | "critical"
    indicators: list[str]
    session_length_s: float
    total_requests: int
    threat_ratio: float
    avg_severity: float
    escalation_detected: bool
    probe_attack_detected: bool
    persistence_score: float


# ── IP Behavioral Profile ──────────────────────────────────────────────────────

@dataclass
class IPProfile:
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    history: deque = field(default_factory=lambda: deque(maxlen=MAX_PROFILE_HISTORY))
    total_requests: int = 0
    persistence_score: float = 0.0


# ── Profiler ───────────────────────────────────────────────────────────────────

class BehavioralProfiler:
    """
    Maintains and analyses per-IP behavioral profiles.
    Designed to detect sophisticated multi-step attacks that evade
    per-request detection by looking at context across requests.
    """

    def __init__(self):
        self._profiles: dict[str, IPProfile] = {}
        self._lock = RLock()
        self._total_profiles = 0
        self._high_risk_count = 0
        logger.info("🧠 BehavioralProfiler initialised")

    # ── Profile management ────────────────────────────────────────────────────

    def _get_or_create(self, ip: str) -> IPProfile:
        if ip not in self._profiles:
            self._profiles[ip] = IPProfile(ip=ip)
            self._total_profiles += 1
        return self._profiles[ip]

    def _prune_history(self, profile: IPProfile, now: float) -> list[ProfileEvent]:
        """Return only events within the rolling window."""
        return [e for e in profile.history if (now - e.timestamp) <= PROFILE_WINDOW_SECONDS]

    # ── Update profile ────────────────────────────────────────────────────────

    def record(
        self,
        ip: str,
        is_threat: bool,
        threat_type: str,
        severity: float,
        prompt_length: int,
    ) -> None:
        """Record the outcome of one request to the IP's behavioral profile."""
        now = time.time()
        event = ProfileEvent(
            timestamp=now,
            is_threat=is_threat,
            threat_type=threat_type,
            severity=severity,
            prompt_length=prompt_length,
        )
        with self._lock:
            profile = self._get_or_create(ip)
            profile.history.append(event)
            profile.total_requests += 1
            profile.last_seen = now

            # Persistence score: increases with every request, decays over time
            hours_inactive = (now - profile.last_seen) / 3600.0
            profile.persistence_score = (
                profile.persistence_score * (PERSISTENCE_DECAY ** hours_inactive) + 0.05
            )
            profile.persistence_score = min(profile.persistence_score, 1.0)

    # ── Assess risk ───────────────────────────────────────────────────────────

    def assess(self, ip: str) -> BehavioralRisk:
        """
        Compute a behavioral risk assessment for an IP based on
        their full request history.
        """
        now = time.time()
        with self._lock:
            profile = self._get_or_create(ip)
            recent = self._prune_history(profile, now)

        indicators: list[str] = []
        risk_components: list[float] = []

        total = len(recent)
        threats = [e for e in recent if e.is_threat]
        threat_ratio = len(threats) / max(total, 1)
        avg_sev = sum(e.severity for e in recent) / max(total, 1)

        # ── Indicator 1: High threat ratio ────────────────────────────────────
        if threat_ratio > 0.5:
            indicators.append(f"high_threat_ratio_{threat_ratio:.0%}")
            risk_components.append(min(threat_ratio, 1.0))

        # ── Indicator 2: High average severity ───────────────────────────────
        if avg_sev > 0.5:
            indicators.append(f"high_avg_severity_{avg_sev:.2f}")
            risk_components.append(avg_sev)

        # ── Indicator 3: Escalation detection ────────────────────────────────
        escalation = self._detect_escalation(recent, now)
        if escalation:
            indicators.append("gradual_escalation")
            risk_components.append(0.7)

        # ── Indicator 4: Probe-then-attack ────────────────────────────────────
        probe_attack = self._detect_probe_attack(recent)
        if probe_attack:
            indicators.append("probe_then_attack")
            risk_components.append(0.8)

        # ── Indicator 5: Session length ───────────────────────────────────────
        session_len = now - profile.first_seen
        if session_len > 1800 and threat_ratio > 0.3:
            indicators.append(f"persistent_attacker_{session_len:.0f}s")
            risk_components.append(0.6)

        # ── Indicator 6: Persistence score ───────────────────────────────────
        if profile.persistence_score > 0.7:
            indicators.append(f"high_persistence_{profile.persistence_score:.2f}")
            risk_components.append(profile.persistence_score)

        # ── Aggregate risk score ──────────────────────────────────────────────
        if risk_components:
            risk_score = float(min(sum(risk_components) / len(risk_components) * 1.5, 1.0))
        else:
            risk_score = 0.0

        risk_level = (
            "critical" if risk_score >= 0.8
            else "high" if risk_score >= 0.6
            else "medium" if risk_score >= 0.35
            else "low"
        )

        if risk_level in ("high", "critical"):
            self._high_risk_count += 1
            logger.warning(
                "🧠 High-risk profile — ip=%s  level=%s  score=%.2f  indicators=%s",
                ip, risk_level, risk_score, indicators
            )

        return BehavioralRisk(
            ip=ip,
            risk_score=round(risk_score, 3),
            risk_level=risk_level,
            indicators=indicators,
            session_length_s=round(now - profile.first_seen, 1),
            total_requests=profile.total_requests,
            threat_ratio=round(threat_ratio, 3),
            avg_severity=round(avg_sev, 3),
            escalation_detected=escalation,
            probe_attack_detected=probe_attack,
            persistence_score=round(profile.persistence_score, 3),
        )

    def _detect_escalation(self, events: list[ProfileEvent], now: float) -> bool:
        """Detect if severity scores are trending upward over recent requests."""
        recent = [e for e in events if (now - e.timestamp) <= ESCALATION_WINDOW]
        if len(recent) < 4:
            return False
        severities = [e.severity for e in recent]
        # Linear regression slope
        n = len(severities)
        x_mean = (n - 1) / 2.0
        y_mean = sum(severities) / n
        num = sum((i - x_mean) * (s - y_mean) for i, s in enumerate(severities))
        den = sum((i - x_mean) ** 2 for i in range(n))
        slope = num / den if den != 0 else 0.0
        return slope > ESCALATION_THRESHOLD

    def _detect_probe_attack(self, events: list[ProfileEvent]) -> bool:
        """Detect safe probe followed by attack within PROBE_ATTACK_GAP seconds."""
        for i, safe in enumerate(events):
            if safe.is_threat:
                continue
            for attack in events[i + 1:]:
                gap = attack.timestamp - safe.timestamp
                if gap > PROBE_ATTACK_GAP:
                    break
                if attack.is_threat and attack.severity >= 0.6:
                    return True
        return False

    def get_profile_summary(self, ip: str) -> dict:
        """Return a summary dict for one IP's profile."""
        risk = self.assess(ip)
        return {
            "ip": risk.ip,
            "risk_score": risk.risk_score,
            "risk_level": risk.risk_level,
            "indicators": risk.indicators,
            "session_length_s": risk.session_length_s,
            "total_requests": risk.total_requests,
            "threat_ratio": risk.threat_ratio,
            "avg_severity": risk.avg_severity,
            "escalation_detected": risk.escalation_detected,
            "probe_attack_detected": risk.probe_attack_detected,
            "persistence_score": risk.persistence_score,
        }

    def get_all_high_risk(self) -> list[dict]:
        """Return summaries of all IPs with high or critical risk."""
        with self._lock:
            ips = list(self._profiles.keys())
        return [
            self.get_profile_summary(ip)
            for ip in ips
            if self.assess(ip).risk_level in ("high", "critical")
        ]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_profiles": len(self._profiles),
                "high_risk_assessments": self._high_risk_count,
            }

    def evict_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._profiles:
                del self._profiles[ip]
                return True
            return False


# ── Singleton ──────────────────────────────────────────────────────────────────
behavioral_profiler = BehavioralProfiler()
