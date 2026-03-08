"""
Commit 76: Session Threat Tracker
====================================
Tracks and aggregates threat signals across an entire user session.
Maintains a rolling risk score that increases with each threat event
and decays slowly when the session is clean.

Features:
  - Per-session rolling threat score (exponential decay)
  - Event timeline for audit purposes
  - Automatic session escalation tiers (GREEN → YELLOW → ORANGE → RED)
  - Cross-session correlation (same IP starting new sessions after blocks)
  - Configurable decay rate and escalation thresholds

Threat tiers:
  GREEN   (0.00 – 0.24) — standard monitoring
  YELLOW  (0.25 – 0.49) — enhanced logging, reduced rate limits
  ORANGE  (0.50 – 0.74) — warn user, flag for review
  RED     (0.75 – 1.00) — block session, escalate to admin
"""

import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
SESSION_TTL_SECONDS    = 3600      # 1 hour idle = session expires
SCORE_DECAY_RATE       = 0.95      # multiply score by this every 60 s
DECAY_INTERVAL_SECONDS = 60.0
MAX_EVENTS_PER_SESSION = 200
MAX_IP_SESSIONS        = 20        # max concurrent sessions per IP


class SessionTier(str, Enum):
    GREEN  = "green"
    YELLOW = "yellow"
    ORANGE = "orange"
    RED    = "red"


def _tier_from_score(score: float) -> SessionTier:
    if score >= 0.75:
        return SessionTier.RED
    if score >= 0.50:
        return SessionTier.ORANGE
    if score >= 0.25:
        return SessionTier.YELLOW
    return SessionTier.GREEN


@dataclass
class ThreatEvent:
    event_id: str
    source_module: str
    event_type: str
    severity: float       # 0.0 – 1.0
    description: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "source_module": self.source_module,
            "event_type": self.event_type,
            "severity": round(float(self.severity), 3),  # type: ignore[call-overload]
            "description": self.description,
            "timestamp": self.timestamp,
        }


@dataclass
class _SessionState:
    session_id: str
    ip: str
    created_at: float
    last_active: float
    threat_score: float
    last_decay_at: float
    events: deque          # deque of ThreatEvent
    tier: SessionTier


@dataclass
class SessionStatus:
    session_id: str
    ip: str
    tier: SessionTier
    threat_score: float
    event_count: int
    session_age_seconds: float
    recent_events: list[dict]
    is_blocked: bool

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "ip": self.ip,
            "tier": self.tier.value,
            "threat_score": round(float(self.threat_score), 3),  # type: ignore[call-overload]
            "event_count": self.event_count,
            "session_age_seconds": round(float(self.session_age_seconds), 1),  # type: ignore[call-overload]
            "recent_events": self.recent_events,
            "is_blocked": self.is_blocked,
        }


class SessionThreatTracker:
    """
    Per-session threat score tracker with exponential decay and tier escalation.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, _SessionState] = {}
        self._ip_to_sessions: dict[str, set[str]] = {}
        self._lock = RLock()
        self._total_sessions_created = 0
        self._total_events_recorded = 0
        self._red_sessions = 0
        logger.info("🎯 SessionThreatTracker initialised")

    def create_session(self, ip: str, session_id: Optional[str] = None) -> str:
        """Create a new session for the given IP. Returns the session_id."""
        sid = session_id or str(uuid.uuid4())
        now = time.time()
        state = _SessionState(
            session_id=sid,
            ip=ip,
            created_at=now,
            last_active=now,
            threat_score=0.0,
            last_decay_at=now,
            events=deque(maxlen=MAX_EVENTS_PER_SESSION),
            tier=SessionTier.GREEN,
        )
        with self._lock:
            self._sessions[sid] = state
            ip_sessions = self._ip_to_sessions.setdefault(ip, set())
            ip_sessions.add(sid)
            # Carry-over: if IP has too many RED sessions, start new session elevated
            red_count = self._count_red_sessions_for_ip(ip)
            if red_count >= 2:
                state.threat_score = 0.5
                state.tier = SessionTier.ORANGE
                logger.warning("🎯 New session for repeat-offender IP %s started at ORANGE", ip)
            self._total_sessions_created += 1
            self._evict_expired()
        return sid

    def record_event(
        self,
        session_id: str,
        source_module: str,
        event_type: str,
        severity: float,
        description: str = "",
    ) -> Optional[SessionTier]:
        """
        Record a threat event for a session.
        Returns the new tier if escalated, or None if no change.
        """
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return None

            self._apply_decay(state)
            event = ThreatEvent(
                event_id=str(uuid.uuid4())[:8],
                source_module=source_module,
                event_type=event_type,
                severity=max(0.0, min(1.0, severity)),
                description=description,
            )
            state.events.append(event)
            state.last_active = time.time()
            self._total_events_recorded += 1

            old_tier = state.tier
            state.threat_score = min(1.0, float(state.threat_score + severity * 0.5))  # type: ignore[operator]
            state.tier = _tier_from_score(state.threat_score)

            if state.tier == SessionTier.RED and old_tier != SessionTier.RED:
                self._red_sessions += 1
                logger.warning(
                    "🎯 Session %s escalated to RED — score=%.2f ip=%s",
                    session_id[:8], state.threat_score, state.ip,
                )

            return state.tier if state.tier != old_tier else None

    def get_status(self, session_id: str) -> Optional[SessionStatus]:
        """Get the current status of a session."""
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return None
            self._apply_decay(state)
            now = time.time()
            recent = [e.to_dict() for e in list(state.events)[-5:]]  # type: ignore[index]
            return SessionStatus(
                session_id=session_id,
                ip=state.ip,
                tier=state.tier,
                threat_score=state.threat_score,
                event_count=len(state.events),
                session_age_seconds=now - state.created_at,
                recent_events=recent,
                is_blocked=state.tier == SessionTier.RED,
            )

    def is_blocked(self, session_id: str) -> bool:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return False
            self._apply_decay(state)
            return state.tier == SessionTier.RED

    def get_ip_sessions(self, ip: str) -> list[str]:
        with self._lock:
            return list(self._ip_to_sessions.get(ip, set()))

    def get_stats(self) -> dict:
        with self._lock:
            active = len(self._sessions)
            tier_counts: dict[str, int] = {t.value: 0 for t in SessionTier}
            for s in self._sessions.values():
                tier_counts[s.tier.value] += 1
            return {
                "active_sessions": active,
                "total_sessions_created": self._total_sessions_created,
                "total_events_recorded": self._total_events_recorded,
                "red_sessions_ever": self._red_sessions,
                "tier_distribution": tier_counts,
                "tracked_ips": len(self._ip_to_sessions),
            }

    # ── Private ────────────────────────────────────────────────────────────────

    def _apply_decay(self, state: _SessionState) -> None:
        """Apply exponential decay to the session's threat score."""
        now = time.time()
        intervals_elapsed = int((now - state.last_decay_at) / DECAY_INTERVAL_SECONDS)
        if intervals_elapsed > 0:
            decay = float(SCORE_DECAY_RATE ** intervals_elapsed)
            state.threat_score = float(state.threat_score * decay)  # type: ignore[operator]
            state.tier = _tier_from_score(state.threat_score)
            state.last_decay_at = float(state.last_decay_at + intervals_elapsed * DECAY_INTERVAL_SECONDS)  # type: ignore[operator]

    def _count_red_sessions_for_ip(self, ip: str) -> int:
        count = 0
        for sid in self._ip_to_sessions.get(ip, set()):
            s = self._sessions.get(sid)
            if s and s.tier == SessionTier.RED:
                count += 1
        return count

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [sid for sid, s in self._sessions.items()
                   if now - s.last_active > SESSION_TTL_SECONDS]
        for sid in expired:
            ip = self._sessions[sid].ip
            del self._sessions[sid]
            ip_set = self._ip_to_sessions.get(ip)
            if ip_set:
                ip_set.discard(sid)
        if expired:
            logger.debug("🎯 Evicted %d expired sessions", len(expired))


session_threat_tracker = SessionThreatTracker()
