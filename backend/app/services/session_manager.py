"""
Commit 48: Session Manager
============================
Tracks user-facing request sessions with security metadata.
Each session is tied to an IP + user-agent fingerprint and has a TTL.

Features:
  - Session creation on first request per fingerprint
  - Session fingerprinting (IP + User-Agent hash)
  - Session-level threat accumulation
  - Auto-expiry with configurable TTL
  - Max concurrent session limit (prevents session flooding)
  - Session token generation (opaque, non-guessable)
  - Risk escalation flag per session
  - Statistics: active sessions, expired, total created
"""

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
SESSION_TTL_SECONDS   = 1800.0    # 30 minutes idle TTL
MAX_SESSIONS          = 5000      # max concurrent sessions
TOKEN_BYTES           = 32        # session token entropy


# ── Session ────────────────────────────────────────────────────────────────────

@dataclass
class Session:
    session_id: str
    token: str
    fingerprint: str
    ip: str
    user_agent: str
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    request_count: int = 0
    threat_count: int = 0
    threat_score_sum: float = 0.0
    is_flagged: bool = False
    flag_reason: str = ""

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_active) > SESSION_TTL_SECONDS

    @property
    def duration_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def avg_threat_score(self) -> float:
        if self.request_count == 0:
            return 0.0
        return round(float(self.threat_score_sum) / self.request_count, 3)  # type: ignore[call-overload]

    @property
    def threat_ratio(self) -> float:
        if self.request_count == 0:
            return 0.0
        return round(float(self.threat_count) / self.request_count, 3)  # type: ignore[call-overload]

    def touch(self) -> None:
        """Update last_active timestamp."""
        self.last_active = time.time()
        self.request_count += 1

    def record_threat(self, score: float) -> None:
        self.threat_count += 1
        self.threat_score_sum += score

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "ip": self.ip,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "duration_seconds": round(self.duration_seconds, 1),  # type: ignore[call-overload]
            "request_count": self.request_count,
            "threat_count": self.threat_count,
            "threat_ratio": self.threat_ratio,
            "avg_threat_score": self.avg_threat_score,
            "is_flagged": self.is_flagged,
            "flag_reason": self.flag_reason,
        }


# ── Session Manager ────────────────────────────────────────────────────────────

class SessionManager:
    """
    Manages user sessions for the Neuro-Sentry platform.
    Sessions are keyed by a fingerprint hash of (IP, User-Agent).
    """

    def __init__(self, ttl: float = SESSION_TTL_SECONDS, max_sessions: int = MAX_SESSIONS):
        self._sessions: dict[str, Session] = {}       # fingerprint → session
        self._by_token: dict[str, str] = {}            # token → fingerprint
        self._lock = RLock()
        self._ttl = ttl
        self._max_sessions = max_sessions
        self._total_created = 0
        self._total_expired = 0
        logger.info("🎫 SessionManager initialised (ttl=%.0fs  max=%d)", ttl, max_sessions)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _fingerprint(self, ip: str, user_agent: str) -> str:
        raw = f"{ip}|{user_agent.strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]  # type: ignore[index]

    def _generate_token(self) -> str:
        return secrets.token_urlsafe(TOKEN_BYTES)

    def _generate_session_id(self) -> str:
        return secrets.token_hex(12)

    def _evict_expired(self) -> int:
        """Remove all expired sessions. Must be called with lock held."""
        expired_keys = [fp for fp, s in self._sessions.items() if s.is_expired]
        for fp in expired_keys:
            s = self._sessions.pop(fp)
            self._by_token.pop(s.token, None)
            self._total_expired += 1
        return len(expired_keys)

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_or_create(self, ip: str, user_agent: str = "") -> Session:
        """
        Return the existing session for this IP+UA, or create a new one.
        Updates last_active on every call.
        """
        fp = self._fingerprint(ip, user_agent)
        with self._lock:
            session = self._sessions.get(fp)

            if session and session.is_expired:
                # Recycle the expired session
                self._by_token.pop(session.token, None)
                self._sessions.pop(fp, None)
                session = None
                self._total_expired += 1

            if session is None:
                # Enforce max session limit
                if len(self._sessions) >= self._max_sessions:
                    evicted = self._evict_expired()
                    if len(self._sessions) >= self._max_sessions:
                        logger.warning("⚠️  Session limit reached — dropping oldest session")
                        oldest = min(self._sessions.values(), key=lambda s: s.last_active)
                        self._by_token.pop(oldest.token, None)
                        oldest_fp = oldest.fingerprint if hasattr(oldest, 'fingerprint') else fp
                        self._sessions.pop(oldest_fp, None)

                token = self._generate_token()
                session = Session(
                    session_id=self._generate_session_id(),
                    token=token,
                    fingerprint=fp,
                    ip=ip,
                    user_agent=user_agent,
                )
                self._sessions[fp] = session
                self._by_token[token] = fp
                self._total_created += 1
                logger.debug("🎫 New session — ip=%s  sid=%s", ip, session.session_id)

            session.touch()
            return session

    def get_by_token(self, token: str) -> Optional[Session]:
        """Look up a session by its opaque token."""
        with self._lock:
            fp = self._by_token.get(token)
            if fp is None:
                return None
            session = self._sessions.get(fp)
            if session and session.is_expired:
                return None
            return session

    def record_threat(self, ip: str, user_agent: str, score: float) -> None:
        """Record a threat event against a session."""
        fp = self._fingerprint(ip, user_agent)
        with self._lock:
            session = self._sessions.get(fp)
            if session:
                session.record_threat(score)
                if session.threat_ratio > 0.5 and not session.is_flagged:
                    session.is_flagged = True
                    session.flag_reason = f"threat_ratio_{session.threat_ratio:.2f}"
                    logger.warning(
                        "🚩 Session flagged — ip=%s  ratio=%.2f",
                        ip, session.threat_ratio
                    )

    def flag_session(self, ip: str, reason: str, user_agent: str = "") -> bool:
        """Manually flag a session."""
        fp = self._fingerprint(ip, user_agent)
        with self._lock:
            session = self._sessions.get(fp)
            if session:
                session.is_flagged = True
                session.flag_reason = reason
                return True
        return False

    def terminate(self, ip: str, user_agent: str = "") -> bool:
        """Terminate (delete) a session."""
        fp = self._fingerprint(ip, user_agent)
        with self._lock:
            session = self._sessions.pop(fp, None)
            if session:
                self._by_token.pop(session.token, None)
                return True
        return False

    def get_all_active(self) -> list[dict]:
        """Return all non-expired sessions as dicts."""
        with self._lock:
            return [s.to_dict() for s in self._sessions.values() if not s.is_expired]

    def get_flagged(self) -> list[dict]:
        """Return all flagged sessions."""
        with self._lock:
            return [s.to_dict() for s in self._sessions.values() if s.is_flagged and not s.is_expired]

    def get_stats(self) -> dict:
        with self._lock:
            active = sum(1 for s in self._sessions.values() if not s.is_expired)
            flagged = sum(1 for s in self._sessions.values() if s.is_flagged)
            return {
                "active_sessions": active,
                "flagged_sessions": flagged,
                "total_created": self._total_created,
                "total_expired": self._total_expired,
                "max_sessions": self._max_sessions,
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
session_manager = SessionManager()
