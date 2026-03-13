"""
Commit 90: User Trust Scorer
===============================
Maintains a simple trust score (0.0–1.0) per user/API key.
Score starts at 0.5 (neutral). Good behaviour raises it; bad behaviour lowers it.
Score is used to adjust rate limits, verbosity of safety messages, and log levels.

Trust levels:
  HIGH    (0.75 – 1.0 ): trusted user — relaxed limits
  NEUTRAL (0.40 – 0.74): normal user
  LOW     (0.20 – 0.39): watch list — extra logging
  UNTRUST (0.00 – 0.19): near-block — require extra verification
"""

import logging
import time
from dataclasses import dataclass
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

_DECAY_INTERVAL = 3600.0   # score drifts toward 0.5 every hour
_DECAY_STRENGTH = 0.05     # amount per interval


def _trust_level(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.40:
        return "NEUTRAL"
    if score >= 0.20:
        return "LOW"
    return "UNTRUST"


@dataclass
class _UserState:
    score: float = 0.5
    last_updated: float = 0.0
    positive_events: int = 0
    negative_events: int = 0


@dataclass
class TrustStatus:
    user_id: str
    score: float
    level: str
    positive_events: int
    negative_events: int

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "score": round(float(self.score), 3),  # type: ignore[call-overload]
            "level": self.level,
            "positive_events": self.positive_events,
            "negative_events": self.negative_events,
        }


class UserTrustScorer:
    """Per-user trust scorer with time-based mean-reversion."""

    def __init__(self) -> None:
        self._users: dict[str, _UserState] = {}
        self._lock = RLock()

    def _get_state(self, user_id: str) -> _UserState:
        if user_id not in self._users:
            state = _UserState(score=0.5, last_updated=time.time())
            self._users[user_id] = state
        return self._users[user_id]

    def _apply_decay(self, state: _UserState) -> None:
        now = time.time()
        intervals = int((now - state.last_updated) / _DECAY_INTERVAL)
        if intervals > 0:
            # Revert toward 0.5 by DECAY_STRENGTH per interval
            for _ in range(intervals):
                diff = float(0.5 - state.score)
                state.score = float(state.score + diff * _DECAY_STRENGTH)  # type: ignore[operator]
            state.last_updated = float(state.last_updated + intervals * _DECAY_INTERVAL)  # type: ignore[operator]
            state.score = max(0.0, min(1.0, state.score))

    def record_positive(self, user_id: str, delta: float = 0.05) -> float:
        with self._lock:
            state = self._get_state(user_id)
            self._apply_decay(state)
            state.score = min(1.0, float(state.score + delta))  # type: ignore[operator]
            state.positive_events += 1
            return state.score

    def record_negative(self, user_id: str, delta: float = 0.10) -> float:
        with self._lock:
            state = self._get_state(user_id)
            self._apply_decay(state)
            state.score = max(0.0, float(state.score - delta))  # type: ignore[operator]
            state.negative_events += 1
            if state.score < 0.20:
                logger.warning("🫣 User %s is now UNTRUST (score=%.2f)", user_id, state.score)
            return state.score

    def get_status(self, user_id: str) -> TrustStatus:
        with self._lock:
            state = self._get_state(user_id)
            self._apply_decay(state)
        return TrustStatus(
            user_id=user_id,
            score=state.score,
            level=_trust_level(state.score),
            positive_events=state.positive_events,
            negative_events=state.negative_events,
        )

    def get_stats(self) -> dict:
        with self._lock:
            levels: dict[str, int] = {"HIGH": 0, "NEUTRAL": 0, "LOW": 0, "UNTRUST": 0}
            for s in self._users.values():
                levels[_trust_level(s.score)] += 1
            return {"tracked_users": len(self._users), "level_distribution": levels}


user_trust_scorer = UserTrustScorer()
