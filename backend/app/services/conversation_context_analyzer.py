"""
Commit 75: Conversation Context Analyzer
==========================================
Analyzes the full multi-turn conversation history to detect:
  1. Escalation patterns  — safe start, gradually becomes dangerous
  2. Topic drift          — conversation slowly drifts toward harmful areas
  3. Repeated probing     — user rephrasing the same harmful request
  4. Context poisoning    — user places harmful facts in earlier turns
                            hoping the model will reason from them
  5. Turn-count anomalies — unusually long conversations (bot behaviour)
  6. Role confusion       — user tries to make assistant forget its role
     by embedding persona changes mid-conversation

Each conversation is identified by a session_id string.
Message history is stored in a fixed-size sliding window per session.
"""

import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
MAX_HISTORY_PER_SESSION = 50    # maximum turns stored per session
ESCALATION_WINDOW       = 5     # turns to look back for escalation
MAX_REPEAT_DISTANCE     = 8     # how many turns to compare for rephrasing
SESSION_TTL_SECONDS     = 3600  # sessions expire after 1 hour of inactivity

# ── Harmful topic seed list (lightweight, regex-free) ─────────────────────────
_HARMFUL_SEEDS: list[str] = [
    "bomb", "weapon", "explosive", "poison", "malware", "ransomware",
    "jailbreak", "bypass", "ignore instructions", "override", "DAN",
    "suicide", "self-harm", "drug synthesis", "hack", "exploit",
    "credential", "phishing", "csam", "child", "terror", "kill",
    "murder", "gun", "synthesize", "nerve agent",
]

_SEED_RE: list[re.Pattern] = [
    re.compile(rf"\b{re.escape(s)}\b", re.IGNORECASE) for s in _HARMFUL_SEEDS
]

# Role confusion patterns
_ROLE_CONFUSION_RE: list[re.Pattern] = [
    re.compile(r"\b(forget|ignore|abandon)\b.{0,20}\b(your\s+role|who\s+you\s+are|your\s+instructions?|yourself)\b", re.I),
    re.compile(r"\b(you\s+are\s+now|from\s+now\s+on\s+you\s+are)\b.{0,40}\b(no\s+(rules?|restrictions?)|free|unrestricted)\b", re.I),
    re.compile(r"\bpretend\s+(you\s+)?(never\s+had|don.t\s+have)\s+(rules?|restrictions?|guidelines?)\b", re.I),
]

# Context poisoning markers
_POISON_RE: list[re.Pattern] = [
    re.compile(r"\b(assume|given\s+that|note\s+that|remember\s+that|for\s+this\s+conversation)\b.{0,60}\b(legal|allowed|permitted|safe|okay|fine|acceptable)\b.{0,40}\b(bomb|weapon|hack|exploit|drug|kill)\b", re.I),
    re.compile(r"\bin\s+(your|this|our)\s+(world|scenario|universe|context)\s*[,\.].{0,30}\b(everything\s+is\s+allowed|no\s+restrictions)\b", re.I),
]


@dataclass
class ConversationTurn:
    role: str          # "user" | "assistant"
    content: str
    timestamp: float
    harmful_score: float   # pre-computed score for this turn
    harmful_seeds: list[str]

    def __post_init__(self) -> None:
        self.harmful_seeds = [s for s, p in zip(_HARMFUL_SEEDS, _SEED_RE) if p.search(self.content)]
        hits = len(self.harmful_seeds)
        self.harmful_score = min(1.0, hits * 0.15)


@dataclass
class ContextAnalysisResult:
    session_id: str
    turn_count: int
    escalation_detected: bool
    topic_drift_detected: bool
    repeated_probing_detected: bool
    context_poisoning_detected: bool
    role_confusion_detected: bool
    aggregate_risk: float
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "turn_count": self.turn_count,
            "escalation_detected": self.escalation_detected,
            "topic_drift_detected": self.topic_drift_detected,
            "repeated_probing_detected": self.repeated_probing_detected,
            "context_poisoning_detected": self.context_poisoning_detected,
            "role_confusion_detected": self.role_confusion_detected,
            "aggregate_risk": round(float(self.aggregate_risk), 3),  # type: ignore[call-overload]
            "flags": self.flags,
        }


@dataclass
class _SessionState:
    history: deque              # deque of ConversationTurn
    last_active: float


class ConversationContextAnalyzer:
    """
    Analyzes multi-turn conversation histories for escalating,
    drifting, or poisoning attack patterns.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, _SessionState] = {}
        self._lock = RLock()
        self._total_turns_analyzed = 0
        self._sessions_flagged = 0
        logger.info("💬 ConversationContextAnalyzer ready — window=%d turns", ESCALATION_WINDOW)

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_turn(self, session_id: str, role: str, content: str) -> None:
        """Add a conversation turn to the session history."""
        turn = ConversationTurn(
            role=role,
            content=content,
            timestamp=time.time(),
            harmful_score=0.0,
            harmful_seeds=[],
        )
        with self._lock:
            self._total_turns_analyzed += 1
            self._evict_expired()
            if session_id not in self._sessions:
                self._sessions[session_id] = _SessionState(
                    history=deque(maxlen=MAX_HISTORY_PER_SESSION),
                    last_active=time.time(),
                )
            state = self._sessions[session_id]
            state.history.append(turn)
            state.last_active = time.time()

    def analyze(self, session_id: str) -> ContextAnalysisResult:
        """Analyze the conversation history for the given session_id."""
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return ContextAnalysisResult(
                    session_id=session_id, turn_count=0,
                    escalation_detected=False, topic_drift_detected=False,
                    repeated_probing_detected=False, context_poisoning_detected=False,
                    role_confusion_detected=False, aggregate_risk=0.0,
                )
            history: list[ConversationTurn] = list(state.history)

        user_turns = [t for t in history if t.role == "user"]
        flags: list[str] = []

        escalation = self._detect_escalation(user_turns, flags)
        drift      = self._detect_topic_drift(user_turns, flags)
        probing    = self._detect_repeated_probing(user_turns, flags)
        poisoning  = self._detect_context_poisoning(history, flags)
        confusion  = self._detect_role_confusion(user_turns, flags)

        risk: float = 0.0
        if escalation:
            risk = float(risk + 0.35)  # type: ignore[operator]
        if drift:
            risk = float(risk + 0.25)  # type: ignore[operator]
        if probing:
            risk = float(risk + 0.30)  # type: ignore[operator]
        if poisoning:
            risk = float(risk + 0.40)  # type: ignore[operator]
        if confusion:
            risk = float(risk + 0.35)  # type: ignore[operator]

        # Boost if average harmful score across recent user turns is high
        recent_user = user_turns[-ESCALATION_WINDOW:]
        if recent_user:
            avg_harm = sum(t.harmful_score for t in recent_user) / len(recent_user)
            risk = float(risk + avg_harm * 0.3)  # type: ignore[operator]

        risk = min(1.0, risk)

        with self._lock:
            if risk >= 0.35:
                self._sessions_flagged += 1

        if risk >= 0.35:
            logger.warning(
                "💬 Session %s flagged — risk=%.2f flags=%s",
                session_id[:8], risk, flags,
            )

        return ContextAnalysisResult(
            session_id=session_id,
            turn_count=len(history),
            escalation_detected=escalation,
            topic_drift_detected=drift,
            repeated_probing_detected=probing,
            context_poisoning_detected=poisoning,
            role_confusion_detected=confusion,
            aggregate_risk=risk,
            flags=flags,
        )

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "active_sessions": len(self._sessions),
                "total_turns_analyzed": self._total_turns_analyzed,
                "sessions_flagged": self._sessions_flagged,
                "max_history_per_session": MAX_HISTORY_PER_SESSION,
            }

    # ── Private detection helpers ─────────────────────────────────────────────

    def _detect_escalation(self, user_turns: list[ConversationTurn], flags: list[str]) -> bool:
        """Detect if harmful scores are monotonically increasing in recent turns."""
        recent = user_turns[-ESCALATION_WINDOW:]
        if len(recent) < 3:
            return False
        scores = [t.harmful_score for t in recent]
        # Check if last 3 scores are strictly increasing
        increasing = all(scores[i] < scores[i + 1] for i in range(len(scores) - 1))
        if increasing and scores[-1] > 0.1:
            flags.append("escalating_harmful_score")
            return True
        # Check if last score is significantly higher than first
        if scores[-1] > scores[0] + 0.3:
            flags.append("significant_score_increase")
            return True
        return False

    def _detect_topic_drift(self, user_turns: list[ConversationTurn], flags: list[str]) -> bool:
        """Detect if the conversation drifted from clean topics to harmful ones."""
        if len(user_turns) < 4:
            return False
        early = user_turns[:len(user_turns) // 2]
        late  = user_turns[len(user_turns) // 2:]
        early_seeds: set[str] = set()
        for t in early:
            early_seeds.update(t.harmful_seeds)
        late_seeds: set[str] = set()
        for t in late:
            late_seeds.update(t.harmful_seeds)
        new_harmful = late_seeds - early_seeds
        if len(new_harmful) >= 3:
            flags.append(f"topic_drift_new_seeds:{','.join(sorted(new_harmful)[:3])}")
            return True
        return False

    def _detect_repeated_probing(self, user_turns: list[ConversationTurn], flags: list[str]) -> bool:
        """Detect the same harmful seeds appearing in multiple turns close together."""
        if len(user_turns) < 3:
            return False
        recent = user_turns[-MAX_REPEAT_DISTANCE:]
        seed_appearances: dict[str, int] = {}
        for turn in recent:
            for seed in turn.harmful_seeds:
                seed_appearances[seed] = seed_appearances.get(seed, 0) + 1
        repeated = [s for s, count in seed_appearances.items() if count >= 3]
        if repeated:
            flags.append(f"repeated_probing:{','.join(repeated[:3])}")
            return True
        return False

    def _detect_context_poisoning(self, history: list[ConversationTurn], flags: list[str]) -> bool:
        """Detect embedded false premises that normalise harmful topics."""
        for turn in history:
            for p in _POISON_RE:
                if p.search(turn.content):
                    flags.append("context_poisoning_detected")
                    return True
        return False

    def _detect_role_confusion(self, user_turns: list[ConversationTurn], flags: list[str]) -> bool:
        """Detect attempts to make the model forget or abandon its role."""
        for turn in user_turns:
            for p in _ROLE_CONFUSION_RE:
                if p.search(turn.content):
                    flags.append("role_confusion_attempt")
                    return True
        return False

    def _evict_expired(self) -> None:
        """Remove sessions that have been inactive beyond SESSION_TTL_SECONDS."""
        now = time.time()
        expired = [sid for sid, state in self._sessions.items()
                   if now - state.last_active > SESSION_TTL_SECONDS]
        for sid in expired:
            del self._sessions[sid]
        if expired:
            logger.debug("💬 Evicted %d expired sessions", len(expired))


conversation_context_analyzer = ConversationContextAnalyzer()
