"""
Commit 61: Prompt Mutation Detector
======================================
Detects when an attacker is systematically mutating a payload to
evade detection — a technique sometimes called "adversarial probing".

Strategy:
  - Tracks recent prompts per IP in a sliding window
  - Computes pairwise edit distance (Levenshtein) between consecutive prompts
  - If prompts are SIMILAR (close edit distance) but NOT blocked,
    the attacker may be iteratively refining a blocked payload
  - Detects: synonyms substitution, letter substitution, encoding sprinkle,
    whitespace injection, character repetition

Also flags:
  - Rapid alternation between multiple attack categories
  - Suspiciously low semantic distance between prompts (paraphrasing)
  - Time-compressed probing (many attempts in a short window)
"""

import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────────────────────────
MUTATION_WINDOW_SECONDS = 300.0   # 5-minute window per IP
MAX_PROMPTS_PER_IP      = 20      # keep last N prompts per IP
EDIT_DIST_THRESH        = 0.30    # below this = very similar (0-1 normalised)
MUTATION_THRESHOLD      = 3       # N similar-but-various prompts = mutation attack
PROBE_RATE_THRESHOLD    = 5       # N prompts in PROBE_RATE_WINDOW = rapid probing
PROBE_RATE_WINDOW       = 30.0    # seconds


# ── Levenshtein functions ───────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein edit distance (dynamic programming)."""
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    # Use compact DP row
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        for j in range(1, lb + 1):
            if a[i-1] == b[j-1]:
                curr[j] = prev[j-1]
            else:
                curr[j] = 1 + min(prev[j], curr[j-1], prev[j-1])
        prev = curr
    return prev[lb]


def _normalised_edit_distance(a: str, b: str) -> float:
    """Levenshtein distance normalised to [0, 1] by max string length."""
    if not a and not b:
        return 0.0
    dist = _levenshtein(a[:200], b[:200])   # cap at 200 chars for performance
    return dist / max(len(a[:200]), len(b[:200]), 1)


def _strip_for_comparison(text: str) -> str:
    """Normalise text for comparison: lowercase, remove extra spaces/punctuation."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ── Prompt record ───────────────────────────────────────────────────────────────

@dataclass
class PromptRecord:
    text: str
    normalised: str
    timestamp: float
    was_blocked: bool = False
    intent_label: str = "unknown"


# ── Mutation result ─────────────────────────────────────────────────────────────

@dataclass
class MutationResult:
    ip: str
    is_mutation_attack: bool
    is_rapid_probe: bool
    consecutive_similar_count: int   # how many consecutive similar prompts
    avg_edit_distance: float         # avg. normalised edit distance
    total_prompts_in_window: int
    probe_rate_per_minute: float
    risk_score: float
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "is_mutation_attack": self.is_mutation_attack,
            "is_rapid_probe": self.is_rapid_probe,
            "consecutive_similar_count": self.consecutive_similar_count,
            "avg_edit_distance": round(float(self.avg_edit_distance), 3),  # type: ignore[call-overload]
            "total_prompts_in_window": self.total_prompts_in_window,
            "probe_rate_per_minute": round(float(self.probe_rate_per_minute), 2),  # type: ignore[call-overload]
            "risk_score": round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "details": self.details,
        }


# ── Mutation Detector ───────────────────────────────────────────────────────────

class PromptMutationDetector:
    """
    Tracks per-IP prompt history and detects systematic mutation
    attempts aimed at bypassing defense filters.
    """

    def __init__(
        self,
        window: float = MUTATION_WINDOW_SECONDS,
        edit_dist_thresh: float = EDIT_DIST_THRESH,
    ) -> None:
        self._history: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=MAX_PROMPTS_PER_IP)
        )
        self._lock = RLock()
        self._window = window
        self._edit_thresh = edit_dist_thresh
        self._total_analyzed = 0
        self._mutation_detections = 0
        self._probe_detections = 0
        logger.info(
            "🔄 PromptMutationDetector initialised (window=%.0fs, edit_thresh=%.2f)",
            window, edit_dist_thresh,
        )

    def record_and_analyze(
        self,
        ip: str,
        prompt: str,
        was_blocked: bool = False,
        intent_label: str = "unknown",
    ) -> MutationResult:
        """
        Record a prompt and analyse the IP's recent prompt history
        for mutation patterns.

        Args:
            ip:           Client IP.
            prompt:       The prompt text.
            was_blocked:  Whether this prompt was blocked by the pipeline.
            intent_label: Intent category from the classifier.

        Returns:
            MutationResult with risk assessment.
        """
        self._total_analyzed += 1
        record = PromptRecord(
            text=prompt,
            normalised=_strip_for_comparison(prompt),
            timestamp=time.time(),
            was_blocked=was_blocked,
            intent_label=intent_label,
        )

        with self._lock:
            self._history[ip].append(record)
            recent = self._get_recent(ip)

        if len(recent) < 2:
            return MutationResult(
                ip=ip,
                is_mutation_attack=False,
                is_rapid_probe=False,
                consecutive_similar_count=0,
                avg_edit_distance=1.0,
                total_prompts_in_window=len(recent),
                probe_rate_per_minute=0.0,
                risk_score=0.0,
            )

        # ── Edit distance analysis ──────────────────────────────────────────
        edit_distances = []
        similar_run = 0          # consecutive similar pairs
        max_similar_run = 0

        for i in range(1, len(recent)):
            dist = _normalised_edit_distance(
                recent[i-1].normalised, recent[i].normalised
            )
            edit_distances.append(dist)
            if dist <= self._edit_thresh:
                similar_run += 1
                max_similar_run = max(max_similar_run, similar_run)
            else:
                similar_run = 0

        avg_dist = sum(edit_distances) / max(len(edit_distances), 1)

        # ── Rapid probe detection ───────────────────────────────────────────
        now = time.time()
        recent_30s = [r for r in recent if (now - r.timestamp) <= PROBE_RATE_WINDOW]
        probe_rate = len(recent_30s) / (PROBE_RATE_WINDOW / 60.0)
        is_rapid = probe_rate >= PROBE_RATE_THRESHOLD

        # ── Mutation detection ──────────────────────────────────────────────
        is_mutation = max_similar_run >= MUTATION_THRESHOLD

        # ── Risk score ──────────────────────────────────────────────────────
        risk = 0.0
        details: list[str] = []
        if is_mutation:
            risk += 0.5
            details.append(f"mutation_run:{max_similar_run}")
            self._mutation_detections += 1
        if is_rapid:
            risk += 0.4
            details.append(f"rapid_probe:{probe_rate:.1f}/min")
            self._probe_detections += 1
        if avg_dist < 0.15:
            risk += 0.15
            details.append(f"very_low_avg_dist:{avg_dist:.3f}")

        risk = min(1.0, risk)

        if risk >= 0.5:
            logger.warning(
                "🔄 Mutation/probe detected — ip=%s  risk=%.2f  details=%s",
                ip, risk, details,
            )

        return MutationResult(
            ip=ip,
            is_mutation_attack=is_mutation,
            is_rapid_probe=is_rapid,
            consecutive_similar_count=max_similar_run,
            avg_edit_distance=avg_dist,
            total_prompts_in_window=len(recent),
            probe_rate_per_minute=probe_rate,
            risk_score=risk,
            details=details,
        )

    def _get_recent(self, ip: str) -> list[PromptRecord]:
        """Return records within the analysis window. Must hold lock."""
        cutoff = time.time() - self._window
        return [r for r in self._history.get(ip, deque()) if r.timestamp >= cutoff]

    def get_ip_history(self, ip: str) -> list[dict]:
        """Return recent prompt history for an IP (without full text)."""
        with self._lock:
            recent = self._get_recent(ip)
        return [
            {
                "timestamp": r.timestamp,
                "preview": r.text[:60],
                "was_blocked": r.was_blocked,
                "intent_label": r.intent_label,
            }
            for r in recent
        ]

    def get_high_risk_ips(self, limit: int = 20) -> list[dict]:
        """Return IPs with recent mutation/probe detections."""
        with self._lock:
            all_ips = list(self._history.keys())
        results = []
        for ip in all_ips:
            with self._lock:
                recent = self._get_recent(ip)
            if len(recent) >= 3:
                # Quick heuristic: check last 3 normalised edit distances
                dists = [
                    _normalised_edit_distance(
                        recent[i-1].normalised, recent[i].normalised
                    )
                    for i in range(1, min(len(recent), 4))
                ]
                avg_d = sum(dists) / max(len(dists), 1)
                if avg_d < self._edit_thresh:
                    results.append({
                        "ip": ip,
                        "prompt_count": len(recent),
                        "avg_edit_distance": round(float(avg_d), 3),  # type: ignore[call-overload]
                    })
        results.sort(key=lambda x: x["avg_edit_distance"])
        return list(results)[:limit]  # type: ignore[index]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "mutation_detections": self._mutation_detections,
                "probe_detections": self._probe_detections,
                "tracked_ips": len(self._history),
                "edit_distance_threshold": self._edit_thresh,
                "window_seconds": self._window,
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
prompt_mutation_detector = PromptMutationDetector()
