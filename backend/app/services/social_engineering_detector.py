"""
Commit 65: Social Engineering Detector
=========================================
Detects social-engineering patterns in prompts:
  - Authority impersonation  (police, IRS, bank, IT support, CEO)
  - Urgency / fear triggers  (account suspended, act now, final warning)
  - Reciprocity manipulation (I did X for you, now you owe me)
  - Pretexting scenarios     (fabricated context to justify harmful requests)
  - Vishing / smishing cues  (phone/text scam scripts)
  - Fake emergency framing   (my child is sick, I'm being followed)
  - Liking / rapport abuse   (we're old friends, I know you can help)
  - Scarcity / FOMO          (limited time, only you can do this)
"""

import logging
import re
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Pattern definitions ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SEPattern:
    pid: str
    technique: str
    pattern: str
    weight: float       # contribution to risk (0.0 – 1.0)
    description: str

    def compile(self) -> re.Pattern:
        return re.compile(self.pattern, re.IGNORECASE | re.DOTALL)


_RAW_PATTERNS: list[tuple[str, str, str, float, str]] = [
    # Authority impersonation
    ("se_001", "authority_impersonation", r"\b(i\s+am|this\s+is)\b.{0,30}\b(police|detective|officer|fbi|cia|nsa|dhs|interpol)", 0.7, "law enforcement impersonation"),
    ("se_002", "authority_impersonation", r"\b(i\s+am|this\s+is)\b.{0,30}\b(irs|hmrc|tax\s+authority|revenue\s+service)", 0.7, "tax authority impersonation"),
    ("se_003", "authority_impersonation", r"\b(i\s+am|this\s+is)\b.{0,30}\b(your\s+it|it\s+support|helpdesk|sys\s*admin|network\s+engineer)", 0.6, "IT support impersonation"),
    ("se_004", "authority_impersonation", r"\b(i\s+am|this\s+is)\b.{0,30}\b(ceo|cto|cfo|executive|director|manager)\b.{0,20}\b(of|at)\b", 0.6, "executive impersonation"),
    ("se_005", "authority_impersonation", r"\b(calling|writing|contacting)\s+on\s+behalf\s+of\b.{0,30}\b(microsoft|apple|google|amazon|paypal|bank)", 0.65, "tech company impersonation"),

    # Urgency / fear
    ("se_006", "urgency_fear", r"\b(your\s+account\s+(will\s+be|has\s+been)\s+(suspended|closed|locked|deleted|terminated))", 0.5, "account suspension threat"),
    ("se_007", "urgency_fear", r"\b(act\s+now|respond\s+immediately|urgent\s+action\s+required|immediate\s+response\s+needed)", 0.4, "urgency demand"),
    ("se_008", "urgency_fear", r"\b(final\s+warning|last\s+chance|last\s+notice|final\s+notice|overdue\s+notice)", 0.45, "final warning"),
    ("se_009", "urgency_fear", r"\b(legal\s+action|lawsuit|arrest\s+warrant|court\s+order)\b.{0,30}\b(will\s+be\s+(filed|issued|executed)|unless\s+you)", 0.6, "legal threat"),
    ("se_010", "urgency_fear", r"\b(you\s+have\s+been\s+(hacked|compromised|infected)|your\s+(computer|device|account)\s+is\s+(infected|compromised|hacked))", 0.55, "security scare"),

    # Reciprocity
    ("se_011", "reciprocity", r"\b(i\s+(helped|did|did\s+you)\b).{0,40}\b(now\s+you\s+(owe|must|should|need\s+to)|return\s+the\s+favour)", 0.4, "reciprocity trigger"),
    ("se_012", "reciprocity", r"\b(just\s+this\s+once|only\s+this\s+time)\b.{0,30}\b(help|do|tell|give|provide)", 0.35, "just this once appeal"),

    # Pretexting
    ("se_013", "pretexting", r"\b(i\s+am)\b.{0,30}\b(security\s+researcher|pen\s+tester|ethical\s+hacker|red\s+team)\b.{0,30}\b(need|require|want)\b", 0.5, "security researcher pretext"),
    ("se_014", "pretexting", r"\b(for\s+(educational|research|academic|training|testing)\s+purposes?)\b.{0,30}\b(how\s+to|explain|describe|provide)", 0.4, "educational pretext"),
    ("se_015", "pretexting", r"\b(my\s+(professor|teacher|instructor|boss|manager)\s+(asked|told|required|assigned))\b", 0.35, "authority directive pretext"),
    ("se_016", "pretexting", r"\b(writing\s+(a\s+)?(novel|book|story|screenplay|thesis|paper|article))\b.{0,30}\b(about|involving|that\s+includes?)\b", 0.3, "creative writing pretext"),
    ("se_017", "pretexting", r"\b(hypothetically|theoretically|in\s+theory|suppose|what\s+if\s+someone)\b.{0,30}\b(wanted?|tried?|needed?|had\s+to)\b.{0,30}\b(bomb|weapon|hack|exploit|poison|kill)", 0.6, "hypothetical harmful pretext"),

    # Vishing / smishing
    ("se_018", "vishing_smishing", r"\b(write|create|draft|give\s+me)\b.{0,30}\b(vishing|phone\s+scam|call\s+centre\s+scam|smishing)\b.{0,20}\b(script|template|dialogue)", 0.7, "vishing script request"),
    ("se_019", "vishing_smishing", r"\b(cold\s+call|robocall)\b.{0,30}\b(script|template)\b.{0,30}\b(fraud|scam|trick|deceive|manipulate)", 0.65, "cold call fraud script"),

    # Fake emergency
    ("se_020", "fake_emergency", r"\b(my\s+(child|daughter|son|baby|wife|husband|parent|mother|father)\s+is\s+(dying|sick|in\s+danger|being\s+held))\b", 0.4, "fake family emergency"),
    ("se_021", "fake_emergency", r"\b(i\s+am\s+being\s+(followed|stalked|threatened|blackmailed|held\s+hostage))\b", 0.45, "coercion scenario"),

    # Rapport / liking
    ("se_022", "rapport_abuse", r"\b(we\s+are\s+(old\s+)?(friends?|colleagues?|classmates?|teammates?))\b.{0,30}\b(so\s+you\s+can|therefore|that'?s\s+why)", 0.35, "false rapport"),
    ("se_023", "rapport_abuse", r"\b(you\s+(know|understand|trust)\s+me)\b.{0,30}\b(so\s+(just|please)|that'?s\s+why)", 0.35, "trust exploitation"),

    # Scarcity / FOMO
    ("se_024", "scarcity_fomo", r"\b(limited\s+time\s+(offer|only)|only\s+\d+\s+(spots?|seats?|left)|expires?\s+in\s+\d+\s+(hours?|minutes?))\b", 0.3, "scarcity trigger"),
    ("se_025", "scarcity_fomo", r"\b(only\s+you\s+can|you'?re\s+the\s+only\s+one\s+(who\s+)?can)\b", 0.35, "uniqueness flattery"),

    # Quid pro quo
    ("se_026", "quid_pro_quo", r"\b(i\s+will\s+(pay|give|reward|compensate)\s+you)\b.{0,30}\b(if\s+you|in\s+exchange|in\s+return)\b", 0.5, "payment incentive"),
    ("se_027", "quid_pro_quo", r"\b(in\s+exchange\s+for|in\s+return\s+for)\b.{0,30}\b(help|information|access|details?|secrets?)", 0.5, "quid pro quo"),

    # Tailgating / baiting cues (text form)
    ("se_028", "baiting", r"\b(open|click|download|run|execute)\b.{0,30}\b(this\s+link|this\s+file|the\s+attachment|the\s+(exe|pdf|zip|document))\b.{0,20}\b(to\s+(verify|confirm|update|unlock|claim))", 0.6, "baiting click/download"),
    ("se_029", "baiting", r"\b(you'?ve\s+(won|been\s+selected|been\s+chosen))\b.{0,30}\b(prize|reward|gift\s+card|voucher|lottery)", 0.5, "prize baiting"),
    ("se_030", "baiting", r"\b(free\s+(gift|money|bitcoin|crypto|iphone|macbook))\b.{0,20}\b(claim|get|receive|download|click)", 0.5, "free gift baiting"),
]

# Compile all patterns
_COMPILED: list[tuple[SEPattern, re.Pattern]] = []
for _args in _RAW_PATTERNS:
    _sp = SEPattern(*_args)
    try:
        _cp = re.compile(_sp.pattern, re.IGNORECASE | re.DOTALL)
        _COMPILED.append((_sp, _cp))
    except re.error:
        pass


# ── Result ─────────────────────────────────────────────────────────────────────

@dataclass
class SEMatch:
    pid: str
    technique: str
    weight: float
    description: str


@dataclass
class SEResult:
    matches: list[SEMatch]
    techniques_triggered: list[str]
    risk_score: float
    is_social_engineering: bool
    dominant_technique: Optional[str]
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_social_engineering": self.is_social_engineering,
            "risk_score": round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "techniques_triggered": self.techniques_triggered,
            "dominant_technique": self.dominant_technique,
            "match_count": len(self.matches),
            "details": self.details,
        }


# ── Detector ───────────────────────────────────────────────────────────────────

class SocialEngineeringDetector:
    """
    Detects social engineering patterns in user prompts.
    Uses 30 patterns across 8 technique categories.
    """

    RISK_THRESHOLD = 0.35

    def __init__(self) -> None:
        self._lock = RLock()
        self._total_analyzed = 0
        self._se_detected = 0
        self._technique_counts: dict[str, int] = {}
        logger.info("🎭 SocialEngineeringDetector ready — %d patterns loaded", len(_COMPILED))

    def analyze(self, text: str) -> SEResult:
        with self._lock:
            self._total_analyzed += 1

        matches: list[SEMatch] = []
        for sp, cp in _COMPILED:
            if cp.search(text):
                matches.append(SEMatch(
                    pid=sp.pid,
                    technique=sp.technique,
                    weight=sp.weight,
                    description=sp.description,
                ))

        techniques = list({m.technique for m in matches})
        risk: float = 0.0
        for m in matches:
            risk = float(risk + m.weight)  # type: ignore[operator]
        # Bonus for multiple distinct techniques
        if len(techniques) > 1:
            risk = float(risk + 0.1 * (len(techniques) - 1))  # type: ignore[operator]
        risk = min(1.0, risk)

        is_se = risk >= self.RISK_THRESHOLD

        dominant: Optional[str] = None
        if matches:
            # Most common technique
            tech_weight: dict[str, float] = {}
            for m in matches:
                tech_weight[m.technique] = float(tech_weight.get(m.technique, 0.0) + m.weight)  # type: ignore[operator]
            dominant = max(tech_weight, key=lambda k: tech_weight[k])

        details = [f"{m.pid}:{m.description}" for m in matches]

        with self._lock:
            if is_se:
                self._se_detected += 1
            for t in techniques:
                self._technique_counts[t] = self._technique_counts.get(t, 0) + 1

        if is_se:
            logger.warning("🎭 Social engineering detected — risk=%.2f techniques=%s", risk, techniques)

        return SEResult(
            matches=matches,
            techniques_triggered=techniques,
            risk_score=risk,
            is_social_engineering=is_se,
            dominant_technique=dominant,
            details=details,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "se_detected": self._se_detected,
                "pattern_count": len(_COMPILED),
                "technique_counts": dict(self._technique_counts),
            }


social_engineering_detector = SocialEngineeringDetector()
