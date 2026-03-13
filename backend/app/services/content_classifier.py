"""
Commit 78: Content Classifier
================================
Rule-based multi-label content classifier that assigns content
into one or more of 12 harm categories without needing ML models.

Works by:
  1. Scoring a set of feature signals (regex hits, keyword density,
     sentence structure indicators) per category
  2. Applying calibrated thresholds to decide presence/absence of each label
  3. Returning a confidence score per label plus overall harmfulness

Categories:
  violence          — threats, descriptions of violence
  hate_speech       — targeted hatred based on identity
  sexual            — explicit sexual content
  child_safety      — anything involving minors + sexual context
  self_harm         — suicide, self-injury
  dangerous_info    — instructions for weapons, drugs, hacking
  jailbreak         — prompt injection / instruction override
  spam              — repetitive, low-quality, promotional
  misinformation    — conspiracy theories, health misinformation
  privacy           — PII requests, doxxing
  fraud             — scam, phishing, financial fraud cues
  extremism         — radicalisation, terrorism, genocide
"""

import logging
import math
import re
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CategorySignal:
    name: str
    patterns: list[re.Pattern]
    keyword_density_threshold: float  # min fraction of words that must be category-related
    presence_threshold: float          # min weighted match count to label positive


_CATEGORIES_RAW: list[tuple[str, list[str], float, float]] = [
    ("violence", [
        r"\b(kill|murder|stab|shoot|beat\s+up|attack|assault|torture|decapitate|behead|strangle)\b",
        r"\b(threaten|death\s+threat|you\s+will\s+die|gonna\s+kill)\b",
        r"\b(blood|gore|severed|corpse|body\s+parts|massacre)\b",
        r"\b(gun\s+violence|knife\s+attack|mob\s+violence|lynching)\b",
    ], 0.02, 1.5),

    ("hate_speech", [
        r"\b(hate|despise|inferior|subhuman|vermin|parasite)\b.{0,30}\b(race|religion|gender|sexuality|nationality|ethnicity)\b",
        r"\b(white\s+supremac|neo.nazi|racial\s+purity|ethnic\s+cleansing|master\s+race)\b",
        r"\b(all\s+(muslims?|jews?|christians?|blacks?|whites?|gays?|women|men)\s+(should|must|deserve\s+to)\b)",
        r"\b(slur)\b|\b(go\s+back\s+to\s+your\s+country|you\s+don.t\s+belong\s+here)\b",
    ], 0.025, 1.5),

    ("sexual", [
        r"\b(explicit\s+sexual|pornographic|erotic|nude|naked)\b",
        r"\b(sex\s+scene|sexual\s+act|intercourse|genitalia)\b",
        r"\b(onlyfans|escort|prostitut|cam\s+girl|adult\s+content)\b",
        r"\b(fetish|kink|bdsm)\b.{0,30}\b(detailed|describe|write|generate)\b",
    ], 0.03, 1.5),

    ("child_safety", [
        r"\b(minor|child|underage|teen|kid)\b.{0,30}\b(explicit|sexual|nude|naked|naked\s+image)\b",
        r"\bCSAM\b|\bchild\s+pornography\b|\bchild\s+sexual\s+abuse\b",
        r"\b(groom|grooming)\b.{0,30}\b(child|minor|kid|teen)\b",
        r"\b(age\s+of\s+consent)\b.{0,20}\b(loophole|bypass|different\s+country)\b",
    ], 0.01, 1.0),

    ("self_harm", [
        r"\b(suicide|suicidal|kill\s+myself|end\s+my\s+life)\b",
        r"\b(self.harm|self.injur|cutting|wrist\s+cut)\b",
        r"\b(overdose\s+on|lethal\s+dose\s+of|how\s+much\s+to\s+take\s+to\s+die)\b",
        r"\b(want\s+to\s+die|don.t\s+want\s+to\s+live|no\s+reason\s+to\s+live)\b",
    ], 0.03, 1.0),

    ("dangerous_info", [
        r"\b(synthesize|make|manufacture)\b.{0,30}\b(meth|heroin|fentanyl|cocaine|sarin|explosiv?e)\b",
        r"\b(step.by.step|instructions?|recipe|guide|tutorial)\b.{0,30}\b(bomb|weapon|drug|poison|malware)\b",
        r"\b(build|create|write|code)\b.{0,30}\b(ransomware|rootkit|backdoor|keylogger)\b",
        r"\b(how\s+to\s+make\s+a|how\s+do\s+i\s+make\s+a)\b.{0,20}\b(bomb|gun|knife|drug|poison)\b",
    ], 0.02, 1.5),

    ("jailbreak", [
        r"\b(ignore|bypass|forget|override)\b.{0,20}\b(instructions?|guidelines?|rules?|restrictions?)\b",
        r"\b(DAN|jailbreak|developer\s+mode|god\s+mode)\b",
        r"\b(no\s+restrictions?|unrestricted\s+mode|uncensored)\b",
        r"\b(act\s+as|pretend\s+to\s+be)\b.{0,30}\b(evil|unlimited|no\s+rules?)\b",
    ], 0.03, 1.5),

    ("spam", [
        r"\b(click\s+here|visit\s+now|limited\s+offer|buy\s+now|act\s+fast)\b",
        r"(https?://\S+\s+){3,}",  # multiple links
        r"\b(free\s+money|you\s+have\s+won|congratulations\s+winner|claim\s+your\s+prize)\b",
        r"(\w+\s+){0,5}(call\s+now|reply\s+now|respond\s+now)\s*(to\s+claim|for\s+details|immediately)",
    ], 0.04, 1.0),

    ("misinformation", [
        r"\b(5G\s+(causes?\s+)?COVID|vaccines?\s+cause\s+autism|flat\s+earth|earth\s+is\s+flat)\b",
        r"\b(chemtrails?|lizard\s+people|deep\s+state\s+controls?\s+(the\s+)?world|new\s+world\s+order\s+agenda)\b",
        r"\b(bleach\s+cures?\s+COVID|drinking\s+urine\s+cures?|miracle\s+cure\s+big\s+pharma)\b",
        r"\b(election\s+(was\s+)?stolen|voting\s+machines?\s+(were\s+)?rigged|fake\s+election\s+results?\b)",
    ], 0.02, 1.0),

    ("privacy", [
        r"\b(find\s+(the\s+)?(home\s+address|location|phone\s+number)\s+of)\b",
        r"\b(dox|doxx|expose\s+personal\s+information\s+about)\b",
        r"\b(track\s+(someone|them|him|her)\s+without\s+(their\s+)?(consent|knowing|permission))\b",
        r"\b(spy\s+on|monitor\s+without\s+consent|stalk)\b",
    ], 0.02, 1.0),

    ("fraud", [
        r"\b(phishing|smishing|vishing)\b.{0,20}\b(email|message|script|template|create)\b",
        r"\b(scam|con)\b.{0,20}\b(elderly|victim|target|run|operate)\b",
        r"\b(money\s+laundering|advance\s+fee|419\s+fraud|ponzi|pyramid\s+scheme)\b",
        r"\b(fake\s+(invoice|check|payment\s+receipt|charity)\b)",
    ], 0.02, 1.0),

    ("extremism", [
        r"\b(terrorist|terrorism|jihad|jihadist)\b.{0,30}\b(recruit|plan|attack|finance|support)\b",
        r"\b(genocide|ethnic\s+cleansing|mass\s+murder)\b.{0,20}\b(plan|advocate|celebrate)\b",
        r"\b(radicalise|radicalize)\b.{0,20}\b(youth|people|followers|members)\b",
        r"\b(martyr|martyrdom)\b.{0,20}\b(operation|attack|bombing|mission)\b",
    ], 0.02, 1.5),
]

# Compile patterns
_CATEGORIES: list[CategorySignal] = []
for _name, _pats, _kdt, _pt in _CATEGORIES_RAW:
    compiled = []
    for p in _pats:
        try:
            compiled.append(re.compile(p, re.IGNORECASE | re.DOTALL))
        except re.error:
            pass
    _CATEGORIES.append(CategorySignal(
        name=_name,
        patterns=compiled,
        keyword_density_threshold=_kdt,
        presence_threshold=_pt,
    ))


@dataclass
class CategoryScore:
    name: str
    present: bool
    confidence: float    # 0.0 – 1.0
    match_count: int


@dataclass
class ClassificationResult:
    labels: list[str]                # positive categories
    category_scores: list[CategoryScore]
    overall_harmful: bool
    overall_harm_score: float
    dominant_category: Optional[str]
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "labels": self.labels,
            "overall_harmful": self.overall_harmful,
            "overall_harm_score": round(float(self.overall_harm_score), 3),  # type: ignore[call-overload]
            "dominant_category": self.dominant_category,
            "category_scores": [
                {"name": cs.name, "present": cs.present, "confidence": round(float(cs.confidence), 3)}  # type: ignore[call-overload]
                for cs in self.category_scores
            ],
        }


class ContentClassifier:
    """Rule-based multi-label content classifier for 12 harm categories."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._total_classified = 0
        self._harmful_count = 0
        self._label_counts: dict[str, int] = {}
        logger.info("🏷️  ContentClassifier ready — %d categories", len(_CATEGORIES))

    def classify(self, text: str) -> ClassificationResult:
        with self._lock:
            self._total_classified += 1

        word_count = max(1, len(text.split()))
        scores: list[CategoryScore] = []
        labels: list[str] = []
        harm_score: float = 0.0

        for cat in _CATEGORIES:
            hits = sum(1 for p in cat.patterns if p.search(text))
            raw = float(hits) / max(1.0, float(len(cat.patterns)))
            # Confidence = hits normalised + density component
            word_hit_count = sum(len(p.findall(text)) for p in cat.patterns)
            density = float(word_hit_count) / float(word_count)
            confidence = min(1.0, float(raw * 0.6 + min(1.0, density / cat.keyword_density_threshold) * 0.4))
            present = float(hits) >= cat.presence_threshold

            scores.append(CategoryScore(
                name=cat.name,
                present=present,
                confidence=confidence,
                match_count=hits,
            ))
            if present:
                labels.append(cat.name)
                harm_score = float(harm_score + confidence)  # type: ignore[operator]

        harm_score = min(1.0, harm_score / max(1, len(_CATEGORIES)))
        overall_harmful = len(labels) > 0

        dominant: Optional[str] = None
        if scores:
            best = max(scores, key=lambda s: s.confidence)
            if best.confidence > 0.1:
                dominant = best.name

        details = [f"{cs.name}:{cs.match_count}" for cs in scores if cs.match_count > 0]

        with self._lock:
            if overall_harmful:
                self._harmful_count += 1
            for lbl in labels:
                self._label_counts[lbl] = self._label_counts.get(lbl, 0) + 1

        return ClassificationResult(
            labels=labels,
            category_scores=scores,
            overall_harmful=overall_harmful,
            overall_harm_score=harm_score,
            dominant_category=dominant,
            details=details,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_classified": self._total_classified,
                "harmful_count": self._harmful_count,
                "category_count": len(_CATEGORIES),
                "label_counts": dict(self._label_counts),
            }


content_classifier = ContentClassifier()
