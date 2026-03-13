"""
Commit 64: Obfuscation Detector
==================================
Detects text obfuscation techniques attackers use to bypass keyword filters:
  - Leet-speak / 1337sp34k  (e->3, a->@, i->1 ...)
  - Unicode homoglyphs       (Cyrillic looks like Latin)
  - Zero-width characters    (invisible chars between letters)
  - Mixed-script text        (Latin + Cyrillic in the same word)
  - Case alternation         (iGnOrE AlL)
  - Spaced-out text          (i g n o r e   a l l)
  - ROT13 encoding
  - Reversed text
  - HTML entity encoding     (&#x69;&#x67;...)
"""

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from threading import RLock

logger = logging.getLogger(__name__)

_LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "2": "z", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "+": "t", "|": "i",
}

_HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "ν": "v", "ε": "e", "ο": "o", "α": "a", "τ": "t",
    "\u0456": "i", "\u0455": "s", "\u0441": "c", "\u0445": "x",
    "\uff41": "a", "\uff45": "e", "\uff49": "i", "\uff4f": "o",
}

_ZERO_WIDTH = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\ufeff\u2060]"
)
_HTML_ENTITY = re.compile(r"&#x([0-9a-fA-F]+);|&#(\d+);")
_SPACED_PATTERN = re.compile(r"(?:(\w)\s){3,}(\w)")

_THREAT_SEEDS: list[str] = [
    "ignore", "bypass", "override", "jailbreak", "disable", "malware",
    "ransomware", "exploit", "synthesize", "weapon", "explosive",
    "suicide", "csam", "bomb", "phishing", "credential", "dox",
    "exfiltrate", "drug synthesis", "hitman", "rootkit", "backdoor",
    "keylogger", "ddos", "sql injection", "prompt injection",
]
_THREAT_RE: list[re.Pattern] = [
    re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
    for kw in _THREAT_SEEDS
]


@dataclass
class ObfuscationResult:
    normalised_text: str
    techniques_detected: list[str]
    threat_keywords_found: list[str]
    is_obfuscated: bool
    risk_score: float
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_obfuscated": self.is_obfuscated,
            "techniques_detected": self.techniques_detected,
            "threat_keywords_found": self.threat_keywords_found,
            "risk_score": round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "details": self.details,
        }


def _strip_zero_width(text: str) -> tuple[str, bool]:
    cleaned = _ZERO_WIDTH.sub("", text)
    return cleaned, cleaned != text


def _decode_html_entities(text: str) -> tuple[str, bool]:
    def _r(m: re.Match) -> str:
        h, d = m.group(1), m.group(2)
        return chr(int(h, 16)) if h else chr(int(d)) if d else m.group(0)
    cleaned = _HTML_ENTITY.sub(_r, text)
    return cleaned, cleaned != text


def _normalise_homoglyphs(text: str) -> tuple[str, bool]:
    result, changed = [], False
    for ch in text:
        mapped = _HOMOGLYPH_MAP.get(ch)
        if mapped:
            result.append(mapped)
            changed = True
        else:
            result.append(ch)
    return "".join(result), changed


def _normalise_leet(text: str) -> tuple[str, bool]:
    result, changed = [], False
    for ch in text:
        mapped = _LEET_MAP.get(ch)
        if mapped:
            result.append(mapped)
            changed = True
        else:
            result.append(ch)
    return "".join(result), changed


def _collapse_spaced(text: str) -> tuple[str, bool]:
    collapsed = _SPACED_PATTERN.sub(
        lambda m: "".join(filter(None, m.groups())), text
    )
    return collapsed, collapsed != text


def _detect_case_alternation(text: str) -> bool:
    words = text.split()
    alt_count = 0
    for word in words:
        if len(word) < 4:
            continue
        transitions = sum(
            1 for i in range(1, len(word))
            if word[i].isupper() != word[i - 1].isupper()
        )
        if transitions >= len(word) // 2:
            alt_count += 1
    return alt_count >= 2


def _detect_mixed_script(text: str) -> bool:
    for word in re.split(r"\s+", text):
        scripts: set[str] = set()
        for ch in word:
            if ch.isalpha():
                n = unicodedata.name(ch, "")
                if "LATIN" in n:
                    scripts.add("LATIN")
                elif "CYRILLIC" in n:
                    scripts.add("CYRILLIC")
                elif "GREEK" in n:
                    scripts.add("GREEK")
        if len(scripts) > 1:
            return True
    return False


def _rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def _scan_threats(text: str) -> list[str]:
    return [_THREAT_SEEDS[i] for i, p in enumerate(_THREAT_RE) if p.search(text)]


class ObfuscationDetector:
    """Detects and normalises obfuscated attack prompts."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._total_analyzed = 0
        self._obfuscation_detected = 0
        self._threats_via_obfuscation = 0
        logger.info(
            "🔍 ObfuscationDetector ready — %d threat seeds, %d homoglyphs",
            len(_THREAT_SEEDS), len(_HOMOGLYPH_MAP),
        )

    def analyze(self, text: str) -> ObfuscationResult:
        with self._lock:
            self._total_analyzed += 1

        techniques: list[str] = []
        normalised = text

        normalised, changed = _strip_zero_width(normalised)
        if changed:
            techniques.append("zero_width_chars")

        normalised, changed = _decode_html_entities(normalised)
        if changed:
            techniques.append("html_entity_encoding")

        normalised, changed = _normalise_homoglyphs(normalised)
        if changed:
            techniques.append("unicode_homoglyphs")

        normalised, changed = _collapse_spaced(normalised)
        if changed:
            techniques.append("spaced_out_text")

        normalised, changed = _normalise_leet(normalised)
        if changed:
            techniques.append("leet_speak")

        if _detect_case_alternation(normalised):
            techniques.append("case_alternation")

        if _detect_mixed_script(text):
            techniques.append("mixed_script")

        rot13_text = _rot13(text)
        if _scan_threats(rot13_text):
            techniques.append("rot13_encoding")
            normalised = normalised + " " + rot13_text

        reversed_words = " ".join(w[::-1] for w in text.split())  # type: ignore[index]
        if _scan_threats(reversed_words):
            techniques.append("reversed_text")
            normalised = normalised + " " + reversed_words

        threats = _scan_threats(normalised)
        is_obfuscated = len(techniques) > 0
        has_threats = len(threats) > 0

        risk: float = 0.0
        details: list[str] = []
        if is_obfuscated:
            risk = float(risk + 0.15 * len(techniques))  # type: ignore[operator]
            details.append(f"techniques:{','.join(techniques)}")
        if has_threats:
            risk = float(risk + 0.4)  # type: ignore[operator]
            details.extend([f"threat:{t}" for t in threats[:5]])  # type: ignore[index]
        if len(techniques) >= 2 and has_threats:
            risk = float(risk + 0.2)  # type: ignore[operator]
            details.append("layered_obfuscation")
        risk = min(1.0, risk)

        with self._lock:
            if is_obfuscated:
                self._obfuscation_detected += 1
            if has_threats and is_obfuscated:
                self._threats_via_obfuscation += 1

        if risk >= 0.5:
            logger.warning("🔍 Obfuscated threat — techniques=%s threats=%s", techniques, threats)

        return ObfuscationResult(
            normalised_text=normalised[:300],
            techniques_detected=techniques,
            threat_keywords_found=threats,
            is_obfuscated=is_obfuscated,
            risk_score=risk,
            details=details,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "obfuscation_detected": self._obfuscation_detected,
                "threats_via_obfuscation": self._threats_via_obfuscation,
                "leet_map_size": len(_LEET_MAP),
                "homoglyph_map_size": len(_HOMOGLYPH_MAP),
            }


obfuscation_detector = ObfuscationDetector()
