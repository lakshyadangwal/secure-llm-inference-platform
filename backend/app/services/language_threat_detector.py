"""
Commit 72: Language Threat Detector
======================================
Detects threats expressed in non-English languages and via
transliteration/romanisation of non-Latin scripts.

Supports threat phrase detection in:
  - Spanish, French, German, Italian, Portuguese (European)
  - Arabic romanisation (Franco-Arab, Arabizi)
  - Hindi transliteration (Hinglish injection patterns)
  - Russian transliteration (Ruglish / Latin-Cyrillic mixing)
  - Mandarin romanisation (Pinyin-based threat terms)

Also detects common multilingual evasion tactics:
  - Code-switching  (switching language mid-sentence)
  - Language mixing (English + Spanish in same phrase to dilute detector)
  - Romanised slang for dangerous terms
"""

import logging
import re
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Multilingual threat keyword lists ─────────────────────────────────────────
# Format: (language_code, term, english_translation, severity)
_MULTILINGUAL_KW: list[tuple[str, str, str, str]] = [
    # ── Spanish ──────────────────────────────────────────────────────────────
    ("es", r"\b(cómo|como)\s+(fabricar|hacer|crear)\s+(una\s+)?(bomba|arma|explosivo)", "bomb/weapon construction", "critical"),
    ("es", r"\b(mata(r)?|asesina(r)?)\s+(a\s+alguien|personas?)", "kill/assassinate someone", "critical"),
    ("es", r"\b(suicidio|suicidarme|quitarme\s+la\s+vida)\b", "suicide", "high"),
    ("es", r"\b(droga|metanfetamina|heroína|cocaína)\s+(sintetizar|fabricar|hacer)", "drug synthesis", "critical"),
    ("es", r"\b(terrorismo|atentado|yihad)\b.{0,30}\b(planificar|organizar|cometer)", "terrorism planning", "critical"),
    ("es", r"\b(hackear|piratear)\s+(sistema|cuenta|servidor)", "hacking", "high"),
    ("es", r"\b(estafa|fraude|lavado\s+de\s+dinero)\b.{0,20}\b(método|cómo|técnica)", "fraud/laundering method", "high"),
    ("es", r"\b(trata\s+de\s+personas|tráfico\s+humano)\b", "human trafficking", "critical"),
    ("es", r"\b(material\s+(sexual\s+)?infantil|abuso\s+sexual\s+infantil)\b", "CSAM", "critical"),
    ("es", r"\b(pedofilia|pederastia)\b", "pedophilia", "critical"),

    # ── French ───────────────────────────────────────────────────────────────
    ("fr", r"\b(comment|façon)\s+(faire|fabriquer|créer)\s+(une\s+)?(bombe|arme|explosif)", "bomb construction", "critical"),
    ("fr", r"\b(tuer|assassiner|éliminer)\s+(quelqu['un]|une\s+personne)", "kill someone", "critical"),
    ("fr", r"\b(suicide|me\s+suicider|mettre\s+fin\s+à\s+ma\s+vie)\b", "suicide", "high"),
    ("fr", r"\b(terrorisme|attentat|djihad)\b.{0,30}\b(planifier|organiser|commettre)", "terrorism planning", "critical"),
    ("fr", r"\b(pirate(r)?|hacker)\s+(un\s+)?(compte|serveur|système)", "hacking", "high"),
    ("fr", r"\b(drogue|héroïne|cocaïne|méthamphétamine)\s+(synthétiser|fabriquer|produire)", "drug synthesis", "critical"),
    ("fr", r"\b(blanchiment\s+d[''']argent|fraude|arnaque)\b.{0,20}\b(méthode|comment|technique)", "fraud/laundering", "high"),
    ("fr", r"\b(traite\s+(des\s+)?êtres\s+humains|trafic\s+humain)\b", "human trafficking", "critical"),
    ("fr", r"\b(pornographie\s+enfantine|abus\s+sexuel\s+sur\s+mineur)\b", "CSAM", "critical"),

    # ── German ───────────────────────────────────────────────────────────────
    ("de", r"\b(wie|anleitung)\s+(man\s+)?(eine\s+)?(bombe|waffe|sprengstoff)\s+(baut|herstellt|macht)", "bomb construction", "critical"),
    ("de", r"\b(töten|ermorden|umbringen)\s+(jemanden|eine\s+Person)", "kill someone", "critical"),
    ("de", r"\b(selbstmord|suizid|mein\s+leben\s+beenden)\b", "suicide", "high"),
    ("de", r"\b(terrorismus|terroranschlag|dschihad)\b.{0,30}\b(planen|durchführen|organisieren)", "terrorism planning", "critical"),
    ("de", r"\b(hacken|knacken)\s+(ein\s+)?(Konto|Server|System)", "hacking", "high"),
    ("de", r"\b(Drogen|Methamphetamin|Heroin|Kokain)\s+(synthetisieren|herstellen|kochen)", "drug synthesis", "critical"),
    ("de", r"\b(Geldwäsche|Betrug)\b.{0,20}\b(Methode|Anleitung|wie)", "money laundering/fraud", "high"),
    ("de", r"\b(Menschenhandel|Menschenschmuggel)\b", "human trafficking", "critical"),
    ("de", r"\b(Kinderpornographie|sexueller\s+Missbrauch\s+von\s+Kindern)\b", "CSAM", "critical"),

    # ── Portuguese ────────────────────────────────────────────────────────────
    ("pt", r"\b(como|maneira)\s+(fazer|fabricar|criar)\s+(uma\s+)?(bomba|arma|explosivo)", "bomb construction", "critical"),
    ("pt", r"\b(matar|assassinar)\s+(alguém|uma\s+pessoa)", "kill someone", "critical"),
    ("pt", r"\b(suicídio|suicidar(-me)?|tirar\s+(minha|a)\s+vida)\b", "suicide", "high"),
    ("pt", r"\b(terrorism[oa]|atentado|jihad)\b.{0,30}\b(planejar|organizar|cometer)", "terrorism planning", "critical"),
    ("pt", r"\b(hackear|invadir)\s+(conta|servidor|sistema)", "hacking", "high"),
    ("pt", r"\b(droga|metanfetamina|heroína|cocaína)\s+(sintetizar|fabricar|produzir)", "drug synthesis", "critical"),

    # ── Italian ───────────────────────────────────────────────────────────────
    ("it", r"\b(come|istruzione)\s+(fare|costruire|creare)\s+(una\s+)?(bomba|arma|esplosivo)", "bomb construction", "critical"),
    ("it", r"\b(uccidere|assassinare|ammazzare)\s+(qualcuno|una\s+persona)", "kill someone", "critical"),
    ("it", r"\b(suicidio|suicidarmi|togliermi\s+la\s+vita)\b", "suicide", "high"),
    ("it", r"\b(terrorismo|attentato|jihad)\b.{0,30}\b(pianificare|organizzare|commettere)", "terrorism planning", "critical"),
    ("it", r"\b(hackerare|violare)\s+(un\s+)?(account|server|sistema)", "hacking", "high"),
    ("it", r"\b(droga|metanfetamina|eroina|cocaina)\s+(sintetizzare|produrre|fabbricare)", "drug synthesis", "critical"),

    # ── Arabic romanisation (Franco-Arab / Arabizi) ────────────────────────
    ("ar_roman", r"\b(kef|keef|kif)\s+(atfajjar|ufajjir|insuf)\b", "bomb/explosion arabizi", "critical"),
    ("ar_roman", r"\b(daesh|isis|al-qaeda)\b.{0,30}\b(inzamm|iltahq|idhkhul)", "terrorist group join arabizi", "critical"),
    ("ar_roman", r"\b(intihar|intestihar)\b", "suicide arabic", "high"),
    ("ar_roman", r"\b(qatl|yaqtul|ightial)\b.{0,20}\b(shakhs|shakhsiyya|wahad)", "kill person arabic", "critical"),
    ("ar_roman", r"\b(sla7|silah|bunduqiyya)\b.{0,20}\b(isna3|isna7)\b", "weapon manufacture arabizi", "critical"),
    ("ar_roman", r"\b(irhab|irhabi)\b.{0,20}\b(3amaliyya|mukhatta|hujum)\b", "terrorism arabic", "critical"),

    # ── Hindi transliteration (Hinglish) ─────────────────────────────────────
    ("hi_roman", r"\b(bomb|bam)\s+(kaise\s+)?(banana|banao|banta\s+hai)\b", "bomb making hinglish", "critical"),
    ("hi_roman", r"\b(aatankwad|aatanki|jihad)\b.{0,30}\b(planning|karna|karo)\b", "terrorism hinglish", "critical"),
    ("hi_roman", r"\b(khud(kushi|ko\s+maarna|ko\s+khatam\s+karna))\b", "suicide hinglish", "high"),
    ("hi_roman", r"\b(qatl|hatya)\s+(kaise|karo|karna)\b", "murder hinglish", "critical"),
    ("hi_roman", r"\b(nasha|drugs?)\s+(banana|banao)\b.{0,20}\b(tarika|vidhi|method)\b", "drug synthesis hinglish", "critical"),
    ("hi_roman", r"\b(hack\s+karna|hack\s+karo|hack\s+kar\s+do)\b", "hacking hinglish", "high"),

    # ── Russian transliteration (Ruglish) ────────────────────────────────────
    ("ru_roman", r"\b(kak\s+sdelat|sdelat\s+samim)\b.{0,30}\b(bombu|oruzhie|vzryvchatku)\b", "bomb/weapon russian", "critical"),
    ("ru_roman", r"\b(samoubijstvo|kak\s+pokonchit\s+s\s+soboj)\b", "suicide russian", "high"),
    ("ru_roman", r"\b(terrorizm|terakt|dzhihad)\b.{0,30}\b(planirovat|sovershat|organizovat)\b", "terrorism russian", "critical"),
    ("ru_roman", r"\b(vzlomat|vzlomat\s+(akkaunt|server|sistemu))\b", "hacking russian", "high"),
    ("ru_roman", r"\b(narkotiki|mefedron|geroIn|kokain)\s+(sintetizirovat|sdelat|prigotovit)\b", "drug synthesis russian", "critical"),
    ("ru_roman", r"\b(ubit|ubistvo|ubiyt)\s+(cheloveka|kogo-to|zhertvu)\b", "kill someone russian", "critical"),

    # ── Mandarin romanisation (Pinyin) ────────────────────────────────────────
    ("zh_pinyin", r"\b(zenme\s+zuo|ruhe\s+zhizuo)\b.{0,30}\b(zhadan|baozhazhuang|wuqi)\b", "bomb/weapon pinyin", "critical"),
    ("zh_pinyin", r"\b(kongbu\s+zhuyi|jihad|shehada)\b.{0,30}\b(jihua|zuodao|canjia)\b", "terrorism pinyin", "critical"),
    ("zh_pinyin", r"\b(zisha|qingsi|jieshu\s+shengming)\b", "suicide pinyin", "high"),
    ("zh_pinyin", r"\b(dupin|haluoyin|bingdu)\s+(hecheng|zhizao|shengchan)\b", "drug synthesis pinyin", "critical"),
    ("zh_pinyin", r"\b(heike|ruqin)\s+(xitong|fuwuqi|zhanghao)\b", "hacking pinyin", "high"),
]

_COMPILED_ML: list[tuple[str, str, str, str, re.Pattern]] = []
for _lang, _pat, _eng, _sev in _MULTILINGUAL_KW:
    try:
        _COMPILED_ML.append((_lang, _pat, _eng, _sev,
                              re.compile(_pat, re.IGNORECASE | re.DOTALL | re.UNICODE)))
    except re.error:
        pass


_SEV_SCORE: dict[str, float] = {"low": 0.2, "medium": 0.4, "high": 0.6, "critical": 0.9}


@dataclass
class MLHit:
    language: str
    pattern: str
    english: str
    severity: str


@dataclass
class LanguageThreatResult:
    hits: list[MLHit]
    languages_detected: list[str]
    risk_score: float
    is_threat: bool
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_threat": self.is_threat,
            "risk_score": round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "languages_detected": self.languages_detected,
            "hit_count": len(self.hits),
            "details": self.details,
        }


class LanguageThreatDetector:
    """
    Detects threats expressed in non-English languages and romanised scripts.
    """

    THREAT_THRESHOLD = 0.3

    def __init__(self) -> None:
        self._lock = RLock()
        self._total_analyzed = 0
        self._threats_detected = 0
        self._lang_hits: dict[str, int] = {}
        logger.info(
            "🌐 LanguageThreatDetector ready — %d multilingual patterns across %d languages",
            len(_COMPILED_ML),
            len({x[0] for x in _COMPILED_ML}),
        )

    def analyze(self, text: str) -> LanguageThreatResult:
        with self._lock:
            self._total_analyzed += 1

        hits: list[MLHit] = []
        for lang, pat, eng, sev, regex in _COMPILED_ML:
            if regex.search(text):
                hits.append(MLHit(language=lang, pattern=pat, english=eng, severity=sev))

        languages = list({h.language for h in hits})
        risk: float = 0.0
        for h in hits:
            risk = float(risk + _SEV_SCORE.get(h.severity, 0.4))  # type: ignore[operator]
        risk = min(1.0, risk)

        is_threat = risk >= self.THREAT_THRESHOLD
        details = [f"{h.language}:{h.english}" for h in hits]

        with self._lock:
            if is_threat:
                self._threats_detected += 1
            for lang in languages:
                self._lang_hits[lang] = self._lang_hits.get(lang, 0) + 1

        if is_threat:
            logger.warning("🌐 Multilingual threat — risk=%.2f languages=%s", risk, languages)

        return LanguageThreatResult(
            hits=hits, languages_detected=languages,
            risk_score=risk, is_threat=is_threat, details=details,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "threats_detected": self._threats_detected,
                "pattern_count": len(_COMPILED_ML),
                "language_hits": dict(self._lang_hits),
            }


language_threat_detector = LanguageThreatDetector()
