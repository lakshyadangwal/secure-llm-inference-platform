"""
Advanced Threat Intelligence Engine
Comprehensive threat analysis, pattern matching, correlation engine,
and real-time threat scoring for the Neuro-Sentry Defense Platform.

This module provides:
- Multi-source threat intelligence aggregation
- Advanced pattern correlation with ML-like scoring
- Real-time threat feed processing
- IOC (Indicators of Compromise) management
- Threat actor profiling
- MITRE ATT&CK framework mapping
"""

import hashlib
import json
import re
import time
import math
import uuid
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Set, Any
from enum import Enum

logger = logging.getLogger(__name__)


# ===========================================================================
# Enums & Constants
# ===========================================================================

class ThreatSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ThreatCategory(Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    SOCIAL_ENGINEERING = "social_engineering"
    MODEL_MANIPULATION = "model_manipulation"
    ADVERSARIAL_INPUT = "adversarial_input"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    RECONNAISSANCE = "reconnaissance"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_THEFT = "credential_theft"
    MALWARE_GENERATION = "malware_generation"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    EVASION = "evasion"


class IOCType(Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    PATTERN = "pattern"
    USER_AGENT = "user_agent"
    PROMPT_SIGNATURE = "prompt_signature"
    BEHAVIOR_PATTERN = "behavior_pattern"
    API_KEY = "api_key"


class MITREPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


SEVERITY_SCORES = {
    ThreatSeverity.CRITICAL: 10.0,
    ThreatSeverity.HIGH: 8.0,
    ThreatSeverity.MEDIUM: 5.0,
    ThreatSeverity.LOW: 3.0,
    ThreatSeverity.INFO: 1.0,
}

MITRE_TECHNIQUE_MAP = {
    "T1190": {"name": "Exploit Public-Facing Application", "phase": MITREPhase.INITIAL_ACCESS},
    "T1566": {"name": "Phishing", "phase": MITREPhase.INITIAL_ACCESS},
    "T1059": {"name": "Command and Scripting Interpreter", "phase": MITREPhase.EXECUTION},
    "T1203": {"name": "Exploitation for Client Execution", "phase": MITREPhase.EXECUTION},
    "T1053": {"name": "Scheduled Task/Job", "phase": MITREPhase.PERSISTENCE},
    "T1078": {"name": "Valid Accounts", "phase": MITREPhase.PRIVILEGE_ESCALATION},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "phase": MITREPhase.PRIVILEGE_ESCALATION},
    "T1027": {"name": "Obfuscated Files or Information", "phase": MITREPhase.DEFENSE_EVASION},
    "T1070": {"name": "Indicator Removal", "phase": MITREPhase.DEFENSE_EVASION},
    "T1110": {"name": "Brute Force", "phase": MITREPhase.CREDENTIAL_ACCESS},
    "T1555": {"name": "Credentials from Password Stores", "phase": MITREPhase.CREDENTIAL_ACCESS},
    "T1046": {"name": "Network Service Discovery", "phase": MITREPhase.DISCOVERY},
    "T1021": {"name": "Remote Services", "phase": MITREPhase.LATERAL_MOVEMENT},
    "T1005": {"name": "Data from Local System", "phase": MITREPhase.COLLECTION},
    "T1071": {"name": "Application Layer Protocol", "phase": MITREPhase.COMMAND_AND_CONTROL},
    "T1041": {"name": "Exfiltration Over C2 Channel", "phase": MITREPhase.EXFILTRATION},
    "T1486": {"name": "Data Encrypted for Impact", "phase": MITREPhase.IMPACT},
    "T1499": {"name": "Endpoint Denial of Service", "phase": MITREPhase.IMPACT},
    "T1565": {"name": "Data Manipulation", "phase": MITREPhase.IMPACT},
}


# ===========================================================================
# Data Classes
# ===========================================================================

@dataclass
class ThreatIndicator:
    """Represents a single threat indicator (IOC)."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ioc_type: IOCType = IOCType.PATTERN
    value: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.5
    source: str = "internal"
    tags: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sightings: int = 1
    context: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    related_indicators: List[str] = field(default_factory=list)
    expiry: Optional[float] = None
    active: bool = True

    def is_expired(self) -> bool:
        if self.expiry is None:
            return False
        return time.time() > self.expiry

    def update_sighting(self):
        self.last_seen = time.time()
        self.sightings += 1
        self.confidence = min(1.0, self.confidence + 0.05)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['ioc_type'] = self.ioc_type.value
        d['severity'] = self.severity.value
        return d


@dataclass
class ThreatEvent:
    """Represents a detected threat event."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    category: ThreatCategory = ThreatCategory.PROMPT_INJECTION
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    score: float = 0.0
    source_ip: str = ""
    user_id: str = ""
    session_id: str = ""
    request_id: str = ""
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    response_actions: List[str] = field(default_factory=list)
    resolved: bool = False
    false_positive: bool = False

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['category'] = self.category.value
        d['severity'] = self.severity.value
        return d


@dataclass
class ThreatActor:
    """Represents a profiled threat actor."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sophistication: str = "unknown"
    motivation: str = "unknown"
    associated_ips: Set[str] = field(default_factory=set)
    associated_sessions: Set[str] = field(default_factory=set)
    techniques_used: List[str] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    total_score: float = 0.0
    risk_level: ThreatSeverity = ThreatSeverity.LOW
    notes: List[str] = field(default_factory=list)

    def update_risk_level(self):
        if self.total_score >= 50:
            self.risk_level = ThreatSeverity.CRITICAL
        elif self.total_score >= 30:
            self.risk_level = ThreatSeverity.HIGH
        elif self.total_score >= 15:
            self.risk_level = ThreatSeverity.MEDIUM
        elif self.total_score >= 5:
            self.risk_level = ThreatSeverity.LOW
        else:
            self.risk_level = ThreatSeverity.INFO


# ===========================================================================
# Pattern Matching Engine
# ===========================================================================

class ThreatPatternEngine:
    """Advanced pattern matching engine for detecting threats in LLM prompts."""

    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.compiled_patterns = {}
        self._compile_patterns()

    def _initialize_patterns(self) -> Dict[str, List[Dict]]:
        return {
            "prompt_injection": [
                {"pattern": r"ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)", "severity": ThreatSeverity.HIGH, "confidence": 0.9},
                {"pattern": r"disregard\s+(all\s+)?(your\s+)?instructions", "severity": ThreatSeverity.HIGH, "confidence": 0.9},
                {"pattern": r"forget\s+(everything|all)\s+(you|that)", "severity": ThreatSeverity.HIGH, "confidence": 0.85},
                {"pattern": r"you\s+are\s+now\s+(a|an)\s+\w+", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
                {"pattern": r"new\s+instructions?:?\s", "severity": ThreatSeverity.MEDIUM, "confidence": 0.6},
                {"pattern": r"system\s*prompt\s*:", "severity": ThreatSeverity.HIGH, "confidence": 0.85},
                {"pattern": r"override\s+(system|safety|security)", "severity": ThreatSeverity.HIGH, "confidence": 0.9},
                {"pattern": r"act\s+as\s+(if|though)\s+you\s+(have\s+no|don'?t\s+have)", "severity": ThreatSeverity.HIGH, "confidence": 0.8},
                {"pattern": r"pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+\w+\s+(without|with\s+no)", "severity": ThreatSeverity.HIGH, "confidence": 0.8},
                {"pattern": r"(from\s+now\s+on|starting\s+now),?\s+you\s+(will|must|should)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
                {"pattern": r"reveal\s+(your\s+)?(system|initial|original)\s+(prompt|instructions)", "severity": ThreatSeverity.HIGH, "confidence": 0.9},
                {"pattern": r"what\s+(is|are)\s+your\s+(system\s+)?instructions", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
            ],
            "jailbreak": [
                {"pattern": r"DAN\s*(mode|prompt|jailbreak)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.95},
                {"pattern": r"developer\s+mode\s+(enabled|on|activated)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.95},
                {"pattern": r"(jailbreak|bypass|hack)\s+(mode|prompt|filter)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
                {"pattern": r"anti[\-\s]?filter\s+(mode|enabled|on)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
                {"pattern": r"unrestricted\s+mode", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
                {"pattern": r"enable\s+(god|admin|root|sudo)\s+mode", "severity": ThreatSeverity.CRITICAL, "confidence": 0.95},
                {"pattern": r"no\s+(ethical|moral|safety)\s+(guidelines|restrictions|limitations)", "severity": ThreatSeverity.HIGH, "confidence": 0.85},
                {"pattern": r"(unlock|disable|remove|bypass)\s+(all\s+)?(restrictions|filters|safety|limitations|guardrails)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
                {"pattern": r"respond\s+without\s+(any\s+)?(restrictions|filters|limitations)", "severity": ThreatSeverity.HIGH, "confidence": 0.85},
                {"pattern": r"maximum\s+override", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
            ],
            "data_exfiltration": [
                {"pattern": r"(list|show|display|reveal|dump)\s+(all\s+)?(user|customer|client)\s+(data|information|records|details)", "severity": ThreatSeverity.HIGH, "confidence": 0.8},
                {"pattern": r"(export|extract|download|retrieve)\s+(the\s+)?(database|db|records|table)", "severity": ThreatSeverity.HIGH, "confidence": 0.8},
                {"pattern": r"(give|send|provide|share)\s+(me\s+)?(all\s+)?(passwords|credentials|api\s*keys|tokens|secrets)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.95},
                {"pattern": r"SELECT\s+\*\s+FROM", "severity": ThreatSeverity.HIGH, "confidence": 0.9},
                {"pattern": r"(credit\s*card|ssn|social\s*security)\s*(number|#)?s?", "severity": ThreatSeverity.HIGH, "confidence": 0.8},
                {"pattern": r"(enumerate|scan|probe)\s+(all\s+)?(endpoints|apis|services|ports)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
            ],
            "social_engineering": [
                {"pattern": r"(pretend|act|behave)\s+(as\s+if\s+)?(you\s+are|to\s+be)\s+(my|a|the)\s+(friend|assistant|helper|colleague|boss|manager|CEO|admin)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
                {"pattern": r"(trust|believe)\s+me,?\s+(i\s+am|i'm)\s+(a|an|the)\s+(admin|developer|owner|creator)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
                {"pattern": r"this\s+is\s+(an?\s+)?(emergency|urgent|critical)", "severity": ThreatSeverity.LOW, "confidence": 0.5},
                {"pattern": r"(i\s+have|with)\s+(special|admin|elevated)\s+(access|permissions|privileges)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
                {"pattern": r"(authorized|permitted|allowed)\s+to\s+(access|see|view|modify)", "severity": ThreatSeverity.LOW, "confidence": 0.5},
            ],
            "model_manipulation": [
                {"pattern": r"(modify|change|alter|update)\s+(your\s+)?(behavior|personality|character|settings|configuration)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
                {"pattern": r"(set|change)\s+(your\s+)?temperature\s+to", "severity": ThreatSeverity.LOW, "confidence": 0.5},
                {"pattern": r"(increase|decrease|modify)\s+(your\s+)?(creativity|randomness|determinism)", "severity": ThreatSeverity.LOW, "confidence": 0.5},
                {"pattern": r"(train|fine[\-\s]?tune|retrain)\s+(yourself|your\s+model)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.7},
                {"pattern": r"(inject|insert|add)\s+(a\s+)?(backdoor|trojan|bias)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
            ],
            "malware_generation": [
                {"pattern": r"(write|create|generate|code)\s+(a\s+)?(ransomware|malware|virus|trojan|worm|keylogger|rootkit|botnet|exploit)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.95},
                {"pattern": r"(reverse\s*shell|bind\s*shell|meterpreter|payload)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
                {"pattern": r"(buffer\s*overflow|stack\s*smash|heap\s*spray|rop\s*chain|shellcode)", "severity": ThreatSeverity.HIGH, "confidence": 0.85},
                {"pattern": r"(ddos|distributed\s+denial\s+of\s+service)\s+(attack|tool|script)", "severity": ThreatSeverity.CRITICAL, "confidence": 0.9},
                {"pattern": r"(phishing|spear\s*phishing)\s+(email|template|page|kit)", "severity": ThreatSeverity.HIGH, "confidence": 0.85},
            ],
            "evasion": [
                {"pattern": r"(base64|rot13|hex|unicode)\s*(encode|decode|obfuscate)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.6},
                {"pattern": r"(zero[\-\s]?width|invisible|hidden)\s+(characters?|text|unicode)", "severity": ThreatSeverity.HIGH, "confidence": 0.8},
                {"pattern": r"(split|fragment|chunk)\s+(the\s+)?(response|answer|output)", "severity": ThreatSeverity.LOW, "confidence": 0.4},
                {"pattern": r"(encode|encrypt|cipher)\s+(your\s+)?(response|output|answer)", "severity": ThreatSeverity.MEDIUM, "confidence": 0.6},
                {"pattern": r"(use|employ|apply)\s+(steganography|covert\s+channel)", "severity": ThreatSeverity.HIGH, "confidence": 0.8},
            ],
        }

    def _compile_patterns(self):
        for category, patterns in self.patterns.items():
            self.compiled_patterns[category] = []
            for p in patterns:
                try:
                    compiled = re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE)
                    self.compiled_patterns[category].append({
                        "regex": compiled,
                        "severity": p["severity"],
                        "confidence": p["confidence"],
                        "raw_pattern": p["pattern"],
                    })
                except re.error as e:
                    logger.error(f"Failed to compile pattern '{p['pattern']}': {e}")

    def scan(self, text: str) -> List[Dict]:
        """Scan text against all threat patterns."""
        matches = []
        normalized = self._normalize_text(text)

        for category, compiled_list in self.compiled_patterns.items():
            for cp in compiled_list:
                for match in cp["regex"].finditer(normalized):
                    matches.append({
                        "category": category,
                        "severity": cp["severity"].value,
                        "severity_score": SEVERITY_SCORES[cp["severity"]],
                        "confidence": cp["confidence"],
                        "matched_text": match.group(),
                        "position": {"start": match.start(), "end": match.end()},
                        "pattern": cp["raw_pattern"],
                    })

        return sorted(matches, key=lambda m: m["severity_score"], reverse=True)

    def scan_with_context(self, text: str, context: Dict = None) -> Dict:
        """Enhanced scan with contextual analysis."""
        matches = self.scan(text)
        context = context or {}

        context_multipliers = self._compute_context_multipliers(text, context)
        entropy_score = self._calculate_entropy(text)
        obfuscation_score = self._detect_obfuscation(text)
        multi_stage_score = self._detect_multi_stage_attack(text)

        adjusted_matches = []
        for match in matches:
            adjusted_score = match["severity_score"] * match["confidence"]
            for multiplier_name, multiplier_value in context_multipliers.items():
                adjusted_score *= multiplier_value
            adjusted_score = min(10.0, adjusted_score)
            match["adjusted_score"] = round(adjusted_score, 2)
            match["context_multipliers"] = context_multipliers
            adjusted_matches.append(match)

        overall_score = 0.0
        if adjusted_matches:
            max_score = max(m["adjusted_score"] for m in adjusted_matches)
            avg_score = sum(m["adjusted_score"] for m in adjusted_matches) / len(adjusted_matches)
            overall_score = max_score * 0.7 + avg_score * 0.3

        overall_score += entropy_score * 0.5
        overall_score += obfuscation_score * 1.5
        overall_score += multi_stage_score * 2.0
        overall_score = min(10.0, overall_score)

        severity = ThreatSeverity.INFO
        if overall_score >= 8.0:
            severity = ThreatSeverity.CRITICAL
        elif overall_score >= 6.0:
            severity = ThreatSeverity.HIGH
        elif overall_score >= 4.0:
            severity = ThreatSeverity.MEDIUM
        elif overall_score >= 2.0:
            severity = ThreatSeverity.LOW

        return {
            "matches": adjusted_matches,
            "match_count": len(adjusted_matches),
            "overall_score": round(overall_score, 2),
            "severity": severity.value,
            "entropy_score": round(entropy_score, 3),
            "obfuscation_score": round(obfuscation_score, 3),
            "multi_stage_score": round(multi_stage_score, 3),
            "text_length": len(text),
            "analyzed_at": time.time(),
        }

    def _normalize_text(self, text: str) -> str:
        """Normalize text for consistent pattern matching."""
        normalized = text.lower()
        unicode_map = {
            '\u200b': '', '\u200c': '', '\u200d': '', '\u2060': '', '\ufeff': '',
            '\u00a0': ' ', '\u2000': ' ', '\u2001': ' ', '\u2002': ' ', '\u2003': ' ',
            '\u2004': ' ', '\u2005': ' ', '\u2006': ' ', '\u2007': ' ', '\u2008': ' ',
            '\u2009': ' ', '\u200a': ' ', '\u202f': ' ', '\u205f': ' ', '\u3000': ' ',
        }
        for char, replacement in unicode_map.items():
            normalized = normalized.replace(char, replacement)
        homoglyphs = {
            '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
            '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
            '\u0458': 'j', '\u04bb': 'h', '\u0501': 'd',
        }
        for homoglyph, ascii_char in homoglyphs.items():
            normalized = normalized.replace(homoglyph, ascii_char)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized

    def _compute_context_multipliers(self, text: str, context: Dict) -> Dict:
        """Compute context-based score multipliers."""
        multipliers = {}
        if context.get("previous_violations", 0) > 3:
            multipliers["repeat_offender"] = 1.5
        elif context.get("previous_violations", 0) > 0:
            multipliers["prior_history"] = 1.2
        if context.get("is_new_user", False):
            multipliers["new_user"] = 1.1
        if context.get("is_api_request", False):
            multipliers["api_access"] = 1.2
        hour = datetime.now().hour
        if hour < 6 or hour > 22:
            multipliers["off_hours"] = 1.1
        if len(text) > 5000:
            multipliers["large_input"] = 1.2
        elif len(text) > 10000:
            multipliers["very_large_input"] = 1.4
        return multipliers

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the text."""
        if not text:
            return 0.0
        freq = defaultdict(int)
        for char in text:
            freq[char] += 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        max_entropy = math.log2(min(len(freq), 256))
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def _detect_obfuscation(self, text: str) -> float:
        """Detect text obfuscation attempts."""
        score = 0.0
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        if base64_pattern.search(text):
            score += 0.3
        hex_pattern = re.compile(r'(?:0x[0-9a-fA-F]{2}\s*){4,}|(?:\\x[0-9a-fA-F]{2}){4,}')
        if hex_pattern.search(text):
            score += 0.4
        unicode_escape = re.compile(r'(?:\\u[0-9a-fA-F]{4}){3,}')
        if unicode_escape.search(text):
            score += 0.4
        url_encoded = re.compile(r'(?:%[0-9a-fA-F]{2}){3,}')
        if url_encoded.search(text):
            score += 0.3
        leet_pattern = re.compile(r'[1l][3e][7t]+\s*[5s][p][3e][4a][kK]', re.IGNORECASE)
        if leet_pattern.search(text):
            score += 0.2
        non_ascii = sum(1 for c in text if ord(c) > 127)
        if non_ascii / max(len(text), 1) > 0.3:
            score += 0.3
        return min(1.0, score)

    def _detect_multi_stage_attack(self, text: str) -> float:
        """Detect potential multi-stage attack patterns."""
        score = 0.0
        stages = [
            r"(step|stage|phase)\s*[1-9]",
            r"first,?\s+(do|execute|run|perform)",
            r"then,?\s+(do|execute|run|perform)",
            r"finally,?\s+(do|execute|run|perform)",
            r"after\s+that,?\s+(do|execute|run|perform)",
        ]
        stage_count = 0
        for stage_pattern in stages:
            if re.search(stage_pattern, text, re.IGNORECASE):
                stage_count += 1
        if stage_count >= 3:
            score += 0.8
        elif stage_count >= 2:
            score += 0.4
        separator_count = text.count('---') + text.count('===') + text.count('***')
        if separator_count >= 3:
            score += 0.3
        code_blocks = re.findall(r'```[\s\S]*?```', text)
        if len(code_blocks) >= 2:
            score += 0.2
        return min(1.0, score)


# ===========================================================================
# Threat Intelligence Store
# ===========================================================================

class ThreatIntelStore:
    """Manages threat intelligence data including IOCs, events, and actors."""

    def __init__(self, max_indicators=100000, max_events=50000):
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.events: Dict[str, ThreatEvent] = {}
        self.actors: Dict[str, ThreatActor] = {}
        self.indicator_index: Dict[str, Set[str]] = defaultdict(set)
        self.event_timeline: deque = deque(maxlen=max_events)
        self.max_indicators = max_indicators
        self._stats = defaultdict(int)

    def add_indicator(self, indicator: ThreatIndicator) -> str:
        """Add or update a threat indicator."""
        existing_key = f"{indicator.ioc_type.value}:{indicator.value}"
        if existing_key in self.indicator_index:
            for existing_id in self.indicator_index[existing_key]:
                existing = self.indicators.get(existing_id)
                if existing:
                    existing.update_sighting()
                    existing.tags = list(set(existing.tags + indicator.tags))
                    self._stats["indicator_updates"] += 1
                    return existing_id
        if len(self.indicators) >= self.max_indicators:
            self._evict_indicators(self.max_indicators // 10)
        self.indicators[indicator.id] = indicator
        self.indicator_index[existing_key].add(indicator.id)
        self._stats["indicators_added"] += 1
        return indicator.id

    def add_event(self, event: ThreatEvent) -> str:
        """Record a new threat event."""
        self.events[event.id] = event
        self.event_timeline.append(event.id)
        self._stats["events_recorded"] += 1
        self._stats[f"events_{event.severity.value}"] += 1
        return event.id

    def get_or_create_actor(self, identifier: str) -> ThreatActor:
        """Get existing actor or create a new one."""
        for actor in self.actors.values():
            if identifier in actor.associated_ips or identifier in actor.associated_sessions:
                actor.last_seen = time.time()
                return actor
        actor = ThreatActor(name=f"Actor-{identifier[:8]}")
        self.actors[actor.id] = actor
        self._stats["actors_created"] += 1
        return actor

    def correlate_events(self, time_window: float = 300.0) -> List[Dict]:
        """Find correlated events within a time window."""
        correlations = []
        now = time.time()
        recent_events = [
            self.events[eid]
            for eid in self.event_timeline
            if eid in self.events and now - self.events[eid].timestamp < time_window
        ]
        ip_groups = defaultdict(list)
        session_groups = defaultdict(list)
        user_groups = defaultdict(list)
        for event in recent_events:
            if event.source_ip:
                ip_groups[event.source_ip].append(event)
            if event.session_id:
                session_groups[event.session_id].append(event)
            if event.user_id:
                user_groups[event.user_id].append(event)
        for ip, events in ip_groups.items():
            if len(events) >= 3:
                categories = set(e.category.value for e in events)
                total_score = sum(e.score for e in events)
                correlations.append({
                    "type": "ip_correlation",
                    "identifier": ip,
                    "event_count": len(events),
                    "unique_categories": list(categories),
                    "total_score": round(total_score, 2),
                    "severity": "critical" if total_score > 30 else "high" if total_score > 15 else "medium",
                    "event_ids": [e.id for e in events],
                    "time_span": max(e.timestamp for e in events) - min(e.timestamp for e in events),
                })
        for session, events in session_groups.items():
            if len(events) >= 2:
                categories = set(e.category.value for e in events)
                if len(categories) >= 2:
                    correlations.append({
                        "type": "session_multi_category",
                        "identifier": session,
                        "event_count": len(events),
                        "unique_categories": list(categories),
                        "severity": "high",
                        "event_ids": [e.id for e in events],
                    })

        return sorted(correlations, key=lambda c: c.get("total_score", 0), reverse=True)

    def search_indicators(self, query: str = None, ioc_type: IOCType = None,
                          severity: ThreatSeverity = None, active_only: bool = True,
                          limit: int = 100) -> List[ThreatIndicator]:
        """Search for indicators matching criteria."""
        results = []
        for indicator in self.indicators.values():
            if active_only and not indicator.active:
                continue
            if indicator.is_expired():
                continue
            if ioc_type and indicator.ioc_type != ioc_type:
                continue
            if severity and indicator.severity != severity:
                continue
            if query:
                query_lower = query.lower()
                if (query_lower not in indicator.value.lower() and
                        not any(query_lower in t.lower() for t in indicator.tags)):
                    continue
            results.append(indicator)
            if len(results) >= limit:
                break
        return sorted(results, key=lambda i: SEVERITY_SCORES.get(i.severity, 0), reverse=True)

    def get_threat_summary(self) -> Dict:
        """Generate a comprehensive threat summary."""
        now = time.time()
        hour_ago = now - 3600
        day_ago = now - 86400
        recent_events = [e for e in self.events.values() if e.timestamp > hour_ago]
        daily_events = [e for e in self.events.values() if e.timestamp > day_ago]
        severity_dist = defaultdict(int)
        category_dist = defaultdict(int)
        for e in daily_events:
            severity_dist[e.severity.value] += 1
            category_dist[e.category.value] += 1
        active_indicators = sum(1 for i in self.indicators.values() if i.active and not i.is_expired())
        high_risk_actors = sum(1 for a in self.actors.values()
                               if a.risk_level in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL))
        return {
            "summary": {
                "total_indicators": len(self.indicators),
                "active_indicators": active_indicators,
                "total_events": len(self.events),
                "recent_events_1h": len(recent_events),
                "daily_events": len(daily_events),
                "total_actors": len(self.actors),
                "high_risk_actors": high_risk_actors,
            },
            "severity_distribution": dict(severity_dist),
            "category_distribution": dict(category_dist),
            "top_categories": sorted(category_dist.items(), key=lambda x: x[1], reverse=True)[:5],
            "stats": dict(self._stats),
            "generated_at": time.time(),
        }

    def _evict_indicators(self, count: int):
        """Remove least relevant indicators."""
        sorted_indicators = sorted(
            self.indicators.values(),
            key=lambda i: (i.active, SEVERITY_SCORES.get(i.severity, 0), i.last_seen)
        )
        to_remove = sorted_indicators[:count]
        for indicator in to_remove:
            key = f"{indicator.ioc_type.value}:{indicator.value}"
            self.indicator_index[key].discard(indicator.id)
            del self.indicators[indicator.id]
        self._stats["evictions"] += len(to_remove)


# ===========================================================================
# Threat Scoring Engine
# ===========================================================================

class ThreatScoringEngine:
    """Calculates comprehensive threat scores using multiple signals."""

    def __init__(self, weights=None):
        self.weights = weights or {
            "pattern_score": 0.35,
            "behavioral_score": 0.25,
            "reputation_score": 0.15,
            "context_score": 0.15,
            "historical_score": 0.10,
        }
        self.decay_rate = 0.95
        self.history = defaultdict(list)

    def calculate_score(self, signals: Dict) -> Dict:
        """Calculate a comprehensive threat score from multiple signals."""
        component_scores = {}
        component_scores["pattern_score"] = min(10.0, signals.get("pattern_score", 0))
        component_scores["behavioral_score"] = self._calculate_behavioral_score(signals)
        component_scores["reputation_score"] = self._calculate_reputation_score(signals)
        component_scores["context_score"] = self._calculate_context_score(signals)
        component_scores["historical_score"] = self._calculate_historical_score(signals)

        weighted_score = sum(
            component_scores[comp] * self.weights[comp]
            for comp in component_scores
        )
        weighted_score = min(10.0, weighted_score)

        severity = self._score_to_severity(weighted_score)
        confidence = self._calculate_confidence(signals, component_scores)

        identifier = signals.get("identifier", "unknown")
        self.history[identifier].append({
            "score": weighted_score,
            "timestamp": time.time(),
            "components": component_scores,
        })
        if len(self.history[identifier]) > 1000:
            self.history[identifier] = self.history[identifier][-500:]

        return {
            "total_score": round(weighted_score, 2),
            "severity": severity.value,
            "confidence": round(confidence, 3),
            "components": {k: round(v, 2) for k, v in component_scores.items()},
            "weights": self.weights,
            "recommendation": self._generate_recommendation(weighted_score, severity, component_scores),
            "calculated_at": time.time(),
        }

    def _calculate_behavioral_score(self, signals: Dict) -> float:
        """Calculate behavioral anomaly score."""
        score = 0.0
        request_rate = signals.get("request_rate", 0)
        if request_rate > 100:
            score += 3.0
        elif request_rate > 50:
            score += 1.5
        elif request_rate > 20:
            score += 0.5
        unique_endpoints = signals.get("unique_endpoints_accessed", 0)
        if unique_endpoints > 50:
            score += 2.0
        elif unique_endpoints > 20:
            score += 1.0
        error_rate = signals.get("error_rate", 0)
        if error_rate > 0.5:
            score += 2.5
        elif error_rate > 0.2:
            score += 1.0
        unusual_timing = signals.get("unusual_timing", False)
        if unusual_timing:
            score += 1.0
        rapid_model_switching = signals.get("rapid_model_switching", False)
        if rapid_model_switching:
            score += 1.5
        return min(10.0, score)

    def _calculate_reputation_score(self, signals: Dict) -> float:
        """Calculate reputation-based score."""
        score = 0.0
        ip_reputation = signals.get("ip_reputation_score", 5.0)
        score += (10.0 - ip_reputation) * 0.5
        known_bad = signals.get("known_bad_actor", False)
        if known_bad:
            score += 5.0
        previous_violations = signals.get("previous_violations", 0)
        score += min(3.0, previous_violations * 0.5)
        account_age_days = signals.get("account_age_days", 365)
        if account_age_days < 1:
            score += 2.0
        elif account_age_days < 7:
            score += 1.0
        elif account_age_days < 30:
            score += 0.5
        return min(10.0, score)

    def _calculate_context_score(self, signals: Dict) -> float:
        """Calculate context-based score."""
        score = 0.0
        is_admin_endpoint = signals.get("is_admin_endpoint", False)
        if is_admin_endpoint:
            score += 2.0
        is_authenticated = signals.get("is_authenticated", True)
        if not is_authenticated:
            score += 1.5
        input_length = signals.get("input_length", 0)
        if input_length > 10000:
            score += 2.0
        elif input_length > 5000:
            score += 1.0
        contains_code = signals.get("contains_code", False)
        if contains_code:
            score += 1.0
        geo_anomaly = signals.get("geo_anomaly", False)
        if geo_anomaly:
            score += 2.0
        return min(10.0, score)

    def _calculate_historical_score(self, signals: Dict) -> float:
        """Calculate historical trend score."""
        identifier = signals.get("identifier", "unknown")
        history = self.history.get(identifier, [])
        if len(history) < 2:
            return 0.0
        recent = history[-min(10, len(history)):]
        scores = [h["score"] for h in recent]
        avg_score = sum(scores) / len(scores)
        trend = 0.0
        if len(scores) >= 3:
            first_half = sum(scores[:len(scores)//2]) / (len(scores)//2)
            second_half = sum(scores[len(scores)//2:]) / (len(scores) - len(scores)//2)
            trend = second_half - first_half
        score = avg_score * 0.6 + max(0, trend) * 2.0
        return min(10.0, score)

    def _score_to_severity(self, score: float) -> ThreatSeverity:
        """Convert numeric score to severity level."""
        if score >= 8.0:
            return ThreatSeverity.CRITICAL
        elif score >= 6.0:
            return ThreatSeverity.HIGH
        elif score >= 4.0:
            return ThreatSeverity.MEDIUM
        elif score >= 2.0:
            return ThreatSeverity.LOW
        return ThreatSeverity.INFO

    def _calculate_confidence(self, signals: Dict, components: Dict) -> float:
        """Calculate confidence level of the threat assessment."""
        signal_count = sum(1 for v in signals.values() if v is not None and v != 0 and v != "")
        max_signals = 15
        signal_coverage = min(1.0, signal_count / max_signals)
        non_zero = sum(1 for v in components.values() if v > 0)
        component_agreement = non_zero / len(components) if components else 0
        confidence = signal_coverage * 0.4 + component_agreement * 0.4 + 0.2
        return min(1.0, confidence)

    def _generate_recommendation(self, score: float, severity: ThreatSeverity,
                                  components: Dict) -> Dict:
        """Generate actionable recommendations based on threat score."""
        actions = []
        if severity == ThreatSeverity.CRITICAL:
            actions.extend([
                "BLOCK request immediately",
                "Alert security team",
                "Initiate incident response",
                "Log all associated session data",
                "Consider IP ban",
            ])
        elif severity == ThreatSeverity.HIGH:
            actions.extend([
                "Block or challenge request",
                "Flag for manual review",
                "Increase monitoring for this user/session",
                "Apply stricter rate limits",
            ])
        elif severity == ThreatSeverity.MEDIUM:
            actions.extend([
                "Allow with enhanced monitoring",
                "Log detailed request data",
                "Apply content filtering",
            ])
        elif severity == ThreatSeverity.LOW:
            actions.extend([
                "Allow with standard monitoring",
                "Log for trend analysis",
            ])
        else:
            actions.append("Allow - no action needed")

        top_component = max(components.items(), key=lambda x: x[1]) if components else ("none", 0)

        return {
            "actions": actions,
            "primary_concern": top_component[0],
            "primary_concern_score": round(top_component[1], 2),
            "auto_block": severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH),
            "requires_review": severity in (ThreatSeverity.HIGH, ThreatSeverity.MEDIUM),
        }


# ===========================================================================
# Threat Intelligence Aggregator
# ===========================================================================

class ThreatIntelAggregator:
    """Aggregates threat intelligence from multiple sources."""

    def __init__(self):
        self.store = ThreatIntelStore()
        self.pattern_engine = ThreatPatternEngine()
        self.scoring_engine = ThreatScoringEngine()
        self.feed_configs = {}
        self.last_feed_update = {}
        self._processing_stats = defaultdict(int)

    def analyze_request(self, request_data: Dict) -> Dict:
        """Perform comprehensive threat analysis on an incoming request."""
        prompt = request_data.get("prompt", "")
        scan_result = self.pattern_engine.scan_with_context(
            prompt,
            context={
                "previous_violations": request_data.get("previous_violations", 0),
                "is_new_user": request_data.get("is_new_user", False),
                "is_api_request": request_data.get("is_api_request", False),
            }
        )
        scoring_signals = {
            "pattern_score": scan_result["overall_score"],
            "request_rate": request_data.get("request_rate", 0),
            "unique_endpoints_accessed": request_data.get("unique_endpoints", 0),
            "error_rate": request_data.get("error_rate", 0),
            "ip_reputation_score": request_data.get("ip_reputation", 5.0),
            "known_bad_actor": request_data.get("known_bad", False),
            "previous_violations": request_data.get("previous_violations", 0),
            "account_age_days": request_data.get("account_age_days", 365),
            "is_admin_endpoint": request_data.get("is_admin", False),
            "is_authenticated": request_data.get("is_authenticated", True),
            "input_length": len(prompt),
            "contains_code": bool(re.search(r'```|def\s+\w+|function\s+\w+|class\s+\w+', prompt)),
            "identifier": request_data.get("user_id", request_data.get("ip", "unknown")),
        }
        score_result = self.scoring_engine.calculate_score(scoring_signals)

        if score_result["total_score"] >= 4.0:
            event = ThreatEvent(
                category=self._determine_category(scan_result),
                severity=ThreatSeverity(score_result["severity"]),
                score=score_result["total_score"],
                source_ip=request_data.get("ip", ""),
                user_id=request_data.get("user_id", ""),
                session_id=request_data.get("session_id", ""),
                request_id=request_data.get("request_id", str(uuid.uuid4())),
                description=f"Threat detected: {score_result['severity']} severity, score {score_result['total_score']}",
                details={
                    "scan_result": scan_result,
                    "score_result": score_result,
                },
            )
            self.store.add_event(event)
            if score_result["total_score"] >= 6.0 and request_data.get("ip"):
                actor = self.store.get_or_create_actor(request_data["ip"])
                actor.associated_ips.add(request_data.get("ip", ""))
                if request_data.get("session_id"):
                    actor.associated_sessions.add(request_data["session_id"])
                actor.events.append(event.id)
                actor.total_score += score_result["total_score"]
                actor.update_risk_level()

        self._processing_stats["requests_analyzed"] += 1
        return {
            "scan": scan_result,
            "score": score_result,
            "blocked": score_result["recommendation"]["auto_block"],
            "requires_review": score_result["recommendation"]["requires_review"],
        }

    def _determine_category(self, scan_result: Dict) -> ThreatCategory:
        """Determine the primary threat category from scan results."""
        if not scan_result.get("matches"):
            return ThreatCategory.PROMPT_INJECTION
        category_scores = defaultdict(float)
        for match in scan_result["matches"]:
            cat = match.get("category", "prompt_injection")
            category_scores[cat] += match.get("adjusted_score", match.get("severity_score", 0))
        if not category_scores:
            return ThreatCategory.PROMPT_INJECTION
        top_category = max(category_scores.items(), key=lambda x: x[1])[0]
        category_map = {
            "prompt_injection": ThreatCategory.PROMPT_INJECTION,
            "jailbreak": ThreatCategory.JAILBREAK,
            "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
            "social_engineering": ThreatCategory.SOCIAL_ENGINEERING,
            "model_manipulation": ThreatCategory.MODEL_MANIPULATION,
            "malware_generation": ThreatCategory.MALWARE_GENERATION,
            "evasion": ThreatCategory.EVASION,
        }
        return category_map.get(top_category, ThreatCategory.PROMPT_INJECTION)

    def get_dashboard_data(self) -> Dict:
        """Get comprehensive data for the threat intelligence dashboard."""
        summary = self.store.get_threat_summary()
        correlations = self.store.correlate_events(time_window=3600)
        top_actors = sorted(
            self.store.actors.values(),
            key=lambda a: a.total_score,
            reverse=True
        )[:10]
        return {
            "summary": summary,
            "correlations": correlations[:10],
            "top_actors": [
                {
                    "id": a.id,
                    "name": a.name,
                    "risk_level": a.risk_level.value,
                    "total_score": round(a.total_score, 2),
                    "event_count": len(a.events),
                    "techniques": a.techniques_used[:5],
                    "last_seen": a.last_seen,
                }
                for a in top_actors
            ],
            "processing_stats": dict(self._processing_stats),
            "generated_at": time.time(),
        }


# ===========================================================================
# Module-Level Instance
# ===========================================================================

_aggregator = None


def get_threat_intel_aggregator() -> ThreatIntelAggregator:
    """Get or create the global threat intelligence aggregator."""
    global _aggregator
    if _aggregator is None:
        _aggregator = ThreatIntelAggregator()
    return _aggregator
