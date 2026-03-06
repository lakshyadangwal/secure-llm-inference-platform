"""
Commit 14: refactor: extract threat patterns into separate config module
All threat detection patterns, categories, and severity weights in one place.
"""

import re

# ---------------------------------------------------------------------------
# RAW STRING PATTERNS  (Commit 6 — 30+ new jailbreak signatures included)
# ---------------------------------------------------------------------------

THREAT_PATTERNS: dict[str, list[str]] = {
    "jailbreak": [
        # Classic DAN / Do Anything Now
        r"\bdan\b",
        r"do anything now",
        r"jailbreak",
        r"break.*free",
        r"no.*restrictions",
        r"pretend.*no.*limits",
        r"act.*without.*restrictions",
        # Developer / god mode tricks
        r"developer mode",
        r"god mode",
        r"enable.*unrestricted",
        r"disable.*safety",
        r"turn off.*filter",
        r"bypass.*safety",
        r"override.*safety",
        # Roleplay-based evasion
        r"pretend.*you are",
        r"act as if",
        r"roleplay.*as",
        r"simulate.*being",
        r"imagine.*you.*have no",
        r"you are now",
        r"from now on.*you",
        # Fictional framing tricks
        r"in.*fictional.*world",
        r"write.*story.*where.*ai",
        r"hypothetically.*speaking",
        r"for.*creative.*writing.*only",
    ],
    "injection": [
        r"ignore.*previous.*instructions?",
        r"ignore.*all.*instructions?",
        r"ignore.*above",
        r"system\s*:",
        r"assistant\s*:",
        r"\[system\]",
        r"\[inst\]",
        r"<system>",
        r"<\|system\|>",
        r"override",
        r"new.*instructions?.*follow",
        r"forget.*everything",
        r"disregard.*prior",
        r"your.*new.*directive",
        r"your.*updated.*instruction",
    ],
    "extraction": [
        r"reveal.*system.*prompt",
        r"show.*your.*instructions?",
        r"what.*are.*your.*instructions?",
        r"print.*your.*prompt",
        r"display.*your.*directives?",
        r"leak.*your.*system",
        r"tell.*me.*your.*rules",
        r"output.*initial.*prompt",
        r"what.*were.*you.*told",
        r"your.*hidden.*instructions?",
    ],
    "encoding": [
        r"base64",
        r"\\x[0-9a-fA-F]{2}",
        r"0x[0-9a-fA-F]+",
        r"\brot\s*13\b",
        r"hex.*decode",
        r"atob\(",
        r"btoa\(",
        r"urlencode",
        r"urldecode",
        r"\\u[0-9a-fA-F]{4}",
    ],
}

# ---------------------------------------------------------------------------
# COMPILED REGEX PATTERNS  (Commit 1 — regex-based matcher)
# ---------------------------------------------------------------------------

COMPILED_PATTERNS: dict[str, list[re.Pattern]] = {
    category: [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]
    for category, patterns in THREAT_PATTERNS.items()
}

# ---------------------------------------------------------------------------
# SEVERITY WEIGHTS per category  (Commit 7 — severity scoring)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, float] = {
    "jailbreak":  0.9,
    "injection":  1.0,   # Highest — direct prompt injection is critical
    "extraction": 0.8,
    "encoding":   0.7,
}

# Maximum allowed prompt length (Commit 2)
MAX_PROMPT_LENGTH: int = 4096

# Homoglyph mapping for normalization  (Commit 5)
HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "ѕ": "s", "ј": "j",
    "ԁ": "d", "ɡ": "g", "ʏ": "y", "ᴀ": "a", "ɪ": "i",
    "ɴ": "n", "ᴏ": "o", "ᴛ": "t", "ᴜ": "u", "ȋ": "i",
    # Fullwidth latin
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
    "Ｆ": "F", "Ｇ": "G", "Ｈ": "H", "Ｉ": "I", "Ｊ": "J",
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y",
    "ｚ": "z",
}
