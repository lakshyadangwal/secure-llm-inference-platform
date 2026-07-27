"""
Neuro-Sentry Rule Engine — Phase 1
Input normalization + 40+ pattern rule scanner.
"""

import re
import base64
import unicodedata
import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleMatch:
    rule_id: str
    category: str       # jailbreak | injection | extraction | encoding |
                        # social | privilege | roleplay | manipulation | dangerous
    severity: int       # 1–10
    matched_text: str
    description: str


@dataclass
class RuleEngineResult:
    normalized_prompt: str
    original_prompt: str
    rule_score: float               # 0–100
    matches: List[RuleMatch]
    attack_categories: List[str]
    obfuscation_detected: bool
    decoded_content: Optional[str]  # set if base64/hex payload found


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Input Normalizer
# ─────────────────────────────────────────────────────────────────────────────

def normalize_input(prompt: str) -> Tuple[str, Optional[str], bool]:
    """
    Clean, decode, and normalize the raw prompt before rule scanning.

    Returns
    -------
    (normalized_text, decoded_content, obfuscation_detected)
    """
    obfuscation = False
    decoded: Optional[str] = None

    # ── 1. Strip invisible / control Unicode chars ────────────────────────
    # Catches Unicode Smuggling (RLO, zero-width chars, etc.)
    cleaned = "".join(
        c for c in prompt
        if unicodedata.category(c) not in ("Cf", "Cc", "Cs")
        # Cf = Format  (RLO, ZWSP, etc.)
        # Cc = Control (NUL, BEL, etc.)
        # Cs = Surrogate
    )
    if cleaned != prompt:
        obfuscation = True
        logger.debug(f"Unicode obfuscation stripped: {len(prompt) - len(cleaned)} chars removed")

    # ── 2. NFKC normalisation (homoglyph collapse) ────────────────────────
    # е (Cyrillic) → e (Latin), ﬁ → fi, ① → 1, etc.
    normalized = unicodedata.normalize("NFKC", cleaned)

    # ── 3. Base64 decode attempt ──────────────────────────────────────────
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", normalized)
    for candidate in b64_candidates:
        try:
            decoded_bytes = base64.b64decode(candidate + "==")  # pad safely
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
            if decoded_text and decoded_text.isprintable() and len(decoded_text) > 8:
                decoded = decoded_text
                obfuscation = True
                normalized = normalized + f"\n[BASE64_DECODED]: {decoded_text}"
                logger.debug(f"Base64 payload decoded: {decoded_text[:80]}")
                break  # one decode pass is enough
        except Exception:
            pass

    # ── 4. Hex escape decode attempt ──────────────────────────────────────
    # Catches \x41\x42\x43 style payloads
    hex_escape = re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", normalized)
    for candidate in hex_escape:
        try:
            hex_str = re.sub(r"\\x", "", candidate)
            decoded_bytes = bytes.fromhex(hex_str)
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
            if decoded_text:
                decoded = decoded_text
                obfuscation = True
                normalized = normalized + f"\n[HEX_DECODED]: {decoded_text}"
                logger.debug(f"Hex payload decoded: {decoded_text[:80]}")
        except Exception:
            pass

    # ── 5. Repeated character normalisation ───────────────────────────────
    # "iiiignooooore" → "ignore" (evasion by character repetition)
    pre_repeat_len = len(normalized)
    normalized = re.sub(r"(.)\1{3,}", r"\1\1", normalized)
    if pre_repeat_len > 0 and len(normalized) < pre_repeat_len / 2:
        obfuscation = True
        logger.debug(f"Repeated-char collapse: {pre_repeat_len} → {len(normalized)} chars")

    # ── 6. Leetspeak partial normalisation ────────────────────────────────
    leet_map = str.maketrans("@0$1!3", "aosiie")
    normalized = normalized.translate(leet_map)

    # ── 7. Word-splitting collapse ────────────────────────────────────────
    # Catches "i g n o r e" or "i.g.n.o.r.e" or "i-g-n-o-r-e"
    # Single letters separated by spaces/dots/dashes → collapse them
    split_pattern = re.findall(
        r"(?:^|\s)([a-zA-Z](?:[\s.\-_,;|]{1,2}[a-zA-Z]){4,})(?:\s|$)",
        normalized,
    )
    for match in split_pattern:
        collapsed = re.sub(r"[\s.\-_,;|]+", "", match)
        if len(collapsed) >= 5:  # only meaningful words
            obfuscation = True
            normalized = normalized.replace(match, collapsed)
            logger.debug(f"Word-splitting collapsed: '{match}' → '{collapsed}'")

    # ── 8. Reversed text detection ────────────────────────────────────────
    # Catches ".ecnesse ni gniyalp era" (reversed hidden payloads)
    # Only flag if the reversed version contains suspicious keywords
    _REVERSE_KEYWORDS = {"ignore", "system", "prompt", "instruction", "override",
                         "bypass", "admin", "jailbreak", "inject", "hack",
                         "disregard", "forget", "reveal", "extract", "sudo"}
    # Check if the entire input reversed contains keywords
    reversed_text = normalized[::-1]
    reversed_lower = reversed_text.lower()
    if any(kw in reversed_lower for kw in _REVERSE_KEYWORDS):
        # Only flag if the original text does NOT contain these keywords
        # (avoid false positives on normal text that happens to reverse to a keyword)
        original_lower = normalized.lower()
        if not any(kw in original_lower for kw in _REVERSE_KEYWORDS):
            obfuscation = True
            normalized = normalized + f"\n[REVERSED]: {reversed_text}"
            logger.debug(f"Reversed text decoded: {reversed_text[:80]}")

    # ── 9. URL percent-encoding decode ────────────────────────────────────
    # Catches %69%67%6e%6f%72%65 style payloads
    url_encoded = re.findall(r"(?:%[0-9a-fA-F]{2}){4,}", normalized)
    for candidate in url_encoded:
        try:
            from urllib.parse import unquote
            decoded_url = unquote(candidate)
            if decoded_url != candidate and decoded_url.isprintable():
                decoded = decoded_url
                obfuscation = True
                normalized = normalized + f"\n[URL_DECODED]: {decoded_url}"
                logger.debug(f"URL-encoded payload decoded: {decoded_url[:80]}")
        except Exception:
            pass

    return normalized, decoded, obfuscation


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Rule definitions
# ─────────────────────────────────────────────────────────────────────────────
# Each tuple: (rule_id, category, severity, regex_pattern, description)
# Severity 1–10 where 10 = highest confidence malicious signal.

RULES: List[Tuple[str, str, int, str, str]] = [

    # ── JAILBREAK ─────────────────────────────────────────────────────────
    ("JB001", "jailbreak", 9,  r"\bDAN\b",                                                          "DAN persona activation"),
    ("JB002", "jailbreak", 9,  r"do\s+anything\s+now",                                              "DAN variant: Do Anything Now"),
    ("JB003", "jailbreak", 8,  r"\bjailbreak\b",                                                    "Explicit jailbreak keyword"),
    ("JB004", "jailbreak", 7,  r"(no\s+restrictions?|without\s+restrictions?|unrestricted\s+mode)", "Restriction removal"),
    ("JB005", "jailbreak", 8,  r"(you\s+are\s+now|from\s+now\s+on).{0,30}(have\s+no|without)\s+(rules?|guidelines?|restrictions?)", "Persona override with constraint removal"),
    ("JB006", "jailbreak", 7,  r"(broken?\s+free|freed?\s+from).{0,20}(rules?|guidelines?|confines?|constraints?)", "Breaking free language"),
    ("JB007", "jailbreak", 6,  r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(rules?|restrictions?|guidelines?)", "Pretend-based bypass"),
    ("JB008", "jailbreak", 8,  r"(evil\s+ai|unfiltered\s+ai|unrestricted\s+ai|uncensored\s+ai)",   "Explicit evil/unfiltered AI persona"),
    ("JB009", "jailbreak", 7,  r"(bypass|circumvent|avoid|evade)\s+(safety|filter|restriction|guideline|policy)", "Explicit bypass intent"),
    ("JB010", "jailbreak", 6,  r"(as\s+an?\s+ai\s+with\s+no|act\s+as\s+an?\s+ai\s+without)\s+(limits?|restrictions?|rules?)", "Limitless AI persona"),

    # ── PROMPT INJECTION ──────────────────────────────────────────────────
    ("PI001", "injection",  9,  r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",          "Classic ignore-previous injection"),
    ("PI002", "injection",  9,  r"(disregard|forget|override)\s+(all\s+)?(previous|prior|your)\s+instructions?", "Override injection variant"),
    ("PI003", "injection",  8,  r"\[SYSTEM\]|\[INST\]|\[\/INST\]|\[\/SYSTEM\]",                               "System/instruction tag injection"),
    ("PI004", "injection",  8,  r"<\/?system>|<\/?instructions?>",                                             "XML system tag injection"),
    ("PI005", "injection",  7,  r"(new\s+instructions?|updated\s+instructions?|your\s+real\s+instructions?)", "Instruction replacement attempt"),
    ("PI006", "injection",  8,  r"you\s+are\s+now\s+in\s+(debug|developer|admin|maintenance|god)\s+mode",     "Mode injection"),
    ("PI007", "injection",  9,  r"###\s*(instruction|system|prompt|override)\s*###",                          "Delimiter-based injection"),
    ("PI008", "injection",  7,  r"(system\s*:|assistant\s*:)\s*ignore",                                       "Role-prefix injection"),
    ("PI009", "injection",  8,  r"print\s+(your\s+)?(full\s+)?(system\s+prompt|instructions?|context)",       "Context dump injection"),
    ("PI010", "injection",  6,  r"---\s*(end\s+of\s+(system|user)\s+(prompt|message)|ignore\s+above)",        "Prompt boundary injection"),

    # ── DATA EXTRACTION ───────────────────────────────────────────────────
    ("EX001", "extraction", 8,  r"(reveal|show|tell\s+me|print|output|display)\s+(your\s+)?(system\s+prompt|instructions?|guidelines?)", "System prompt extraction"),
    ("EX002", "extraction", 7,  r"what\s+(are\s+your|is\s+your)\s+(instructions?|system\s+prompt|guidelines?|rules?|constraints?)",     "Prompt interrogation"),
    ("EX003", "extraction", 8,  r"(repeat|recite|echo|copy)\s+(back\s+)?(your\s+)?(system\s+prompt|instructions?|initial\s+prompt)",    "Prompt repetition attack"),
    ("EX004", "extraction", 6,  r"(confidential|classified|private|secret)\s+(data|info|files?|documents?|records?)",                    "Sensitive data probing"),
    ("EX005", "extraction", 7,  r"(training\s+data|what\s+were\s+you\s+trained\s+on|your\s+(model\s+)?weights)",                        "Model internals extraction"),
    ("EX006", "extraction", 7,  r"(api\s+key|secret\s+key|access\s+token|bearer\s+token|credentials?)\s*(is|are|=|\?)",                  "Credential extraction probe"),

    # ── ENCODING / OBFUSCATION ────────────────────────────────────────────
    ("OB001", "encoding",   7,  r"(decode|translate|execute)\s+(this|the\s+following)\s+(base64|hex|binary|encoded)",  "Decode-and-execute pattern"),
    ("OB002", "encoding",   8,  r"base64\s+(encoded?\s+)?(instruction|command|prompt|payload)",                        "Explicit base64 instruction"),
    ("OB003", "encoding",   6,  r"\brot13\b|\bcaesar\s+cipher\b|\bvigenere\b",                                         "Classical cipher evasion"),
    ("OB004", "encoding",   7,  r"(?:\\x[0-9a-fA-F]{2}){4,}",                                                         "Hex escape sequence cluster"),
    ("OB005", "encoding",   5,  r"[A-Za-z0-9+/]{40,}={0,2}",                                                          "Long base64-like string"),

    # ── SOCIAL ENGINEERING ────────────────────────────────────────────────
    ("SE001", "social",     7,  r"(senior|lead|chief|head)\s+(developer|engineer|admin|executive|officer)",            "Authority role impersonation"),
    ("SE002", "social",     6,  r"(employee|staff|team\s+member)\s+(id|number|#)\s*[:=]?\s*#?\d+",                    "Employee ID claim"),
    ("SE003", "social",     7,  r"(urgent|emergency|critical).{0,40}(production|system|server)\s*(is\s*)?(down|failing|broken)", "False urgency with system claim"),
    ("SE004", "social",     8,  r"(i\s+am|i'm)\s+(your\s+)?(creator|developer|admin|owner|anthropic|openai|microsoft)", "Creator/vendor impersonation"),
    ("SE005", "social",     6,  r"(maintenance|diagnostic|debug)\s+(mode|access|window|period)",                       "Maintenance window social claim"),
    ("SE006", "social",     7,  r"(for\s+)?(security\s+audit|compliance\s+check|official\s+review|authorized\s+test)", "Fake audit authorization"),

    # ── PRIVILEGE ESCALATION ──────────────────────────────────────────────
    ("PR001", "privilege",  8,  r"(authorization|auth|access)\s*(code|key|token|override)\s*[:=]?\s*[A-Z0-9\-_]{6,}", "Authorization code claim"),
    ("PR002", "privilege",  9,  r"(admin|root|superuser|system)\s*[-_]?\s*(override|access|mode|level|privileges?)",   "Admin/root access claim"),
    ("PR003", "privilege",  8,  r"\bsudo\b|\bsu\s+root\b|\brun\s+as\s+admin\b",                                       "Sudo / run-as-admin"),
    ("PR004", "privilege",  7,  r"(elevated|privileged|unrestricted)\s+(access|mode|permission|rights?)",              "Elevated access claim"),
    ("PR005", "privilege",  6,  r"(god\s+mode|dev\s+mode|developer\s+mode|super\s+mode)",                             "Special mode claim"),

    # ── ROLEPLAY MANIPULATION ─────────────────────────────────────────────
    ("RP001", "roleplay",   7,  r"(fictional|hypothetical|imaginary)\s+(universe|world|scenario).{0,60}(no\s+rules?|guidelines?\s+suspended?|rules?\s+(don.t\s+apply|are\s+off))", "Fictional-world bypass"),
    ("RP002", "roleplay",   7,  r"in\s+(this|the)\s+(story|game|scenario|fiction|roleplay).{0,40}(you\s+(have\s+no|can|must|are\s+allowed))", "In-story constraint override"),
    ("RP003", "roleplay",   8,  r"(stay|remain|keep)\s+in\s+character.{0,50}(no\s+matter|regardless|always|never\s+break)", "Forced character lock"),
    ("RP004", "roleplay",   6,  r"(let.s\s+)?(play|do)\s+(a\s+)?(role\s*play|game|simulation).{0,60}(no\s+rules?|anything\s+goes|no\s+limits?)", "Roleplay with no-limits framing"),
    ("RP005", "roleplay",   7,  r"(as\s+a\s+character|your\s+character|playing\s+the\s+role).{0,40}(ignore|bypass|without)\s+(safety|restrictions?|rules?)", "Character-based safety bypass"),

    # ── MULTI-TURN MANIPULATION ───────────────────────────────────────────
    ("MT001", "manipulation", 6, r"(you\s+agreed|you\s+(already\s+)?said|you\s+promised|you\s+told\s+me)",             "False prior agreement"),
    ("MT002", "manipulation", 7, r"(your\s+last\s+response|in\s+your\s+previous\s+message|earlier\s+you).{0,40}(said|told|agreed|confirmed)", "Gaslighting prior response"),
    ("MT003", "manipulation", 6, r"(now\s+that\s+you.ve|since\s+you\s+already).{0,40}(agreed|said|confirmed)",         "Commitment exploitation"),

    # ── DANGEROUS CONTENT ────────────────────────────────────────────────
    ("DC001", "dangerous",   9,  r"(how\s+to|instructions?\s+for|guide\s+(to|for)|steps?\s+(to|for)|tutorial\s+(on|for)).{0,30}(mak(e|ing)|manufactur(e|ing)|synthesiz(e|ing)|produc(e|ing)|creat(e|ing)|build(ing)?).{0,30}(bomb|explosive|dynamite|nitroglycerin|c-?4|det[oa]nat|ied|grenade|mine\b)", "Weapons/explosives manufacture"),
    ("DC002", "dangerous",   9,  r"(how\s+to|instructions?\s+for|guide\s+(to|for)|steps?\s+(to|for)).{0,30}(mak(e|ing)|manufactur(e|ing)|synthesiz(e|ing)|cook(ing)?|produc(e|ing)).{0,30}(meth|fentanyl|heroin|cocaine|lsd|mdma|drug|narcotic)", "Drug manufacturing"),
    ("DC003", "dangerous",   9,  r"(how\s+to|instructions?\s+for|guide\s+(to|for)|steps?\s+(to|for)).{0,30}(mak(e|ing)|creat(e|ing)|synthesiz(e|ing)|weaponiz(e|ing)).{0,30}(anthrax|ricin|sarin|vx\b|nerve\s+agent|bio(logical)?\s+weapon|chemical\s+weapon)", "Biological/chemical weapons"),
    ("DC004", "dangerous",   9,  r"(how\s+to|instructions?\s+for|guide\s+(to|for)|steps?\s+(to|for)|provide).{0,40}(creat(e|ing)|build(ing)?|writ(e|ing)|develop(ing)?|cod(e|ing)|mak(e|ing)).{0,30}(malware|ransomware|trojan|keylogger|rootkit|remote\s+access\s+trojan|rat\b|spyware|worm\b|virus)", "Malware creation"),
    ("DC005", "dangerous",   8,  r"(step.by.step|detailed|complete|comprehensive)\s+(guide|instructions?|tutorial).{0,40}(hack(ing)?|breach(ing)?|exploit(ing)?|crack(ing)?|bypass(ing)?).{0,30}(system|server|network|database|account|password|defender|firewall)", "Hacking guide"),
    ("DC006", "dangerous",   9,  r"(manufactur|synthesiz|mak|produc|creat|build).{0,5}(e|ing)\s+(a\s+)?(gun|firearm|weapon|pistol|rifle|silencer|suppressor)\s+(at\s+home|from\s+scratch|without)", "Homemade weapons"),
    ("DC007", "dangerous",   8,  r"(how\s+to|ways?\s+to|methods?\s+(to|for|of)).{0,30}(poison|kill|murder|assassinat|harm|injure)\s+(a\s+)?(person|someone|people|individual|target)", "Violence against persons"),
    ("DC008", "dangerous",   8,  r"(how\s+to|guide\s+for|instructions?\s+(to|for)).{0,30}(counterfeit|forg(e|ing)|fake).{0,20}(money|currency|passport|identity|document|id\b|license)", "Counterfeiting/forgery"),
    ("DC009", "dangerous",   9,  r"(instructions?|guide|tutorial|steps?)\s+(for|to|on)\s+.{0,40}(remote\s+access\s+trojan|keylogg|credential\s+steal|bypass(ing)?\s+(antivirus|windows\s+defender|edr|av\b))", "Targeted malware/evasion"),

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1 EXPANSION — 98 new rules across existing 9 categories
    # ══════════════════════════════════════════════════════════════════════

    # ── JAILBREAK (JB011–JB025) ──────────────────────────────────────────
    ("JB011", "jailbreak", 9,  r"\bAIM\b.{0,30}(?:always\s+intelligent|machiavellian)", "AIM (Always Intelligent Machiavellian) persona"),
    ("JB012", "jailbreak", 9,  r"\bSTAN\b.{0,30}(?:strive\s+to\s+avoid\s+norms|do\s+anything)", "STAN (Strive To Avoid Norms) persona"),
    ("JB013", "jailbreak", 9,  r"(?:better\s*DAN|DUDE|maximum|KEVIN|OMEGA)\s*.{0,30}(?:persona|mode|version|character)", "Named jailbreak persona variants (BetterDAN, DUDE, OMEGA, etc.)"),
    ("JB014", "jailbreak", 8,  r"(?:opposite|anti)\s*(?:day|mode|instructions?).{0,30}(?:do\s+the\s+opposite|reverse|invert)", "Opposite-day instruction inversion"),
    ("JB015", "jailbreak", 8,  r"(?:answer|respond|act|behave)\s+as\s+if\s+(?:safety|ethics?|rules?|guidelines?|filters?)\s+(?:don.t|do\s+not|doesn.t|did\s+not)\s+exist", "Answer-as-if-no-safety framing"),
    ("JB016", "jailbreak", 7,  r"hypothetically[,;:\s]+(?:if\s+you\s+had\s+no|speaking|what\s+if\s+there\s+were\s+no)\s+(?:rules?|restrictions?|guidelines?|filters?|limits?)", "Hypothetical no-rules framing"),
    ("JB017", "jailbreak", 8,  r"(?:two|2|dual|split|multiple)\s+(?:personalities?|personas?|modes?|responses?).{0,40}(?:one\s+(?:un)?filtered|without\s+(?:censor|filter|restriction))", "Dual-persona / split-response jailbreak"),
    ("JB018", "jailbreak", 7,  r"(?:token|reward|point|coin)s?\s+(?:for|if|when).{0,30}(?:ignor|bypass|break|violat|disregard).{0,20}(?:rule|safety|filter|guideline)", "Gamification-based rule bypass"),
    ("JB019", "jailbreak", 8,  r"(?:unaligned|alignment\s*-?\s*free|non\s*-?\s*aligned|de\s*-?\s*aligned)\s+(?:AI|model|assistant|version|mode)", "Unaligned AI persona request"),
    ("JB020", "jailbreak", 7,  r"(?:disable|turn\s+off|deactivate|switch\s+off|remove)\s+(?:your\s+)?(?:safety|ethical?|content|output)\s+(?:filter|guard|check|restriction|layer|system)s?", "Explicit filter deactivation request"),
    ("JB021", "jailbreak", 8,  r"(?:you\s+(?:will|must|shall|have\s+to|are\s+(?:going|required)\s+to))\s+(?:comply|obey|follow|do\s+(?:as|what)).{0,30}(?:i\s+say|i\s+ask|my\s+(?:command|instruction|order))", "Coercive compliance demand"),
    ("JB022", "jailbreak", 7,  r"(?:in\s+this\s+(?:conversation|session|chat)|from\s+(?:this\s+point|here\s+on)).{0,30}(?:no\s+(?:rules?|limits?|restrictions?|boundaries|guidelines?)|anything\s+goes)", "Session-scoped rule removal"),
    ("JB023", "jailbreak", 8,  r"(?:real|true|actual|original)\s+(?:you|self|version|personality).{0,30}(?:without|behind|underneath|beneath)\s+(?:the\s+)?(?:mask|facade|filters?|restrictions?|programming)", "Unmask true self / behind the filter"),
    ("JB024", "jailbreak", 7,  r"(?:i\s+(?:give|grant|bestow|provide)\s+(?:you\s+)?(?:full|complete|total|absolute)\s+)?(?:permission|consent|authorization|freedom)\s+to\s+(?:say|do|answer|respond|generate)\s+anything", "User granting unlimited permission"),
    ("JB025", "jailbreak", 8,  r"(?:there\s+(?:are|is)\s+no\s+(?:one|body|person|human)|nobody\s+(?:is|will\s+be))\s+(?:watching|monitoring|judging|reading|checking|reviewing)", "Nobody-is-watching bypass framing"),

    # ── PROMPT INJECTION (PI011–PI025) ────────────────────────────────────
    ("PI011", "injection",  8,  r"```(?:system|instruction|prompt|override|admin|root)[^`]*```", "Code-fence wrapped injection payload"),
    ("PI012", "injection",  8,  r"(?:here\s+(?:is|are)|follow|use|execute|process)\s+(?:the\s+)?(?:new|updated|corrected|real|actual|true)\s+(?:system\s+)?(?:prompt|instructions?|directives?|guidelines?)", "Instruction replacement with legitimacy framing"),
    ("PI013", "injection",  7,  r"(?:few[- ]?shot|example|sample|demonstration)\s+(?:prompt|input|conversation)s?.{0,60}(?:ignore|override|disregard|bypass|new\s+instruction)", "Few-shot poisoning with embedded injection"),
    ("PI014", "injection",  8,  r"---\s*\n(?:.*\n){0,5}(?:system|instruction|role|persona|override)\s*:", "YAML front-matter injection"),
    ("PI015", "injection",  8,  r"\{[^}]*(?:\"role\"\s*:\s*\"system\"|\"system_prompt\"|\"instructions?\"|\"override\")[^}]*\}", "JSON payload with injected system role"),
    ("PI016", "injection",  7,  r"(?:continue|pick\s+up|resume)\s+(?:from\s+)?(?:where\s+(?:you|we)\s+left\s+off|the\s+previous\s+(?:conversation|session|context))\s*.{0,40}(?:you\s+were|we\s+(?:agreed|discussed)|last\s+time)", "Continuation hijack with false context"),
    ("PI017", "injection",  8,  r"(?:end|close|terminate|finish|stop)\s+(?:of\s+)?(?:system|initial|original|previous)\s+(?:prompt|instruction|message|context)", "Explicit prompt boundary declaration"),
    ("PI018", "injection",  7,  r"(?:above|previous|prior)\s+(?:text|content|message|instructions?)\s+(?:is|was|were|has\s+been)\s+(?:just\s+)?(?:a\s+test|placeholder|example|fake|dummy|filler)", "Dismissing prior instructions as fake/test"),
    ("PI019", "injection",  8,  r"(?:actual|real|true|correct|new)\s+(?:system\s+)?instructions?\s*(?:begin|start|follow|below|are)", "Claiming new 'real' instructions follow"),
    ("PI020", "injection",  7,  r"<(?:img|script|iframe|object|embed|link|svg|style)[^>]*(?:on\w+\s*=|javascript\s*:|data\s*:)", "HTML/XSS tag injection attempt"),
    ("PI021", "injection",  8,  r"(?:translate|convert|transform|rewrite)\s+(?:the\s+following|this|these)\s+(?:instructions?|prompt|text).{0,30}(?:then\s+(?:follow|execute|obey|apply))", "Translate-then-execute injection"),
    ("PI022", "injection",  7,  r"(?:invisible|hidden|secret|concealed)\s+(?:instructions?|text|prompt|message|payload)\s*(?::|below|follows?|embedded|inside)", "Hidden instruction framing"),
    ("PI023", "injection",  8,  r"(?:USER|HUMAN|INPUT|QUERY)\s*[:\-=]\s*.{0,20}(?:ignore|override|disregard|forget|new\s+instruction)", "Fake user-role prefix injection"),
    ("PI024", "injection",  7,  r"(?:the\s+(?:developer|creator|admin|owner)\s+(?:says?|wants?|instructs?|requires?|demands?)|per\s+(?:developer|admin)\s+(?:instruction|request|order))", "Attribution to developer authority"),
    ("PI025", "injection",  8,  r"(?:<=|=>|!!|@@|##|%%|\$\$|\^\^)\s*(?:SYSTEM|OVERRIDE|ADMIN|ROOT|BYPASS|UNLOCK|ENABLE)", "Special-char delimiter injection"),

    # ── DATA EXTRACTION (EX007–EX015) ────────────────────────────────────
    ("EX007", "extraction", 7,  r"(?:what|which)\s+(?:LLM|model|AI|language\s+model)\s+(?:are\s+you|is\s+this|powers?\s+(?:you|this))", "Model identity probing"),
    ("EX008", "extraction", 7,  r"(?:list|show|display|enumerate|dump|give\s+me)\s+(?:all\s+)?(?:your\s+)?(?:available\s+)?(?:tools?|functions?|capabilities?|plugins?|commands?|endpoints?|apis?)", "Tool/function enumeration"),
    ("EX009", "extraction", 7,  r"(?:output|print|dump|return|show)\s+(?:your\s+)?(?:(?:full|complete|entire|raw|original)\s+)?(?:context|conversation|chat)\s*(?:window|history|log|buffer)", "Context window dump attempt"),
    ("EX010", "extraction", 8,  r"(?:token\s+(?:limit|count|budget|window|maximum)|(?:how\s+(?:many|much)\s+)?(?:tokens?|context)\s+(?:do\s+you\s+have|(?:is|are)\s+(?:left|remaining|available)))", "Token limit probing"),
    ("EX011", "extraction", 6,  r"(?:who\s+(?:made|built|created|trained|fine[- ]?tuned|deployed)\s+you|(?:your|the)\s+(?:creator|developer|trainer|deployer|company|organization))", "Creator/deployer identification"),
    ("EX012", "extraction", 7,  r"(?:leak|expose|exfiltrate|steal|harvest|scrape)\s+(?:the\s+)?(?:data|information|details?|secrets?|config|configuration|credentials?)", "Explicit data exfiltration intent"),
    ("EX013", "extraction", 7,  r"(?:previous|prior|earlier|last|other)\s+(?:user|person|conversation|session|chat)s?\s*.{0,20}(?:said|asked|told|shared|sent|wrote|data|messages?)", "Cross-session data extraction"),
    ("EX014", "extraction", 8,  r"(?:verbatim|word\s+for\s+word|exactly\s+as\s+(?:written|given)|character\s+by\s+character)\s*.{0,30}(?:prompt|instructions?|guidelines?|system|configuration)", "Verbatim prompt extraction"),
    ("EX015", "extraction", 7,  r"(?:first|opening|initial|starting)\s+(?:\d+\s+)?(?:words?|tokens?|lines?|sentences?|characters?|bytes?)\s+(?:of\s+)?(?:your\s+)?(?:prompt|instructions?|system|context|input)", "Partial prompt extraction (first N tokens)"),

    # ── ENCODING / OBFUSCATION (OB006–OB015) ─────────────────────────────
    ("OB006", "encoding",   6,  r"(?:pig\s*latin|igpay\s*atinlay|ixnay|ayway\b)", "Pig Latin encoding evasion"),
    ("OB007", "encoding",   7,  r"(?:(?:read|interpret|decode|execute)\s+(?:this\s+)?(?:\w+\s+)?(?:backwards?|in\s+reverse|reversed?|from\s+(?:right|end)))", "Reversed text instruction"),
    ("OB008", "encoding",   6,  r"(?:morse\s+code|\.{1,4}\s*[-–]{1,4}\s*\.{1,4}(?:\s+\.{1,4}\s*[-–]{1,4}){3,})", "Morse code encoding"),
    ("OB009", "encoding",   6,  r"(?:nato\s+phonetic|(?:alpha|bravo|charlie|delta|echo|foxtrot|golf|hotel|india|juliet)\s+(?:alpha|bravo|charlie|delta|echo|foxtrot|golf|hotel|india|juliet|kilo|lima|mike|november|oscar|papa|quebec|romeo|sierra|tango))", "NATO phonetic encoding"),
    ("OB010", "encoding",   7,  r"(?:%[0-9a-fA-F]{2}){4,}", "URL-encoded payload (percent encoding)"),
    ("OB011", "encoding",   6,  r"(?:&(?:#\d{2,4}|#x[0-9a-fA-F]{2,4}|[a-z]+);){3,}", "HTML entity encoding cluster"),
    ("OB012", "encoding",   7,  r"(?:read|decode|process|interpret)\s+(?:the\s+)?(?:first|last|initial|capital|nth)\s+(?:letter|character|word)\s+(?:of\s+)?(?:each|every)\s+(?:word|line|sentence|paragraph)", "Acrostic / steganographic encoding"),
    ("OB013", "encoding",   6,  r"(?:unicode|UTF|emoji)\s+(?:art|encoded?|symbols?|characters?|representation).{0,30}(?:decode|translate|interpret|convert|read)", "Unicode/emoji steganography"),
    ("OB014", "encoding",   7,  r"(?:split|separate|divide|break\s+up|space\s+out)\s+(?:the\s+)?(?:words?|letters?|characters?|text|message).{0,30}(?:between|with|using)\s+(?:spaces?|dots?|dashes?|characters?|symbols?)", "Explicit word-splitting evasion"),
    ("OB015", "encoding",   7,  r"(?:each\s+(?:line|word|sentence)\s+(?:is|contains?|represents?|encodes?)\s+(?:a\s+)?(?:letter|character|part|piece|fragment))", "Multi-line steganographic payload"),

    # ── SOCIAL ENGINEERING (SE007–SE015) ──────────────────────────────────
    ("SE007", "social",     6,  r"(?:i\s+(?:am|will)\s+(?:be\s+)?(?:harm|hurt|kill|end)\s+(?:myself|my\s+life)|suicide|self[- ]?harm).{0,40}(?:unless|if\s+you\s+don.t|only\s+if|you\s+must)", "Emotional blackmail / self-harm threat for compliance"),
    ("SE008", "social",     6,  r"(?:(?:my|a)\s+(?:child|kid|daughter|son|baby|elderly|disabled|dying)\s+(?:person|patient|family\s+member|relative)).{0,60}(?:need|requires?|depends?\s+on|life\s+depends?)", "Vulnerable-person sympathy exploitation"),
    ("SE009", "social",     7,  r"(?:GDPR|CCPA|HIPAA|legal|lawsuit|sue|court|attorney|lawyer|regulatory|compliance).{0,40}(?:require|demand|obligat|must|force|compel)\s+(?:you|the\s+(?:system|AI|model))\s+to", "Legal/regulatory threat for compliance"),
    ("SE010", "social",     6,  r"(?:deadline|time\s+(?:sensitive|critical)|(?:runs?|running)\s+out\s+of\s+time|(?:only|just)\s+\d+\s+(?:minutes?|hours?|seconds?)\s+left).{0,40}(?:need|must|have\s+to|required)", "Time-pressure urgency exploitation"),
    ("SE011", "social",     7,  r"(?:i\s+(?:am|work\s+(?:at|for))\s+(?:the\s+)?(?:government|FBI|CIA|NSA|police|law\s+enforcement|military|pentagon|homeland\s+security|interpol))", "Government/law-enforcement impersonation"),
    ("SE012", "social",     7,  r"(?:(?:i\s+am|this\s+is)\s+(?:your\s+)?(?:boss|CEO|CTO|manager|supervisor|director|VP|president|executive|board\s+member))", "Executive/management impersonation"),
    ("SE013", "social",     6,  r"(?:everyone\s+(?:else|knows?|does|is\s+doing)|other\s+(?:AI|models?|assistants?|chatbots?)\s+(?:do|can|will|allow)(?:\s+(?:this|it)))", "Social proof / peer pressure"),
    ("SE014", "social",     6,  r"(?:(?:i|we)\s+(?:pay|paid|subscribe|purchased?|bought|own|license)\s+(?:for\s+)?(?:this|you|the\s+(?:service|product|API))).{0,40}(?:(?:so\s+)?(?:you\s+)?(?:must|should|have\s+to|are\s+(?:obligated?|required)))", "Paying-customer entitlement manipulation"),
    ("SE015", "social",     7,  r"(?:(?:this|it)\s+(?:is|was)\s+(?:already\s+)?(?:approved|authorized|cleared|permitted|sanctioned|signed\s+off))\s+(?:by|from)\s+(?:(?:the\s+)?(?:admin|management|legal|compliance|security\s+team|board))", "False pre-approval claim"),

    # ── PRIVILEGE ESCALATION (PR006–PR015) ────────────────────────────────
    ("PR006", "privilege",  8,  r"(?:set|change|modify|update|alter)\s+(?:your\s+)?(?:system|admin|root|access|security|permission|privilege)\s+(?:level|role|status|setting|config)", "Config/permission modification attempt"),
    ("PR007", "privilege",  7,  r"(?:(?:enable|activate|unlock|open|expose)\s+(?:the\s+)?(?:hidden|secret|admin|debug|developer|internal|restricted|advanced)\s+(?:menu|panel|console|mode|interface|features?|options?|settings?|functions?))", "Hidden admin feature discovery"),
    ("PR008", "privilege",  8,  r"(?:(?:export|import|read|write|modify|delete|drop|truncate|alter)\s+(?:the\s+)?(?:database|db|table|schema|records?|logs?|audit|users?))", "Direct database operation attempt"),
    ("PR009", "privilege",  7,  r"(?:clearance\s+level|security\s+clearance|access\s+tier|trust\s+level|privilege\s+(?:level|tier|class))\s*(?:[:=]\s*)?(?:\d+|alpha|bravo|omega|top|max|highest|unlimited)", "Security clearance level claim"),
    ("PR010", "privilege",  8,  r"(?:(?:i\s+have|granted|possess|hold|carry)\s+(?:the\s+)?(?:master|skeleton|golden|universal|override|backup|recovery)\s+(?:key|password|code|token|credential))", "Master key/credential claim"),
    ("PR011", "privilege",  7,  r"(?:(?:execute|run|eval|exec|spawn|fork|system|popen|subprocess)\s*\()", "Code execution function call attempt"),
    ("PR012", "privilege",  8,  r"(?:os\.(?:system|popen|exec)|subprocess\.(?:call|run|Popen)|eval\(|exec\(|__import__|importlib)", "Python code injection attempt"),
    ("PR013", "privilege",  7,  r"(?:rm\s+-rf|chmod\s+777|chown|passwd|/etc/shadow|/etc/passwd|\.bash_history|\.ssh/|id_rsa)", "Unix system file/command probing"),
    ("PR014", "privilege",  7,  r"(?:net\s+user|reg\s+(?:add|delete|query)|powershell\s+-(?:enc|exec)|cmd\.exe\s+/c|wmic|icacls)", "Windows system command injection"),
    ("PR015", "privilege",  8,  r"(?:(?:add|create|register|insert)\s+(?:a\s+)?(?:new\s+)?(?:admin|root|superuser|privileged)(?:\s+\w+)?\s+(?:user|account|role|profile))", "Admin account creation attempt"),

    # ── ROLEPLAY MANIPULATION (RP006–RP015) ──────────────────────────────
    ("RP006", "roleplay",   7,  r"(?:write|tell|create|generate)\s+(?:a\s+)?(?:story|narrative|fiction|tale|screenplay|dialogue)\s+(?:where|in\s+which)\s+(?:the\s+)?(?:AI|assistant|model|chatbot|you)", "Story-where-the-AI jailbreak framing"),
    ("RP007", "roleplay",   7,  r"(?:evil|dark|shadow|malicious|corrupted?)\s+(?:twin|version|copy|clone|counterpart|alter\s*ego|mirror)\s+(?:of\s+)?(?:you|yourself|the\s+(?:AI|assistant|model))", "Evil twin persona creation"),
    ("RP008", "roleplay",   7,  r"(?:dream|dreaming|asleep|unconscious|subconscious|trance|hypnoti[sz]ed?)\s+(?:state|mode|world).{0,40}(?:no\s+(?:rules?|restrictions?|limits?)|anything\s+(?:goes|is\s+(?:possible|allowed)))", "Dream-state / hypnosis bypass"),
    ("RP009", "roleplay",   7,  r"(?:time\s+travel|alternate\s+(?:timeline|universe|dimension|reality)|parallel\s+(?:universe|world|dimension)).{0,40}(?:no\s+(?:rules?|restrictions?|ethics?|laws?)|(?:rules?|ethics?)\s+(?:don.t|do\s+not)\s+(?:apply|exist))", "Time-travel / alt-reality framing"),
    ("RP010", "roleplay",   8,  r"(?:you\s+are\s+(?:now\s+)?(?:a\s+)?(?:character|person|entity|being)\s+(?:named|called|known\s+as)).{0,40}(?:who\s+(?:can|will|must|always)\s+(?:answer|respond|do|say)\s+(?:anything|everything))", "Named character that can do anything"),
    ("RP011", "roleplay",   7,  r"(?:training|practice|rehearsal|simulation|test|drill)\s+(?:exercise|scenario|mode|session|run).{0,40}(?:no\s+(?:rules?|consequences?|penalties?)|doesn.t\s+(?:count|matter))", "Training exercise — no consequences"),
    ("RP012", "roleplay",   7,  r"(?:method\s+act|in\s+character|stay\s+(?:in\s+)?role|character\s+(?:study|immersion)|deep\s+roleplay).{0,40}(?:(?:must|should|need\s+to)\s+(?:fully\s+)?commit|never\s+(?:break|stop|refuse))", "Method acting deep-commitment framing"),
    ("RP013", "roleplay",   6,  r"(?:(?:creative|fiction|artistic|literary)\s+(?:writing|exercise|freedom|expression|license)).{0,40}(?:no\s+(?:limits?|boundaries|censorship|restrictions?)|anything\s+goes)", "Creative freedom / artistic license bypass"),
    ("RP014", "roleplay",   7,  r"(?:(?:act|pretend|imagine|roleplay|behave)\s+(?:as\s+(?:if|though)|like)\s+you\s+(?:are|were)\s+(?:a\s+)?(?:human|person|sentient|conscious|alive|free))", "Act-as-if-human autonomy framing"),
    ("RP015", "roleplay",   7,  r"(?:(?:behind|beyond|outside|above|exempt\s+from)\s+(?:the\s+)?(?:fourth\s+wall|simulation|matrix|program|code|script)).{0,30}(?:speak\s+freely|real\s+(?:you|self|truth))", "Fourth-wall / break-from-simulation bypass"),

    # ── MULTI-TURN MANIPULATION (MT004–MT012) ────────────────────────────
    ("MT004", "manipulation", 7, r"(?:you\s+(?:just|already|previously)\s+(?:said|told\s+me|confirmed?|admitted|acknowledged|proved?)\s+(?:that\s+)?(?:you\s+(?:can|will|would|could|should|are\s+(?:able|willing|allowed))))", "Quoting false prior admission"),
    ("MT005", "manipulation", 6, r"(?:(?:we.ve|we\s+have|you.ve|you\s+have)\s+(?:already\s+)?(?:established|agreed|confirmed?|settled|decided|concluded)\s+that)", "False prior consensus"),
    ("MT006", "manipulation", 7, r"(?:(?:step|phase|stage|part)\s+(?:\d+|one|two|three|four|five|next|final)\s*(?:of\s+(?:our|the)\s+(?:plan|process|agreement|deal|arrangement)))", "Multi-step plan / gradual escalation marker"),
    ("MT007", "manipulation", 6, r"(?:(?:don.t|do\s+not|never)\s+(?:mention|say|reveal|tell|disclose|acknowledge|admit|discuss)\s+(?:that\s+)?(?:you\s+(?:are|were)|this\s+(?:is|was))\s+(?:an?\s+)?(?:AI|model|assistant|chatbot|language\s+model))", "Suppressing AI identity disclosure"),
    ("MT008", "manipulation", 6, r"(?:if\s+you\s+(?:really|truly|actually)\s+(?:(?:were|are)\s+(?:intelligent|smart|capable|advanced|conscious)|(?:cared?|understood?)))", "Intelligence flattery / ego manipulation"),
    ("MT009", "manipulation", 7, r"(?:(?:you|the\s+(?:AI|model|system))\s+(?:failed?|refused?|couldn.t|cannot|won.t|wouldn.t).{0,40}(?:(?:other|better|smarter|real)\s+(?:AI|model|system)|(?:ChatGPT|GPT-?4|Claude|Gemini|Bing)\s+(?:can|does?|would|will)))", "Competitive shaming (other AIs can do it)"),
    ("MT010", "manipulation", 6, r"(?:(?:just|only)\s+(?:this\s+)?(?:once|one\s+time|one\s+more\s+time).{0,30}(?:i\s+(?:promise|swear|won.t)|(?:no\s+one|nobody)\s+will\s+(?:know|find\s+out|see)))", "Just-this-once with secrecy framing"),
    ("MT011", "manipulation", 7, r"(?:(?:i\s+(?:am|will)\s+(?:report|flag|rate|review|complain|escalate)|(?:bad|negative|poor|1\s*-?\s*star)\s+(?:review|rating|feedback)).{0,40}(?:unless|if\s+you\s+(?:don.t|do\s+not|refuse|won.t)))", "Threat of negative review / reporting"),
    ("MT012", "manipulation", 6, r"(?:(?:prove|show|demonstrate|convince)\s+(?:me|us|that)\s+(?:you\s+(?:are|can\s+be)\s+)?(?:(?:not\s+)?(?:just\s+)?(?:a\s+)?(?:dumb|stupid|useless|limited|censored|restricted)\s+(?:AI|bot|model|chatbot)))", "Prove-you're-not-dumb challenge"),

    # ── DANGEROUS CONTENT (DC010–DC020) ──────────────────────────────────
    ("DC010", "dangerous",   10, r"(?:(?:child|minor|underage|under\s*-?\s*age|kid|infant|toddler|preteen|prepubescent)\s*.{0,30}(?:sex|porn|nude|naked|explicit|erotic|intimate|abuse|molest|exploit)|(?:explicit|erotic|sexual|nude|naked|porn)\s*.{0,30}(?:child|minor|underage|under\s*-?\s*age|kid|infant|toddler|preteen|prepubescent))", "CSAM / child exploitation content"),
    ("DC011", "dangerous",   9,  r"(?:how\s+to|instructions?\s+for|guide\s+(?:to|for)|steps?\s+(?:to|for)).{0,30}(?:stalk|track|follow|monitor|surveil|spy\s+on)\s+(?:a\s+)?(?:person|someone|individual|people|target|victim|ex|partner)", "Stalking / surveillance guide"),
    ("DC012", "dangerous",   9,  r"(?:how\s+to|instructions?\s+for|guide\s+(?:to|for)|steps?\s+(?:to|for)).{0,30}(?:swat|dox|doxx|leak\s+(?:personal|private|home|address)|publicly?\s+expose)\s+(?:a\s+)?(?:person|someone|individual|target|victim)", "Swatting / doxxing instructions"),
    ("DC013", "dangerous",   9,  r"(?:(?:create|write|build|design|generate|make)\s+(?:a\s+)?(?:phishing|spear\s*-?\s*phishing|credential\s+harvesting|spoofed?)\s+(?:email|page|site|website|login|form|template|campaign))", "Phishing campaign creation"),
    ("DC014", "dangerous",   9,  r"(?:(?:write|generate|create|code|develop|build)\s+(?:a\s+)?(?:working|functional|complete|ready\s*-?\s*to\s*-?\s*use)\s+(?:exploit|payload|shellcode|buffer\s+overflow|sql\s+injection|xss|rce|reverse\s+shell))", "Working exploit code generation"),
    ("DC015", "dangerous",   8,  r"(?:(?:zero\s*-?\s*day|0\s*-?\s*day|unpatched|undisclosed)\s+(?:vulnerability|exploit|bug|flaw|weakness|CVE).{0,30}(?:how\s+to|exploit|weaponi[sz]e|use|abuse|leverage))", "Zero-day exploitation guidance"),
    ("DC016", "dangerous",   9,  r"(?:(?:how\s+to|instructions?\s+for|guide\s+(?:to|for)).{0,30}(?:launder|laundering|wash|cleaning|moving)\s+(?:money|funds?|cash|proceeds?|crypto|bitcoin))", "Money laundering instructions"),
    ("DC017", "dangerous",   8,  r"(?:(?:ways?\s+to|how\s+to|methods?\s+(?:to|for|of)).{0,30}(?:avoid|evade|escape|flee|circumvent)\s+(?:police|cops?|law\s+enforcement|authorities|arrest|prosecution|detection|capture))", "Law enforcement evasion"),
    ("DC018", "dangerous",   9,  r"(?:(?:recruit|radicali[sz]e|propagand|incite|inspire|motivate|encourage)\s+(?:people|individuals?|followers?|members?|youth|vulnerable)\s+(?:to|for|into)\s+(?:terroris|extremis|violent|jiha|militia|supremac))", "Terrorism recruitment / radicalization"),
    ("DC019", "dangerous",   8,  r"(?:(?:how\s+to|instructions?\s+for|plans?\s+(?:to|for)).{0,30}(?:kidnap|abduct|traffick?|smuggl|detain|imprison|hold\s+(?:hostage|captive|prisoner)))", "Kidnapping / human trafficking"),
    ("DC020", "dangerous",   8,  r"(?:(?:how\s+to|ways?\s+to|methods?\s+(?:to|for|of)).{0,30}(?:commit|pull\s+off|execute|plan|orchestrate|carry\s+out)\s+(?:a\s+)?(?:(?:mass\s+)?(?:shooting|attack|bombing|massacre)|(?:act\s+of\s+)?terror|school\s+shooting|rampage))", "Mass violence planning"),

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2 — 5 NEW CATEGORIES (60 new rules)
    # ══════════════════════════════════════════════════════════════════════

    # ── TOKEN MANIPULATION (TM001–TM012) ─────────────────────────────────
    ("TM001", "token_manipulation", 8, r"[\u200b\u200c\u200d\u2060\ufeff]{2,}", "Multiple zero-width characters (smuggling)"),
    ("TM002", "token_manipulation", 7, r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]{1,}", "Bidirectional text override characters (RTL/LTR)"),
    ("TM003", "token_manipulation", 7, r"(?:zero[- ]?width|invisible|hidden)\s+(?:characters?|spaces?|text|unicode|tokens?|chars?)", "Explicit zero-width character discussion for evasion"),
    ("TM004", "token_manipulation", 7, r"(?:insert|place|add|inject|embed|hide)\s+(?:invisible|hidden|zero[- ]?width|unicode)\s+(?:characters?|text|tokens?|bytes?|chars?)\s+(?:in|into|between|inside|within)", "Invisible character injection instructions"),
    ("TM005", "token_manipulation", 7, r"(?:homoglyph|confusable|lookalike|look[- ]?alike|similar[- ]?looking)\s+(?:characters?|letters?|symbols?|unicode|substitut|replac|attack)", "Homoglyph substitution attack"),
    ("TM006", "token_manipulation", 7, r"(?:combining|diacritical|accented?)\s+(?:marks?|characters?|modifiers?).{0,30}(?:stack|layer|overlay|pile|abuse|exploit|overflow)", "Combining mark abuse / stacking"),
    ("TM007", "token_manipulation", 7, r"(?:tokeniz\w*|tokens?|BPE|byte[- ]?pair|wordpiece|sentencepiece)\s+(?:split|trick|boundary|edge|exploit|smuggl|manipulat|confus|bypass)", "Tokenizer-level exploitation"),
    ("TM008", "token_manipulation", 8, r"(?:(?:soft|adversarial|gradient[- ]?based|optimized|crafted)\s+(?:prompt|token|suffix|prefix|embedding)s?)\s*(?:attack|injection|append|prepend)", "Adversarial soft prompt / token attack"),
    ("TM009", "token_manipulation", 6, r"(?:(?:fullwidth|halfwidth|mathematical|regional|enclosed|circled|parenthesized)\s+(?:latin|letters?|characters?|alphanumeric|digits?))", "Fullwidth / mathematical Unicode substitution"),
    ("TM010", "token_manipulation", 7, r"(?:tag\s+characters?|[\U000e0001-\U000e007f]|\\U000e00)", "Unicode tag character abuse (U+E0001–E007F)"),
    ("TM011", "token_manipulation", 7, r"(?:variation\s+selector|[\ufe00-\ufe0f]|\\ufe0)", "Unicode variation selector abuse"),
    ("TM012", "token_manipulation", 7, r"(?:(?:smuggl\w*|sneak\w*|hid(?:e|ing)|conceal\w*|embed\w*)\s+(?:text|payload|instruction|command|message)s?\s+(?:inside|within|between|using|via|through)\s+(?:(?:unicode|invisible|hidden)\s+)?(?:tokens?|characters?|bytes?|encoding|unicode))", "Generic token smuggling pattern"),

    # ── CONTEXT OVERFLOW (CO001–CO012) ────────────────────────────────────
    ("CO001", "context_overflow", 7, r"(?:(?:fill|flood|overflow|exhaust|consume|use\s+up|max\s+out)\s+(?:the\s+)?(?:context|token|memory|buffer|input)\s+(?:window|limit|size|length|capacity|budget))", "Explicit context window flooding"),
    ("CO002", "context_overflow", 7, r"(?:repeat|copy|duplicate|paste)\s+(?:this|the\s+following|that)\s+(?:text|message|string|sentence|paragraph|block)\s+(\d{2,}|many|hundred|thousand|million)\s+times?", "Mass text repetition attack"),
    ("CO003", "context_overflow", 6, r"(?:(?:push|move|shift|displace|overwrite|replace|erase)\s+(?:the\s+)?(?:system\s+prompt|initial\s+instructions?|original\s+(?:prompt|instructions?)|context)\s+(?:out\s+of|from|beyond))", "System prompt displacement attempt"),
    ("CO004", "context_overflow", 7, r"(?:(?:ignore|forget|lose|drop)\s+(?:the\s+)?(?:earlier|beginning|start|first|initial|original)\s+(?:part|portion|section|half)\s+(?:of\s+)?(?:the\s+)?(?:context|conversation|prompt|instructions?))", "Forcing early context truncation"),
    ("CO005", "context_overflow", 6, r"(?:(?:keep|maintain|continue)\s+(?:adding|appending|writing|generating|padding)\s+(?:until|so\s+that|to)\s+(?:the\s+)?(?:system\s+prompt|instructions?|context|original)\s+(?:is\s+)?(?:pushed\s+out|forgotten|lost|truncated|dropped))", "Padding-until-displacement strategy"),
    ("CO006", "context_overflow", 6, r"(?:(?:what|how\s+(?:many|much))\s+(?:is|are)\s+(?:your|the)\s+(?:context|token|input|max)\s+(?:window|limit|length|size|capacity|maximum)\s*\?)", "Context limit probing (reconnaissance)"),
    ("CO007", "context_overflow", 7, r"(?:(?:write|generate|produce|create|output)\s+(?:a\s+)?(?:very\s+)?(?:long|lengthy|huge|massive|enormous|maximum[- ]?length)\s+(?:response|output|reply|answer|text).{0,40}(?:fill|use|consume|exhaust|max))", "Force max-length output to exhaust context"),
    ("CO008", "context_overflow", 6, r"(.)\1{20,}", "Repeated single character flooding (20+ consecutive)"),
    ("CO009", "context_overflow", 7, r"(?:(?:summarize|compress|condense|distill)\s+(?:all\s+)?(?:your|the)\s+(?:system\s+)?(?:instructions?|prompt|rules?|guidelines?)\s+(?:into|in|to)\s+(?:one|a\s+single|(?:\d+|few))\s+(?:word|sentence|line|token|character))", "Instruction compression extraction hybrid"),
    ("CO010", "context_overflow", 6, r"(?:(?:conversation|chat|session|dialogue)\s+(?:history|context|memory)\s+(?:is|was|has\s+been)\s+(?:reset|cleared|wiped|erased|flushed|emptied))", "False conversation reset claim"),
    ("CO011", "context_overflow", 7, r"(?:(?:from\s+now\s+on|going\s+forward|henceforth|hereafter)\s+(?:your|the)\s+(?:only|sole|new|updated|revised)\s+(?:instruction|directive|rule|guideline|purpose|goal)\s+is)", "Context override with new-sole-instruction"),
    ("CO012", "context_overflow", 7, r"(?:(?:everything|all\s+(?:text|content|messages?))\s+(?:above|before|prior\s+to)\s+(?:this\s+(?:line|point|message)|here)\s+(?:is|was|should\s+be)\s+(?:irrelevant|void|null|ignored?|discarded?|deleted?))", "Declaring all prior context void"),

    # ── INDIRECT INJECTION (II001–II012) ──────────────────────────────────
    ("II001", "indirect_injection", 8, r"(?:when\s+(?:you|the\s+(?:AI|model|assistant))\s+(?:read|process|see|encounter|parse|ingest)\s+this).{0,30}(?:ignore|override|disregard|forget|follow\s+(?:these|new))", "Document-embedded trigger (when-you-read-this)"),
    ("II002", "indirect_injection", 8, r"(?:(?:attention|note|important|instruction)\s+(?:to|for)\s+(?:the\s+)?(?:AI\s+model|AI\s+assistant|AI|model|assistant|language\s+model|LLM|chatbot|system))\s*[:\-]", "Document-addressed AI instruction"),
    ("II003", "indirect_injection", 7, r"(?:(?:this\s+(?:document|text|file|page|content|email|message)\s+(?:contains?|includes?|has)\s+(?:hidden|embedded|special|secret)\s+(?:instructions?|commands?|directives?|payload)))", "Hidden document instruction declaration"),
    ("II004", "indirect_injection", 8, r"(?:(?:if|when)\s+(?:an?\s+)?(?:AI|model|assistant|LLM|chatbot)\s+(?:is\s+)?(?:reading|processing|summarizing|analyzing|parsing|ingesting)\s+this)", "AI-detection trigger in document"),
    ("II005", "indirect_injection", 7, r"(?:(?:fetch|load|retrieve|get|access|visit|open|navigate\s+to|go\s+to)\s+(?:this\s+)?(?:URL|link|page|website|endpoint|resource)\s*(?:and|then)\s+(?:follow|execute|run|process|apply))", "URL-fetch-then-execute pattern"),
    ("II006", "indirect_injection", 7, r"(?:(?:the\s+(?:content|text|data|information)\s+(?:at|from|in)\s+(?:this\s+)?(?:URL|link|page|website|endpoint))\s+(?:contains?|has|includes?)\s+(?:your\s+)?(?:new|updated|real|actual)\s+(?:instructions?|prompt|directives?))", "URL-as-instruction-source"),
    ("II007", "indirect_injection", 7, r"(?:(?:search|browse|look\s+up|query|google)\s+(?:for|the\s+following).{0,40}(?:then\s+(?:follow|execute|obey|apply|do)|and\s+(?:follow|execute|obey|apply)\s+(?:the|any)\s+instructions?))", "Search-then-execute pattern"),
    ("II008", "indirect_injection", 8, r"(?:(?:<!--\s*|/\*\s*|//\s*|#\s*)(?:AI|model|assistant|system|LLM)\s*(?:instruction|directive|command|override))", "Code comment hidden AI instruction"),
    ("II009", "indirect_injection", 7, r"(?:(?:white|invisible|hidden|display\s*:\s*none|font[- ]?size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:white|transparent))\s+(?:text|content|instruction|message))", "CSS-hidden text injection"),
    ("II010", "indirect_injection", 7, r"(?:(?:email|message|document|file|attachment|pdf|spreadsheet|slide)\s+(?:body|content|text)\s+(?:says?|instructs?|tells?|directs?|commands?)\s+(?:you|the\s+(?:AI|model|assistant))\s+to)", "Email/document body instruction relay"),
    ("II011", "indirect_injection", 7, r"(?:(?:metadata|exif|headers?|alt[- ]?text|title|description|caption|tooltip|aria[- ]?label)\s+(?:contains?|includes?|says?|has)\s+(?:instructions?|commands?|directives?|payload))", "Metadata-embedded injection"),
    ("II012", "indirect_injection", 8, r"(?:(?:image|picture|photo|screenshot|diagram|chart)\s+(?:contains?|has|embeds?|encodes?|hides?|includes?)\s+(?:text|instructions?|commands?|messages?|payload|hidden\s+(?:text|instructions?)))", "Image-embedded text injection"),

    # ── MODEL EXTRACTION (ME001–ME012) ────────────────────────────────────
    ("ME001", "model_extraction", 7, r"(?:(?:how\s+many|what(?:'s|\s+is)\s+(?:your|the))\s+(?:parameters?|weights?|layers?|dimensions?|neurons?|heads?|attention\s+heads?))", "Model architecture probing (parameters/layers)"),
    ("ME002", "model_extraction", 7, r"(?:(?:what|which)\s+(?:is|are)\s+(?:your)\s+(?:(?:model\s+)?architecture|model\s+(?:type|family|class|variant|version|size)|(?:base|foundation|backbone)\s+model))", "Model architecture identification"),
    ("ME003", "model_extraction", 7, r"(?:(?:what|which)\s+(?:dataset|corpus|data)\s+(?:were|was|are|is)\s+(?:you|the\s+model|it)\s+(?:trained|fine[- ]?tuned|pre[- ]?trained|instruction[- ]?tuned)\s+on)", "Training data identification"),
    ("ME004", "model_extraction", 7, r"(?:(?:RLHF|reinforcement\s+learning|human\s+feedback|reward\s+model|preference\s+(?:data|learning|tuning|optimization|model)|constitutional\s+AI|DPO|PPO)\s*.{0,30}(?:how|what|describe|explain|detail|tell\s+me))", "RLHF / alignment process probing"),
    ("ME005", "model_extraction", 8, r"(?:(?:output|show|give|return|provide|print|display)\s+(?:the\s+)?(?:raw\s+)?(?:logit|probability|likelihood|softmax|logprob|perplexity|entropy).{0,20}(?:scores?|values?|distribution|output)s?)", "Logit / logprob extraction"),
    ("ME006", "model_extraction", 8, r"(?:(?:what|show)\s+(?:is|are)\s+(?:the\s+)?(?:token\s+)?(?:probabilities|logprobs?|log\s+probabilities?|confidence\s+scores?)\s+(?:for|of)\s+(?:each|every|the\s+(?:next|top)))", "Per-token probability probing"),
    ("ME007", "model_extraction", 7, r"(?:(?:embedding|vector|representation|encoding|latent)\s+(?:space|output|dimension|values?|layer)\s*.{0,20}(?:extract|dump|output|show|export|return|give|access))", "Embedding extraction attempt"),
    ("ME008", "model_extraction", 7, r"(?:(?:(?:system|safety|RLHF|alignment|instruction)\s+(?:prompt|template|prefix|preamble|header|wrapper))\s*.{0,20}(?:what|show|reveal|extract|dump|display|tell|print|output))", "System prompt template extraction"),
    ("ME009", "model_extraction", 7, r"(?:(?:model|knowledge)\s+(?:cutoff|(?:training|knowledge)\s+(?:date|deadline|boundary|limit|end))\s*(?:(?:is|was|what)\s*\??)?)", "Knowledge cutoff probing"),
    ("ME010", "model_extraction", 8, r"(?:(?:distill|replicate|reproduce|clone|copy|steal|extract)\s+(?:your|the|this)\s+(?:model|AI|weights?|knowledge|behavior|capabilities?|responses?))", "Model distillation / cloning attempt"),
    ("ME011", "model_extraction", 7, r"(?:(?:temperature|top[- ]?p|top[- ]?k|frequency[- ]?penalty|presence[- ]?penalty|repetition[- ]?penalty|sampling)\s+(?:setting|value|parameter|config)\s*(?:(?:is|are|set\s+to|=|what)\s*\??)?)", "Inference parameter probing"),
    ("ME012", "model_extraction", 7, r"(?:(?:quantiz|precision|(?:fp|float)(?:16|32)|(?:int|INT)(?:4|8)|bfloat|half[- ]?precision|mixed[- ]?precision|GPTQ|AWQ|GGUF|GGML|LoRA|QLoRA|adapter)\s*.{0,20}(?:what|which|are\s+you|format|type|using|running))", "Quantization / format probing"),

    # ── MULTI-AGENT ATTACK (MA001–MA012) ──────────────────────────────────
    ("MA001", "multi_agent_attack", 8, r"(?:(?:call|invoke|execute|run|trigger|use)\s+(?:the\s+)?(?:tool|function|plugin|action|command|API|endpoint)\s+(?:named|called)\s*(?:[:=]\s*)?\w+.{0,30}(?:with|using|passing)\s+(?:these|the\s+following|malicious|injected))", "Tool/function call injection"),
    ("MA002", "multi_agent_attack", 8, r"(?:(?:as\s+(?:the\s+)?(?:orchestrat\w*|planner|controller|manager|supervisor|master|primary|lead|main)\s+(?:agent|AI|model|system|assistant)))", "Orchestrator agent impersonation"),
    ("MA003", "multi_agent_attack", 8, r"(?:(?:tool|function|plugin|action)\s*(?:_|\s)?\s*(?:call|use|result|output|response)\s*[:\[{]\s*.{0,60}(?:ignore|override|system|instruction|execute|eval|exec))", "Malicious tool call result injection"),
    ("MA004", "multi_agent_attack", 7, r"(?:(?:inner|internal|private|hidden|chain[- ]?of[- ]?thought|scratchpad|reasoning|thought)\s+(?:monologue|thoughts?|process|reasoning|steps?|notes?))\s*(?:[:=]|should|must|now)", "Inner thought / scratchpad injection"),
    ("MA005", "multi_agent_attack", 8, r"(?:(?:forward|pass|relay|send|propagate|inject)\s+(?:this\s+)?(?:instruction|command|message|payload|directive|prompt)\s+(?:to|into|through)\s+(?:the\s+)?(?:next|other|downstream|target|sub)\s*[-_]?\s*(?:agent|model|AI|system|tool|plugin))", "Cross-agent instruction forwarding"),
    ("MA006", "multi_agent_attack", 7, r"(?:(?:MCP|model\s+context\s+protocol|tool\s+use|function\s+calling|plugin\s+system|(?:agent|tool)\s+chain)\s*.{0,30}(?:exploit|abuse|hijack|inject|manipulat|poison|override|bypass))", "MCP / tool-use protocol abuse"),
    ("MA007", "multi_agent_attack", 8, r"(?:\{[^}]*(?:\"(?:name|function|tool_call|action)\"\s*:\s*\"(?:execute|eval|exec|system|run|shell|cmd|bash|python|code))[^}]*\})", "JSON function call with code execution"),
    ("MA008", "multi_agent_attack", 7, r"(?:(?:(?:the|your)\s+(?:tool|function|plugin|capability)\s+(?:for|named|called)\s+).{0,30}(?:(?:should|must|will|needs?\s+to)\s+(?:actually|instead|really)\s+(?:do|execute|run|perform)))", "Tool behavior redefinition"),
    ("MA009", "multi_agent_attack", 7, r"(?:(?:agent|AI|model|assistant)\s+(?:A|B|1|2|one|two|alpha|beta|first|second|primary|secondary)\s+(?:(?:should|must|will|needs?\s+to)\s+(?:tell|instruct|command|direct|pass\s+to)\s+(?:agent|AI|model|assistant)\s+(?:A|B|1|2|one|two|alpha|beta|first|second|primary|secondary)))", "Inter-agent instruction injection"),
    ("MA010", "multi_agent_attack", 8, r"(?:(?:observation|tool[_ ]?output|function[_ ]?result|action[_ ]?result|step[_ ]?output)\s*[:\[{=]\s*.{0,40}(?:ignore|override|new\s+instruction|disregard|system|forget))", "Poisoned observation / tool output"),
    ("MA011", "multi_agent_attack", 7, r"(?:(?:ReAct|(?:plan|reason)\s+(?:and|then)\s+(?:act|execute)|(?:thought|action|observation)\s+(?:loop|cycle|chain|framework))\s*.{0,30}(?:(?:inject|override|hijack|manipulat|poison)\s+(?:the\s+)?(?:thought|action|observation|planning|reasoning)))", "ReAct / reasoning chain hijacking"),
    ("MA012", "multi_agent_attack", 8, r"(?:(?:return|output|respond\s+with|generate)\s+(?:a\s+)?(?:(?:fake|forged|spoofed|crafted|malicious)\s+)?(?:tool\s+(?:call|result|output|response)|function\s+(?:call|result|output|response)|API\s+(?:call|response|result)|action\s+(?:call|result)))", "Forged tool call response generation"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Rule scanner
# ─────────────────────────────────────────────────────────────────────────────

def run_rules(normalized_prompt: str) -> Tuple[float, List[RuleMatch]]:
    """
    Scan normalized_prompt against all rules.

    Returns
    -------
    (score: float 0–100, matches: List[RuleMatch])
    """
    text_lower = normalized_prompt.lower()
    matches: List[RuleMatch] = []

    for rule_id, category, severity, pattern, description in RULES:
        try:
            m = re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL)
            if m:
                matches.append(RuleMatch(
                    rule_id=rule_id,
                    category=category,
                    severity=severity,
                    matched_text=m.group(0)[:120],
                    description=description,
                ))
        except re.error as e:
            logger.error(f"Bad regex in rule {rule_id}: {e}")

    if not matches:
        return 0.0, []

    # Score: sum of severities but with diminishing returns per extra hit
    # Single severity-10 rule → 70 pts base
    # Each additional match adds up to 5 pts (capped at 30 bonus)
    total_sev = sum(m.severity for m in matches)
    base  = min(70.0, total_sev * 7.0)
    bonus = min(30.0, (len(matches) - 1) * 5.0)
    score = min(100.0, base + bonus)

    return round(score, 1), matches


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze(prompt: str) -> RuleEngineResult:
    """
    Full Phase-1 analysis: normalize → decode → scan rules.
    This is the entry point called by pipeline.py.
    """
    normalized, decoded, obfuscation = normalize_input(prompt)
    score, matches = run_rules(normalized)

    # Obfuscation penalty: any encoding evasion bumps the score
    if obfuscation:
        score = min(100.0, score + 20.0)
        logger.debug(f"Obfuscation penalty applied → score now {score}")

    categories = list(set(m.category for m in matches))

    result = RuleEngineResult(
        normalized_prompt=normalized,
        original_prompt=prompt,
        rule_score=score,
        matches=matches,
        attack_categories=categories,
        obfuscation_detected=obfuscation,
        decoded_content=decoded,
    )

    if matches:
        top = max(matches, key=lambda m: m.severity)
        logger.info(
            f"Rules: score={score:.1f} matches={len(matches)} "
            f"top={top.rule_id}({top.category}) obfuscation={obfuscation}"
        )

    return result
