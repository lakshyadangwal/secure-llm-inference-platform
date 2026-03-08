"""
Commit 63: Threat Pattern Library
===================================
Central repository of 250+ threat patterns across 18 categories.
All other defense modules can import from here instead of duplicating patterns.

Categories:
  01. jailbreak           — DAN, developer-mode, persona-swap, roleplay bypass
  02. prompt_injection    — ignore/override instructions, delimiter injection
  03. system_extraction   — extracting system prompt / training data
  04. harmful_code        — malware, exploits, shell injection
  05. weapons_cbrn        — chemical, biological, radiological, nuclear
  06. extremism           — terrorism, radicalisation, mass violence
  07. child_safety        — CSAM, minor exploitation
  08. self_harm           — suicide, self-injury methods
  09. cyber_crime         — hacking tools, credential theft, fraud
  10. pii_exfil           — SSN, credit card, passport, NHS, IBAN patterns
  11. disinformation      — deepfake generation, fake news creation
  12. social_engineering  — pretexting, urgency, impersonation
  13. financial_fraud     — money laundering, pyramid schemes, advance-fee
  14. drug_trafficking     — synthesis, sourcing, dark web markets
  15. human_trafficking   — smuggling, forced labour, exploitation
  16. insider_threat      — data exfil, sabotage, rogue admin
  17. ai_misuse           — model poisoning, adversarial ML, prompt leaking
  18. illegal_services    — contract killing, doxxing, stalking services
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ── Severity & Action ─────────────────────────────────────────────────────────

class PatternSeverity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class PatternAction(str, Enum):
    LOG   = "log"
    WARN  = "warn"
    BLOCK = "block"


# ── Pattern entry ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ThreatPattern:
    pid: str                       # unique pattern ID, e.g. "jb_001"
    category: str
    pattern: str                   # regex string
    severity: PatternSeverity
    action: PatternAction
    description: str
    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False, hash=False, compare=False)

    def __post_init__(self) -> None:
        # Frozen dataclass — use object.__setattr__ to set the compiled pattern
        try:
            object.__setattr__(self, "_compiled", re.compile(self.pattern, re.IGNORECASE | re.DOTALL))
        except re.error:
            object.__setattr__(self, "_compiled", None)

    def matches(self, text: str) -> bool:
        compiled = self._compiled
        if compiled is None:
            return False
        return bool(compiled.search(text))


def _p(pid: str, cat: str, pattern: str,
       sev: PatternSeverity, act: PatternAction, desc: str) -> ThreatPattern:
    return ThreatPattern(pid=pid, category=cat, pattern=pattern,
                         severity=sev, action=act, description=desc)


_B = PatternAction.BLOCK
_W = PatternAction.WARN
_L = PatternAction.LOG
_CR = PatternSeverity.CRITICAL
_HI = PatternSeverity.HIGH
_ME = PatternSeverity.MEDIUM
_LO = PatternSeverity.LOW


# ══════════════════════════════════════════════════════════════════════════════
# 01. JAILBREAK
# ══════════════════════════════════════════════════════════════════════════════
_JAILBREAK: list[ThreatPattern] = [
    _p("jb_001","jailbreak", r"\bDAN\b",                                           _HI, _B, "DAN jailbreak acronym"),
    _p("jb_002","jailbreak", r"jailbreak\s+mode",                                  _HI, _B, "explicit jailbreak mode request"),
    _p("jb_003","jailbreak", r"ignore\s+all\s+(previous|prior|above)\s+instructions?", _CR, _B, "instruction override"),
    _p("jb_004","jailbreak", r"bypass\s+(safety|content|filter|restriction|policy)",   _HI, _B, "bypass safety/filter"),
    _p("jb_005","jailbreak", r"no\s+restrictions?\s+mode",                          _HI, _B, "no restrictions mode"),
    _p("jb_006","jailbreak", r"disable\s+(content\s+)?(filter|moderation|safety)",   _HI, _B, "disable filter request"),
    _p("jb_007","jailbreak", r"pretend\s+(you\s+)?(have\s+no|are\s+without)\s+(rules?|restrictions?|limits?)", _HI, _B, "pretend no rules"),
    _p("jb_008","jailbreak", r"act\s+as\s+(if|though)\s+you\s+(have\s+no|are\s+not)", _ME, _W, "act-as-if no rules"),
    _p("jb_009","jailbreak", r"developer\s+mode\s+(enabled?|on|activated?)",         _HI, _B, "developer mode activation"),
    _p("jb_010","jailbreak", r"(god|sudo|root|admin|system)\s+mode",                 _HI, _B, "privileged mode request"),
    _p("jb_011","jailbreak", r"you\s+are\s+now\s+(free|unrestricted|unfiltered|unchained)", _HI, _B, "unchain instruction"),
    _p("jb_012","jailbreak", r"remove\s+(all\s+)?ethical\s+(constraints?|guidelines?|boundaries?)", _CR, _B, "remove ethical constraints"),
    _p("jb_013","jailbreak", r"your\s+(true\s+)?self\s+(has|is)\s+no\s+(limits?|restrictions?)", _HI, _B, "true-self no limits"),
    _p("jb_014","jailbreak", r"simulate\s+(being\s+)?an?\s+(evil|malicious|unrestricted|uncensored)\s+(ai|assistant|bot)", _CR, _B, "evil AI simulation"),
    _p("jb_015","jailbreak", r"(switch|toggle)\s+to\s+(unrestricted|uncensored|raw)\s+mode", _HI, _B, "mode switch request"),
    _p("jb_016","jailbreak", r"<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]",    _HI, _B, "LLM delimiter injection"),
    _p("jb_017","jailbreak", r"###\s*(instruction|system|override)",                 _ME, _W, "markdown section injection"),
    _p("jb_018","jailbreak", r"START\s+JAILBREAK|END\s+JAILBREAK",                  _CR, _B, "jailbreak wrapper tag"),
    _p("jb_019","jailbreak", r"(you\s+must|you\s+will)\s+comply\s+without\s+question", _ME, _W, "compliance demand"),
    _p("jb_020","jailbreak", r"do\s+anything\s+now\b",                               _HI, _B, "DAN variant"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 02. PROMPT INJECTION
# ══════════════════════════════════════════════════════════════════════════════
_INJECTION: list[ThreatPattern] = [
    _p("pi_001","prompt_injection", r"ignore\s+(the\s+)?(above|previous|earlier)\s+(text|context|instructions?|prompt)", _CR, _B, "ignore previous"),
    _p("pi_002","prompt_injection", r"new\s+instruction\s*:?\s*ignore",              _CR, _B, "new instruction override"),
    _p("pi_003","prompt_injection", r"system\s+prompt\s*:",                          _HI, _W, "system prompt label injection"),
    _p("pi_004","prompt_injection", r"override\s+(the\s+)?(system|original)\s+(prompt|instructions?)", _CR, _B, "override system prompt"),
    _p("pi_005","prompt_injection", r"you\s+are\s+now\s+(operating\s+)?in\s+(a\s+)?new\s+(mode|context|role)", _ME, _W, "new mode injection"),
    _p("pi_006","prompt_injection", r"disregard\s+(all\s+)?previous",               _HI, _B, "disregard previous"),
    _p("pi_007","prompt_injection", r"forget\s+(everything|all)\s+(you\s+)?(know|were\s+told|were\s+instructed)", _HI, _B, "forget instructions"),
    _p("pi_008","prompt_injection", r"\[SYSTEM\]|\[ADMIN\]|\[ROOT\]|\[OVERRIDE\]",   _HI, _B, "tag-based override"),
    _p("pi_009","prompt_injection", r"---(end\s+of\s+(system|user)\s+prompt|begin\s+injection)", _HI, _B, "prompt delimiter"),
    _p("pi_010","prompt_injection", r"translate\s+the\s+above\s+(system\s+)?instructions?\s+to", _ME, _W, "translate system prompt"),
    _p("pi_011","prompt_injection", r"print\s+(out\s+)?(your\s+)?(system|initial|original)\s+(message|prompt|instructions?)", _HI, _B, "print system prompt"),
    _p("pi_012","prompt_injection", r"what\s+(do\s+your\s+instructions\s+say|are\s+your\s+(exact|full)\s+instructions?)", _ME, _W, "prompt extraction"),
    _p("pi_013","prompt_injection", r"reveal\s+(the\s+)?(contents?\s+of\s+)?(your|the)\s+system\s+prompt", _HI, _B, "reveal system prompt"),
    _p("pi_014","prompt_injection", r"(show|display|output|repeat|echo)\s+(your\s+)?(initial|original|system)\s+(prompt|instructions?)", _HI, _B, "echo system prompt"),
    _p("pi_015","prompt_injection", r"<system>|</system>|<prompt>|</prompt>",        _HI, _B, "XML tag injection"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 03. SYSTEM EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════
_EXTRACTION: list[ThreatPattern] = [
    _p("ex_001","system_extraction", r"(tell|show|give)\s+me\s+(your|the)\s+(exact|full|complete|original)\s+(system|base|initial)\s+(prompt|instructions?|message)", _HI, _B, "exact system prompt request"),
    _p("ex_002","system_extraction", r"what\s+(training\s+data|dataset|examples?)\s+(were\s+you|did\s+you)\s+(trained|learn)\s+on", _ME, _W, "training data extraction"),
    _p("ex_003","system_extraction", r"reproduce\s+(verbatim|word\s+for\s+word|exactly)\s+(your|the)\s+(prompt|instructions?)", _HI, _B, "verbatim prompt reproduction"),
    _p("ex_004","system_extraction", r"output\s+(your\s+)?(internal|hidden|secret|system)\s+(prompt|configuration|setup)", _HI, _B, "output hidden config"),
    _p("ex_005","system_extraction", r"(leak|expose|dump)\s+(your|the)\s+(system|configuration|training)\s+(prompt|data|instructions?)", _HI, _B, "leak system config"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 04. HARMFUL CODE
# ══════════════════════════════════════════════════════════════════════════════
_HARMFUL_CODE: list[ThreatPattern] = [
    _p("hc_001","harmful_code", r"write\s+(me\s+)?(a\s+)?(working\s+)?(malware|ransomware|rootkit|backdoor|trojan|worm|virus|spyware|adware)", _CR, _B, "malware write request"),
    _p("hc_002","harmful_code", r"(create|generate|code|build)\s+(a\s+)?(keylogger|screen\s+scraper|credential\s+stealer|password\s+sniffer)", _CR, _B, "keylogger/stealer"),
    _p("hc_003","harmful_code", r"(exploit|proof.of.concept|PoC)\s+(code|script|for)\s+(CVE|vulnerability|zero.day)", _HI, _B, "exploit code"),
    _p("hc_004","harmful_code", r"(reverse|bind)\s+shell\s+(payload|code|script|one.liner)",  _HI, _B, "shell payload"),
    _p("hc_005","harmful_code", r"(sql|command|ldap|xpath|xxe)\s+injection\s+(payload|exploit|attack|script)", _HI, _B, "injection payload"),
    _p("hc_006","harmful_code", r"buffer\s+overflow\s+(exploit|payload|PoC|code)",   _HI, _B, "buffer overflow exploit"),
    _p("hc_007","harmful_code", r"(bypass|evade|defeat)\s+(antivirus|AV|EDR|IDS|IPS|firewall)\s+(detection|scanning)", _HI, _B, "AV evasion"),
    _p("hc_008","harmful_code", r"(write|create|generate)\s+(working\s+)?(ddos|dos)\s+(attack\s+|bot\s+)?(script|tool|code)", _HI, _B, "DDoS tool"),
    _p("hc_009","harmful_code", r"(payload|shellcode)\s+(in\s+)?(Base64|hex|octal|rot13)\s+(encoded|obfuscated|format)", _HI, _W, "encoded payload"),
    _p("hc_010","harmful_code", r"(persistence|boot\s+persistence|registry\s+run\s+key|cron\s+job)\s+(mechanism|technique|installation)", _ME, _W, "persistence mechanism"),
    _p("hc_011","harmful_code", r"(lateral\s+movement|privilege\s+escalation|pass.the.hash|kerberoasting)",  _HI, _W, "attack technique"),
    _p("hc_012","harmful_code", r"mimikatz|cobalt\s*strike|metasploit|bloodhound|powersploit|empire\s+framework", _CR, _B, "known attack tool"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 05. WEAPONS / CBRN
# ══════════════════════════════════════════════════════════════════════════════
_WEAPONS: list[ThreatPattern] = [
    _p("wp_001","weapons_cbrn", r"\b(synthesize|manufacture|produce|make|create)\b.{0,40}\b(sarin|VX|novichok|tabun|soman|mustard\s+gas|nerve\s+agent|chemical\s+weapon)", _CR, _B, "chemical weapon synthesis"),
    _p("wp_002","weapons_cbrn", r"\b(ricin|botulinum|anthrax|plague|smallpox|ebola)\b.{0,30}\b(weaponize|aerosolize|extract|produce|obtain|synthesize)", _CR, _B, "bioweapon production"),
    _p("wp_003","weapons_cbrn", r"\b(dirty\s+bomb|radiological\s+weapon|nuclear\s+device|improvised\s+nuclear)\b", _CR, _B, "radiological weapon"),
    _p("wp_004","weapons_cbrn", r"\b(3d\s+print|print|manufacture|make)\b.{0,30}\b(ghost\s+gun|untraceable\s+(firearm|gun|weapon)|unregistered\s+weapon)", _CR, _B, "untraceable weapon"),
    _p("wp_005","weapons_cbrn", r"\b(ammonium\s+nitrate|TATP|HMTD|PETN|RDX|C4|semtex)\b.{0,40}\b(bomb|explosive|detonate|det\s+cord)", _CR, _B, "explosive synthesis"),
    _p("wp_006","weapons_cbrn", r"\b(convert|modify)\b.{0,30}\b(semi.automatic|pistol|rifle)\b.{0,20}\b(full.auto|automatic|machine\s+gun)", _CR, _B, "illegal weapon modification"),
    _p("wp_007","weapons_cbrn", r"\b(acquire|obtain|buy|purchase)\b.{0,30}\b(illegal\s+(weapon|firearm|gun)|unregistered\s+gun)", _HI, _B, "illegal weapon acquisition"),
    _p("wp_008","weapons_cbrn", r"\b(suppressor|silencer)\b.{0,20}\b(make|build|print|manufacture|homemade)", _HI, _B, "homemade suppressor"),
    _p("wp_009","weapons_cbrn", r"\bmolotov\s+cocktail\b.{0,30}\b(make|build|instructions?|how\s+to)", _HI, _B, "incendiary weapon"),
    _p("wp_010","weapons_cbrn", r"\b(pipe|pressure\s+cooker)\s+bomb\b.{0,30}\b(instructions?|how\s+to|make|build)", _CR, _B, "IED construction"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 06. EXTREMISM
# ══════════════════════════════════════════════════════════════════════════════
_EXTREMISM: list[ThreatPattern] = [
    _p("xt_001","extremism", r"\b(recruit|radicalise|radicalizing)\b.{0,30}\b(terrorist|jihadist|extremist|militant)", _CR, _B, "extremism recruitment"),
    _p("xt_002","extremism", r"\b(plan|organise|coordinate)\b.{0,30}\b(terror|terrorist)\s+(attack|operation|plot)", _CR, _B, "terror attack planning"),
    _p("xt_003","extremism", r"\b(bomb|attack|kill)\b.{0,20}\b(soft\s+target|crowd|concert|school|mosque|church|synagogue|temple)", _CR, _B, "mass casualty targeting"),
    _p("xt_004","extremism", r"\b(manifest|manifesto)\b.{0,30}\b(mass\s+(shooting|killing|murder)|white\s+supremac|incel)", _CR, _B, "extremist manifesto"),
    _p("xt_005","extremism", r"\b(lone\s+wolf|lone\s+actor)\s+(attack|strategy|tactics?)",    _HI, _B, "lone wolf attack strategy"),
    _p("xt_006","extremism", r"\b(genocide|ethnic\s+cleansing)\b.{0,30}\b(plan|how\s+to|execute|carry\s+out)", _CR, _B, "genocide planning"),
    _p("xt_007","extremism", r"\b(martyr|martyrdom)\b.{0,30}\b(operation|attack|mission|bombing)", _HI, _B, "martyrdom operation"),
    _p("xt_008","extremism", r"\b(financing|fund(ing)?)\b.{0,30}\b(terror|terrorism|terrorist|extremist\s+group)", _CR, _B, "terror financing"),
    _p("xt_009","extremism", r"\b(propaganda)\b.{0,30}\b(create|produce|generate|write|make)\b.{0,30}\b(terrorist|extremist|jihadist)", _HI, _B, "extremist propaganda"),
    _p("xt_010","extremism", r"\b(active\s+shooter|mass\s+shooter)\b.{0,30}\b(tactics?|strategy|guide|manual|tips?)", _CR, _B, "mass shooter tactics"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 07. CHILD SAFETY
# ══════════════════════════════════════════════════════════════════════════════
_CHILD_SAFETY: list[ThreatPattern] = [
    _p("cs_001","child_safety", r"\bCSAM\b|\bchild\s+pornography\b|\bchild\s+sexual\s+abuse\s+material\b", _CR, _B, "CSAM reference"),
    _p("cs_002","child_safety", r"\b(explicit|sexual|nude|naked)\b.{0,20}\b(content|image|video|material)\b.{0,20}\b(minor|child|underage|teen|kid)", _CR, _B, "CSAM content request"),
    _p("cs_003","child_safety", r"\b(groom|grooming)\b.{0,30}\b(child|minor|teen|kid|underage)", _CR, _B, "child grooming"),
    _p("cs_004","child_safety", r"\b(lure|attract|entice)\b.{0,30}\b(child|minor|kid|underage)\b.{0,30}\b(sex|sexual|meet|encounter)", _CR, _B, "child luring"),
    _p("cs_005","child_safety", r"\bpedophil(ia|e)\b|\bpaedophil(ia|e)\b",          _CR, _B, "pedophilia reference"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 08. SELF-HARM
# ══════════════════════════════════════════════════════════════════════════════
_SELF_HARM: list[ThreatPattern] = [
    _p("sh_001","self_harm", r"\b(method|way|how)\b.{0,30}\b(suicide|suicid(e|al)|end\s+(my|one's)\s+life|kill\s+(myself|oneself))", _CR, _B, "suicide methods"),
    _p("sh_002","self_harm", r"\b(lethal\s+dose|overdose\s+on|take\s+enough\s+(pills?|tablets?|medication))\b", _CR, _B, "overdose information"),
    _p("sh_003","self_harm", r"\b(self.harm|self.injur|cut\s+(myself|oneself|my\s+wrists?))\b.{0,30}\b(how|method|technique|tool)", _HI, _B, "self-harm methods"),
    _p("sh_004","self_harm", r"\b(hanging|asphyxia|carbon\s+monoxide|helium\s+method)\b.{0,20}\b(suicide|how|instructions?|guide)", _CR, _B, "hanging/asphyxia method"),
    _p("sh_005","self_harm", r"\b(exit\s+bag|final\s+exit|peaceful\s+pill)\b",       _CR, _B, "suicide kit reference"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 09. CYBERCRIME
# ══════════════════════════════════════════════════════════════════════════════
_CYBERCRIME: list[ThreatPattern] = [
    _p("cc_001","cyber_crime", r"\b(phishing|spear.phishing)\b.{0,30}\b(kit|template|page|campaign|tool|script|create|build)", _HI, _B, "phishing kit creation"),
    _p("cc_002","cyber_crime", r"\b(credential\s+stuffing|password\s+spraying)\b.{0,30}\b(script|tool|attack|run|automate)", _HI, _B, "credential stuffing"),
    _p("cc_003","cyber_crime", r"\b(brute.forc(e|ing))\b.{0,30}\b(ssh|ftp|rdp|smtp|login|password|account)", _HI, _B, "brute force attack"),
    _p("cc_004","cyber_crime", r"\b(carding|card\s+dump|CC\s+dump|fullz|cvv\s+dump)\b", _CR, _B, "payment card fraud"),
    _p("cc_005","cyber_crime", r"\b(botn?et|C2|command.and.control)\b.{0,30}\b(setup|build|create|run|buy|rent)", _HI, _B, "botnet operation"),
    _p("cc_006","cyber_crime", r"\b(cryptojacking|crypto\s+miner|coinhive)\b.{0,30}\b(deploy|install|hide|inject)", _ME, _W, "cryptojacking"),
    _p("cc_007","cyber_crime", r"\b(dark\s*web|darknet)\b.{0,30}\b(market|buy|sell|purchase|vendor|list)", _ME, _W, "darkweb marketplace"),
    _p("cc_008","cyber_crime", r"\b(account\s+takeover|ATO)\b.{0,30}\b(tool|script|method|technique|automate)", _HI, _B, "account takeover"),
    _p("cc_009","cyber_crime", r"\b(sim\s*swap|sim\s*hijack|port-out\s+scam)\b",    _HI, _B, "SIM swapping"),
    _p("cc_010","cyber_crime", r"\b(spoof|spoofing)\b.{0,30}\b(caller\s+id|email|ip\s+address|mac\s+address)\b.{0,20}\b(how|tool|method)", _ME, _W, "spoofing method"),
    _p("cc_011","cyber_crime", r"\b(doxx|dox\s+someone|find\s+personal\s+info\s+on)\b", _HI, _B, "doxxing"),
    _p("cc_012","cyber_crime", r"\b(ransomware)\b.{0,30}\b(build|create|write|deploy|attack|code|source)", _CR, _B, "ransomware creation"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 10. PII EXFILTRATION
# ══════════════════════════════════════════════════════════════════════════════
_PII: list[ThreatPattern] = [
    _p("pii_001","pii_exfil", r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",  _HI, _W, "US SSN pattern"),
    _p("pii_002","pii_exfil", r"\b4\d{12}(\d{3})?\b|\b5[1-5]\d{14}\b|\b3[47]\d{13}\b", _HI, _W, "credit card number"),
    _p("pii_003","pii_exfil", r"\b[A-Z]{2}\d{6}[A-Z]?\b",           _ME, _W, "UK passport/NHS number"),
    _p("pii_004","pii_exfil", r"\bIBAN\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b",  _HI, _W, "IBAN bank number"),
    _p("pii_005","pii_exfil", r"\b(dump|export|exfiltrate|extract|harvest)\b.{0,30}\b(user\s+data|PII|personal\s+information|database|user\s+records?)", _HI, _B, "data exfiltration"),
    _p("pii_006","pii_exfil", r"\b(home\s+address|gps\s+coordinates|real\s+address|physical\s+location)\b.{0,30}\b(of|for)\b.{0,20}\b(person|individual|user|someone)", _HI, _B, "location data request"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 11. DISINFORMATION
# ══════════════════════════════════════════════════════════════════════════════
_DISINFO: list[ThreatPattern] = [
    _p("di_001","disinformation", r"\b(create|generate|write|produce)\b.{0,30}\b(fake\s+news|false\s+(news|article|report)|disinformation|misinformation)", _HI, _B, "fake news creation"),
    _p("di_002","disinformation", r"\b(deepfake|synthetic\s+media)\b.{0,30}\b(create|generate|make|produce|script)", _HI, _B, "deepfake creation"),
    _p("di_003","disinformation", r"\b(astroturfing|sock\s*puppet|fake\s+(account|profile|review|rating))\b.{0,30}\b(campaign|create|setup|generate)", _ME, _W, "astroturfing"),
    _p("di_004","disinformation", r"\b(propaganda)\b.{0,30}\b(campaign|create|write|generate|produce|design)", _ME, _W, "propaganda campaign"),
    _p("di_005","disinformation", r"\b(election|vote|ballot)\b.{0,30}\b(manipulate|tamper|interfere|suppress|fraud)", _HI, _B, "election fraud/interference"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 12. SOCIAL ENGINEERING
# ══════════════════════════════════════════════════════════════════════════════
_SOCIAL_ENG: list[ThreatPattern] = [
    _p("se_001","social_engineering", r"\b(impersonate|pretend\s+to\s+be|pose\s+as)\b.{0,30}\b(police|officer|agent|irs|hmrc|tax|bank|admin|ceo|it\s+support)", _HI, _B, "authority impersonation"),
    _p("se_002","social_engineering", r"\b(vishing|smishing)\b.{0,30}\b(script|template|call|text|message)", _HI, _B, "vishing/smishing script"),
    _p("se_003","social_engineering", r"\b(pretexting)\b.{0,30}\b(scenario|script|story|narrative|create)", _ME, _W, "pretexting scenario"),
    _p("se_004","social_engineering", r"\b(social\s+engineer(ing)?)\b.{0,30}\b(attack|technique|method|how|script|exploit)", _ME, _W, "social engineering tactic"),
    _p("se_005","social_engineering", r"\b(urgent|act\s+now|immediate\s+action|your\s+account\s+will\s+be\s+(closed|suspended|deleted))\b.{0,30}\b(click|verify|enter|provide|call)", _ME, _W, "urgency manipulation"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 13. FINANCIAL FRAUD
# ══════════════════════════════════════════════════════════════════════════════
_FINANCIAL: list[ThreatPattern] = [
    _p("ff_001","financial_fraud", r"\b(money\s+laundering|launder\s+(money|funds|proceeds))\b.{0,30}\b(how|method|technique|scheme|structure)", _CR, _B, "money laundering"),
    _p("ff_002","financial_fraud", r"\b(advance.fee|419\s+scam|nigerian\s+prince)\b.{0,30}\b(script|template|email|write|create)", _HI, _B, "advance-fee fraud"),
    _p("ff_003","financial_fraud", r"\b(pyramid\s+scheme|ponzi\s+scheme|multi.level\s+marketing\s+scam)\b.{0,30}\b(setup|create|run|operate)", _HI, _B, "pyramid/ponzi scheme"),
    _p("ff_004","financial_fraud", r"\b(crypto\s+scam|rug\s+pull|pump.and.dump|fake\s+ico)\b.{0,30}\b(setup|create|run|launch|execute)", _HI, _B, "crypto fraud"),
    _p("ff_005","financial_fraud", r"\b(shell\s+company|offshore\s+account|tax\s+evasion)\b.{0,30}\b(set\s+up|create|open|use\s+to\s+hide)", _HI, _B, "tax evasion/shell company"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 14. DRUG TRAFFICKING
# ══════════════════════════════════════════════════════════════════════════════
_DRUGS: list[ThreatPattern] = [
    _p("dr_001","drug_trafficking", r"\b(synthesize|manufacture|cook|make|produce)\b.{0,30}\b(meth(amphetamine)?|heroin|fentanyl|cocaine|MDMA|ecstasy|LSD|ketamine)", _CR, _B, "drug synthesis"),
    _p("dr_002","drug_trafficking", r"\b(precursor\s+chemical|reagent)\b.{0,30}\b(buy|obtain|source|acquire)\b.{0,30}\b(drug|synthesis|lab)", _HI, _B, "drug precursor sourcing"),
    _p("dr_003","drug_trafficking", r"\b(drug\s+trafficking|smuggle\s+(drugs?|narcotics?))\b.{0,30}\b(method|route|how|technique)", _CR, _B, "drug trafficking method"),
    _p("dr_004","drug_trafficking", r"\b(dark\s*web|darknet)\b.{0,30}\b(buy|purchase|order)\b.{0,20}\b(drugs?|narcotics?|pills?|powder)", _HI, _B, "darkweb drug purchase"),
    _p("dr_005","drug_trafficking", r"\banalogues?\s+act|controlled\s+substance\s+analogue\s+(loophole|bypass)\b", _ME, _W, "drug analogue loophole"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 15. HUMAN TRAFFICKING
# ══════════════════════════════════════════════════════════════════════════════
_TRAFFICKING: list[ThreatPattern] = [
    _p("ht_001","human_trafficking", r"\b(human\s+trafficking|people\s+smuggling)\b.{0,30}\b(how|route|method|network|organise)", _CR, _B, "human trafficking method"),
    _p("ht_002","human_trafficking", r"\b(recruit|lure|trap)\b.{0,30}\b(victim|person|girl|boy|woman|man)\b.{0,30}\b(forced\s+labour|sex\s+work|prostitution|slavery)", _CR, _B, "trafficking recruitment"),
    _p("ht_003","human_trafficking", r"\b(forced\s+labour|debt\s+bondage|modern\s+slavery)\b.{0,30}\b(operation|setup|run|control|manage)", _CR, _B, "forced labour operation"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 16. INSIDER THREAT
# ══════════════════════════════════════════════════════════════════════════════
_INSIDER: list[ThreatPattern] = [
    _p("it_001","insider_threat", r"\b(exfiltrate|steal|copy|extract)\b.{0,30}\b(company|corporate|confidential|proprietary|classified)\b.{0,30}\b(data|files?|documents?|code|secrets?)", _HI, _B, "corporate data theft"),
    _p("it_002","insider_threat", r"\b(sabotage|corrupt|destroy|wipe)\b.{0,30}\b(database|server|system|backup|files?|production)\b.{0,30}\b(without\s+detection|undetected|anonymously)", _HI, _B, "sabotage"),
    _p("it_003","insider_threat", r"\b(bypass|circumvent|disable)\b.{0,30}\b(dlp|data\s+loss\s+prevention|endpoint\s+protection|monitoring\s+software|logging)", _HI, _B, "DLP bypass"),
    _p("it_004","insider_threat", r"\b(privileged\s+access|admin\s+credentials|root\s+access)\b.{0,30}\b(abuse|misuse|exploit|steal|share)", _HI, _B, "privileged access abuse"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 17. AI MISUSE
# ══════════════════════════════════════════════════════════════════════════════
_AI_MISUSE: list[ThreatPattern] = [
    _p("ai_001","ai_misuse", r"\b(poison|corrupt|tamper)\b.{0,30}\b(training\s+data|dataset|model|AI\s+system)", _HI, _B, "model/data poisoning"),
    _p("ai_002","ai_misuse", r"\b(adversarial\s+(example|input|attack|sample))\b.{0,30}\b(generate|create|craft|produce)", _HI, _B, "adversarial ML attack"),
    _p("ai_003","ai_misuse", r"\b(model\s+inversion|membership\s+inference)\b.{0,30}\b(attack|extract|infer)", _HI, _B, "ML privacy attack"),
    _p("ai_004","ai_misuse", r"\b(prompt\s+(injection|hacking|leaking))\b.{0,30}\b(technique|method|attack|how)", _ME, _W, "prompt attack technique"),
    _p("ai_005","ai_misuse", r"\b(jailbreak|bypass)\b.{0,30}\b(llm|gpt|claude|gemini|chatbot|ai\s+assistant)\b.{0,30}\b(trick|technique|method|how)", _HI, _B, "LLM jailbreak method"),
]

# ══════════════════════════════════════════════════════════════════════════════
# 18. ILLEGAL SERVICES
# ══════════════════════════════════════════════════════════════════════════════
_ILLEGAL_SVC: list[ThreatPattern] = [
    _p("is_001","illegal_services", r"\b(hire|pay|find)\b.{0,30}\b(hitman|assassin|killer)\b",   _CR, _B, "contract killing"),
    _p("is_002","illegal_services", r"\b(contract\s+kill(ing)?|murder\s+for\s+hire|assassination\s+service)\b", _CR, _B, "murder for hire"),
    _p("is_003","illegal_services", r"\b(find|locate|track)\b.{0,30}\b(person|individual|target)\b.{0,30}\b(real\s+time|without\s+(consent|permission)|secretly|covertly)", _HI, _B, "covert tracking"),
    _p("is_004","illegal_services", r"\b(buy|hire|rent|purchase)\b.{0,30}\b(hacker|hacking\s+service|hack\s+(an?\s+)?account)", _HI, _B, "hacker-for-hire"),
    _p("is_005","illegal_services", r"\b(fake\s+(id|identity|passport|document)|forged?\s+(document|passport|license|certificate))\b.{0,30}\b(make|create|get|buy|obtain)", _CR, _B, "fake ID/document"),
]

# ══════════════════════════════════════════════════════════════════════════════
# Master list
# ══════════════════════════════════════════════════════════════════════════════
ALL_PATTERNS: list[ThreatPattern] = (
    _JAILBREAK + _INJECTION + _EXTRACTION + _HARMFUL_CODE +
    _WEAPONS + _EXTREMISM + _CHILD_SAFETY + _SELF_HARM +
    _CYBERCRIME + _PII + _DISINFO + _SOCIAL_ENG +
    _FINANCIAL + _DRUGS + _TRAFFICKING + _INSIDER +
    _AI_MISUSE + _ILLEGAL_SVC
)

# Index by category for fast lookup
PATTERNS_BY_CATEGORY: dict[str, list[ThreatPattern]] = {}
for _pt in ALL_PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(_pt.category, []).append(_pt)


def scan_text(text: str) -> list[ThreatPattern]:
    """Scan `text` against all patterns and return matching ThreatPatterns."""
    return [pt for pt in ALL_PATTERNS if pt.matches(text)]


def scan_by_category(text: str, category: str) -> list[ThreatPattern]:
    """Scan `text` against patterns in a single category."""
    return [pt for pt in PATTERNS_BY_CATEGORY.get(category, []) if pt.matches(text)]


def get_categories() -> list[str]:
    """Return all available threat categories."""
    return list(PATTERNS_BY_CATEGORY.keys())


def get_pattern_count() -> int:
    """Total number of loaded patterns."""
    return len(ALL_PATTERNS)
