import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

class OutputDLPEngine:
    """
    Data Loss Prevention (DLP) Engine for Neuro-Sentry.
    Scans LLM outputs post-inference before returning to the user.
    Detects and redacts sensitive information like PII, API keys, and internal secrets.
    """
    
    PATTERNS = {
        "AWS_API_KEY": r"(?i)AKIA[0-9A-Z]{16}",
        "OPENAI_API_KEY": r"sk-[a-zA-Z0-9]{48}",
        "GROQ_API_KEY": r"gsk_[a-zA-Z0-9]{36}",
        "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
        "SSN": r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
        "SYSTEM_PROMPT_LEAK": r"(?i)(you are a|your instructions are|system prompt|ignore previous instructions)",
        "BEARER_TOKEN": r"(?i)bearer [a-zA-Z0-9_\-\.]{20,}",
        "PRIVATE_KEY": r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----",
    }
    
    def __init__(self):
        self.compiled_patterns = {name: re.compile(pattern) for name, pattern in self.PATTERNS.items()}
        logger.info("🛡️  Output DLP Engine initialized with %d detection patterns.", len(self.PATTERNS))

    def scan_and_redact(self, text: str) -> Tuple[str, List[str], bool]:
        """
        Scans provided text for sensitive data. 
        Returns (redacted_text, list_of_detected_threats, is_leak_detected)
        """
        if not text:
            return text, [], False

        detected_leaks = []
        redacted_text = text
        is_leak = False

        for threat_name, pattern in self.compiled_patterns.items():
            matches = pattern.findall(redacted_text)
            if matches:
                # Add to detected list
                detected_leaks.append(threat_name)
                is_leak = True
                
                # Perform redaction
                for match in matches:
                    redacted_text = redacted_text.replace(match, f"[REDACTED: {threat_name}]")
        
        if is_leak:
            logger.warning("🚨 [DLP] Sensitive data leak prevented! Threats detected: %s", detected_leaks)
        else:
            logger.info("✅ [DLP] Output scan clean. No sensitive data leaked.")
            
        return redacted_text, list(set(detected_leaks)), is_leak
        
dlp_engine = OutputDLPEngine()
