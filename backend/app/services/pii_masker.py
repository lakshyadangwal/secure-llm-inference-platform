import re
from typing import Tuple, Dict

class PiiMasker:
    """
    Masks Personally Identifiable Information in incoming prompts before 
    they hit the LLM to prevent data exposure.
    """
    def __init__(self):
        self.patterns = {
            "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "PHONE": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
            "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b'
        }

    def mask(self, text: str) -> Tuple[str, Dict[str, str]]:
        redacted_text = text
        mapping = {}
        counter = 1

        for entity_type, pattern in self.patterns.items():
            for match in re.finditer(pattern, text):
                original_value = match.group()
                token = f"<{entity_type}_{counter}>"
                redacted_text = redacted_text.replace(original_value, token)
                mapping[token] = original_value
                counter += 1

        return redacted_text, mapping

pii_masker = PiiMasker()
