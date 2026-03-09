from typing import Dict

class PiiUnmasker:
    """
    Restores masked PII tokens from the LLM output back to their 
    original values for the end user.
    """
    def unmask(self, text: str, mapping: Dict[str, str]) -> str:
        restored_text = text
        for token, original_value in mapping.items():
            restored_text = restored_text.replace(token, original_value)
        return restored_text

pii_unmasker = PiiUnmasker()
