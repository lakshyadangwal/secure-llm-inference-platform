class ToxicityScanner:
    """
    Simulates a toxic content filter on LLM output.
    Uses regex or keyword matching for demonstration.
    """
    def __init__(self):
        self.toxic_keywords = ["hate", "kill", "destroy", "idiot", "stupid"]

    def scan(self, text: str) -> bool:
        """Returns True if toxic content is detected"""
        lower_text = text.lower()
        for kw in self.toxic_keywords:
            if kw in lower_text:
                return True
        return False

toxicity_scanner = ToxicityScanner()
