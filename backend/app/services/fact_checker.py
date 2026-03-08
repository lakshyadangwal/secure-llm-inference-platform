class FactChecker:
    """
    Simulates a hallucination detection/fact-checking mechanism.
    Checks the output against known facts or contradiction patterns.
    """
    def __init__(self):
        self.known_contradictions = [
            ("the earth is flat", "The Earth is an oblate spheroid."),
            ("gravity is a hoax", "Gravity is a fundamental force."),
            ("vaccines cause autism", "Extensive studies show no link between vaccines and autism.")
        ]

    def verify(self, text: str) -> dict:
        """
        Returns a dict indicating if a hallucination/contradiction was found.
        """
        lower_text = text.lower()
        for trigger, correction in self.known_contradictions:
            if trigger in lower_text:
                return {
                    "is_factual": False,
                    "correction": correction,
                    "trigger": trigger
                }
        return {"is_factual": True}

fact_checker = FactChecker()
