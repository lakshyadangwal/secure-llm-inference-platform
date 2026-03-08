class CostCalculator:
    """
    Calculates dynamic pricing and token costs for different models.
    Provides estimates for chargeback/showback reporting per project.
    """
    def __init__(self):
        # Cost per 1K tokens ($ USD)
        self.pricing_table = {
            "llama3.1:latest": {"input": 0.001, "output": 0.002},
            "phi:latest": {"input": 0.0005, "output": 0.001},
            "mistral:latest": {"input": 0.002, "output": 0.004},
        }

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        rates = self.pricing_table.get(model, {"input": 0.001, "output": 0.002})
        in_cost = (input_tokens / 1000) * rates["input"]
        out_cost = (output_tokens / 1000) * rates["output"]
        return round(in_cost + out_cost, 6)

cost_calculator = CostCalculator()
