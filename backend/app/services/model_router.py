from typing import List

class ModelRouter:
    """
    Intelligently routes inference requests to the most appropriate base
    model depending on factors like complexity, speed required, and 
    availability (mocked for concept).
    """
    def __init__(self):
        self.available_models = [
            {"id": "llama3.1:latest", "speed": "fast", "capability": "high", "type": "general"},
            {"id": "phi:latest", "speed": "very_fast", "capability": "medium", "type": "general"},
            {"id": "mistral:latest", "speed": "fast", "capability": "high", "type": "code"},
        ]

    def select_model(self, task_type: str = "general", priority: str = "balanced") -> str:
        """
        Selects best model based on requirement. 
        In standard scenario, returns typical default.
        """
        if priority == "speed":
            return "phi:latest"
        elif task_type == "code":
            return "mistral:latest"
        else:
            return "llama3.1:latest"

model_router = ModelRouter()
