from typing import Dict

class QuotaManager:
    """
    Enforces spending limits and token quotas at the Project level
    to prevent runaway inference costs or abuse.
    """
    def __init__(self):
        # Format: { "project_id": { "tokens_used": int, "limit": int, "spend": float, "budget": float } }
        self.quotas: Dict[str, dict] = {}

    def init_project_quota(self, project_id: str, token_limit: int = 1000000, budget: float = 100.0) -> None:
        if project_id not in self.quotas:
            self.quotas[project_id] = {
                "tokens_used": 0,
                "token_limit": token_limit,
                "spend": 0.0,
                "budget": budget
            }

    def record_usage(self, project_id: str, tokens: int, cost: float) -> bool:
        """Returns False if over quota, True otherwise"""
        self.init_project_quota(project_id)
        
        q = self.quotas[project_id]
        if q["tokens_used"] + tokens > q["token_limit"] or q["spend"] + cost > q["budget"]:
            return False
            
        q["tokens_used"] += tokens
        q["spend"] += cost
        return True

    def get_quota(self, project_id: str) -> dict:
        self.init_project_quota(project_id)
        return self.quotas[project_id]

quota_manager = QuotaManager()
