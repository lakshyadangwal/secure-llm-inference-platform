import random

class LoadBalancer:
    """
    Simulates traffic distribution among inference nodes representing LLMs 
    to ensure not a single Ollama node or GPU is over-saturated.
    """
    def __init__(self):
        self.nodes = [
            {"id": "node-alpha", "capacity": 100, "current_load": 45, "status": "healthy"},
            {"id": "node-beta",  "capacity": 100, "current_load": 85, "status": "degraded"},
            {"id": "node-gamma", "capacity": 100, "current_load": 12, "status": "healthy"}
        ]

    def get_next_healthy_node(self) -> str:
        # Simplistic round-robin or least-loaded simulation
        healthy_nodes = [n for n in self.nodes if n["status"] == "healthy"]
        if not healthy_nodes:
            # Fallback to anything if all degraded
            return self.nodes[0]["id"]
        
        # Sort by lowest load
        healthy_nodes.sort(key=lambda x: x["current_load"])
        chosen_node = healthy_nodes[0]
        
        # Simulate load increasing slightly upon selection
        chosen_node["current_load"] = min(chosen_node["capacity"], chosen_node["current_load"] + 1)
        
        return chosen_node["id"]

load_balancer = LoadBalancer()
