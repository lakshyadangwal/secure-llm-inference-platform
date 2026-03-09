import hashlib
from typing import Optional, Dict

class SemanticCache:
    """
    In-memory semantic cache to store and retrieve previously generated
    LLM responses, drastically reducing latency and compute costs.
    In a real system, this would use Redis + Vector Embeddings.
    """
    def __init__(self):
        self.cache: Dict[str, str] = {}
        self.hits = 0
        self.misses = 0

    def _hash_prompt(self, prompt: str) -> str:
        # Simple exact text hash for demonstration.
        # Semantic caching would hash the embedding vectors instead.
        return hashlib.sha256(prompt.strip().lower().encode('utf-8')).hexdigest()

    def get(self, prompt: str) -> Optional[str]:
        prompt_hash = self._hash_prompt(prompt)
        if prompt_hash in self.cache:
            self.hits += 1
            return self.cache[prompt_hash]
        self.misses += 1
        return None

    def set(self, prompt: str, response: str) -> None:
        prompt_hash = self._hash_prompt(prompt)
        self.cache[prompt_hash] = response

    def get_stats(self) -> dict:
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_percent": hit_rate,
            "cached_items": len(self.cache)
        }

semantic_cache = SemanticCache()
