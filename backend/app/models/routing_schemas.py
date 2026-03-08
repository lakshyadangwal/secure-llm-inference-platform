from pydantic import BaseModel
from typing import Optional

class QuotaResponse(BaseModel):
    project_id: str
    tokens_used: int
    token_limit: int
    spend: float
    budget: float
    is_exhausted: bool

class QuotaUpdateRequest(BaseModel):
    token_limit: Optional[int] = None
    budget: Optional[float] = None
