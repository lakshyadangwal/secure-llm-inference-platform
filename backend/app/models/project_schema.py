from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class ApiKey(BaseModel):
    id: str
    key: str
    name: str
    created_at: datetime
    last_used: Optional[datetime] = None
    is_active: bool = True

class Project(BaseModel):
    id: str
    name: str
    description: str
    api_keys: List[ApiKey]
    created_at: datetime
    environments: List[str] = ["development", "production"]

class ProjectCreate(BaseModel):
    name: str
    description: str
