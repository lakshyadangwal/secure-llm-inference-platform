from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/settings", tags=["Settings"])

class GlobalConfig(BaseModel):
    max_tokens_per_user: int = 150000
    default_model: str = "llama3.1:latest"
    enforce_pii_masking_globally: bool = True
    logging_level: str = "INFO"

@router.get("/")
async def get_system_settings():
    # Return mock settings based on GlobalConfig defaults
    return GlobalConfig()

@router.put("/")
async def update_system_settings(cfg: GlobalConfig):
    # Just echo the settings back
    return {"status": "success", "settings": cfg}
