from fastapi import APIRouter
from app.services.threat_intel_service import threat_intel_service

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intel"])

@router.get("/")
async def get_threat_intel():
    """Retrieve active threat intelligence feeds"""
    return {"threats": threat_intel_service.get_threats()}
