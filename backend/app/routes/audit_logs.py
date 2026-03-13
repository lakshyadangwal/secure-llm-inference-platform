from fastapi import APIRouter, Depends, HTTPException
import logging

from app.models.audit_schema import AuditLogResponse
from app.services.audit import audit_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit_logs", tags=["Audit Logs"])

@router.get("/all", response_model=AuditLogResponse)
async def get_all_audit_logs(limit: int = 100, skip: int = 0):
    """Get paginated audit logs for the new Epic 2 dashboard"""
    logs = audit_service.get_logs(limit=limit, skip=skip)
    total = audit_service.get_total_count()
    return {
        "logs": logs,
        "total_count": total
    }
