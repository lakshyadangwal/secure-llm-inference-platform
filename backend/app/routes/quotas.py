from fastapi import APIRouter, HTTPException
from app.services.quota_manager import quota_manager
from app.models.routing_schemas import QuotaResponse, QuotaUpdateRequest

router = APIRouter(prefix="/api/quotas", tags=["Quotas"])

@router.get("/{project_id}", response_model=QuotaResponse)
async def get_project_quota(project_id: str):
    q = quota_manager.get_quota(project_id)
    return QuotaResponse(
        project_id=project_id,
        tokens_used=q["tokens_used"],
        token_limit=q["token_limit"],
        spend=q["spend"],
        budget=q["budget"],
        is_exhausted=(q["tokens_used"] >= q["token_limit"] or q["spend"] >= q["budget"])
    )

@router.put("/{project_id}")
async def update_project_quota(project_id: str, req: QuotaUpdateRequest):
    q = quota_manager.get_quota(project_id)
    if req.token_limit is not None:
        q["token_limit"] = req.token_limit
    if req.budget is not None:
        q["budget"] = req.budget
    return {"status": "success", "message": "Quota updated"}
