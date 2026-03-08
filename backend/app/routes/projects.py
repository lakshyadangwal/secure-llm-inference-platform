from fastapi import APIRouter, HTTPException
from app.services.project_manager import project_manager
from app.models.project_schema import ProjectCreate, Project

router = APIRouter(prefix="/api/projects", tags=["Projects"])

@router.get("/", response_model=list[Project])
async def list_projects():
    return project_manager.get_projects()

@router.post("/", response_model=Project)
async def create_project(req: ProjectCreate):
    return project_manager.create_project(req.name, req.description)

@router.post("/{project_id}/keys")
async def create_api_key(project_id: str, name: str = "New Key"):
    key = project_manager.generate_api_key(project_id, name)
    if not key:
        raise HTTPException(status_code=404, detail="Project not found")
    return key

@router.delete("/{project_id}/keys/{key_id}")
async def revoke_api_key(project_id: str, key_id: str):
    success = project_manager.revoke_api_key(project_id, key_id)
    if not success:
        raise HTTPException(status_code=404, detail="Key or Project not found")
    return {"status": "success", "message": "API Key revoked"}
