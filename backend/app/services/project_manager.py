import uuid
from datetime import datetime
from typing import List, Optional, Dict
from app.models.project_schema import Project, ApiKey
import secrets

class ProjectManager:
    """
    Service to manage Projects and API Keys for platform users.
    Using in-memory dicts for demonstration.
    """
    def __init__(self):
        self.projects: Dict[str, Project] = {}
        # Seed an initial project
        self.create_project("Default Infrastructure", "Main production environment for Neuro-Sentry operations.")
        self.create_project("Red Team Lab", "Isolated environment for fuzzing and exploit development.")

    def create_project(self, name: str, description: str) -> Project:
        pid = str(uuid.uuid4())
        project = Project(
            id=pid,
            name=name,
            description=description,
            api_keys=[],
            created_at=datetime.utcnow()
        )
        # Create an initial API key
        self.generate_api_key(pid, "Default Key")
        self.projects[pid] = project
        return project

    def get_projects(self) -> List[Project]:
        return list(self.projects.values())

    def get_project(self, project_id: str) -> Optional[Project]:
        return self.projects.get(project_id)

    def generate_api_key(self, project_id: str, key_name: str) -> Optional[ApiKey]:
        if project_id not in self.projects:
            return None
            
        key_str = "sk-" + secrets.token_hex(24)
        api_key = ApiKey(
            id=str(uuid.uuid4()),
            key=key_str,
            name=key_name,
            created_at=datetime.utcnow()
        )
        self.projects[project_id].api_keys.append(api_key)
        return api_key

    def revoke_api_key(self, project_id: str, key_id: str) -> bool:
        if project_id not in self.projects:
            return False
        
        project = self.projects[project_id]
        for idx, key in enumerate(project.api_keys):
            if key.id == key_id:
                project.api_keys[idx].is_active = False
                return True
        return False

project_manager = ProjectManager()
