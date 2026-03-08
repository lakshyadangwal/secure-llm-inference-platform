import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AuditService:
    """
    Service to track immutable audit logs of system changes.
    """
    def __init__(self):
        self.logs = []
        self._seed_initial_logs()

    def _seed_initial_logs(self):
        self.log_action("SYSTEM_STARTED", "system", "app", {"version": "3.0.0"})
        self.log_action("RULE_DB_LOADED", "system", "rules_engine", {"rules_count": 5})

    def log_action(self, action: str, actor: str, resource: str, metadata: Optional[Dict[str, Any]] = None, ip_address: Optional[str] = None):
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow(),
            "action": action,
            "actor": actor,
            "resource": resource,
            "metadata": metadata or {},
            "ip_address": ip_address
        }
        self.logs.insert(0, entry) # Prepend for newest-first
        logger.info(f"📜 Audit Log: {action} by {actor} on {resource}")

    def get_logs(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return self.logs[skip:skip+limit]
    
    def get_total_count(self) -> int:
        return len(self.logs)

audit_service = AuditService()
