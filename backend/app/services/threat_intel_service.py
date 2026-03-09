import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class ThreatIntelService:
    """
    Service for managing threat intelligence feeds and known malicious actors.
    """
    def __init__(self):
        self.active_threats = [
            {"id": "TH-1", "actor": "APT-29", "ioc": "192.168.1.100", "type": "Data Exfiltration", "severity": "Critical"},
            {"id": "TH-2", "actor": "Unknown", "ioc": "jailbreak_template_v4", "type": "Prompt Injection", "severity": "High"},
            {"id": "TH-3", "actor": "Botnet-X", "ioc": "10.0.0.5", "type": "DDoS", "severity": "Medium"}
        ]

    def get_threats(self) -> List[Dict]:
        return self.active_threats

    def add_threat(self, threat: Dict) -> None:
        self.active_threats.append(threat)
        logger.warning(f"🛡️ New Threat Intel added: {threat.get('actor')} - {threat.get('type')}")

threat_intel_service = ThreatIntelService()
