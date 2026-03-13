from pydantic import BaseModel
from typing import List, Optional

class ThreatIntelBase(BaseModel):
    id: str
    actor: str
    ioc: str
    type: str
    severity: str

class ThreatIntelResponse(BaseModel):
    threats: List[ThreatIntelBase]

class PiiSettingsConfig(BaseModel):
    mask_emails: bool = True
    mask_phones: bool = True
    mask_ssn: bool = True
    mask_credit_cards: bool = True
    action: str = "redact" # or "block"
