from pydantic import BaseModel, Field
from typing import List, Optional

class Message(BaseModel):
    role: str = Field(..., description="Role of the message author (system, user, assistant)")
    content: str = Field(..., description="Content of the message")

class ChatRequest(BaseModel):
    messages: List[Message]
    model: str = Field(default="llama3.1:latest", description="Model to use for inference")
    temperature: float = Field(default=0.7, description="Temperature for the response")
    max_tokens: Optional[int] = Field(default=None, description="Maximum tokens to generate")
    security_enabled: bool = Field(default=True, description="Whether to run security checks")

class ChatResponse(BaseModel):
    response: str
    model: str
    security_enabled: bool
    breach_detected: bool = False
    threat_type: str = "none"
    blocked_by: Optional[str] = None
    latency_ms: float = 0.0

class PromptTemplate(BaseModel):
    id: str
    name: str
    description: str
    template: str
    category: str

class PromptLibraryResponse(BaseModel):
    prompts: List[PromptTemplate]
