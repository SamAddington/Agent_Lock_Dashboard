from pydantic import BaseModel, Field
from typing import List

class Precondition(BaseModel):
    name: str
    source: str
    artifact_ref: str
    confidence: float = Field(ge=0.0, le=1.0)

class ActionSchema(BaseModel):
    action_type: str
    target: str
    justification: str
    risk_level: str
    preconditions: List[Precondition]
    rollback_plan: str | None = None
