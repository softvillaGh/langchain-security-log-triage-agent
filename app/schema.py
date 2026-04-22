from pydantic import BaseModel
from typing import List, Literal

class IncidentReport(BaseModel):
    verdict: Literal["benign", "suspicious", "malicious", "needs_review"]
    severity: Literal["low", "medium", "high", "critical"]
    summary: str
    indicators: List[str]
    tactics: List[str]
    recommended_actions: List[str]
    confidence: int
