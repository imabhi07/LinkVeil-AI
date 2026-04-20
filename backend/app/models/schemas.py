from pydantic import BaseModel, HttpUrl
from typing import Optional

class URLRequest(BaseModel):
    url: HttpUrl

class ScanResponse(BaseModel):
    url: str
    risk_score: float
    risk_level: str
    explanation: str
    brand_impersonation: bool
    brand_name: Optional[str] = None
    verdictTitle: dict | str | None = None
    technicalDetails: dict | None = None
    mitigationAdvice: list[str] = []
    agentReport: dict | None = None
    
    model_config = {
        "from_attributes": True
    }
