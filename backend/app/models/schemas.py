from pydantic import BaseModel, HttpUrl
from typing import Optional

class URLRequest(BaseModel):
    url: HttpUrl

class ScanResponse(BaseModel):
    url: str
    risk_score: float
    risk_level: str
    recommendation: Optional[str] = None
    explanation: str
    brand_impersonation: bool
    brand_name: Optional[str] = None
    verdictTitle: dict | str | None = None
    technicalDetails: dict | None = None
    mitigationAdvice: list[str] = []
    agentReport: dict | None = None
    
    # New Phase 1-6 fields
    normalized_url: Optional[str] = None
    probe_artifacts: Optional[dict] = None
    visual_forensics: Optional[dict] = None
    whois_info: Optional[dict] = None
    threat_intel: Optional[dict] = None
    fusion_trace: Optional[dict] = None
    analytics_summary: Optional[dict] = None
    
    model_config = {
        "from_attributes": True
    }
