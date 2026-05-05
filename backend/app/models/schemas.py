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
    
    # Graceful Degradation
    forensic_errors: list[dict] = []
    degraded_engines: list[str] = []

    model_config = {
        "from_attributes": True
    }
class EmailScanRequest(BaseModel):
    from_name: Optional[str] = None
    from_email: Optional[str] = None
    reply_to: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    raw_email: Optional[str] = None

class EmailScanResponse(BaseModel):
    email_risk_score: float
    email_risk_level: str
    reasons: list[str]
    suspicious_indicators: dict
    extracted_urls: list[str]
    link_results: list[ScanResponse]
    parsed_email: Optional[dict] = None
    
    # Triage Info
    auth_results: Optional[dict] = None
    triage_stats: Optional[dict] = None
    skipped_urls: Optional[list[dict]] = None
    scanned_count: int = 0
    total_extracted: int = 0
    
    # Forensic Transparency
    heuristic_score: float = 0.0
    link_score: float = 0.0
    forensic_errors: list[dict] = []
    deep_dive_target: Optional[str] = None
    unwrap_events: list[dict] = []
