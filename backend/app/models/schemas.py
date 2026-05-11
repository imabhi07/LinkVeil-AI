from pydantic import BaseModel, HttpUrl
from typing import Optional

class URLRequest(BaseModel):
    url: HttpUrl
    force_refresh: bool = False

class ScanResponse(BaseModel):
    url: str
    risk_score: float
    risk_level: str
    recommendation: Optional[str] = None
    explanation: str
    brand_impersonation: bool
    brand_name: Optional[str] = None
    functional_category: Optional[str] = None
    functional_description: Optional[str] = None
    verdictTitle: Optional[str] = None
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
    force_refresh: bool = False

class EmailScanResponse(BaseModel):
    schema_version: str = "forensics++-v1"
    scan_id: str
    scanned_at: str
    scan_type: str = "email"
    input_type: str  # "manual" | "paste" | "eml"

    # Scoring
    email_risk_score: float
    link_risk_score: float
    final_risk_score: float
    verdict_label: str  # "safe" | "suspicious" | "malicious" | "inconclusive"
    final_verdict_source: str  # "email" | "link" | "tie"

    analysis_quality: str  # "high" | "medium" | "low"
    confidence: dict  # { level: "high" | "medium" | "low", reasons: list[str] }
    
    # Granular Scores
    score_identity: float = 0.0
    score_linguistic: float = 0.0

    # Score Breakdown
    score_breakdown: Optional[dict] = None

    # Failures / Partial Results
    forensic_errors: list[dict] = []

    # Link Triage Explainability
    triage_stats: dict

    # Identity
    identity: dict

    # Authentication
    auth: dict

    # HTML Forensics
    html_findings: dict

    # Social Engineering
    social_engineering: dict

    # Evidence (PII-safe)
    evidence: dict

    # Attachments
    attachments: list[dict] = []

    # Legacy compatibility / Link details (Optional)
    link_results: list[ScanResponse] = []
    functional_description: Optional[str] = None
    extracted_urls: list[str] = []
    reasons: list[str] = []
    unwrap_events: list[dict] = []
    deep_dive_target: Optional[str] = None

    model_config = {
        "from_attributes": True
    }
