from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, CheckConstraint, Enum
import enum
from backend.app.database import Base
from datetime import datetime, timezone

class AnalysisQualityEnum(str, enum.Enum):
    high = "high"
    medium = "medium"
    low = "low"

class ScanResult(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    risk_score = Column(Float)
    risk_level = Column(String)
    recommendation = Column(String, nullable=True)
    explanation = Column(String)
    brand_impersonation = Column(Boolean, default=False)
    brand_name = Column(String, nullable=True)
    model_version = Column(String, default="distilbert-base-uncased-v1")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Phase 1: Evidence & canonicalization
    screenshot_path = Column(String, nullable=True)
    visual_score = Column(Float, nullable=True)
    brand_logo_guess = Column(String, nullable=True)
    probe_artifacts = Column(Text, nullable=True)  # JSON blob

    # Phase 2: WHOIS
    domain_age_days = Column(Integer, nullable=True)
    registrar = Column(String, nullable=True)
    whois_privacy = Column(Boolean, nullable=True)

    # Phase 6: Threat intel
    threat_intel_match = Column(Boolean, default=False)
    threat_intel_source = Column(String, nullable=True)

    # Phase 5: Explainability
    fusion_trace = Column(Text, nullable=True)  # JSON blob
    
    # Forensic Analytics Enhancements
    tld = Column(String, nullable=True)              # e.g., "xyz", "com", "top"
    functional_category = Column(String, nullable=True)  # e.g., "Login Page"

class EmailScanResult(Base):
    __tablename__ = "email_scans"
    __table_args__ = (
        CheckConstraint('links_malicious <= links_total', name='chk_links_malicious_le_total'),
    )

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    verdict_label = Column(String)              # safe | suspicious | malicious
    final_risk_score = Column(Float)
    email_risk_score = Column(Float)
    link_risk_score = Column(Float)
    
    # Social Engineering (for Attack Vector analytics)
    se_categories = Column(Text, nullable=True)  # JSON blob
    se_score = Column(Float, default=0.0)
    
    # Authentication (for Auth Posture analytics)
    spf_result = Column(String, nullable=True)   # pass | fail | none
    dkim_result = Column(String, nullable=True)
    dmarc_result = Column(String, nullable=True)
    sender_domain = Column(String, nullable=True)
    
    # Obfuscation (for Heat Map analytics)
    obfuscation_techniques = Column(Text, nullable=True)  # JSON blob
    
    # Quality (for Confidence analytics)
    analysis_quality = Column(Enum(AnalysisQualityEnum), nullable=True)  # high | medium | low
    confidence_level = Column(Enum(AnalysisQualityEnum), nullable=True)
    
    # Links analyzed
    links_total = Column(Integer, default=0)
    links_malicious = Column(Integer, default=0)
    
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
