from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from backend.app.database import Base
from datetime import datetime, timezone

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
