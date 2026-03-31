from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from backend.app.database import Base
from datetime import datetime, timezone

class ScanResult(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    risk_score = Column(Float)
    risk_level = Column(String)
    explanation = Column(String)
    brand_impersonation = Column(Boolean, default=False)
    brand_name = Column(String, nullable=True)
    model_version = Column(String, default="distilbert-base-uncased-v1")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
