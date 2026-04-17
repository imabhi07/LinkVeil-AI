import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.database import Base
from backend.app.models.db_models import ScanResult
from backend.app.models.schemas import ScanResponse

# Setup an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

def test_create_scan_result(db_session):
    new_scan = ScanResult(
        url="http://test-phish.com",
        risk_score=95.0,
        risk_level="High",
        explanation="Testing the DB.",
        brand_impersonation=True,
        brand_name="TestBrand"
    )
    db_session.add(new_scan)
    db_session.commit()
    db_session.refresh(new_scan)
    
    assert new_scan.id is not None
    assert new_scan.url == "http://test-phish.com"
    assert new_scan.risk_score == 95.0
    assert new_scan.brand_impersonation is True

def test_pydantic_schema_validation():
    # Validating ScanResponse from mock data
    mock_data = {
        "url": "http://safe-site.com",
        "risk_score": 10.0,
        "risk_level": "Low",
        "explanation": "Looks safe.",
        "brand_impersonation": False,
        "brand_name": None
    }
    
    response = ScanResponse(**mock_data)
    assert response.risk_level == "Low"
    assert response.brand_impersonation is False
