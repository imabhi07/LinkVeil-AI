import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.database import Base, get_db

# --- Test DB Setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = None
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        if db:
            db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

# --- Tests ---

@patch('backend.app.routes.scan.evaluate_url', new_callable=AsyncMock)
def test_email_scan_with_phishing_content(mock_evaluate_url):
    # Mock evaluate_url to return a high-risk result for the extracted URL
    mock_evaluate_url.return_value = {
        "url": "http://phish-site.com/login",
        "risk_score": 90.0,
        "risk_level": "High",
        "explanation": "Malicious link detected.",
        "brand_impersonation": True,
        "brand_name": "PayPal"
    }
    
    email_payload = {
        "from_name": "PayPal Security",
        "from_email": "security@paypa1.com",
        "reply_to": "attacker@gmail.com",
        "subject": "Urgent: Account Suspended",
        "body": "Dear user, your account has been suspended. Please verify now at http://phish-site.com/login"
    }
    
    response = client.post("/api/v1/scan/email", json=email_payload)
    
    assert response.status_code == 200
    data = response.json()
    
    # Combined score check
    # Combined = 90*0.7 + 40*0.3 (capped) = 63 + 12 = 75.0
    assert data["email_risk_score"] == 75.0
    assert data["email_risk_level"] == "High"
    assert "urgency" in str(data["reasons"]).lower()
    assert "reply-to" in str(data["reasons"]).lower()
    assert len(data["extracted_urls"]) == 1
    assert data["extracted_urls"][0] == "http://phish-site.com/login"
    assert len(data["link_results"]) == 1
    assert data["link_results"][0]["risk_level"] == "High"

def test_email_scan_no_urls():
    email_payload = {
        "subject": "Just checking in",
        "body": "Hello, how are you? No links here."
    }
    
    response = client.post("/api/v1/scan/email", json=email_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email_risk_score"] == 0.0
    assert data["email_risk_level"] == "Low"
    assert "No URLs found" in data["reasons"][0]
    assert data["extracted_urls"] == []

def test_email_scan_heuristic_only_medium():
    # Only heuristics, no URLs. Score should be > 35 for Medium.
    # Urgency (+8) + Credentials (+12) + Impersonation (+6) + Reply-to (+10) = 36
    email_payload = {
        "from_email": "a@test.com",
        "reply_to": "b@other.com",
        "subject": "Urgent password reset",
        "body": "Verify account immediately. Microsoft support."
    }
    
    response = client.post("/api/v1/scan/email", json=email_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email_risk_score"] == 36.0
    assert data["email_risk_level"] == "Medium"
