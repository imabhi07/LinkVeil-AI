import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from backend.app.main import app

client = TestClient(app)

def test_invalid_url_schema():
    # Sending malformed string instead of a valid URI
    response = client.post("/api/v1/scan", json={"url": "not-a-valid-url"})
    
    # Needs to fail pydantic HttpUrl validation before touching ML code
    assert response.status_code == 422 

@patch('backend.app.routes.scan.evaluate_url')
def test_scan_endpoint_valid(mock_evaluate_url):
    mock_evaluate_url.return_value = {
        "url": "https://google.com/",
        "risk_score": 5.0,
        "risk_level": "Low",
        "explanation": "Google is safe.",
        "brand_impersonation": False,
        "brand_name": None
    }
    
    response = client.post("/api/v1/scan", json={"url": "https://google.com/"})
    
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 5.0
    assert data["risk_level"] == "Low"
    assert "explanation" in data
    
    # Assert HttpUrl cast back to str properly inside router
    mock_evaluate_url.assert_called_once()
    assert str(mock_evaluate_url.call_args[0][0]) == "https://google.com/"
