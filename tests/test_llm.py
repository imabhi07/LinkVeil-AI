import pytest
import os
import json
from unittest.mock import AsyncMock, patch, MagicMock
from backend.app.services.llm_service import analyze_url, RiskAnalysis

@pytest.fixture
def mock_features():
    return {
        "url_length": 50,
        "url_entropy": 4.1,
        "subdomain_count": 2
    }

@pytest.mark.asyncio
async def test_analyze_url_fallback_no_api_key(mock_features):
    # Temporarily remove API key if present
    original_key = os.environ.get("GEMINI_API_KEY")
    if "GEMINI_API_KEY" in os.environ:
        del os.environ["GEMINI_API_KEY"]
        
    result = await analyze_url("http://example.com", mock_features)
    
    assert result["risk_level"] == "Unknown"
    assert result["brand_impersonation"] is False
    
    if original_key:
        os.environ["GEMINI_API_KEY"] = original_key

@pytest.mark.asyncio
@patch('backend.app.services.llm_service.genai.Client')
async def test_analyze_url_structure(mock_client_class, mock_features):
    os.environ["GEMINI_API_KEY"] = "fake-key"
    
    # Setup mock response
    mock_instance = mock_client_class.return_value
    mock_aio = MagicMock()
    mock_instance.aio = mock_aio
    
    expected_output = {
        "risk_level": "High",
        "explanation": "This is a test explanation.",
        "brand_impersonation": True,
        "brand_name": "TestBrand"
    }
    
    mock_response = MagicMock()
    mock_response.text = json.dumps(expected_output)
    
    mock_aio.models.generate_content = AsyncMock(return_value=mock_response)
    
    result = await analyze_url("http://test-phish.com", mock_features)
    
    assert result["risk_level"] == "High"
    assert result["explanation"] == "This is a test explanation."
    assert result["brand_impersonation"] is True
    assert result["brand_name"] == "TestBrand"

@pytest.mark.asyncio
@patch('backend.app.services.llm_service.genai.Client')
async def test_analyze_url_api_error_fallback(mock_client_class, mock_features):
    os.environ["GEMINI_API_KEY"] = "fake-key"
    
    # Setup mock to raise exception
    mock_instance = mock_client_class.return_value
    mock_aio = MagicMock()
    mock_instance.aio = mock_aio
    
    mock_aio.models.generate_content = AsyncMock(side_effect=Exception("API Timeout"))
    
    result = await analyze_url("http://test-phish.com", mock_features)
    
    assert result["risk_level"] == "Unknown"
    assert "unavailable" in result["explanation"]
    assert result["brand_impersonation"] is False
