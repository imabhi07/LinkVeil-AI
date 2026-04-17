import pytest
from unittest.mock import patch, MagicMock
from backend.app.services.engine_service import evaluate_url
from backend.app.services.probe_agent import ProbeResult

@pytest.fixture
def mock_db_session():
    # Simple MagicMock for SQLAlchemy session
    db = MagicMock()
    return db

@pytest.mark.asyncio
@patch('backend.app.services.engine_service.run_probe')
@patch('backend.app.services.engine_service.dl_service.predict')
@patch('backend.app.services.engine_service.analyze_url')
async def test_evaluate_url_eng02_high_dl_always_malicious(mock_analyze_url, mock_dl_predict, mock_run_probe, mock_db_session):
    mock_run_probe.return_value = ProbeResult(performed=False, outcome="Probe skipped in test.")
    # Setup PRD Rule ENG-02: DL > 0.7 forces High risk level
    mock_dl_predict.return_value = 0.95
    # Even if LLM says low...
    mock_analyze_url.return_value = {
        "risk_level": "Low",
        "explanation": "LLM thought it was safe.",
        "brand_impersonation": False,
        "brand_name": None
    }
    
    result = await evaluate_url("http://obvious-phish.com", mock_db_session)
    
    assert result["risk_score"] == 95.0
    assert result["risk_level"] == "High"
    assert "LLM thought it was safe" in result["explanation"]
    
    # Verify DB save was called
    mock_db_session.add.assert_called_once()
    mock_db_session.commit.assert_called_once()

@pytest.mark.asyncio
@patch('backend.app.services.engine_service.run_probe')
@patch('backend.app.services.engine_service.dl_service.predict')
@patch('backend.app.services.engine_service.analyze_url')
async def test_evaluate_url_eng03_medium_dl_high_llm(mock_analyze_url, mock_dl_predict, mock_run_probe, mock_db_session):
    mock_run_probe.return_value = ProbeResult(performed=False, outcome="Probe skipped in test.")
    # Setup PRD Rule ENG-03: Medium DL + High LLM forces Suspicious (Medium) risk level
    mock_dl_predict.return_value = 0.50
    mock_analyze_url.return_value = {
        "risk_level": "High",
        "explanation": "LLM found brand impersonation metrics.",
        "brand_impersonation": True,
        "brand_name": "Microsoft"
    }
    
    result = await evaluate_url("http://microsoft-login-update.com", mock_db_session)
    
    assert result["risk_score"] == 50.0
    assert result["risk_level"] == "Medium"
    assert result["brand_impersonation"] is True
    assert result["brand_name"] == "Microsoft"

@pytest.mark.asyncio
@patch('backend.app.services.engine_service.run_probe')
@patch('backend.app.services.engine_service.dl_service.predict')
@patch('backend.app.services.engine_service.analyze_url')
async def test_evaluate_url_eng04_low_dl_low_llm(mock_analyze_url, mock_dl_predict, mock_run_probe, mock_db_session):
    mock_run_probe.return_value = ProbeResult(performed=False, outcome="Probe skipped in test.")
    # Setup PRD Rule ENG-04: Low DL + Low LLM triggers Safe (Low)
    mock_dl_predict.return_value = 0.10
    mock_analyze_url.return_value = {
        "risk_level": "Low",
        "explanation": "Clean url.",
        "brand_impersonation": False,
        "brand_name": None
    }
    
    result = await evaluate_url("https://google.com", mock_db_session)
    
    assert result["risk_score"] == 10.0
    assert result["risk_level"] == "Low"
