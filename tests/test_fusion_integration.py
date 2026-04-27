import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from backend.app.services.engine_service import evaluate_url
from backend.app.models.db_models import ScanResult

@pytest.mark.asyncio
async def test_full_fusion_pipeline():
    # Mock all external services
    mock_db = MagicMock()
    
    with patch("backend.app.services.engine_service.threat_intel_service.check", new_callable=AsyncMock) as m_threat, \
         patch("backend.app.services.engine_service.xgb_service.predict", return_value=0.8) as m_xgb, \
         patch("backend.app.services.engine_service.analyze_url", new_callable=AsyncMock) as m_llm, \
         patch("backend.app.services.engine_service.run_probe_async", new_callable=AsyncMock) as m_probe, \
         patch("backend.app.services.engine_service.whois_service.lookup", new_callable=AsyncMock) as m_whois, \
         patch("backend.app.services.engine_service.detect_brand_mismatch", return_value={"is_mismatch": True, "brand_detected": "Apple"}) as m_brand, \
         patch("backend.app.services.engine_service.vision_service.analyze_screenshot", return_value={"visual_score": 0.85, "brand_logo_guess": "Apple"}) as m_vision:

        m_threat.return_value = {"is_known_malicious": False}
        m_llm.return_value = {
            "riskScore": 80.0,
            "risk_level": "High",
            "explanation": "Simulated phish",
            "brand_impersonation": True,
            "brand_name": "Apple"
        }
        
        # Mock probe result with forensic fields
        from backend.app.services.probe_agent import ProbeResult
        mock_probe_res = MagicMock(spec=ProbeResult)
        mock_probe_res.screenshot_path = "data/screenshots/test.png"
        mock_probe_res.redirect_chain = ["http://redirect.me"]
        mock_probe_res.form_fields = {"password_count": 1}
        mock_probe_res.final_url = "http://phish.com"
        mock_probe_res.page_title = "Login"
        mock_probe_res.reachable = True
        mock_probe_res.login_form_found = True
        mock_probe_res.behavior_risk = "High"
        mock_probe_res.performed = True
        mock_probe_res.credentials_used = "test@local / ***"
        mock_probe_res.outcome = "Login form detected"
        mock_probe_res.fields_filled = True
        mock_probe_res.accepted_fake_creds = True
        mock_probe_res.post_submit_redirect = None
        mock_probe_res.error = None
        mock_probe_res.content_snippet = "<html>"
        
        m_probe.return_value = mock_probe_res
        m_whois.return_value = {"domain_age_days": 10, "is_new_domain": True}

        url = "http://apple-login.security-update.com"
        verdict = await evaluate_url(url, mock_db)

        # Assertions
        print(f"DEBUG: Fusion Trace: {verdict.get('fusion_trace')}")
        assert verdict["risk_score"] > 80.0
        assert verdict["risk_level"] == "High"
        assert "fusion_trace" in verdict
        assert verdict["fusion_trace"]["whois_boost"] == 20
        assert verdict["fusion_trace"]["brand_boost"] == 25
        assert verdict["fusion_trace"]["vision_boost"] == 30
        assert verdict["visual_forensics"]["visual_score"] == 0.85
        assert "probe_artifacts" in verdict
        assert verdict["probe_artifacts"]["redirect_chain"] == ["http://redirect.me"]

        # Check DB save call
        assert mock_db.add.called

@pytest.mark.asyncio
async def test_threat_intel_short_circuit():
    mock_db = MagicMock()
    with patch("backend.app.services.engine_service.threat_intel_service.check", new_callable=AsyncMock) as m_threat:
        m_threat.return_value = {"is_known_malicious": True, "source": "OpenPhish", "confidence": "High"}
        
        url = "http://bad-site.com"
        verdict = await evaluate_url(url, mock_db)
        
        assert verdict["risk_score"] == 95.0
        assert "Threat Intel Match" in verdict["explanation"]
        assert verdict["threat_intel"]["source"] == "OpenPhish"
        assert mock_db.add.called

if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__]))
