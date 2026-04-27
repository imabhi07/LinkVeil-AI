import pytest
from backend.app.services.threat_intel_service import threat_intel_service

@pytest.mark.asyncio
async def test_threat_intel_check_clean():
    # Empty cache first
    threat_intel_service._feed_cache = {"test": {"http://malicious.com"}}
    result = await threat_intel_service.check("http://google.com")
    assert result["is_known_malicious"] is False

@pytest.mark.asyncio
async def test_threat_intel_check_match():
    url = "http://malicious-phish.com/login"
    threat_intel_service._feed_cache = {"openphish": {url}}
    result = await threat_intel_service.check(url)
    assert result["is_known_malicious"] is True
    assert result["source"] == "openphish"

@pytest.mark.asyncio
async def test_threat_intel_check_normalized_match():
    url = "malicious-phish.com/login"
    threat_intel_service._feed_cache = {"urlhaus": {url}}
    # Should match even with protocol
    result = await threat_intel_service.check("https://malicious-phish.com/login/")
    assert result["is_known_malicious"] is True
