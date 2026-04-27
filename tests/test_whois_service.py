import pytest
from backend.app.services.whois_service import whois_service
from datetime import datetime, timedelta

@pytest.mark.asyncio
async def test_whois_lookup_google():
    # google.com should definitely have a valid WHOIS
    result = await whois_service.lookup("google.com")
    assert result["domain_age_days"] > 365 * 20 # Over 20 years old
    assert result["is_new_domain"] is False
    # Google uses MarkMonitor
    assert "markmonitor" in result["registrar"].lower()

@pytest.mark.asyncio
async def test_whois_cache():
    domain = "example.com"
    res1 = await whois_service.lookup(domain)
    # Modify cache timestamp to verify hit
    whois_service._cache[domain] = (datetime.now().timestamp() - 10, {"cached": True})
    res2 = await whois_service.lookup(domain)
    assert res2.get("cached") is True
