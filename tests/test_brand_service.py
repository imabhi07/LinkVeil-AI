import pytest
from backend.app.services.brand_service import detect_brand_mismatch

def test_brand_mismatch_paypal_correct():
    url = "https://www.paypal.com/signin"
    result = detect_brand_mismatch(url)
    assert result["is_mismatch"] is False
    assert result["brand_detected"] is None

def test_brand_mismatch_paypal_fake():
    url = "https://paypal-login-secure.com/"
    result = detect_brand_mismatch(url)
    assert result["is_mismatch"] is True
    assert result["brand_detected"] == "Paypal"
    assert "untrusted domain" in result["reason"]

def test_brand_mismatch_paypal_path():
    url = "https://xyz-hosting.net/paypal/login.php"
    result = detect_brand_mismatch(url)
    assert result["is_mismatch"] is True
    assert result["brand_detected"] == "Paypal"
    assert "in path" in result["reason"]

def test_brand_mismatch_google_correct():
    url = "https://accounts.google.com/v3/signin"
    result = detect_brand_mismatch(url)
    assert result["is_mismatch"] is False

def test_brand_mismatch_google_fake():
    url = "https://google-accounts-security.info/login"
    result = detect_brand_mismatch(url)
    assert result["is_mismatch"] is True
    assert result["brand_detected"] == "Google"

def test_brand_mismatch_no_brand():
    url = "https://example.com/some/random/page"
    result = detect_brand_mismatch(url)
    assert result["is_mismatch"] is False
    assert result["brand_detected"] is None
