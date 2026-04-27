import pytest
from backend.app.routes.scan import _normalize_url

def test_normalize_url_basic():
    assert _normalize_url("google.com") == "https://google.com/"
    assert _normalize_url("http://google.com/") == "http://google.com/"
    assert _normalize_url("HTTPS://GOOGLE.COM") == "https://google.com/"

def test_normalize_url_strip_ports():
    assert _normalize_url("https://google.com:443") == "https://google.com/"
    assert _normalize_url("http://google.com:80") == "http://google.com/"
    assert _normalize_url("http://google.com:8080") == "http://google.com:8080/"

def test_normalize_url_strip_tracking():
    url = "https://example.com/path?utm_source=twitter&fbclid=123&q=phishing"
    # utm_source and fbclid should be gone, q=phishing remains
    assert _normalize_url(url) == "https://example.com/path?q=phishing"

def test_normalize_url_sort_params():
    url = "https://example.com/path?z=1&a=2&m=3"
    assert _normalize_url(url) == "https://example.com/path?a=2&m=3&z=1"

def test_normalize_url_empty_params_after_strip():
    url = "https://example.com/path?utm_source=google"
    assert _normalize_url(url) == "https://example.com/path"

def test_normalize_url_fragment_drop():
    url = "https://example.com/path#section"
    # Fragments should be dropped as per implementation
    assert _normalize_url(url) == "https://example.com/path"

def test_normalize_url_mixed_case_tracking():
    url = "https://example.com/?UTM_SOURCE=ad&valid=true"
    assert _normalize_url(url) == "https://example.com/?valid=true"
