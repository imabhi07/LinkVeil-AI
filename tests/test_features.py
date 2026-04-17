import pytest
from backend.app.features.url_features import extract_features

def test_extract_features_valid_https():
    url = "https://www.paypal.com/login"
    features = extract_features(url)
    
    assert features['url_length'] == len(url)
    assert features['hostname_length'] == len("www.paypal.com")
    assert features['path_length'] == len("/login")
    assert features['has_https'] == 1
    assert features['is_ip_address'] == 0
    assert features['subdomain_count'] == 1 # 'www'

def test_extract_features_no_scheme():
    url = "google.com"
    features = extract_features(url)
    assert features['has_https'] == 0
    assert features['hostname_length'] == len("google.com")
    assert features['is_ip_address'] == 0

def test_extract_features_ip_address():
    url = "http://192.168.1.1/admin"
    features = extract_features(url)
    assert features['has_https'] == 0
    # Our simple heuristic currently flags standard ipv4-like numeric strings if tldextract finds no suffix.
    # While exact behavior depends on tldextract, it should catch raw IP inputs.
    # For a robust URL, parsed netloc is "192.168.1.1".
    assert features['is_ip_address'] == 1
    
def test_extract_features_long_subdomains():
    url = "http://login.verification.secure.paypal.com.scam-site.info/update"
    features = extract_features(url)
    # The domain is scam-site with .info suffix
    # The subdomain is login.verification.secure.paypal.com -> 4 dots -> 5 subdomains
    assert features['subdomain_count'] == 5
    assert features['url_length'] == len(url)

def test_extract_features_special_chars():
    url = "http://bad.com/file?id=123&user=admin@example.com-true_1%20."
    features = extract_features(url)
    
    assert features['count_question'] == 1
    assert features['count_equals'] == 2
    assert features['count_ampersand'] == 1
    assert features['count_at'] == 1
    assert features['count_dash'] == 1
    assert features['count_underscore'] == 1
    assert features['count_percent'] == 1
    assert features['count_dot'] >= 2
