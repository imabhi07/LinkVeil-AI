import math
import tldextract
import urllib.parse
from collections import Counter

def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def extract_features(url: str) -> dict:
    """
    Extracts deterministic lexical features from a URL string for phishing detection.
    
    Returns:
        dict: Features like total length, entropy, special char counts, subdomain counts.
    """
    if not isinstance(url, str):
        url = str(url)
    
    # Basic URL normalisation
    url_lower = url.lower().strip()
    
    # Ensure URL has a scheme for parsing purposes (if missing, assume http)
    if not url_lower.startswith('http://') and not url_lower.startswith('https://'):
        parsed_url = urllib.parse.urlparse('http://' + url_lower)
    else:
        parsed_url = urllib.parse.urlparse(url_lower)
        
    extracted = tldextract.extract(url_lower)
    
    # Feature calculation
    features = {}
    
    # 1. Length features
    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed_url.netloc)
    features['path_length'] = len(parsed_url.path)
    
    # 2. Entropy
    features['url_entropy'] = calculate_entropy(url)
    
    # 3. Special character counts (across whole URL)
    features['count_dash'] = url.count('-')
    features['count_underscore'] = url.count('_')
    features['count_at'] = url.count('@')
    features['count_percent'] = url.count('%')
    features['count_question'] = url.count('?')
    features['count_equals'] = url.count('=')
    features['count_ampersand'] = url.count('&')
    features['count_dot'] = url.count('.')
    
    # 4. Subdomain metrics
    subdomain_str = extracted.subdomain
    # Count dots in subdomain plus one (e.g., 'a.b' -> 2 subdomains)
    features['subdomain_count'] = subdomain_str.count('.') + 1 if subdomain_str else 0
    
    # 5. Domain features
    features['count_digits_in_hostname'] = sum(c.isdigit() for c in parsed_url.netloc)
    features['has_https'] = 1 if url_lower.startswith('https://') else 0
    
    # 6. Check for IP address in netloc proxying
    # A quick heuristic: if the domain extraction yields no suffix, it might be an IP or internal host
    features['is_ip_address'] = 1 if not extracted.suffix and extracted.domain.replace('.', '').isdigit() else 0
    
    return features
