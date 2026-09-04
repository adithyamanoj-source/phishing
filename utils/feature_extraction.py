import re
from urllib.parse import urlparse
import numpy as np

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'bank', 'secure', 'account', 'update', 'signin',
    'recovery', 'confirm', 'netflix', 'amazon', 'apple', 'paypal', 'chase',
    'support', 'billing', 'pass', 'token', 'security', 'wallet'
]

def extract_url_features(url: str) -> np.ndarray:
    """
    Extracts 10 numerical features from a URL for machine learning model input:
    1. url_length
    2. special_char_count
    3. domain_length
    4. subdomain_count
    5. has_ip_address (0/1)
    6. uses_https (0/1)
    7. suspicious_keyword_count
    8. has_at_symbol (0/1)
    9. has_nonstandard_port (0/1)
    10. path_depth
    """
    if not url.startswith(('http://', 'https://')):
        test_url = 'http://' + url
    else:
        test_url = url

    try:
        parsed = urlparse(test_url)
        hostname = parsed.netloc.split(':')[0]
    except Exception:
        hostname = url.split('/')[0]

    # Feature 1: URL Length
    url_len = len(url)

    # Feature 2: Special Characters Count
    special_chars = sum(url.count(c) for c in ['.', '-', '_', '@', '?', '=', '&', '%', '!'])

    # Feature 3: Domain Length
    domain_len = len(hostname)

    # Feature 4: Subdomain Count
    subdomain_cnt = (hostname.count('.'))

    # Feature 5: Has IP Address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    has_ip = 1 if re.match(ip_pattern, hostname) else 0

    # Feature 6: Uses HTTPS
    uses_https = 1 if url.lower().startswith('https://') else 0

    # Feature 7: Suspicious Keywords Count
    url_lower = url.lower()
    keyword_cnt = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Feature 8: Has @ Symbol
    has_at = 1 if '@' in url else 0

    # Feature 9: Has Non-Standard Port
    has_port = 0
    if ':' in parsed.netloc:
        port_str = parsed.netloc.split(':')[-1]
        if port_str.isdigit() and port_str not in ('80', '443'):
            has_port = 1

    # Feature 10: Path Depth
    path_depth = len([segment for segment in parsed.path.split('/') if segment])

    return np.array([
        url_len,
        special_chars,
        domain_len,
        subdomain_cnt,
        has_ip,
        uses_https,
        keyword_cnt,
        has_at,
        has_port,
        path_depth
    ], dtype=np.float64)


def get_url_explanation(url: str, features: np.ndarray, prediction_prob: float) -> list:
    """Generates human-readable explainable AI factor items based on extracted features."""
    explanations = []
    
    # Check HTTP vs HTTPS
    if features[5] == 0:
        explanations.append({'type': 'warning', 'text': 'Uses insecure HTTP protocol instead of encrypted HTTPS.'})
    else:
        explanations.append({'type': 'safe', 'text': 'Uses SSL encryption protocol (HTTPS).'})
        
    # Check IP address
    if features[4] == 1:
        explanations.append({'type': 'warning', 'text': 'Domain resolves directly to a raw IP address, bypassing standard DNS.'})
        
    # Check URL length
    if features[0] > 70:
        explanations.append({'type': 'warning', 'text': f'Unusually long URL string ({int(features[0])} chars) often used to disguise intent.'})
        
    # Check Subdomains
    if features[3] >= 3:
        explanations.append({'type': 'warning', 'text': f'Multiple subdomains detected ({int(features[3])}), indicating domain layering.'})
        
    # Check Keywords
    if features[6] > 0:
        url_lower = url.lower()
        matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        explanations.append({'type': 'warning', 'text': f'Contains high-risk brand keywords: "{", ".join(matched[:3])}"'})
        
    # Check @ symbol
    if features[7] == 1:
        explanations.append({'type': 'warning', 'text': 'Contains "@" symbol, commonly used in URL spoofing techniques.'})

    if not any(e['type'] == 'warning' for e in explanations):
        explanations.append({'type': 'safe', 'text': 'Domain SSL & keyword parameters appear legitimate.'})

    return explanations
