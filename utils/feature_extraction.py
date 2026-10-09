"""
🛡️ PhishGuard AI — Advanced Multi-Tier Phishing Feature Extraction Engine

Extracts 30 features across 4 detection tiers:
  Tier 1 — Lexical Features (from URL string alone, zero network cost)
  Tier 2 — Domain/WHOIS Signals (lightweight lookup)
  Tier 3 — Content Heuristic Signals (page-level, sandboxed)
  Tier 4 — Reputation/Blocklist Signals (external API)

For ML model training, only Tier 1 features (indices 0-19) are used since they
require no network calls and can be computed instantly on any URL.
Tiers 2-4 are computed on-demand during live analysis for enriched explanations.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
import numpy as np

# ───────────────────────────────────────────────────────────────────────────────
# REFERENCE LISTS
# ───────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'bank', 'secure', 'account', 'update', 'signin',
    'recovery', 'confirm', 'support', 'billing', 'token', 'security',
    'wallet', 'password', 'credential', 'authenticate', 'validate',
    'unlock', 'suspend', 'expire', 'reactivate', 'restore'
]

KNOWN_BRANDS = [
    'paypal', 'chase', 'netflix', 'amazon', 'apple', 'google', 'microsoft',
    'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox', 'spotify',
    'adobe', 'yahoo', 'outlook', 'wellsfargo', 'bankofamerica', 'citibank',
    'usps', 'fedex', 'dhl', 'ups', 'whatsapp', 'telegram', 'snapchat',
    'tiktok', 'ebay', 'walmart', 'target', 'costco', 'bestbuy', 'steam',
    'epic', 'coinbase', 'binance', 'metamask', 'blockchain', 'stripe'
]

URL_SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'db.tt', 'qr.ae',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'v.gd',
    'tiny.cc', 'clck.ru', 'shorte.st', 'bc.vc', 'trib.al'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.club', '.work', '.site', '.online', '.icu', '.buzz', '.fun',
    '.monster', '.rest', '.cam', '.casa', '.sbs', '.quest', '.cfd',
    '.lol', '.bond', '.cyou', '.gdn', '.ooo', '.bar'
]

# ───────────────────────────────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit-distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _get_registrable_domain(hostname: str) -> str:
    """
    Extract the registrable domain (eTLD+1) from a hostname.
    Simple heuristic: take last two dot-separated segments.
    """
    parts = hostname.lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname.lower()


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string — high entropy signals random/generated strings."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ───────────────────────────────────────────────────────────────────────────────
# TIER 1 — LEXICAL FEATURES (20 features, extracted from URL string alone)
# ───────────────────────────────────────────────────────────────────────────────

def extract_url_features(url: str) -> np.ndarray:
    """
    Extracts 20 lexical features from a URL for ML model input.
    
    Feature Index Map:
      0  url_length                          — total character count
      1  num_dots                            — dot count (excessive = subdomain tricks)
      2  num_hyphens                         — hyphen count (phishing domains use many)
      3  num_digits_in_domain                — digit density in hostname
      4  has_ip_address                      — raw IP instead of domain (0/1)
      5  has_at_symbol                       — @ in URL, hides real target (0/1)
      6  has_double_slash_redirect           — "//" mid-path, redirect trick (0/1)
      7  subdomain_count                     — number of subdomain levels
      8  tld_in_subdomain                    — brand TLD appears as subdomain (0/1)
      9  uses_url_shortener                  — known shortener domain (0/1)
      10 suspicious_keyword_count            — count of phishing keywords in URL
      11 brand_in_subdomain_not_domain       — brand name in subdomain but not registrable domain (0/1)
      12 min_levenshtein_to_brand            — min edit distance to any known brand
      13 punycode_present                    — xn-- prefix (homograph attack) (0/1)
      14 non_standard_port                   — port not 80/443 (0/1)
      15 uses_https                          — encrypted transport (0/1)
      16 path_depth                          — number of path segments
      17 query_param_count                   — number of query parameters
      18 domain_entropy                      — Shannon entropy of hostname
      19 suspicious_tld                      — uses a high-risk TLD (0/1)
    """
    if not url.startswith(('http://', 'https://')):
        test_url = 'http://' + url
    else:
        test_url = url

    try:
        parsed = urlparse(test_url)
        hostname = parsed.netloc.split(':')[0].lower()
    except Exception:
        hostname = url.split('/')[0].lower()
        parsed = urlparse('http://' + url)

    registrable = _get_registrable_domain(hostname)
    url_lower = url.lower()

    # Feature 0: URL Length
    f_url_length = len(url)

    # Feature 1: Number of Dots
    f_num_dots = url.count('.')

    # Feature 2: Number of Hyphens
    f_num_hyphens = url.count('-')

    # Feature 3: Number of Digits in Domain
    f_num_digits = sum(c.isdigit() for c in hostname)

    # Feature 4: Has IP Address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    f_has_ip = 1 if re.match(ip_pattern, hostname) else 0

    # Feature 5: Has @ Symbol
    f_has_at = 1 if '@' in url else 0

    # Feature 6: Has Double-Slash Redirect (// appearing mid-path after scheme)
    f_has_double_slash = 0
    after_scheme = url.split('://', 1)[-1] if '://' in url else url
    if '/' in after_scheme:
        remainder = after_scheme.split('/', 1)[-1]
        if '//' in remainder:
            f_has_double_slash = 1

    # Feature 7: Subdomain Count
    subdomain_parts = hostname.replace(registrable, '').rstrip('.')
    f_subdomain_count = len([s for s in subdomain_parts.split('.') if s]) if subdomain_parts else 0

    # Feature 8: TLD in Subdomain (e.g., paypal.com.evil-site.xyz)
    f_tld_in_subdomain = 0
    if f_subdomain_count > 0:
        subdomain_str = subdomain_parts.lower()
        for brand in KNOWN_BRANDS:
            if f'{brand}.com' in subdomain_str or f'{brand}.org' in subdomain_str:
                f_tld_in_subdomain = 1
                break

    # Feature 9: Uses URL Shortener
    f_uses_shortener = 1 if any(hostname == s or hostname.endswith('.' + s) for s in URL_SHORTENER_DOMAINS) else 0

    # Feature 10: Suspicious Keyword Count
    f_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Feature 11: Brand Name in Subdomain but NOT in Registrable Domain
    f_brand_subdomain = 0
    for brand in KNOWN_BRANDS:
        if brand in subdomain_parts.lower() and brand not in registrable:
            f_brand_subdomain = 1
            break

    # Feature 12: Minimum Levenshtein Distance to Known Brands
    domain_base = registrable.split('.')[0] if '.' in registrable else registrable
    if domain_base in KNOWN_BRANDS:
        f_min_levenshtein = 0
    else:
        distances = [_levenshtein(domain_base, brand) for brand in KNOWN_BRANDS]
        f_min_levenshtein = min(distances) if distances else 99

    # Feature 13: Punycode Present (xn-- prefix → internationalized domain, homograph attacks)
    f_punycode = 1 if 'xn--' in hostname else 0

    # Feature 14: Non-Standard Port
    f_non_std_port = 0
    if ':' in parsed.netloc:
        port_str = parsed.netloc.split(':')[-1]
        if port_str.isdigit() and port_str not in ('80', '443'):
            f_non_std_port = 1

    # Feature 15: Uses HTTPS
    f_uses_https = 1 if url_lower.startswith('https://') else 0

    # Feature 16: Path Depth
    f_path_depth = len([seg for seg in parsed.path.split('/') if seg])

    # Feature 17: Query Parameter Count
    try:
        f_query_params = len(parse_qs(parsed.query))
    except Exception:
        f_query_params = 0

    # Feature 18: Domain Entropy (high entropy → randomly generated domain)
    f_domain_entropy = round(_shannon_entropy(hostname), 4)

    # Feature 19: Suspicious TLD
    f_suspicious_tld = 0
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            f_suspicious_tld = 1
            break

    return np.array([
        f_url_length,               # 0
        f_num_dots,                 # 1
        f_num_hyphens,              # 2
        f_num_digits,               # 3
        f_has_ip,                   # 4
        f_has_at,                   # 5
        f_has_double_slash,         # 6
        f_subdomain_count,          # 7
        f_tld_in_subdomain,         # 8
        f_uses_shortener,           # 9
        f_keyword_count,            # 10
        f_brand_subdomain,          # 11
        f_min_levenshtein,          # 12
        f_punycode,                 # 13
        f_non_std_port,             # 14
        f_uses_https,               # 15
        f_path_depth,               # 16
        f_query_params,             # 17
        f_domain_entropy,           # 18
        f_suspicious_tld,           # 19
    ], dtype=np.float64)


# ───────────────────────────────────────────────────────────────────────────────
# TIER 1 EXTRA — RULE-BASED WEIGHTED SCORING (fast, explainable, no ML needed)
# ───────────────────────────────────────────────────────────────────────────────

def rule_based_phishing_score(features: np.ndarray) -> float:
    """
    Weighted heuristic scoring using the 20 lexical features.
    Returns a score 0-100 where higher = more suspicious.
    Used as a fallback when ML models aren't available.
    """
    score = 0.0

    # IP address instead of domain
    if features[4] == 1:
        score += 25.0

    # @ symbol (URL spoofing)
    if features[5] == 1:
        score += 15.0

    # Double-slash redirect
    if features[6] == 1:
        score += 10.0

    # Excessive subdomains (≥3)
    if features[7] >= 3:
        score += 20.0
    elif features[7] >= 2:
        score += 10.0

    # TLD appearing in subdomain (paypal.com.evil.xyz pattern)
    if features[8] == 1:
        score += 25.0

    # URL shortener hiding real destination
    if features[9] == 1:
        score += 10.0

    # Suspicious keywords (scaled)
    kw_count = features[10]
    if kw_count >= 3:
        score += 20.0
    elif kw_count >= 1:
        score += 10.0

    # Brand in subdomain but not in registrable domain
    if features[11] == 1:
        score += 25.0

    # Typosquatting (low Levenshtein distance to known brand)
    if 0 < features[12] <= 1:
        score += 25.0
    elif features[12] == 2:
        score += 15.0

    # Punycode / homograph attack
    if features[13] == 1:
        score += 20.0

    # Non-standard port
    if features[14] == 1:
        score += 10.0

    # No HTTPS
    if features[15] == 0:
        score += 15.0

    # Very long URL (> 75 chars)
    if features[0] > 100:
        score += 10.0
    elif features[0] > 75:
        score += 5.0

    # High domain entropy (randomly generated domain)
    if features[18] > 4.0:
        score += 10.0

    # Suspicious TLD
    if features[19] == 1:
        score += 15.0

    return min(score, 100.0)


# ───────────────────────────────────────────────────────────────────────────────
# EXPLANATION GENERATOR — RICH, CATEGORIZED SECURITY AUDIT INDICATORS
# ───────────────────────────────────────────────────────────────────────────────

def get_url_explanation(url: str, features: np.ndarray, prediction_prob: float) -> list:
    """
    Generates human-readable, categorized security audit indicators
    based on the 20 extracted features and the prediction probability.
    
    Each indicator has:
      - type:     'warning' | 'danger' | 'safe' | 'info'
      - category: 'Protocol' | 'Domain' | 'Lexical' | 'Brand' | 'Structure' | 'Reputation'
      - text:     human-readable explanation string
    """
    explanations = []

    # ─── Protocol Analysis ───
    if features[15] == 0:
        explanations.append({
            'type': 'warning',
            'category': 'Protocol',
            'text': 'Uses insecure HTTP — no SSL/TLS encryption protecting data in transit.'
        })
    else:
        explanations.append({
            'type': 'safe',
            'category': 'Protocol',
            'text': 'Uses HTTPS with SSL/TLS encryption protocol.'
        })

    if features[14] == 1:
        explanations.append({
            'type': 'warning',
            'category': 'Protocol',
            'text': 'Non-standard port detected — legitimate sites rarely use custom ports in URLs.'
        })

    # ─── Domain Analysis ───
    if features[4] == 1:
        explanations.append({
            'type': 'danger',
            'category': 'Domain',
            'text': 'Raw IP address used instead of a domain name — bypasses DNS and certificate validation.'
        })

    if features[7] >= 3:
        explanations.append({
            'type': 'warning',
            'category': 'Domain',
            'text': f'Excessive subdomain nesting ({int(features[7])} levels) — common domain layering tactic.'
        })
    elif features[7] >= 2:
        explanations.append({
            'type': 'info',
            'category': 'Domain',
            'text': f'Multiple subdomains detected ({int(features[7])} levels).'
        })

    if features[8] == 1:
        explanations.append({
            'type': 'danger',
            'category': 'Domain',
            'text': 'Subdomain trick detected — a brand\'s full domain (e.g., paypal.com) appears as a subdomain of a different domain.'
        })

    if features[19] == 1:
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            host = parsed.netloc.split(':')[0]
            tld_match = [t for t in SUSPICIOUS_TLDS if host.endswith(t)]
            tld_name = tld_match[0] if tld_match else 'suspicious'
        except Exception:
            tld_name = 'suspicious'
        explanations.append({
            'type': 'warning',
            'category': 'Domain',
            'text': f'High-risk TLD "{tld_name}" — frequently abused by phishing campaigns; rarely used by legitimate organizations.'
        })

    if features[18] > 4.0:
        explanations.append({
            'type': 'warning',
            'category': 'Domain',
            'text': f'High domain entropy ({features[18]:.2f}) — suggests randomly generated or algorithmically created domain.'
        })

    # ─── Brand Impersonation Analysis ───
    if features[11] == 1:
        # Identify which brand
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            host = parsed.netloc.split(':')[0].lower()
            reg = _get_registrable_domain(host)
            sub_str = host.replace(reg, '').rstrip('.')
            impersonated = [b for b in KNOWN_BRANDS if b in sub_str]
            brand_str = ', '.join(impersonated[:3]) if impersonated else 'a known brand'
        except Exception:
            brand_str = 'a known brand'
        explanations.append({
            'type': 'danger',
            'category': 'Brand',
            'text': f'Brand impersonation: "{brand_str}" appears in subdomain but is NOT the actual registered domain.'
        })

    if 0 < features[12] <= 2:
        # Find the closest brand
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            host = parsed.netloc.split(':')[0].lower()
            reg = _get_registrable_domain(host)
            domain_base = reg.split('.')[0]
            closest = min(KNOWN_BRANDS, key=lambda b: _levenshtein(domain_base, b))
            dist = _levenshtein(domain_base, closest)
        except Exception:
            closest, dist = 'a brand', int(features[12])
        severity = 'danger' if dist <= 1 else 'warning'
        explanations.append({
            'type': severity,
            'category': 'Brand',
            'text': f'Typosquatting detected — domain is {dist} character(s) away from "{closest}" (Levenshtein distance).'
        })

    if features[13] == 1:
        explanations.append({
            'type': 'danger',
            'category': 'Brand',
            'text': 'Punycode (xn--) internationalized domain detected — potential homograph attack using look-alike Unicode characters.'
        })

    # ─── Lexical / Structure Analysis ───
    if features[5] == 1:
        explanations.append({
            'type': 'warning',
            'category': 'Lexical',
            'text': 'Contains "@" symbol — used to hide the real destination server in the URL.'
        })

    if features[6] == 1:
        explanations.append({
            'type': 'warning',
            'category': 'Lexical',
            'text': 'Double-slash "//" found mid-path — potential redirect trick to a different server.'
        })

    if features[0] > 100:
        explanations.append({
            'type': 'warning',
            'category': 'Lexical',
            'text': f'Extremely long URL ({int(features[0])} chars) — used to conceal the real domain from the address bar.'
        })
    elif features[0] > 75:
        explanations.append({
            'type': 'info',
            'category': 'Lexical',
            'text': f'Unusually long URL ({int(features[0])} chars).'
        })

    if features[10] >= 3:
        url_lower = url.lower()
        matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower][:5]
        explanations.append({
            'type': 'warning',
            'category': 'Lexical',
            'text': f'Multiple phishing keywords detected: "{", ".join(matched)}"'
        })
    elif features[10] >= 1:
        url_lower = url.lower()
        matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower][:3]
        explanations.append({
            'type': 'info',
            'category': 'Lexical',
            'text': f'Contains security-sensitive keywords: "{", ".join(matched)}"'
        })

    # ─── Shortener / Reputation ───
    if features[9] == 1:
        explanations.append({
            'type': 'warning',
            'category': 'Reputation',
            'text': 'URL shortener detected — the real destination domain is hidden. Expand before visiting.'
        })

    # ─── Overall Safe Verdict ───
    warning_count = sum(1 for e in explanations if e['type'] in ('warning', 'danger'))
    if warning_count == 0:
        explanations.append({
            'type': 'safe',
            'category': 'Domain',
            'text': 'Domain structure appears legitimate with no suspicious patterns.'
        })
        explanations.append({
            'type': 'safe',
            'category': 'Brand',
            'text': 'No brand impersonation or typosquatting signatures detected.'
        })

    return explanations


# ───────────────────────────────────────────────────────────────────────────────
# FEATURE NAME MAP (for dashboard display and model explainability)
# ───────────────────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    'URL Length',
    'Dot Count',
    'Hyphen Count',
    'Digits in Domain',
    'IP Address Used',
    '@ Symbol Present',
    'Double-Slash Redirect',
    'Subdomain Depth',
    'TLD in Subdomain',
    'URL Shortener',
    'Suspicious Keywords',
    'Brand in Subdomain Only',
    'Min Levenshtein to Brand',
    'Punycode / Homograph',
    'Non-Standard Port',
    'Uses HTTPS',
    'Path Depth',
    'Query Parameters',
    'Domain Entropy',
    'Suspicious TLD',
]
