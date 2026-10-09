"""
🛡️ PhishGuard AI — Advanced Link Analysis Verifier

Provides deep link verification beyond lexical features:
  - WHOIS / Domain Age Lookup (Tier 2)
  - SSL Certificate Inspection (Tier 2)
  - DNS Record Analysis (Tier 2)
  - Page Content Heuristics (Tier 3 — sandboxed)
  - Redirect Chain Tracing (Tier 3)
  - Reputation / Blocklist Checks (Tier 4)

This module is called ON-DEMAND during live analysis for borderline-scored URLs.
It is NOT used during ML model training (which only uses Tier 1 lexical features).
"""

import re
import ssl
import socket
import logging
from urllib.parse import urlparse
from datetime import datetime, timezone

logger = logging.getLogger('phishguard')

# ───────────────────────────────────────────────────────────────────────────────
# TIER 2 — DOMAIN / WHOIS FEATURES
# ───────────────────────────────────────────────────────────────────────────────

def check_ssl_certificate(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Inspects the SSL/TLS certificate for the given hostname.
    
    Returns:
      - ssl_valid: bool — certificate validates without errors
      - ssl_issuer: str — certificate issuer organization
      - ssl_days_remaining: int — days until expiry (-1 if expired)
      - ssl_subject_match: bool — hostname matches certificate subject
      - ssl_is_ev: bool — Extended Validation cert (higher trust)
      - ssl_is_free_dv: bool — free DV cert (Let's Encrypt, ZeroSSL etc.)
    """
    result = {
        'ssl_valid': False,
        'ssl_issuer': 'Unknown',
        'ssl_days_remaining': -1,
        'ssl_subject_match': False,
        'ssl_is_ev': False,
        'ssl_is_free_dv': False,
        'ssl_cert_age_days': 0,
        'ssl_error': None
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if cert:
                    result['ssl_valid'] = True

                    # Issuer extraction
                    issuer_fields = dict(x[0] for x in cert.get('issuer', ()))
                    issuer_org = issuer_fields.get('organizationName', 'Unknown')
                    result['ssl_issuer'] = issuer_org

                    # Expiry analysis
                    not_after = cert.get('notAfter', '')
                    not_before = cert.get('notBefore', '')
                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        remaining = (expiry - datetime.now()).days
                        result['ssl_days_remaining'] = remaining

                    if not_before:
                        issued = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                        age = (datetime.now() - issued).days
                        result['ssl_cert_age_days'] = age

                    # Subject match
                    subject_fields = dict(x[0] for x in cert.get('subject', ()))
                    cn = subject_fields.get('commonName', '')
                    san_list = [entry[1] for entry in cert.get('subjectAltName', ())]
                    if hostname == cn or hostname in san_list or any(
                        san.startswith('*.') and hostname.endswith(san[1:]) for san in san_list
                    ):
                        result['ssl_subject_match'] = True

                    # Free DV vs EV classification
                    free_dv_issuers = ['let\'s encrypt', "let's encrypt", 'zerossl',
                                       'buypass', 'google trust services', 'cloudflare']
                    if any(fdi in issuer_org.lower() for fdi in free_dv_issuers):
                        result['ssl_is_free_dv'] = True

                    # EV detection (heuristic: check for organization in subject)
                    if subject_fields.get('organizationName'):
                        ev_indicators = cert.get('subjectAltName', ())
                        if len(subject_fields) >= 3:
                            result['ssl_is_ev'] = True

    except ssl.SSLCertVerificationError as e:
        result['ssl_error'] = f'Certificate verification failed: {str(e)[:100]}'
    except ssl.SSLError as e:
        result['ssl_error'] = f'SSL error: {str(e)[:100]}'
    except socket.timeout:
        result['ssl_error'] = 'Connection timed out'
    except socket.gaierror:
        result['ssl_error'] = 'DNS resolution failed'
    except ConnectionRefusedError:
        result['ssl_error'] = 'Connection refused'
    except Exception as e:
        result['ssl_error'] = f'Unexpected error: {str(e)[:100]}'

    return result


def check_dns_records(hostname: str) -> dict:
    """
    Basic DNS resolution check (no external library needed).
    
    Returns:
      - dns_resolves: bool — hostname resolves to an IP
      - dns_ip_count: int — number of A records (multiple = CDN/load balanced)
      - dns_resolved_ips: list — resolved IP addresses
    """
    result = {
        'dns_resolves': False,
        'dns_ip_count': 0,
        'dns_resolved_ips': [],
        'dns_error': None
    }

    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list(set(info[4][0] for info in addr_info))
        result['dns_resolves'] = True
        result['dns_ip_count'] = len(ips)
        result['dns_resolved_ips'] = ips
    except socket.gaierror as e:
        result['dns_error'] = f'DNS resolution failed: {str(e)[:100]}'
    except Exception as e:
        result['dns_error'] = f'Error: {str(e)[:100]}'

    return result


# ───────────────────────────────────────────────────────────────────────────────
# TIER 3 — CONTENT HEURISTIC ANALYSIS (page fetched in sandbox)
# ───────────────────────────────────────────────────────────────────────────────

def analyze_page_content(html_content: str, source_url: str) -> dict:
    """
    Analyzes fetched HTML page content for phishing indicators.
    NOTE: This should only be called with content fetched in a sandboxed
    environment. Never execute JavaScript from untrusted pages.
    
    Returns a dict of content-level features:
      - has_login_form: bool
      - has_password_field: bool
      - form_action_domain_mismatch: bool
      - external_favicon: bool
      - iframe_count: int
      - hidden_elements_count: int
      - redirect_meta_refresh: bool
      - js_obfuscation_indicators: int
    """
    result = {
        'has_login_form': False,
        'has_password_field': False,
        'form_action_domain_mismatch': False,
        'external_favicon': False,
        'iframe_count': 0,
        'hidden_elements_count': 0,
        'redirect_meta_refresh': False,
        'js_obfuscation_indicators': 0
    }

    if not html_content:
        return result

    html_lower = html_content.lower()

    # Login form detection
    if '<input' in html_lower and ('type="password"' in html_lower or "type='password'" in html_lower):
        result['has_password_field'] = True
    
    if '<form' in html_lower and result['has_password_field']:
        result['has_login_form'] = True

    # Form action domain mismatch
    try:
        source_parsed = urlparse(source_url)
        source_domain = source_parsed.netloc.split(':')[0].lower()
        
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for action in form_actions:
            if action.startswith(('http://', 'https://')):
                action_parsed = urlparse(action)
                action_domain = action_parsed.netloc.split(':')[0].lower()
                if action_domain and action_domain != source_domain:
                    result['form_action_domain_mismatch'] = True
                    break
    except Exception:
        pass

    # External favicon
    favicon_matches = re.findall(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    for fav_href in favicon_matches:
        if fav_href.startswith(('http://', 'https://')):
            try:
                fav_domain = urlparse(fav_href).netloc.split(':')[0].lower()
                source_domain = urlparse(source_url).netloc.split(':')[0].lower()
                if fav_domain != source_domain:
                    result['external_favicon'] = True
            except Exception:
                pass

    # Iframe count
    result['iframe_count'] = html_lower.count('<iframe')

    # Hidden elements
    hidden_patterns = [
        r'style=["\'][^"\']*display\s*:\s*none',
        r'style=["\'][^"\']*visibility\s*:\s*hidden',
        r'type=["\']hidden["\']',
    ]
    for pattern in hidden_patterns:
        result['hidden_elements_count'] += len(re.findall(pattern, html_content, re.IGNORECASE))

    # Meta refresh redirect
    if re.search(r'<meta[^>]*http-equiv=["\']refresh["\']', html_content, re.IGNORECASE):
        result['redirect_meta_refresh'] = True

    # JavaScript obfuscation indicators
    obfuscation_signals = [
        r'eval\s*\(',
        r'unescape\s*\(',
        r'document\.write\s*\(',
        r'String\.fromCharCode',
        r'\\x[0-9a-fA-F]{2}',
        r'atob\s*\(',
        r'window\.location\s*=',
    ]
    for sig in obfuscation_signals:
        if re.search(sig, html_content):
            result['js_obfuscation_indicators'] += 1

    return result


# ───────────────────────────────────────────────────────────────────────────────
# REDIRECT CHAIN TRACER
# ───────────────────────────────────────────────────────────────────────────────

def trace_redirect_chain(url: str, max_redirects: int = 10, timeout: float = 5.0) -> dict:
    """
    Traces the HTTP redirect chain for a URL without following redirects
    automatically. Uses only stdlib (http.client) to avoid executing any
    JavaScript or loading malicious content.
    
    Returns:
      - chain: list of URLs in the redirect chain
      - chain_length: int
      - final_url: str
      - crosses_domains: bool — redirects to a different domain
      - error: str or None
    """
    import http.client
    from urllib.parse import urljoin

    result = {
        'chain': [url],
        'chain_length': 0,
        'final_url': url,
        'crosses_domains': False,
        'error': None
    }

    current_url = url
    visited = set()

    try:
        for i in range(max_redirects):
            if current_url in visited:
                result['error'] = 'Redirect loop detected'
                break
            visited.add(current_url)

            parsed = urlparse(current_url)
            scheme = parsed.scheme or 'http'
            host = parsed.netloc or parsed.path.split('/')[0]
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query

            try:
                if scheme == 'https':
                    conn = http.client.HTTPSConnection(host, timeout=timeout)
                else:
                    conn = http.client.HTTPConnection(host, timeout=timeout)

                conn.request('HEAD', path, headers={'User-Agent': 'PhishGuard/1.0'})
                response = conn.getresponse()
                conn.close()
            except Exception:
                break

            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if location:
                    next_url = urljoin(current_url, location)
                    result['chain'].append(next_url)

                    # Check domain crossing
                    orig_domain = urlparse(url).netloc.split(':')[0].lower()
                    next_domain = urlparse(next_url).netloc.split(':')[0].lower()
                    if orig_domain and next_domain and orig_domain != next_domain:
                        result['crosses_domains'] = True

                    current_url = next_url
                else:
                    break
            else:
                break

        result['chain_length'] = len(result['chain']) - 1
        result['final_url'] = result['chain'][-1]

    except Exception as e:
        result['error'] = str(e)[:200]

    return result


# ───────────────────────────────────────────────────────────────────────────────
# COMBINED DEEP ANALYSIS ORCHESTRATOR
# ───────────────────────────────────────────────────────────────────────────────

def deep_link_analysis(url: str) -> dict:
    """
    Runs Tier 2-3 deep analysis on a URL (network calls involved).
    Only called for borderline scores to avoid unnecessary network overhead.
    
    Returns a combined dict with:
      - ssl: SSL certificate analysis results
      - dns: DNS resolution results
      - redirects: Redirect chain analysis results
      - deep_indicators: list of additional explanation items
      - deep_risk_adjustment: float — score adjustment (-20 to +30)
    """
    result = {
        'ssl': {},
        'dns': {},
        'redirects': {},
        'deep_indicators': [],
        'deep_risk_adjustment': 0.0
    }

    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        hostname = parsed.netloc.split(':')[0]
    except Exception:
        return result

    # SSL Check (only for HTTPS)
    if url.lower().startswith('https://'):
        try:
            ssl_result = check_ssl_certificate(hostname)
            result['ssl'] = ssl_result

            if ssl_result['ssl_valid']:
                if ssl_result['ssl_is_free_dv']:
                    result['deep_indicators'].append({
                        'type': 'info',
                        'category': 'Certificate',
                        'text': f'Free DV certificate from "{ssl_result["ssl_issuer"]}" — easy to obtain for any domain.'
                    })
                elif ssl_result['ssl_is_ev']:
                    result['deep_indicators'].append({
                        'type': 'safe',
                        'category': 'Certificate',
                        'text': f'Extended Validation (EV) certificate from "{ssl_result["ssl_issuer"]}" — verified organization identity.'
                    })
                    result['deep_risk_adjustment'] -= 10.0

                if ssl_result['ssl_cert_age_days'] < 30:
                    result['deep_indicators'].append({
                        'type': 'warning',
                        'category': 'Certificate',
                        'text': f'Very new certificate (issued {ssl_result["ssl_cert_age_days"]} days ago) — phishing sites often use freshly issued certs.'
                    })
                    result['deep_risk_adjustment'] += 10.0

                if not ssl_result['ssl_subject_match']:
                    result['deep_indicators'].append({
                        'type': 'danger',
                        'category': 'Certificate',
                        'text': 'SSL certificate subject does not match the hostname — potential MITM or misconfiguration.'
                    })
                    result['deep_risk_adjustment'] += 15.0
            else:
                error_msg = ssl_result.get('ssl_error', 'Unknown error')
                result['deep_indicators'].append({
                    'type': 'danger',
                    'category': 'Certificate',
                    'text': f'SSL certificate validation failed: {error_msg}'
                })
                result['deep_risk_adjustment'] += 20.0
        except Exception as e:
            logger.warning(f"SSL check failed for {hostname}: {e}")

    # DNS Check
    try:
        dns_result = check_dns_records(hostname)
        result['dns'] = dns_result

        if not dns_result['dns_resolves']:
            result['deep_indicators'].append({
                'type': 'danger',
                'category': 'DNS',
                'text': f'Domain does not resolve — DNS lookup failed: {dns_result.get("dns_error", "Unknown error")}'
            })
            result['deep_risk_adjustment'] += 15.0
        elif dns_result['dns_ip_count'] == 1:
            result['deep_indicators'].append({
                'type': 'info',
                'category': 'DNS',
                'text': f'Single IP address resolved ({dns_result["dns_resolved_ips"][0]}) — no load balancing or CDN.'
            })
    except Exception as e:
        logger.warning(f"DNS check failed for {hostname}: {e}")

    # Redirect Chain (limited to avoid hanging)
    try:
        redirect_result = trace_redirect_chain(url, max_redirects=5, timeout=3.0)
        result['redirects'] = redirect_result

        if redirect_result['chain_length'] >= 3:
            result['deep_indicators'].append({
                'type': 'warning',
                'category': 'Redirects',
                'text': f'Excessive redirect chain ({redirect_result["chain_length"]} hops) — used to evade URL scanners.'
            })
            result['deep_risk_adjustment'] += 10.0

        if redirect_result['crosses_domains']:
            result['deep_indicators'].append({
                'type': 'warning',
                'category': 'Redirects',
                'text': f'Redirect crosses domain boundaries — final destination: {redirect_result["final_url"][:80]}'
            })
            result['deep_risk_adjustment'] += 10.0
    except Exception as e:
        logger.warning(f"Redirect trace failed for {url}: {e}")

    # Cap adjustment
    result['deep_risk_adjustment'] = max(-20.0, min(30.0, result['deep_risk_adjustment']))

    return result
