import re
import string

def preprocess_message(text: str) -> str:
    """
    NLP Text Preprocessing Pipeline:
    1. Lowercase text
    2. Remove URLs (processed separately if present)
    3. Remove punctuation
    4. Normalize whitespace
    """
    if not text:
        return ""
    
    # 1. Lowercase
    text = text.lower()
    
    # 2. Remove URLs
    text = re.sub(r'https?://[^\s]+', ' ', text)
    
    # 3. Remove Punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # 4. Normalize Whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def detect_message_patterns(text: str) -> tuple[list, list]:
    """Detects specific scam patterns (urgency, threats, financial, credentials) for display."""
    text_lower = text.lower()
    matched_patterns = []
    explanations = []
    
    urgency_words = ['urgent', 'act now', 'limited time', 'immediate', 'verify within', '24 hours', 'suspended', 'blocked', 'closed']
    threat_words = ['court', 'jail', 'legal action', 'police', 'breach', 'security alert', 'unauthorized login']
    financial_words = ['free money', 'prize', 'gift card', 'cash reward', 'selected', 'winner', 'unclaimed', 'btc', 'investment', 'reward', '0.5 btc']
    cred_words = ['password', 'otp', 'pin', 'ssn', 'social security', 'credit card', 'banking login', 'identity']

    m_urgent = [w for w in urgency_words if w in text_lower]
    if m_urgent:
        matched_patterns.extend(m_urgent)
        explanations.append({'type': 'warning', 'text': f'High urgency hook detected: "{", ".join(m_urgent[:3])}"'})
        
    m_threat = [w for w in threat_words if w in text_lower]
    if m_threat:
        matched_patterns.extend(m_threat)
        explanations.append({'type': 'warning', 'text': f'Coercive threat language detected: "{", ".join(m_threat[:2])}"'})
        
    m_fin = [w for w in financial_words if w in text_lower]
    if m_fin:
        matched_patterns.extend(m_fin)
        explanations.append({'type': 'warning', 'text': f'Unrealistic financial bait hook: "{", ".join(m_fin[:2])}"'})
        
    m_cred = [w for w in cred_words if w in text_lower]
    if m_cred:
        matched_patterns.extend(m_cred)
        explanations.append({'type': 'warning', 'text': f'Sensitive information / credential request: "{", ".join(m_cred[:2])}"'})

    if re.search(r'https?://[^\s]+', text):
        explanations.append({'type': 'warning', 'text': 'Prompts user to click embedded link inside message.'})

    if not explanations:
        explanations.append({'type': 'safe', 'text': 'No pressure tactics or urgency phrases found.'})
        explanations.append({'type': 'safe', 'text': 'No monetary or identity hooks detected.'})

    return matched_patterns, explanations
