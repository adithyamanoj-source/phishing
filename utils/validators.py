import re
from urllib.parse import urlparse

def validate_url(url: str) -> tuple[bool, str]:
    """Validates URL format and constraints."""
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"
    
    url = url.strip()
    if len(url) > 2048:
        return False, "URL exceeds maximum allowed length of 2048 characters"
    
    # Prepend http:// if user forgot scheme for parsing
    test_url = url if re.match(r'^https?://', url, re.IGNORECASE) else f"http://{url}"
    
    try:
        parsed = urlparse(test_url)
        if not parsed.netloc:
            return False, "Invalid URL domain format"
        return True, "Valid"
    except Exception:
        return False, "Malformed URL string"


def validate_message(text: str) -> tuple[bool, str]:
    """Validates suspicious message input text."""
    if not text or not isinstance(text, str):
        return False, "Message text cannot be empty"
    
    text = text.strip()
    if len(text) < 5:
        return False, "Message must be at least 5 characters long"
    
    if len(text) > 5000:
        return False, "Message exceeds maximum allowed length of 5000 characters"
        
    return True, "Valid"


def validate_email(email: str) -> tuple[bool, str]:
    """Validates email format."""
    if not email or not isinstance(email, str):
        return False, "Email address is required"
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email.strip()):
        return False, "Invalid email address format"
        
    return True, "Valid"


def validate_password(password: str) -> tuple[bool, str]:
    """Validates password security requirements (8+ chars, upper, lower, digit)."""
    if not password or not isinstance(password, str):
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
        
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
        
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
        
    return True, "Valid"
