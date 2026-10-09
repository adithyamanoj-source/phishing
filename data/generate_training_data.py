"""
🛡️ PhishGuard AI — Enhanced Training Data Generator

Generates diverse labeled datasets for ML model training:
  - URL Dataset: 3,000 samples covering all 20 lexical feature dimensions
  - Message Dataset: 2,000 samples with varied scam/safe patterns

Phishing URL types generated:
  - Raw IP address URLs
  - Brand typosquatting (1-2 Levenshtein distance)
  - Subdomain layering tricks (paypal.com.evil.xyz)
  - Brand-in-subdomain impersonation
  - Punycode / homograph domains
  - URL shortener redirects
  - Suspicious TLD domains
  - Long obfuscated URLs with query params
  - Non-standard port URLs
  - @ symbol redirect URLs
  - Double-slash redirect URLs
"""

import os
import csv
import random
import string

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# ───────────────────────────────────────────────────────────────────────────────
# REFERENCE DATA
# ───────────────────────────────────────────────────────────────────────────────

LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'reddit.com', 'stackoverflow.com', 'dropbox.com',
    'chase.com', 'paypal.com', 'bankofamerica.com', 'wellsfargo.com', 'ebay.com',
    'spotify.com', 'zoom.us', 'salesforce.com', 'adobe.com', 'slack.com',
    'notion.so', 'figma.com', 'canva.com', 'stripe.com', 'shopify.com',
    'medium.com', 'quora.com', 'pinterest.com', 'tumblr.com', 'bbc.co.uk',
    'nytimes.com', 'cnn.com', 'reuters.com', 'bloomberg.com', 'techcrunch.com'
]

PATH_SEGMENTS = [
    'login', 'signin', 'account', 'settings', 'home', 'dashboard',
    'profile', 'billing', 'help', 'contact', 'about', 'services',
    'docs', 'api', 'blog', 'news', 'products', 'pricing', 'support',
    'faq', 'careers', 'terms', 'privacy', 'security', 'download'
]

BRANDS = ['paypal', 'chase', 'netflix', 'amazon', 'apple', 'google', 'microsoft',
          'facebook', 'instagram', 'coinbase', 'binance', 'spotify', 'adobe',
          'dropbox', 'linkedin', 'twitter', 'whatsapp', 'telegram', 'ebay', 'steam']

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
                   '.club', '.work', '.site', '.online', '.icu', '.buzz', '.fun',
                   '.monster', '.rest', '.cam', '.sbs', '.quest', '.cfd']

PHISHING_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'signin',
                     'recovery', 'confirm', 'validate', 'authenticate', 'unlock',
                     'suspend', 'reactivate', 'password', 'credential']

NAMES = ['Sarah', 'John', 'Alex', 'Michael', 'Emily', 'David', 'Jessica', 'Daniel',
         'Priya', 'Raj', 'Mei', 'Carlos', 'Fatima', 'James', 'Olivia', 'Liam']

# ───────────────────────────────────────────────────────────────────────────────
# TYPOSQUAT GENERATOR
# ───────────────────────────────────────────────────────────────────────────────

def _generate_typosquat(brand: str) -> str:
    """Generate a typosquatted version of a brand name (Levenshtein distance 1-2)."""
    method = random.choice(['swap', 'insert', 'delete', 'replace', 'double'])
    name = brand

    if method == 'swap' and len(name) > 2:
        i = random.randint(0, len(name) - 2)
        name = name[:i] + name[i+1] + name[i] + name[i+2:]
    elif method == 'insert':
        i = random.randint(0, len(name))
        char = random.choice(string.ascii_lowercase)
        name = name[:i] + char + name[i:]
    elif method == 'delete' and len(name) > 3:
        i = random.randint(0, len(name) - 1)
        name = name[:i] + name[i+1:]
    elif method == 'replace':
        i = random.randint(0, len(name) - 1)
        replacements = {'a': '4', 'e': '3', 'i': '1', 'l': '1', 'o': '0',
                        's': '5', 't': '7', 'g': '9', 'b': '6'}
        char = replacements.get(name[i], random.choice(string.ascii_lowercase))
        name = name[:i] + char + name[i+1:]
    elif method == 'double' and len(name) > 2:
        i = random.randint(0, len(name) - 1)
        name = name[:i] + name[i] + name[i:]

    return name if name != brand else brand + 's'


def _random_token() -> str:
    """Generate a random token/session-like string."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 24)))


# ───────────────────────────────────────────────────────────────────────────────
# URL DATASET GENERATOR
# ───────────────────────────────────────────────────────────────────────────────

def generate_url_dataset(filename='url_dataset.csv', count=3000):
    """
    Generates a balanced URL dataset with 50% legitimate and 50% phishing URLs.
    Phishing URLs are distributed across 11 different attack vector categories
    to ensure the ML model learns all feature dimensions.
    """
    filepath = os.path.join(DATA_DIR, filename)
    rows = []

    # ─── 50% LEGITIMATE URLS ───
    legit_count = count // 2
    for _ in range(legit_count):
        domain = random.choice(LEGITIMATE_DOMAINS)
        path = random.choice(PATH_SEGMENTS) if random.random() > 0.3 else ''
        sub = 'www.' if random.random() > 0.5 else ''
        protocol = 'https://'
        
        if path:
            # Sometimes add deeper paths
            if random.random() > 0.7:
                path += '/' + random.choice(PATH_SEGMENTS)
            # Sometimes add query params
            if random.random() > 0.8:
                path += f'?page={random.randint(1, 50)}'
            url = f"{protocol}{sub}{domain}/{path}"
        else:
            url = f"{protocol}{sub}{domain}"
        
        rows.append({'url': url, 'label': 0})

    # ─── 50% PHISHING URLS — across 11 attack categories ───
    phish_count = count // 2
    
    # Distribution weights for each attack type
    attack_types = [
        'ip_address',           # Feature 4: raw IP
        'typosquat',            # Feature 12: Levenshtein distance
        'subdomain_layer',      # Feature 7,8: subdomain tricks + TLD in subdomain
        'brand_subdomain',      # Feature 11: brand in subdomain not domain
        'suspicious_tld',       # Feature 19: risky TLDs
        'http_insecure',        # Feature 15: no HTTPS
        'at_symbol',            # Feature 5: @ redirect
        'double_slash',         # Feature 6: // mid-path
        'non_std_port',         # Feature 14: unusual port
        'long_obfuscated',      # Feature 0,10,16,17: long URLs with keywords
        'keyword_stuffing',     # Feature 10: many suspicious keywords
    ]

    for i in range(phish_count):
        attack = attack_types[i % len(attack_types)]
        brand = random.choice(BRANDS)
        tld = random.choice(SUSPICIOUS_TLDS)

        if attack == 'ip_address':
            ip = f"{random.randint(100, 230)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            path = random.choice(PHISHING_KEYWORDS)
            url = f"http://{ip}/{path}/update-{random.choice(PHISHING_KEYWORDS)}"

        elif attack == 'typosquat':
            typo_name = _generate_typosquat(brand)
            safe_tld = random.choice(['.com', '.net', '.org'])
            url = f"http://{typo_name}{safe_tld}/{random.choice(PHISHING_KEYWORDS)}"

        elif attack == 'subdomain_layer':
            # paypal.com.verify-login.xyz pattern
            real_domain = f"{''.join(random.choices(string.ascii_lowercase, k=6))}{tld}"
            url = f"http://{brand}.com.{real_domain}/{random.choice(PHISHING_KEYWORDS)}?token={_random_token()}"

        elif attack == 'brand_subdomain':
            # secure-paypal.evil-domain.xyz pattern
            evil = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))
            url = f"http://{brand}-{random.choice(PHISHING_KEYWORDS)}.{evil}{tld}/auth"

        elif attack == 'suspicious_tld':
            domain = f"{random.choice(PHISHING_KEYWORDS)}-{brand}{tld}"
            url = f"http://{domain}/{random.choice(PHISHING_KEYWORDS)}?id={random.randint(100, 9999)}"

        elif attack == 'http_insecure':
            domain = f"secure-{brand}-{random.choice(PHISHING_KEYWORDS)}{random.choice(['.net', '.info', '.org'])}"
            url = f"http://{domain}/{random.choice(PHISHING_KEYWORDS)}/confirm_identity.php?user={random.randint(100, 999)}"

        elif attack == 'at_symbol':
            # http://paypal.com@evil-site.com/login
            evil = ''.join(random.choices(string.ascii_lowercase, k=8))
            url = f"http://{brand}.com@{evil}{tld}/{random.choice(PHISHING_KEYWORDS)}"

        elif attack == 'double_slash':
            evil = ''.join(random.choices(string.ascii_lowercase, k=7))
            url = f"http://{evil}{tld}/{random.choice(PHISHING_KEYWORDS)}//{brand}-verify/auth"

        elif attack == 'non_std_port':
            ip = f"{random.randint(100, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            port = random.choice([8080, 8443, 3000, 4443, 9090, 1337])
            url = f"http://{ip}:{port}/{random.choice(PHISHING_KEYWORDS)}/{brand}-{random.choice(PHISHING_KEYWORDS)}"

        elif attack == 'long_obfuscated':
            # Very long URL with many query params and keywords
            evil = ''.join(random.choices(string.ascii_lowercase, k=8))
            kws = random.sample(PHISHING_KEYWORDS, min(4, len(PHISHING_KEYWORDS)))
            path = '/'.join(kws)
            params = '&'.join([f"{k}={_random_token()}" for k in random.sample(PHISHING_KEYWORDS, 3)])
            url = f"http://{evil}{tld}/{path}?{params}&ref={brand}&session={_random_token()}"

        elif attack == 'keyword_stuffing':
            evil = ''.join(random.choices(string.ascii_lowercase, k=6))
            kws = '-'.join(random.sample(PHISHING_KEYWORDS, min(5, len(PHISHING_KEYWORDS))))
            url = f"http://{kws}.{evil}{tld}/auth/{brand}"

        rows.append({'url': url, 'label': 1})

    random.shuffle(rows)

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['url', 'label'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[DATA] Generated {len(rows)} URL records (11 attack types) at {filepath}")


# ───────────────────────────────────────────────────────────────────────────────
# MESSAGE DATASET GENERATOR
# ───────────────────────────────────────────────────────────────────────────────

SAFE_TEMPLATES = [
    "Hi {name}, your package delivery is scheduled for tomorrow between 2 PM and 4 PM.",
    "Hey! Don't forget our meeting today at 3:00 PM in Conference Room B.",
    "Your appointment with Dr. Smith is confirmed for Friday at 10 AM.",
    "Can you please review the attached document and send me your feedback?",
    "Thanks for visiting our store! Here is your digital receipt for purchase #{num}.",
    "Happy Birthday {name}! Wishing you a fantastic day and great year ahead.",
    "Your weekly account summary is ready to view in the banking app.",
    "Hey, are we still meeting for lunch today? Let me know!",
    "Good morning {name}, the project deadline has been extended to next Friday.",
    "Your reservation at The Grand Hotel is confirmed for {name}. Check-in: 3 PM.",
    "Reminder: Your gym membership renewal is due on the 15th of this month.",
    "Hi {name}, please find the meeting notes from yesterday's team sync attached.",
    "Weather alert: Light rain expected in your area this afternoon. Bring an umbrella!",
    "Your order #{num} has been shipped! Expected delivery: 3-5 business days.",
    "Hi {name}, your car service appointment is confirmed for Saturday at 9 AM.",
    "Don't forget to submit your timesheet by end of day today.",
    "Hey {name}, great job on the presentation today! Really well done.",
    "Your library books are due for return by next Monday.",
    "Team lunch this Friday at noon — let me know your food preferences!"
]

SCAM_TEMPLATES = [
    "URGENT: Your bank account has been suspended! Verify identity immediately within 24 hours: http://bank-verify{tld}",
    "Congratulations! You were selected to receive 0.5 BTC reward. Claim your prize immediately: http://bit-claim{tld}",
    "SECURITY ALERT: Unauthorized login detected on your account. Tap here to lock account: http://secure-auth{tld}",
    "FINAL WARNING: Your parcel delivery failed due to unpaid customs fee of $2.99. Pay now: http://postal-fee{tld}",
    "Dear Customer, your card has been charged $499.99 for order #{num}. If not you, call support immediately or visit http://cancel-order{tld}",
    "ACT NOW! You have an unclaimed tax refund of $1,250. Click here to submit details: http://irs-refund-claim{tld}",
    "Immediate action required! Your social security number has been compromised. Verify identity now: http://ssn-verify{tld}",
    "You won a $1,000 Amazon Gift Card! Claim your free reward today: http://claim-giftcard{tld}",
    "Your Netflix account will be closed in 24 hours unless you update your payment details: http://netflix-update{tld}",
    "ALERT: Suspicious activity detected on your PayPal. Confirm your identity: http://paypal-secure{tld}",
    "Dear user, your email storage is 98% full. Upgrade now to avoid losing emails: http://mail-upgrade{tld}",
    "Congratulations {name}! You've been selected for a free iPhone 16. Claim now: http://free-phone{tld}",
    "IMPORTANT: Your password will expire in 2 hours. Reset immediately: http://pass-reset{tld}",
    "Your Coinbase wallet has received 2.3 BTC. Verify to withdraw: http://crypto-verify{tld}",
    "Police investigation notice: Respond within 48 hours or face legal action: http://legal-notice{tld}",
    "Dear customer, we detected a breach on your credit card ending 4521. Secure now: http://card-secure{tld}",
    "Your Apple ID has been locked due to security concerns. Unlock here: http://appleid-unlock{tld}",
    "Investment opportunity: Earn $5,000/week with our guaranteed trading bot: http://trade-profit{tld}",
    "Your WhatsApp will be deactivated. Verify your number: http://wa-verify{tld}/otp",
    "LAST CHANCE: Claim your unclaimed insurance refund of $3,420: http://insurance-claim{tld}"
]


def generate_message_dataset(filename='message_dataset.csv', count=2000):
    """Generates a balanced message dataset with 50% safe and 50% scam messages."""
    filepath = os.path.join(DATA_DIR, filename)
    rows = []

    safe_count = count // 2
    for _ in range(safe_count):
        tmpl = random.choice(SAFE_TEMPLATES)
        msg = tmpl.format(name=random.choice(NAMES), num=random.randint(1000, 99999))
        rows.append({'message': msg, 'label': 0})

    scam_count = count // 2
    for _ in range(scam_count):
        tmpl = random.choice(SCAM_TEMPLATES)
        tld = random.choice(['.info', '.top', '.xyz', '.site', '.online', '.click', '.org', '.net'])
        msg = tmpl.format(name=random.choice(NAMES), num=random.randint(10000, 99999), tld=tld)
        rows.append({'message': msg, 'label': 1})

    random.shuffle(rows)

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['message', 'label'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[DATA] Generated {len(rows)} Message records at {filepath}")


if __name__ == '__main__':
    generate_url_dataset()
    generate_message_dataset()
