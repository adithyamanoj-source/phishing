import os
import csv
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# --- 1. GENERATE URL DATASET ---

LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'reddit.com', 'stackoverflow.com', 'dropbox.com',
    'chase.com', 'paypal.com', 'bankofamerica.com', 'wellsfargo.com', 'ebay.com'
]

PATH_COMPONENTS = [
    'login', 'signin', 'account', 'verify', 'security', 'settings', 'home',
    'dashboard', 'profile', 'billing', 'help', 'contact', 'about', 'services', 'docs'
]

PHISHING_KEYWORDS = ['login', 'verify', 'bank', 'secure', 'account', 'update', 'signin', 'recovery', 'confirm']
PHISHING_DOMAINS = ['secure-login', 'verify-account', 'banking-update', 'netflix-billing', 'paypal-security', 'appleid-verify']
SUSPICIOUS_TLDS = ['.net', '.info', '.top', '.xyz', '.site', '.online', '.club', '.tech']

def generate_url_dataset(filename='url_dataset.csv', count=2000):
    filepath = os.path.join(DATA_DIR, filename)
    rows = []
    
    # 50% Legitimate URLs
    for _ in range(count // 2):
        domain = random.choice(LEGITIMATE_DOMAINS)
        path = random.choice(PATH_COMPONENTS) if random.random() > 0.3 else ''
        sub = 'www.' if random.random() > 0.5 else ''
        protocol = 'https://'
        url = f"{protocol}{sub}{domain}/{path}" if path else f"{protocol}{sub}{domain}"
        rows.append({'url': url, 'label': 0})  # 0 = Legitimate
        
    # 50% Phishing URLs
    for _ in range(count // 2):
        rand_type = random.choice(['ip', 'brand_spoof', 'subdomain_layer', 'http_insecure'])
        
        if rand_type == 'ip':
            ip = f"{random.randint(100, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            path = random.choice(PATH_COMPONENTS)
            url = f"http://{ip}/{path}/update-account-recovery"
        elif rand_type == 'brand_spoof':
            brand = random.choice(['paypal', 'chase', 'netflix', 'amazon', 'apple'])
            tld = random.choice(SUSPICIOUS_TLDS)
            url = f"http://secure-{brand}-login-verify{tld}/signin?token={random.randint(10000, 99999)}"
        elif rand_type == 'subdomain_layer':
            url = f"http://login.verify.security.account.{random.choice(LEGITIMATE_DOMAINS)}.scam-node.net/auth"
        else:
            domain = random.choice(PHISHING_DOMAINS) + random.choice(SUSPICIOUS_TLDS)
            url = f"http://{domain}/login/confirm_identity.php?user_id={random.randint(100,999)}"
            
        rows.append({'url': url, 'label': 1})  # 1 = Phishing
        
    random.shuffle(rows)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['url', 'label'])
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"[DATA] Generated {len(rows)} URL records at {filepath}")


# --- 2. GENERATE MESSAGE DATASET ---

SAFE_TEMPLATES = [
    "Hi {name}, your package delivery is scheduled for tomorrow between 2 PM and 4 PM.",
    "Hey! Don't forget our meeting today at 3:00 PM in Conference Room B.",
    "Your appointment with Dr. Smith is confirmed for Friday at 10 AM.",
    "Can you please review the attached document and send me your feedback?",
    "Thanks for visiting our store! Here is your digital receipt for purchase #{num}.",
    "Happy Birthday {name}! Wishing you a fantastic day and great year ahead.",
    "Your weekly account summary is ready to view in the banking app.",
    "Hey, are we still meeting for lunch today? Let me know!"
]

SCAM_TEMPLATES = [
    "URGENT: Your bank account has been suspended! Verify identity immediately within 24 hours: http://bank-verify.info",
    "Congratulations! You were selected to receive 0.5 BTC reward. Claim your prize immediately: http://bit-claim.org",
    "SECURITY ALERT: Unauthorized login detected on your account. Tap here to lock account: http://secure-auth.net",
    "FINAL WARNING: Your parcel delivery failed due to unpaid customs fee of $2.99. Pay now: http://postal-fee.org",
    "Dear Customer, your card has been charged $499.99 for order #{num}. If not you, call support immediately or visit http://cancel-order.top",
    "ACT NOW! You have an unclaimed tax refund of $1,250. Click here to submit details: http://irs-refund-claim.com",
    "Immediate action required! Your social security number has been compromised. Verify identity now: http://ssn-verify.info",
    "You won a $1,000 Amazon Gift Card! Claim your free reward today: http://claim-giftcard.xyz"
]

NAMES = ['Sarah', 'John', 'Alex', 'Michael', 'Emily', 'David', 'Jessica', 'Daniel']

def generate_message_dataset(filename='message_dataset.csv', count=1500):
    filepath = os.path.join(DATA_DIR, filename)
    rows = []
    
    # 50% Safe Messages
    for _ in range(count // 2):
        tmpl = random.choice(SAFE_TEMPLATES)
        msg = tmpl.format(name=random.choice(NAMES), num=random.randint(1000, 9999))
        rows.append({'message': msg, 'label': 0})  # 0 = Safe
        
    # 50% Scam Messages
    for _ in range(count // 2):
        tmpl = random.choice(SCAM_TEMPLATES)
        msg = tmpl.format(num=random.randint(10000, 99999))
        rows.append({'message': msg, 'label': 1})  # 1 = Scam
        
    random.shuffle(rows)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['message', 'label'])
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"[DATA] Generated {len(rows)} Message records at {filepath}")


if __name__ == '__main__':
    generate_url_dataset()
    generate_message_dataset()
