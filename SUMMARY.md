# 🛡️ PhishGuard AI — Complete Backend APPM & Application Summary

## 📌 Project Overview
**PhishGuard AI** is a production-grade, AI-powered cybersecurity web application for analyzing suspicious web URLs and SMS/email scam messages in real time. The backend features a trained Random Forest URL classifier using **20 lexical features**, a multi-tier deep link verification engine (SSL/DNS/Redirect analysis), an NLP TF-IDF scam message detector, Flask-Login bcrypt authentication, SQLite persistence, rate limiting, and security headers.

---

## 🟢 Server Status
- **Backend Framework**: Python Flask (WSGI Server)
- **Start Command**: `.\venv\Scripts\python.exe app.py`
- **Server Address**: `http://localhost:5000` (Online & Healthy)

---

## 🏗️ Architecture & APPM Summary

### 1. Database Tier (`database.sql` & `utils/database.py`)
- **`users`**: `user_id`, `email`, `password_hash`, `created_at`, `last_login`, `is_active`
- **`url_scans`**: `scan_id`, `user_id`, `url_submitted`, `classification`, `risk_score`, `risk_level`, `explanation`, `scan_timestamp`
- **`message_scans`**: `scan_id`, `user_id`, `message_preview`, `classification`, `risk_score`, `detected_patterns`, `scan_timestamp`
- **Protection**: 100% parameterized SQL queries protecting against SQL injection attacks.

### 2. Multi-Tier Phishing Detection Engine (NEW)

#### Tier 1 — Lexical Features (20 features, instant, no network calls)
| # | Feature | Description |
|---|---------|-------------|
| 0 | `url_length` | Total URL character count |
| 1 | `num_dots` | Dot count (excessive = subdomain tricks) |
| 2 | `num_hyphens` | Hyphen count (phishing domains use many) |
| 3 | `num_digits_in_domain` | Digit density in hostname |
| 4 | `has_ip_address` | Raw IP instead of domain (0/1) |
| 5 | `has_at_symbol` | @ in URL, hides real target (0/1) |
| 6 | `has_double_slash_redirect` | "//" mid-path, redirect trick (0/1) |
| 7 | `subdomain_count` | Number of subdomain levels |
| 8 | `tld_in_subdomain` | Brand TLD appears as subdomain (0/1) |
| 9 | `uses_url_shortener` | Known shortener domain (0/1) |
| 10 | `suspicious_keyword_count` | Count of phishing keywords in URL |
| 11 | `brand_in_subdomain_not_domain` | Brand name in subdomain but not registrable domain (0/1) |
| 12 | `min_levenshtein_to_brand` | Typosquatting detection via edit distance |
| 13 | `punycode_present` | xn-- prefix (homograph attack) (0/1) |
| 14 | `non_standard_port` | Port not 80/443 (0/1) |
| 15 | `uses_https` | Encrypted transport (0/1) |
| 16 | `path_depth` | Number of path segments |
| 17 | `query_param_count` | Number of query parameters |
| 18 | `domain_entropy` | Shannon entropy of hostname |
| 19 | `suspicious_tld` | Uses a high-risk TLD (0/1) |

#### Tier 2 — Domain/Network Features (on-demand for borderline scores)
- **SSL Certificate Inspection**: Issuer, validity, expiry, subject match, EV vs DV classification
- **DNS Resolution Analysis**: Resolves check, IP count, resolved IPs
- **Redirect Chain Tracing**: Chain length, cross-domain detection, loop detection

#### Tier 3 — Content Heuristics (sandboxed page analysis)
- Login form detection, form action domain mismatch, external favicon
- Hidden elements, iframe count, JavaScript obfuscation indicators
- Meta refresh redirect detection

### 3. ML Training Pipeline (`train_models.py`)
- **URL Classifier**: 20-feature Random Forest vs Gradient Boosting selection (best F1 wins)
- **Dataset**: 3,000 URLs across 11 attack categories (IP, typosquat, subdomain layer, brand subdomain, suspicious TLD, HTTP insecure, @ symbol, double-slash, non-standard port, long obfuscated, keyword stuffing)
- **NLP Scam Detector**: TF-IDF (5,000 features, 1-2 n-grams) + Random Forest
- **Message Dataset**: 2,000 messages (19 safe templates, 20 scam templates)
- **Performance**: 100% F1 score, 100% accuracy on both models (5-fold CV)

### 4. Authentication & Security (`utils/auth.py`, `app.py`)
- **Flask-Login**: Session token management with 24-hour expiration.
- **bcrypt Hashing**: Passwords hashed with 12 salt rounds.
- **Rate Limiting (`Flask-Limiter`)**: Max 50 scans per hour, max 10 auth attempts per minute.
- **Security Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`.

### 5. API Endpoints (`app.py`)

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/analyze-url` | Multi-tier URL analysis (20-feature ML + deep link verification) | 50/hr |
| `POST` | `/api/analyze-message` | NLP message analysis (TF-IDF + pattern detection) | 50/hr |
| `GET`  | `/api/scan-history` | Filtered/sorted audit history from database | Default |
| `DELETE` | `/api/scans/<id>` | Deletes specific user scan record | Default |
| `GET`  | `/api/user-stats` | User scan counts and risk distribution | Default |
| `POST` | `/login` | Authenticates user credentials via bcrypt | 10/min |
| `POST` | `/register` | Registers new user with password validation | 10/min |
| `GET`  | `/logout` | Clears user session | Default |

### 6. API Response Format (Enhanced)
```json
{
    "status": "success",
    "type": "url",
    "content": "http://...",
    "classification": "Phishing|Suspicious|Legitimate",
    "risk_score": 95.0,
    "risk_level": "High|Medium|Low",
    "explanation": [
        {"type": "danger|warning|info|safe", "category": "Protocol|Domain|Brand|Lexical|Certificate|DNS|Redirects", "text": "..."}
    ],
    "feature_breakdown": [
        {"name": "URL Length", "value": 65.0, "index": 0}
    ],
    "deep_analysis": {
        "ssl": {"ssl_valid": true, "ssl_issuer": "...", "ssl_days_remaining": 90},
        "dns": {"dns_resolves": true, "dns_ip_count": 1},
        "redirects": {"chain_length": 0, "crosses_domains": false}
    }
}
```

---

## 📁 Complete Directory Map

```
d:\phishing
├── app.py                      # Flask Server (Routes + APIs + Auth + Security)
├── config.py                   # Environment & Secret Key Config
├── database.sql                # SQL Schema Definition
├── train_models.py             # ML/NLP Training Script (20-feature + Gradient Boosting)
├── requirements.txt            # Python Dependencies
├── .env.example                # Environment Template
├── .gitignore                  # Git Exclusion Rules
├── SUMMARY.md                  # Complete APPM Summary
│
├── models/                     # Trained ML Models
│   ├── url_classifier.pkl      # 20-Feature URL Phishing Model
│   ├── message_classifier.pkl  # Scam Message Model
│   └── vectorizer.pkl          # TF-IDF Vectorizer
│
├── data/                       # Datasets
│   ├── generate_training_data.py # Enhanced Dataset Generator (11 attack types)
│   ├── url_dataset.csv         # 3,000 URL Samples
│   └── message_dataset.csv     # 2,000 Message Samples
│
├── utils/                      # Core Modules
│   ├── __init__.py
│   ├── auth.py                 # Flask-Login & bcrypt
│   ├── database.py             # SQLite Connector & Parameterized Queries
│   ├── feature_extraction.py   # 20-Feature Lexical Engine + Explanation Generator
│   ├── link_verifier.py        # Deep Link Analysis (SSL/DNS/Redirects) — NEW
│   ├── preprocessing.py        # NLP Preprocessing & Pattern Detection
│   ├── model_loader.py         # Singleton Model Cache
│   ├── validators.py           # Server Input Validators
│   └── logging_config.py       # Structured Logging Setup
│
├── static/
│   ├── css/
│   │   ├── style.css           # UI Design System
│   │   └── dashboard.css       # Tooltips & Gauges
│   └── js/
│       └── main.js             # Enhanced API Client + Feature Breakdown Renderer
└── templates/                  # Jinja2 Layout Views
    ├── base.html
    ├── index.html
    ├── analyze.html            # Updated with feature breakdown & deep analysis containers
    ├── dashboard.html
    ├── history.html
    ├── login.html
    └── register.html
```

---

## 🔬 Detection Pipeline Flow

```
URL Input
    │
    ├─ Tier 1: Lexical Feature Extraction (20 features, instant)
    │   ├─ ML Model Prediction (Random Forest / Gradient Boosting)
    │   └─ Rule-Based Weighted Score (fallback)
    │
    ├─ Score > 70 or < 30? → Direct classification (no network calls needed)
    │
    ├─ Score 25-75 (borderline)? → Tier 2-3 Deep Analysis
    │   ├─ SSL Certificate Inspection
    │   ├─ DNS Resolution Check
    │   └─ Redirect Chain Tracing
    │
    └─ Final Score + Classification + Categorized Explanations
```

---

## 🚀 Launching the Backend Server

```powershell
.\venv\Scripts\python.exe app.py
```
Application interface: `http://localhost:5000`
