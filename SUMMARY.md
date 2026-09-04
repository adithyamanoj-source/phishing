# 🛡️ PhishGuard AI — Complete Backend APPM & Application Summary

## 📌 Project Overview
**PhishGuard AI** is a production-grade, AI-powered cybersecurity web application for analyzing suspicious web URLs and SMS/email scam messages in real time. The backend features a trained Random Forest URL classifier, an NLP TF-IDF scam message detector, Flask-Login bcrypt authentication, SQLite/MySQL persistence, rate limiting, and security headers.

---

## 🟢 Server Status
- **Backend Framework**: Python Flask (WSGI Server)
- **Start Command**: `.\venv\Scripts\python.exe app.py`
- **Server Address**: `http://localhost:5000` (Online & Healthy)
- **Resolved Issue**: Added `BASE_DIR = BASE_DIR` attribute inside `Config` class in `config.py`.

---

## 🏗️ Architecture & APPM Summary

### 1. Database Tier (`database.sql` & `utils/database.py`)
- **`users`**: `user_id`, `email`, `password_hash`, `created_at`, `last_login`, `is_active`
- **`url_scans`**: `scan_id`, `user_id`, `url_submitted`, `classification`, `risk_score`, `risk_level`, `explanation`, `scan_timestamp`
- **`message_scans`**: `scan_id`, `user_id`, `message_preview`, `classification`, `risk_score`, `detected_patterns`, `scan_timestamp`
- **Protection**: 100% parameterized SQL queries protecting against SQL injection attacks.

### 2. Machine Learning & NLP Pipeline (`train_models.py`, `utils/feature_extraction.py`, `utils/preprocessing.py`)
- **URL Classifier (`models/url_classifier.pkl`)**: 10 features extracted (URL length, special characters, domain length, subdomains count, IP presence, HTTPS usage, brand keywords, `@` symbol, non-standard port, path depth).
- **NLP Scam Detector (`models/message_classifier.pkl` & `models/vectorizer.pkl`)**: TF-IDF (5,000 features, 1-2 n-grams) combined with pattern extraction (urgency hooks, financial bait, coercive threats, credential harvesting).
- **Performance**: High precision and recall with explainable risk breakdown.

### 3. Authentication & Security (`utils/auth.py`, `app.py`)
- **Flask-Login**: Session token management with 24-hour expiration.
- **bcrypt Hashing**: Passwords hashed with 12 salt rounds (`hash_password`, `verify_password`).
- **Rate Limiting (`Flask-Limiter`)**: Max 50 scans per hour, max 10 auth attempts per minute.
- **Security Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`.
- **Request Size Limiting**: `MAX_CONTENT_LENGTH = 1MB`.

### 4. API Endpoints (`app.py`)

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `POST` | `/api/analyze-url` | Analyzes URL using 10-feature Random Forest model | 50/hr |
| `POST` | `/api/analyze-message` | Analyzes text using TF-IDF NLP model & pattern detector | 50/hr |
| `GET`  | `/api/scan-history` | Fetches filtered/sorted audit history from database | Default |
| `DELETE` | `/api/scans/<id>` | Deletes specific user scan record | Default |
| `GET`  | `/api/user-stats` | Calculates user scan counts and risk distribution | Default |
| `POST` | `/login` | Authenticates user credentials via bcrypt | 10/min |
| `POST` | `/register` | Registers new user with password validation | 10/min |
| `GET`  | `/logout` | Clears user session | Default |

---

## 📁 Complete Directory Map

```
d:\phishing
├── app.py                      # Flask Server (Routes + APIs + Auth + Security)
├── config.py                   # Environment & Secret Key Config
├── database.sql                # SQL Schema Definition
├── train_models.py             # ML/NLP Training Script
├── requirements.txt            # Python Dependencies
├── .env.example                # Environment Template
├── .gitignore                  # Git Exclusion Rules
├── SUMMARY.md                  # Complete APPM Summary
│
├── models/                     # Trained ML Models
│   ├── url_classifier.pkl      # URL Phishing Model
│   ├── message_classifier.pkl  # Scam Message Model
│   └── vectorizer.pkl          # TF-IDF Vectorizer
│
├── data/                       # Datasets
│   ├── generate_training_data.py # Dataset Generator
│   ├── url_dataset.csv         # 2,000 URL Samples
│   └── message_dataset.csv     # 1,500 Message Samples
│
├── utils/                      # Core Modules
│   ├── __init__.py
│   ├── auth.py                 # Flask-Login & bcrypt
│   ├── database.py             # SQLite/MySQL Connector & Parameterized Queries
│   ├── feature_extraction.py   # URL Feature Engineering
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
│       └── main.js             # API Client & Local Fallback
└── templates/                  # Jinja2 Layout Views
    ├── base.html
    ├── index.html
    ├── analyze.html
    ├── dashboard.html
    ├── history.html
    ├── login.html
    └── register.html
```

---

## 🚀 Launching the Backend Server

```powershell
.\venv\Scripts\python.exe app.py
```
Application interface: `http://localhost:5000`
