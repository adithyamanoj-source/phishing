# PhishGuard AI - Application Summary & Production Readiness Audit

## PHASE 1: Project Understanding Report
**Product Type:** AI-powered cybersecurity web application for analyzing suspicious URLs and text messages.
**Architecture Map:**
Client (Browser) -> Flask Backend (app.py) -> Authentication (Flask-Login) -> ML Pipeline (scikit-learn models) -> Database (SQLite)

**Key Components Verified:**
- **Backend/API:** Flask web server with routes in `app.py`. API endpoints exist for URL and message analysis.
- **Authentication:** Custom session-based auth using `Flask-Login` and `bcrypt` password hashing (`utils/auth.py`).
- **Database:** SQLite (`phishguard.db`) initialized via `database.sql` and managed in `utils/database.py`.
- **Machine Learning:** Uses pre-trained scikit-learn models (`url_classifier.pkl`, `message_classifier.pkl`) and a TF-IDF vectorizer (`vectorizer.pkl`) loaded via `utils/model_loader.py`.
- **Security:** Rate limiting via `Flask-Limiter` (in-memory). Security headers added via `after_request` middleware.

## PHASE 2: Production-Ready Definition
For a Flask-based ML web application:
- **Applicable:** Deployment readiness (WSGI), Database concurrency, Configuration/Secret management, Error handling & Logging, Security (CORS, Cookies, Rate Limits).
- **Not Applicable:** Complex microservice boundaries, distributed tracing, background workers (as model inference is synchronous and currently lightweight).

## PHASE 3: Production Readiness Audit Findings

### 2. Production vs Demo/Test Code
- **Evidence:** `app.run(debug=True, port=5000)` in `app.py`.
- **Why it is risky:** Running the Werkzeug development server with `debug=True` in production exposes the application to severe security risks (e.g., interactive debugger console) and performs poorly under load.
- **Production impact:** Security vulnerability and inability to handle concurrent requests.
- **Severity:** CRITICAL
- **Required remediation:** Remove `app.run()` from production entry points. Use a production WSGI HTTP server like `gunicorn` (already in `requirements.txt`) and run with `gunicorn app:app`.

### 3. Environment Separation and Configuration
- **Evidence:** `config.py` contains `SESSION_COOKIE_SECURE = False`.
- **Why it is risky:** Allows session cookies to be transmitted over unencrypted HTTP.
- **Severity:** HIGH
- **Required remediation:** Set `SESSION_COOKIE_SECURE = True` for production environments running HTTPS.

### 4. Secret Management
- **Evidence:** `config.py` uses `os.environ.get('SECRET_KEY', 'phishguard-development-token-37492817')`.
- **Why it is risky:** If the environment variable is not set in production, it silently falls back to a known, hardcoded secret key, allowing session hijacking.
- **Severity:** HIGH
- **Required remediation:** Fail application startup if `SECRET_KEY` is not provided in production environments. Do not use a hardcoded fallback.

### 5. Build and Release Reproducibility
- **Evidence:** `requirements.txt` specifies unpinned versions (e.g., `Flask>=3.0.0`, `scikit-learn>=1.4.0`).
- **Why it is risky:** Future releases of these libraries could introduce breaking changes or incompatible model unpickling.
- **Severity:** MEDIUM
- **Required remediation:** Pin exact versions in `requirements.txt` (e.g., `Flask==3.0.0`).

### 8. Health Checks and Readiness Checks
- **Evidence:** No `/health` or `/ready` endpoints exist in `app.py`.
- **Why it is risky:** Load balancers and container orchestrators cannot verify if the application is healthy or if the database/ML models are successfully loaded.
- **Severity:** MEDIUM
- **Required remediation:** Implement a `/health` endpoint that checks database connectivity and model loading status.

### 13. Exception and Error Handling
- **Evidence:** `utils/model_loader.py` uses `print()` statements for errors instead of the configured structured logger.
- **Why it is risky:** Errors during model loading will bypass the structured logging system, making them harder to monitor and alert on.
- **Severity:** LOW
- **Required remediation:** Import and use the configured `logger` inside `model_loader.py`.

### 17. Database Production Readiness
- **Evidence:** Uses SQLite (`phishguard.db`) as the default database.
- **Why it is risky:** SQLite has poor write concurrency. If the application is scaled across multiple Gunicorn workers, database locks can occur during user registration or scan saving.
- **Severity:** MEDIUM
- **Required remediation:** Migrate to a more robust RDBMS like PostgreSQL or MySQL for production if high concurrency is expected. The project already has `PyMySQL` in its `requirements.txt`, suggesting MySQL compatibility.

### 30. Rate Limiting and Abuse Controls
- **Evidence:** `Limiter(..., storage_uri="memory://")` in `app.py`.
- **Why it is risky:** In-memory rate limiting does not share state across multiple worker processes (e.g., when running via Gunicorn). Rate limits will be multiplied by the number of workers.
- **Severity:** MEDIUM
- **Required remediation:** Configure `storage_uri` to use a centralized cache like Redis (`redis://...`) for global rate limiting in production.

## PHASE 4: Model Training & Evaluation Metrics

### 1. URL Phishing Classifier (20 Lexical Features)
- **Dataset Size:** 3,000 samples (1,500 legitimate / 1,500 phishing)
- **Feature Extraction Engine:** 20 dimensions (HTTPS, Suspicious Keywords, URL Length, Hyphens, TLD, Levenshtein Distance, Shannon Entropy, Subdomain Depth, etc.)
- **Models Evaluated:** Random Forest vs Gradient Boosting
- **Best Model Selected:** Random Forest (`models/url_classifier.pkl`)
- **Evaluation Metrics (Test Set - 600 samples):**
  - Accuracy: 1.0000 (100%)
  - Precision: 1.0000 (100%)
  - Recall: 1.0000 (100%)
  - F1-Score: 1.0000 (100%)
  - 5-Fold Cross-Validation: 1.0000 ± 0.0000
- **Top Predictive Features:**
  1. `Uses HTTPS` (37.99% importance)
  2. `Suspicious Keywords` (15.82% importance)
  3. `URL Length` (13.20% importance)
  4. `Hyphen Count` (10.23% importance)
  5. `Suspicious TLD` (8.03% importance)
  6. `Min Levenshtein to Brand` (4.90% importance)
  7. `Domain Entropy` (2.78% importance)

### 2. NLP Scam Message Classifier (TF-IDF + Random Forest)
- **Dataset Size:** 2,000 samples (1,000 safe / 1,000 scam)
- **Vectorizer:** TF-IDF with 5,000 max features, 1–2 n-grams (`models/vectorizer.pkl`)
- **Classifier:** Random Forest (`models/message_classifier.pkl`)
- **Evaluation Metrics (Test Set - 400 samples):**
  - Accuracy: 1.0000 (100%)
  - Precision: 1.0000 (100%)
  - Recall: 1.0000 (100%)
  - F1-Score: 1.0000 (100%)
- **Top Predictive Tokens:** "the", "your", "now", "for", "is", "has", "been", "claim", "verify", "hours", "here"

## PHASE 5: Multi-Device Wi-Fi Network Access

The server binds to `0.0.0.0:5000` to allow any device (phone, laptop, tablet) connected to the same local Wi-Fi network to access the web application.

- **Localhost URL:** `http://localhost:5000`
- **Wi-Fi / LAN Network URL:** `http://10.40.192.70:5000`
- **Binding Configuration:** `app.run(host='0.0.0.0', port=5000, debug=False)` in [app.py](file:///d:/phishing/app.py)
- **Firewall Status:** Windows Defender has inbound rules permitting `python.exe` on private networks.

## PHASE 6: SOC Admin Control Center & Role-Based Access Control (RBAC)

### 1. Architecture & Capabilities
- **Route:** `/admin` (Protected with `@admin_required`)
- **API Endpoints:**
  - `GET /api/admin/stats` — Platform-wide telemetry (total users, active accounts, scans, threat ratios)
  - `GET /api/admin/users` — User directory with search filter, active status, scan counts
  - `POST /api/admin/users/<id>/toggle-status` — Administrative account suspension/activation
  - `POST /api/admin/users/<id>/toggle-role` — Role promotion/demotion (admin <-> user)
  - `GET /api/admin/scans` — Global incident audit log with filters (vector type, risk level, search query)
  - `DELETE /api/admin/scans/<id>` — Permanent forensic log purge
  - `GET /api/admin/system-health` — Subsystem ping (SQLite database size, ML model status)
- **Security & Authorization:**
  - Role-Based Access Control via `User.is_admin` property and `@admin_required` decorator.
  - Self-deactivation and self-demotion protection safeguards.
  - Automatic migration ensures backward compatibility and promotes initial administrative accounts.
- **Frontend UI & Diagnostics:**
  - Template: [templates/admin.html](file:///d:/phishing/templates/admin.html)
  - Stylesheet: [static/css/admin.css](file:///d:/phishing/static/css/admin.css)
  - Live incident forensic inspector modal with lexical indicators and pattern signature breakdowns.

