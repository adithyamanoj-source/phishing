# AI-Based Phishing and Scam Detection System

## Technical Requirements Document (TRD)

**Version:** 1.0  
**Date:** August 2026  
**Status:** Final

---

## 1. System Architecture Overview

The system follows a three-tier architecture:

### Presentation Layer (Frontend)

- HTML/CSS/JavaScript web interface
- Responsive design for desktop and tablet
- Client-side validation for user inputs

### Business Logic Layer (Backend)

- Python Flask web framework
- ML model serving for URL classification
- NLP model serving for message classification
- Authentication and session management

### Data Layer (Database & Storage)

- MySQL relational database
- Trained ML models stored as .pkl files
- User data, scan results, and history

---

## 2. Technology Stack

### Frontend

- **HTML5:** Semantic markup and forms
- **CSS3:** Responsive layouts and styling
- **JavaScript (ES6+):** Form handling, AJAX requests, DOM manipulation
- **Bootstrap or custom CSS framework:** Consistency and responsiveness

### Backend

- **Python 3.8+:** Core language
- **Flask 2.0+:** Web framework
- **Flask-Login:** User authentication and session management
- **Flask-MySQL:** Database connectivity
- **Werkzeug:** URL and request utilities
- **python-dotenv:** Environment configuration

### Machine Learning & NLP

- **Pandas 1.3+:** Data manipulation and preprocessing
- **NumPy 1.21+:** Numerical computations
- **Scikit-learn 0.24+:** ML algorithms (Logistic Regression, Random Forest, SVM)
- **NLTK or spaCy:** NLP preprocessing and feature extraction
- **Joblib or pickle:** Model serialization

### Database

- **MySQL 5.7+:** Relational database
- **PyMySQL:** Python MySQL driver

### Development & Deployment

- **Git:** Version control
- **Visual Studio Code:** IDE
- **Postman:** API testing
- **Gunicorn:** WSGI application server (production)

---

## 3. Database Schema

### 3.1 Users Table

Stores user account information and authentication credentials.

```sql
CREATE TABLE users (
  user_id INT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP NULL,
  is_active BOOLEAN DEFAULT 1
);
```

### 3.2 URL Scans Table

Stores all URL analysis results.

```sql
CREATE TABLE url_scans (
  scan_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  url_submitted VARCHAR(2048) NOT NULL,
  classification VARCHAR(50),
  risk_score DECIMAL(5,2),
  risk_level VARCHAR(20),
  explanation TEXT,
  scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id),
  INDEX idx_user_id (user_id),
  INDEX idx_timestamp (scan_timestamp)
);
```

**Fields:**
- `scan_id`: Unique identifier
- `user_id`: Reference to user
- `url_submitted`: URL that was analyzed
- `classification`: 'Legitimate', 'Suspicious', or 'Phishing'
- `risk_score`: 0-100 numerical score
- `risk_level`: 'Low', 'Medium', or 'High'
- `explanation`: Detected red flags and reasons
- `scan_timestamp`: When the scan was performed

### 3.3 Message Scans Table

Stores all message analysis results.

```sql
CREATE TABLE message_scans (
  scan_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  message_preview VARCHAR(500),
  classification VARCHAR(50),
  risk_score DECIMAL(5,2),
  detected_patterns TEXT,
  scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id),
  INDEX idx_user_id (user_id),
  INDEX idx_timestamp (scan_timestamp)
);
```

**Fields:**
- `scan_id`: Unique identifier
- `user_id`: Reference to user
- `message_preview`: First 500 chars of message
- `classification`: 'Safe', 'Suspicious', or 'Scam'
- `risk_score`: 0-100 numerical score
- `detected_patterns`: JSON array of detected scam patterns
- `scan_timestamp`: When the scan was performed

---

## 4. API Endpoints

### 4.1 Authentication Endpoints

#### POST /api/register

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response (Success):**
```json
{
  "status": "success",
  "message": "Account created successfully",
  "user_id": 1
}
```

**Response (Error):**
```json
{
  "status": "error",
  "message": "Email already exists"
}
```

#### POST /api/login

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response (Success):**
```json
{
  "status": "success",
  "message": "Login successful",
  "session_token": "abc123xyz789"
}
```

#### POST /api/logout

Clears user session and invalidates token.

**Response:**
```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

### 4.2 URL Detection Endpoints

#### POST /api/analyze-url

**Request:**
```json
{
  "url": "https://example.com/login"
}
```

**Response:**
```json
{
  "classification": "Legitimate",
  "risk_score": 15,
  "risk_level": "Low",
  "explanation": [
    "Domain age: 5 years",
    "HTTPS: Valid certificate",
    "No suspicious keywords detected"
  ],
  "scan_id": 42
}
```

### 4.3 Message Detection Endpoints

#### POST /api/analyze-message

**Request:**
```json
{
  "message": "URGENT: Verify your account now! Click here to confirm your identity..."
}
```

**Response:**
```json
{
  "classification": "Scam",
  "risk_score": 92,
  "detected_patterns": [
    "urgency_words",
    "account_verification",
    "suspicious_link_request"
  ],
  "scan_id": 43
}
```

### 4.4 History Endpoints

#### GET /api/scan-history

**Query Parameters:**
- `type`: 'url' or 'message' (optional)
- `risk_level`: 'Low', 'Medium', 'High' (optional)
- `sort_by`: 'date_desc', 'date_asc', 'risk_score' (default: 'date_desc')
- `limit`: Max results (default: 20)

**Response:**
```json
{
  "scans": [
    {
      "scan_id": 42,
      "type": "url",
      "content": "https://example.com",
      "classification": "Legitimate",
      "risk_score": 15,
      "scan_timestamp": "2026-08-29 10:30:00"
    }
  ],
  "total_count": 45,
  "stats": {
    "total_scans": 45,
    "high_risk_count": 3,
    "phishing_urls": 2,
    "scam_messages": 1
  }
}
```

#### DELETE /api/scans/{scan_id}

Requires authentication. Deletes a single scan from history.

**Response:**
```json
{
  "status": "success",
  "message": "Scan deleted"
}
```

---

## 5. Machine Learning Pipeline

### 5.1 URL Feature Extraction

Extract 10 key features from each URL:

1. **URL Length:** Total characters in URL
2. **Special Characters Count:** Presence of `.`, `-`, `_`, etc.
3. **Domain Name Length:** Length of domain portion
4. **Subdomain Count:** Number of subdomains
5. **IP Address Presence:** 0 = no, 1 = yes
6. **HTTPS Usage:** 0 = HTTP, 1 = HTTPS
7. **Domain Age:** Days since registration (requires WHOIS data)
8. **Suspicious Keywords:** Count of known phishing keywords
9. **@ Symbol Presence:** Indicates URL spoofing attempt
10. **Non-Standard Port:** 0 = standard (80/443), 1 = non-standard

### 5.2 URL Classification Models

Compare three algorithms during development:

#### Logistic Regression
- Fast baseline model
- Interpretable feature weights
- Good for understanding which features matter

#### Random Forest
- Handles non-linear relationships
- Feature importance ranking
- Robust to overfitting

#### Support Vector Machine (SVM)
- High-dimensional feature space
- Kernel trick for complex boundaries
- Good generalization

**Training Split:**
- 70% training data
- 20% validation data
- 10% test data

**Evaluation Metrics:**
- Accuracy
- Precision (minimize false positives)
- Recall (minimize false negatives)
- F1-Score
- Confusion Matrix
- ROC-AUC Curve

### 5.3 NLP Message Detection

**Preprocessing:**
1. Lowercase text
2. Remove punctuation
3. Tokenization (split into words)
4. Remove stopwords (the, a, an, etc.)
5. Stemming or lemmatization

**Feature Extraction:**
- TF-IDF (Term Frequency-Inverse Document Frequency)
- Or word embeddings (Word2Vec, GloVe)

**Scam Indicators:**
- **Urgency Words:** URGENT, ACT NOW, LIMITED TIME, IMMEDIATE
- **Threats:** Account closure, legal action, security breach
- **Sensitive Info Requests:** Password, OTP, PIN, credit card
- **Unrealistic Offers:** Free money, instant wealth, unclaimed prizes
- **Spelling Errors:** Common in scam messages
- **Generic Greetings:** "Dear User" instead of name

**Output:**
- Binary classification: Safe / Scam
- Or multi-class: Safe / Suspicious / Confirmed Scam
- Risk score based on model confidence (probability)

---

## 6. Data Flow

### User Input → Result

1. **User submits** URL or message via web form
2. **Frontend validates** input format and length
3. **AJAX request** sent to Flask backend with `Content-Type: application/json`
4. **Backend validates** input again (never trust client)
5. **Load ML/NLP model** from disk (.pkl file)
6. **Extract features** from URL or preprocess message
7. **Run prediction** through trained model
8. **Calculate risk score** and classification
9. **Generate explanation** of contributing factors
10. **Save result** to MySQL database
11. **Return JSON response** to frontend
12. **Frontend displays** result with visual indicators (color-coded)
13. **User can save** scan to history (automatic)

---

## 7. Security Requirements

### Authentication & Authorization

- **Password Hashing:** bcrypt with minimum 10 salt rounds
- **Session Tokens:** Secure, HTTP-only cookies
- **Login Validation:** Email + password must match database record
- **Protected Endpoints:** All endpoints except login/register require valid session
- **Session Timeout:** Automatic logout after 24 hours of inactivity

### Data Protection

- **HTTPS/TLS 1.2+:** All communication encrypted
- **SQL Injection Prevention:** Use parameterized queries in all DB operations
- **XSS Prevention:** Sanitize user input on frontend and backend
- **CSRF Protection:** Token validation for state-changing requests
- **Rate Limiting:** Max 50 scans per user per hour (prevent abuse)
- **Data Minimization:** Store only necessary data (email, not full messages)

### Error Handling

- **Generic Error Messages:** Users see "An error occurred", not system details
- **Server-Side Logging:** Detailed logs for debugging by developers
- **Graceful Degradation:** If ML model fails, return error response (not crash)
- **No Information Leakage:** Don't expose file paths, database names, etc.

### Input Validation

- **URL Format:** Regex pattern or URL parsing library
- **Message Length:** Max 5000 characters
- **Email Format:** Valid email syntax
- **Password Strength:** 8+ chars, 1 uppercase, 1 lowercase, 1 number

---

## 8. Performance Requirements

### Response Times

| Operation | Target | Threshold |
|-----------|--------|-----------|
| URL Analysis | <2s | <3s |
| Message Analysis | <2s | <3s |
| Database Query | <100ms | <200ms |
| Page Load | <3s | <5s |
| API Response | <1s | <2s |

### Scalability

- Support 100+ concurrent users
- Handle 1000+ scan requests per day
- Database indexed on frequently queried columns (`user_id`, `scan_timestamp`)
- Connection pooling for database (reuse connections)
- Model serving optimized (load model once, reuse)

### Load Testing

- Use Apache JMeter or Locust to simulate concurrent users
- Test with varying request rates
- Monitor CPU, memory, disk usage
- Identify and optimize bottlenecks

---

## 9. Deployment Strategy

### Development Environment

- **Flask Development Server:** Running on `localhost:5000`
- **Database:** Local MySQL or SQLite for testing
- **Python Environment:** Virtual environment (venv or conda)
- **Version Control:** Git with GitHub for collaboration

### Production Environment (Future)

- **WSGI Server:** Gunicorn with multiple worker processes
- **Reverse Proxy:** Nginx for load balancing and SSL termination
- **Cloud Hosting:** AWS EC2, Google Cloud Compute, or Azure VM
- **Managed Database:** AWS RDS MySQL or Google Cloud SQL
- **Static Files:** CDN (CloudFront, Cloudflare) for CSS/JS
- **Monitoring:** CloudWatch or Datadog for logs and metrics
- **CI/CD:** GitHub Actions or GitLab CI for automated testing and deployment

### Docker (Optional)

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

---

## 10. Testing Strategy

### Unit Testing

- **Model Testing:** Test feature extraction and predictions on known datasets
- **Function Testing:** Test preprocessing, validation, helper functions
- **API Testing:** Test request validation and response format

**Tools:** pytest, unittest, scikit-learn's model_selection

### Integration Testing

- **End-to-End Workflows:**
  - Register → Login → Analyze URL → View History → Logout
  - Login → Analyze Message → Export History
- **Database Operations:** Create, read, update, delete user scans
- **API Integration:** Frontend calls backend correctly

**Tools:** pytest, requests, Postman

### Performance Testing

- **Load Testing:** Simulate 100 concurrent users
- **Stress Testing:** Gradually increase load until system fails
- **Response Time:** Verify <2s response times under load

**Tools:** Apache JMeter, Locust

### Security Testing

- **SQL Injection:** Test with malicious SQL input
- **XSS:** Test with JavaScript payloads
- **Authentication:** Verify tokens expire and protect endpoints
- **Rate Limiting:** Verify max scans per user enforced

---

## 11. File Structure

```
phishing_detection_system/
├── app.py                    # Flask main application
├── config.py                 # Configuration variables
├── requirements.txt          # Python dependencies
├── database.sql              # MySQL schema and initialization
│
├── models/
│   ├── url_classifier.pkl    # Trained URL classification model
│   ├── message_classifier.pkl # Trained message classification model
│   └── vectorizer.pkl        # TF-IDF vectorizer for NLP
│
├── data/
│   ├── url_dataset.csv       # URL training data
│   └── message_dataset.csv   # Message training data
│
├── static/
│   ├── css/
│   │   └── style.css         # Main stylesheet
│   ├── js/
│   │   └── main.js           # Frontend JavaScript
│   └── images/
│       └── logo.png
│
├── templates/
│   ├── base.html             # Base template
│   ├── index.html            # Home page
│   ├── login.html            # Login page
│   ├── register.html         # Registration page
│   ├── analyze.html          # Analysis page (URL/Message)
│   ├── results.html          # Results display
│   └── history.html          # Scan history dashboard
│
├── utils/
│   ├── preprocessing.py      # Text/URL preprocessing
│   ├── feature_extraction.py # Feature extraction functions
│   ├── model_loader.py       # Load and cache models
│   └── validators.py         # Input validation functions
│
└── README.md                 # Project documentation
```

---

## 12. Known Limitations & Future Enhancements

### Current Limitations

- Model accuracy depends on training dataset quality and size
- New phishing techniques may not be detected by current model
- No real-time threat intelligence integration
- Single-language support (English only)
- No image-based phishing detection

### Future Enhancements

- **Deep Learning Models:** LSTM, BERT for improved NLP accuracy
- **Browser Extension:** Real-time URL checking while browsing
- **Mobile App:** iOS/Android native applications
- **Real-Time Threat Feeds:** Integration with PhishTank, URLhaus
- **Automated Retraining:** Model updates with new data monthly
- **Email Analysis:** Integration with email clients
- **Screenshot Detection:** OCR-based scam detection from images
- **Multilingual Support:** Support for multiple languages
- **Reporting System:** User reports feed back into model improvement
- **API for Third Parties:** Allow other apps to use detection service
