# AI-Based Phishing and Scam Detection System

## Product Requirements Document (PRD)

**Version:** 1.0  
**Date:** August 2026  
**Status:** Final

---

## 1. Product Vision

An accessible, AI-powered web platform that enables users to identify phishing URLs and scam messages in real-time, protecting them from credential theft and financial fraud through explainable machine learning and natural language processing.

---

## 2. Problem Statement

Phishing and online scams cost users billions annually. Traditional security solutions are either too technical for average users or inaccessible during everyday interactions. Users need a simple, trustworthy tool to verify suspicious URLs and messages before engaging with them.

---

## 3. Goals & Success Metrics

### Primary Goals

- Detect 90%+ of phishing URLs with <5% false positive rate
- Classify scam messages with 85%+ accuracy
- Provide clear, non-technical explanations for risk assessments
- Enable users to track scan history and build awareness

### Success Metrics

- **URL Detection:** Precision ≥ 0.95, Recall ≥ 0.90, F1-Score ≥ 0.92
- **Message Detection:** Accuracy ≥ 0.85, Precision ≥ 0.87
- **Response Time:** <2 seconds per URL/message scan
- **User Retention:** 70%+ of registered users perform ≥3 scans

---

## 4. User Personas

### Persona 1: Non-Technical User (Cautious Internet User)

- **Age:** 25-55, moderate to high internet usage
- **Pain Point:** Struggles to identify phishing emails and links
- **Goal:** Quickly verify URLs before clicking and messages before sharing data
- **Behavior:** Clicks links from emails/social media without verification

### Persona 2: Business Professional

- **Age:** 30-60, high email/messaging volume
- **Pain Point:** Receives frequent phishing attempts targeting corporate accounts
- **Goal:** Quickly validate suspicious emails and messages to protect company data
- **Behavior:** Needs fast, reliable verification during busy workday

### Persona 3: Security-Conscious Individual

- **Age:** 20-45, highly aware of cybersecurity risks
- **Pain Point:** Wants to understand *why* a message is flagged as risky
- **Goal:** Learn patterns and educate themselves on scam techniques
- **Behavior:** Reviews scan history, studies threat indicators

---

## 5. Core Features

### 5.1 URL Phishing Detection

- Submit URL for instant analysis
- Display risk classification: Legitimate / Suspicious / Phishing
- Risk Score: 0-100% with severity level indicator
- Explanation of red flags: domain age, HTTPS status, URL length, suspicious keywords, IP address presence
- Save results to user scan history

### 5.2 Scam Message Detection

- Submit text/SMS for scam analysis
- Identify linguistic patterns: urgency, threats, requests for sensitive info, unrealistic offers
- Risk Score with confidence level
- Extract and highlight suspicious phrases/patterns
- Store scan history with message preview

### 5.3 User Management

- Registration and login with email validation
- User profile with scan statistics
- Session management and account security

### 5.4 Scan History & Analytics

- View all past scans with timestamps
- Filter by type (URL/Message) and risk level
- Dashboard showing scan statistics and trends
- Export scan history

---

## 6. User Stories & Acceptance Criteria

### US-01: URL Phishing Detection

**Story:** As a concerned user, I want to submit a URL for instant analysis so I can determine if it's safe before clicking.

**Acceptance Criteria:**
- User can enter or paste a URL in the input field
- System validates URL format before processing
- Analysis completes within 2 seconds
- Result displays classification + risk score + explanation
- User can add result to scan history with one click

### US-02: Scam Message Detection

**Story:** As a user, I want to paste a suspicious message and know if it contains scam indicators.

**Acceptance Criteria:**
- User can submit message text up to 5000 characters
- System highlights suspicious phrases in the result
- Result includes risk score and list of detected patterns
- Analysis completes within 2 seconds
- User can view scan history entry with original message preview

### US-03: User Registration & Authentication

**Story:** As a new user, I want to create an account so I can save and track my scans.

**Acceptance Criteria:**
- Registration form requires email and password
- Email validation ensures valid format
- Password must meet complexity requirements (8+ chars, mixed case, number)
- Login persists user session for 24 hours
- Logout clears session and redirects to login page

### US-04: Scan History Dashboard

**Story:** As a user, I want to view and manage my scan history to track threats I've encountered.

**Acceptance Criteria:**
- Dashboard displays stats: total scans, high-risk results, detection rate
- Scan list shows date, type, content, and risk level
- Filter by type (URL/Message) and risk level
- Sort by date (newest first) or risk score
- Can delete individual scans or clear all history

---

## 7. Non-Functional Requirements

### Performance

- Response time <2 seconds for URL and message analysis
- Support 100+ concurrent users
- Database query response: <100ms average

### Security

- HTTPS encryption for all data transmission
- Password hashing with bcrypt (minimum 10 rounds)
- SQL injection prevention via parameterized queries
- XSS protection in frontend input validation
- Rate limiting: max 50 scans per user per hour
- No storage of sensitive user data beyond email

### Availability

- System uptime: 95%+ availability
- Error logging and monitoring for debugging
- Graceful error messages for failed scans

### Scalability

- Modular architecture allows independent scaling of ML models
- Database optimized with indexing on frequently queried fields
- Prepared for integration with additional detection models

---

## 8. Out of Scope (MVP)

- Browser extension (future enhancement)
- Mobile app (future enhancement)
- Email client integration
- Multilingual support
- Screenshot/OCR-based scam detection
- Real-time threat intelligence feeds

---

## 9. Project Roadmap

### Phase 1 (Weeks 1-4): Core Development

- Dataset collection and preprocessing for both URL and message data
- ML model training for URL phishing detection
- NLP model training for message scam detection
- Flask backend setup and API skeleton

### Phase 2 (Weeks 5-7): Frontend & Integration

- Web UI development (HTML/CSS/JavaScript)
- API endpoint development and integration
- User authentication and session management
- MySQL database schema and integration

### Phase 3 (Weeks 8-10): Testing & Refinement

- Unit testing of ML models
- End-to-end testing of all workflows
- Performance optimization and load testing
- Security audit and vulnerability fixes

### Phase 4 (Weeks 11-12): Deployment & Documentation

- Final bug fixes and refinements
- User guide and technical documentation
- Deployment preparation
- Project defense presentation

---

## 10. Success Criteria

- ML and NLP models trained, evaluated, and integrated successfully
- Web application fully functional with all core features
- System meets all performance and security requirements
- User documentation complete and comprehensive
- Defense demonstrates working prototype with live demos
