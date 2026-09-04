-- PhishGuard AI Database Schema Definition
-- Compatible with MySQL 5.7+ and SQLite

CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP NULL,
  is_active BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS url_scans (
  scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  url_submitted VARCHAR(2048) NOT NULL,
  classification VARCHAR(50) NOT NULL,
  risk_score DECIMAL(5,2) NOT NULL,
  risk_level VARCHAR(20) NOT NULL,
  explanation TEXT,
  scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_url_user_id ON url_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_url_timestamp ON url_scans(scan_timestamp);

CREATE TABLE IF NOT EXISTS message_scans (
  scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message_preview VARCHAR(500) NOT NULL,
  classification VARCHAR(50) NOT NULL,
  risk_score DECIMAL(5,2) NOT NULL,
  detected_patterns TEXT,
  scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_msg_user_id ON message_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_msg_timestamp ON message_scans(scan_timestamp);
