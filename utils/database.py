import os
import sqlite3
import json
from flask import g
from config import Config

def get_db():
    """Returns an active SQLite database connection stored in Flask request context."""
    if 'db' not in g:
        g.db = sqlite3.connect(Config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        # Enable foreign key constraints
        g.db.execute('PRAGMA foreign_keys = ON;')
    return g.db

def close_db(e=None):
    """Closes the database connection at the end of the request context."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(app=None):
    """Initializes the database schema if tables do not exist."""
    db_path = Config.DB_PATH
    schema_path = os.path.join(Config.BASE_DIR, 'database.sql')
    
    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA foreign_keys = ON;')
    
    if os.path.exists(schema_path):
        with open(schema_path, 'r', encoding='utf-8') as f:
            conn.executescript(f.read())
        conn.commit()
    conn.close()

# --- DATABASE QUERY HELPERS (ALL PARAMETERIZED TO PREVENT SQL INJECTION) ---

def create_user(email: str, password_hash: str) -> int:
    """Inserts a new user record and returns the created user_id."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (email.strip().lower(), password_hash)
    )
    db.commit()
    return cursor.lastrowid

def get_user_by_email(email: str):
    """Retrieves a user row by email address."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
    return cursor.fetchone()

def get_user_by_id(user_id: int):
    """Retrieves a user row by ID."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    return cursor.fetchone()

def update_last_login(user_id: int):
    """Updates the last_login timestamp for a user."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?", (user_id,))
    db.commit()

def save_url_scan(user_id: int, url: str, classification: str, score: float, risk_level: str, explanation: list) -> int:
    """Saves a URL scan result to url_scans table."""
    db = get_db()
    cursor = db.cursor()
    explanation_json = json.dumps(explanation) if isinstance(explanation, list) else str(explanation)
    cursor.execute(
        """INSERT INTO url_scans (user_id, url_submitted, classification, risk_score, risk_level, explanation)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, url, classification, score, risk_level, explanation_json)
    )
    db.commit()
    return cursor.lastrowid

def save_message_scan(user_id: int, preview: str, classification: str, score: float, patterns: list) -> int:
    """Saves a message scan result to message_scans table."""
    db = get_db()
    cursor = db.cursor()
    patterns_json = json.dumps(patterns) if isinstance(patterns, list) else str(patterns)
    cursor.execute(
        """INSERT INTO message_scans (user_id, message_preview, classification, risk_score, detected_patterns)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, preview, classification, score, patterns_json)
    )
    db.commit()
    return cursor.lastrowid

def get_user_scans(user_id: int, scan_type: str = 'all', risk_level: str = 'all', sort_by: str = 'date_desc', limit: int = 50):
    """Fetches combined scan history for a given user with filtering and sorting."""
    db = get_db()
    cursor = db.cursor()
    
    scans = []
    
    if scan_type in ('all', 'url'):
        cursor.execute(
            """SELECT scan_id, 'url' as type, url_submitted as content, classification, risk_score, risk_level, explanation, scan_timestamp
               FROM url_scans WHERE user_id = ?""", (user_id,)
        )
        for r in cursor.fetchall():
            expl = r['explanation']
            try:
                expl = json.loads(expl)
            except Exception:
                pass
            scans.append({
                'id': f"url_{r['scan_id']}",
                'raw_id': r['scan_id'],
                'type': 'url',
                'content': r['content'],
                'classification': r['classification'],
                'score': float(r['risk_score']),
                'risk_level': r['risk_level'],
                'explanation': expl,
                'timestamp': r['scan_timestamp']
            })
            
    if scan_type in ('all', 'message'):
        cursor.execute(
            """SELECT scan_id, 'message' as type, message_preview as content, classification, risk_score, detected_patterns, scan_timestamp
               FROM message_scans WHERE user_id = ?""", (user_id,)
        )
        for r in cursor.fetchall():
            pats = r['detected_patterns']
            try:
                pats = json.loads(pats)
            except Exception:
                pass
            
            score = float(r['risk_score'])
            rl = 'High' if score > 70 else ('Medium' if score > 30 else 'Low')
            scans.append({
                'id': f"msg_{r['scan_id']}",
                'raw_id': r['scan_id'],
                'type': 'message',
                'content': r['content'],
                'classification': r['classification'],
                'score': score,
                'risk_level': rl,
                'detected_patterns': pats,
                'timestamp': r['scan_timestamp']
            })

    # Apply Risk Filter
    if risk_level != 'all':
        rl_lower = risk_level.lower()
        scans = [s for s in scans if s['risk_level'].lower() == rl_lower]

    # Apply Sorting
    if sort_by == 'date_desc':
        scans.sort(key=lambda x: str(x['timestamp']), reverse=True)
    elif sort_by == 'date_asc':
        scans.sort(key=lambda x: str(x['timestamp']))
    elif sort_by == 'risk_desc':
        scans.sort(key=lambda x: x['score'], reverse=True)

    return scans[:limit]

def delete_user_scan(user_id: int, scan_id_str: str) -> bool:
    """Deletes a specific scan record belonging to the user."""
    db = get_db()
    cursor = db.cursor()
    
    if scan_id_str.startswith('url_'):
        raw_id = int(scan_id_str.replace('url_', ''))
        cursor.execute("DELETE FROM url_scans WHERE scan_id = ? AND user_id = ?", (raw_id, user_id))
    elif scan_id_str.startswith('msg_'):
        raw_id = int(scan_id_str.replace('msg_', ''))
        cursor.execute("DELETE FROM message_scans WHERE scan_id = ? AND user_id = ?", (raw_id, user_id))
    else:
        try:
            raw_id = int(scan_id_str)
            cursor.execute("DELETE FROM url_scans WHERE scan_id = ? AND user_id = ?", (raw_id, user_id))
            cursor.execute("DELETE FROM message_scans WHERE scan_id = ? AND user_id = ?", (raw_id, user_id))
        except ValueError:
            return False
            
    db.commit()
    return cursor.rowcount > 0

def get_user_stats(user_id: int) -> dict:
    """Calculates statistics for a user's scan history."""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT COUNT(*) as cnt FROM url_scans WHERE user_id = ?", (user_id,))
    url_count = cursor.fetchone()['cnt']
    
    cursor.execute("SELECT COUNT(*) as cnt FROM message_scans WHERE user_id = ?", (user_id,))
    msg_count = cursor.fetchone()['cnt']
    
    cursor.execute("SELECT COUNT(*) as cnt FROM url_scans WHERE user_id = ? AND risk_score > 70", (user_id,))
    high_url = cursor.fetchone()['cnt']
    
    cursor.execute("SELECT COUNT(*) as cnt FROM message_scans WHERE user_id = ? AND risk_score > 70", (user_id,))
    high_msg = cursor.fetchone()['cnt']
    
    total = url_count + msg_count
    high_risk = high_url + high_msg
    safe = total - high_risk
    
    return {
        'total_scans': total,
        'high_risk_count': high_risk,
        'safe_count': safe,
        'url_scans_count': url_count,
        'message_scans_count': msg_count
    }
