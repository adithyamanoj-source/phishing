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
    """Initializes the database schema if tables do not exist and applies migrations."""
    db_path = Config.DB_PATH
    schema_path = os.path.join(Config.BASE_DIR, 'database.sql')
    
    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA foreign_keys = ON;')
    
    if os.path.exists(schema_path):
        with open(schema_path, 'r', encoding='utf-8') as f:
            conn.executescript(f.read())
        conn.commit()

    # Migration: Ensure 'role' column exists in 'users'
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users);")
    cols = [row[1] for row in cursor.fetchall()]
    if 'role' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user';")
        conn.commit()

    # If users exist but none has admin role, promote the earliest registered user
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admin_count = cursor.fetchone()[0]
    if admin_count == 0:
        cursor.execute("UPDATE users SET role = 'admin' WHERE user_id = (SELECT MIN(user_id) FROM users)")
        conn.commit()

    conn.close()

# --- DATABASE QUERY HELPERS (ALL PARAMETERIZED TO PREVENT SQL INJECTION) ---

def create_user(email: str, password_hash: str, role: str = 'user') -> int:
    """Inserts a new user record and returns the created user_id."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
        (email.strip().lower(), password_hash, role)
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


# --- ADMINISTRATIVE SOC & MANAGEMENT QUERIES ---

def get_admin_overview_stats() -> dict:
    """Calculates platform-wide metrics for the SOC Admin Control Panel."""
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE is_active = 1")
    active_users = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM url_scans")
    url_scans = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM message_scans")
    msg_scans = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM url_scans WHERE risk_score > 70")
    high_url = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM message_scans WHERE risk_score > 70")
    high_msg = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM url_scans WHERE risk_score BETWEEN 30 AND 70")
    med_url = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM message_scans WHERE risk_score BETWEEN 30 AND 70")
    med_msg = cursor.fetchone()['cnt']

    total_scans = url_scans + msg_scans
    high_risk = high_url + high_msg
    suspicious = med_url + med_msg
    safe = max(0, total_scans - (high_risk + suspicious))

    threat_rate = round((high_risk / total_scans * 100), 1) if total_scans > 0 else 0.0

    return {
        'total_users': total_users,
        'active_users': active_users,
        'total_scans': total_scans,
        'url_scans_count': url_scans,
        'message_scans_count': msg_scans,
        'high_risk_count': high_risk,
        'suspicious_count': suspicious,
        'safe_count': safe,
        'threat_rate': threat_rate
    }


def get_all_users(search: str = None) -> list:
    """Retrieves all users with their computed scan statistics and role info."""
    db = get_db()
    cursor = db.cursor()

    query = """
        SELECT u.user_id, u.email, u.created_at, u.last_login, u.is_active, 
               COALESCE(u.role, 'user') as role,
               (SELECT COUNT(*) FROM url_scans WHERE user_id = u.user_id) +
               (SELECT COUNT(*) FROM message_scans WHERE user_id = u.user_id) AS total_scans,
               (SELECT COUNT(*) FROM url_scans WHERE user_id = u.user_id AND risk_score > 70) +
               (SELECT COUNT(*) FROM message_scans WHERE user_id = u.user_id AND risk_score > 70) AS high_risk_scans
        FROM users u
    """
    params = []
    if search:
        query += " WHERE u.email LIKE ?"
        params.append(f"%{search.strip().lower()}%")

    query += " ORDER BY u.created_at DESC"
    cursor.execute(query, params)

    users = []
    for r in cursor.fetchall():
        users.append({
            'user_id': r['user_id'],
            'email': r['email'],
            'created_at': str(r['created_at']) if r['created_at'] else 'N/A',
            'last_login': str(r['last_login']) if r['last_login'] else 'Never',
            'is_active': bool(r['is_active']),
            'role': r['role'] or 'user',
            'total_scans': r['total_scans'],
            'high_risk_scans': r['high_risk_scans']
        })
    return users


def toggle_user_status(user_id: int) -> dict:
    """Flips active state for a user."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_active FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        return {'success': False, 'message': 'User not found'}

    new_status = 0 if row['is_active'] else 1
    cursor.execute("UPDATE users SET is_active = ? WHERE user_id = ?", (new_status, user_id))
    db.commit()
    return {'success': True, 'is_active': bool(new_status)}


def toggle_user_role(user_id: int) -> dict:
    """Toggles role between admin and user."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT role FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        return {'success': False, 'message': 'User not found'}

    current_role = row['role'] or 'user'
    # Prevent demoting the last admin
    if current_role == 'admin':
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if cursor.fetchone()[0] <= 1:
            return {'success': False, 'message': 'Cannot demote the sole administrator.'}

    new_role = 'user' if current_role == 'admin' else 'admin'
    cursor.execute("UPDATE users SET role = ? WHERE user_id = ?", (new_role, user_id))
    db.commit()
    return {'success': True, 'role': new_role}


def get_global_scans(scan_type: str = 'all', risk_level: str = 'all', sort_by: str = 'date_desc', limit: int = 100, search: str = None) -> list:
    """Fetches global scan log across all users for admin threat investigation."""
    db = get_db()
    cursor = db.cursor()
    scans = []

    if scan_type in ('all', 'url'):
        query = """
            SELECT s.scan_id, 'url' as type, s.url_submitted as content, s.classification, 
                   s.risk_score, s.risk_level, s.explanation, s.scan_timestamp, u.email as user_email
            FROM url_scans s
            JOIN users u ON s.user_id = u.user_id
        """
        params = []
        if search:
            query += " WHERE (s.url_submitted LIKE ? OR u.email LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        cursor.execute(query, params)
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
                'user_email': r['user_email'],
                'content': r['content'],
                'classification': r['classification'],
                'score': float(r['risk_score']),
                'risk_level': r['risk_level'],
                'explanation': expl,
                'timestamp': str(r['scan_timestamp'])
            })

    if scan_type in ('all', 'message'):
        query = """
            SELECT s.scan_id, 'message' as type, s.message_preview as content, s.classification, 
                   s.risk_score, s.detected_patterns, s.scan_timestamp, u.email as user_email
            FROM message_scans s
            JOIN users u ON s.user_id = u.user_id
        """
        params = []
        if search:
            query += " WHERE (s.message_preview LIKE ? OR u.email LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        cursor.execute(query, params)
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
                'user_email': r['user_email'],
                'content': r['content'],
                'classification': r['classification'],
                'score': score,
                'risk_level': rl,
                'detected_patterns': pats,
                'timestamp': str(r['scan_timestamp'])
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


def delete_scan_as_admin(scan_id_str: str) -> bool:
    """Removes a scan record globally as administrator."""
    db = get_db()
    cursor = db.cursor()

    if scan_id_str.startswith('url_'):
        raw_id = int(scan_id_str.replace('url_', ''))
        cursor.execute("DELETE FROM url_scans WHERE scan_id = ?", (raw_id,))
    elif scan_id_str.startswith('msg_'):
        raw_id = int(scan_id_str.replace('msg_', ''))
        cursor.execute("DELETE FROM message_scans WHERE scan_id = ?", (raw_id,))
    else:
        try:
            raw_id = int(scan_id_str)
            cursor.execute("DELETE FROM url_scans WHERE scan_id = ?", (raw_id,))
            cursor.execute("DELETE FROM message_scans WHERE scan_id = ?", (raw_id,))
        except ValueError:
            return False

    db.commit()
    return cursor.rowcount > 0


def get_system_health_info() -> dict:
    """Returns database size, table records, and environment stats."""
    db_path = Config.DB_PATH
    size_kb = 0
    if os.path.exists(db_path):
        size_kb = round(os.path.getsize(db_path) / 1024, 2)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT sqlite_version()")
    sqlite_ver = cursor.fetchone()[0]

    return {
        'database_file': os.path.basename(db_path),
        'database_size_kb': size_kb,
        'sqlite_version': sqlite_ver,
        'status': 'Healthy'
    }

