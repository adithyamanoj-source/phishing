import bcrypt
from functools import wraps
from flask import redirect, url_for, flash, request, jsonify
from flask_login import current_user, UserMixin
from utils.database import get_user_by_id, get_user_by_email

class User(UserMixin):
    def __init__(self, user_id: int, email: str, password_hash: str, is_active: bool = True, role: str = 'user'):
        self.id = user_id
        self.email = email
        self.password_hash = password_hash
        self._is_active = is_active
        self.role = role or 'user'

    @property
    def is_active(self):
        return self._is_active

    @property
    def is_admin(self):
        return self.role == 'admin'

    @classmethod
    def get_by_id(cls, user_id: int):
        row = get_user_by_id(user_id)
        if row:
            role = row['role'] if 'role' in row.keys() else 'user'
            return cls(
                user_id=row['user_id'],
                email=row['email'],
                password_hash=row['password_hash'],
                is_active=bool(row['is_active']),
                role=role
            )
        return None

    @classmethod
    def get_by_email(cls, email: str):
        row = get_user_by_email(email)
        if row:
            role = row['role'] if 'role' in row.keys() else 'user'
            return cls(
                user_id=row['user_id'],
                email=row['email'],
                password_hash=row['password_hash'],
                is_active=bool(row['is_active']),
                role=role
            )
        return None


def admin_required(f):
    """Enforces authentication and administrator role privilege."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith('/api/'):
                return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
            flash('Please log in with an administrator account to access this area.', 'error')
            return redirect(url_for('login', next=request.url))
        if not current_user.is_admin:
            if request.path.startswith('/api/'):
                return jsonify({'status': 'error', 'message': 'Administrator access privileges required'}), 403
            flash('Access Denied: Administrator privileges required to access the SOC Control Center.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def hash_password(plain_password: str) -> str:
    """Hashes a password using bcrypt with 12 rounds of salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False
