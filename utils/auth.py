import bcrypt
from flask_login import UserMixin
from utils.database import get_user_by_id, get_user_by_email

class User(UserMixin):
    def __init__(self, user_id: int, email: str, password_hash: str, is_active: bool = True):
        self.id = user_id
        self.email = email
        self.password_hash = password_hash
        self._is_active = is_active

    @property
    def is_active(self):
        return self._is_active

    @classmethod
    def get_by_id(cls, user_id: int):
        row = get_user_by_id(user_id)
        if row:
            return cls(
                user_id=row['user_id'],
                email=row['email'],
                password_hash=row['password_hash'],
                is_active=bool(row['is_active'])
            )
        return None

    @classmethod
    def get_by_email(cls, email: str):
        row = get_user_by_email(email)
        if row:
            return cls(
                user_id=row['user_id'],
                email=row['email'],
                password_hash=row['password_hash'],
                is_active=bool(row['is_active'])
            )
        return None


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
