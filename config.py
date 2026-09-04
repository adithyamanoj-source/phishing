import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

class Config:
    BASE_DIR = BASE_DIR
    # Flask Security Cryptography Key
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-development-token-37492817')
    
    # Database Configuration (Defaults to SQLite in root dir)
    DATABASE_URL = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(BASE_DIR, 'phishguard.db')}")
    DB_PATH = os.path.join(BASE_DIR, 'phishguard.db')
    
    # Model storage directory
    MODEL_DIR = os.path.join(BASE_DIR, 'models')
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    
    # Session & Security configurations
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_SAMESITE = 'Lax'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 1024 * 1024)) # 1MB limit
