import os
import joblib
from config import Config

_URL_MODEL = None
_MSG_MODEL = None
_VECTORIZER = None

def load_url_model():
    """Loads and caches the URL phishing classification model."""
    global _URL_MODEL
    if _URL_MODEL is None:
        model_path = os.path.join(Config.MODEL_DIR, 'url_classifier.pkl')
        if os.path.exists(model_path):
            try:
                _URL_MODEL = joblib.load(model_path)
            except Exception as e:
                print(f"[ERROR] Failed to load URL model: {e}")
                _URL_MODEL = None
    return _URL_MODEL


def load_message_model():
    """Loads and caches the Message scam classification model and TF-IDF vectorizer."""
    global _MSG_MODEL, _VECTORIZER
    if _MSG_MODEL is None or _VECTORIZER is None:
        model_path = os.path.join(Config.MODEL_DIR, 'message_classifier.pkl')
        vec_path = os.path.join(Config.MODEL_DIR, 'vectorizer.pkl')
        
        if os.path.exists(model_path) and os.path.exists(vec_path):
            try:
                _MSG_MODEL = joblib.load(model_path)
                _VECTORIZER = joblib.load(vec_path)
            except Exception as e:
                print(f"[ERROR] Failed to load Message model or vectorizer: {e}")
                _MSG_MODEL, _VECTORIZER = None, None
                
    return _MSG_MODEL, _VECTORIZER
