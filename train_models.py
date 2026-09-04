import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score, f1_score, precision_score, recall_score

from config import Config
from data.generate_training_data import generate_url_dataset, generate_message_dataset
from utils.feature_extraction import extract_url_features
from utils.preprocessing import preprocess_message

def train_url_model():
    """Trains and evaluates the URL Phishing Classification Model."""
    print("\n==================================================")
    print(" [TRAIN] URL PHISHING CLASSIFICATION MODEL  ")
    print("==================================================")
    
    url_csv = os.path.join(Config.DATA_DIR, 'url_dataset.csv')
    if not os.path.exists(url_csv):
        generate_url_dataset()
        
    df = pd.read_csv(url_csv)
    print(f"[DATA] Loaded {len(df)} URL samples from dataset.")
    
    # Feature extraction
    X = np.array([extract_url_features(url) for url in df['url']])
    y = df['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Model 1: Random Forest
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_f1 = f1_score(y_test, rf_preds)
    
    # Model 2: Logistic Regression
    lr_model = LogisticRegression(max_iter=1000, random_state=42)
    lr_model.fit(X_train, y_train)
    lr_preds = lr_model.predict(X_test)
    lr_f1 = f1_score(y_test, lr_preds)
    
    print(f"[EVAL] Random Forest F1-Score: {rf_f1:.4f} (Accuracy: {accuracy_score(y_test, rf_preds):.4f})")
    print(f"[EVAL] Logistic Regression F1-Score: {lr_f1:.4f} (Accuracy: {accuracy_score(y_test, lr_preds):.4f})")
    
    # Select best model
    best_model = rf_model if rf_f1 >= lr_f1 else lr_model
    best_name = "Random Forest" if rf_f1 >= lr_f1 else "Logistic Regression"
    print(f"[SELECT] Best URL Model: {best_name}")
    
    os.makedirs(Config.MODEL_DIR, exist_ok=True)
    model_path = os.path.join(Config.MODEL_DIR, 'url_classifier.pkl')
    joblib.dump(best_model, model_path)
    print(f"[EXPORT] Saved URL classifier model to {model_path}")
    
    return best_model


def train_message_model():
    """Trains and evaluates the NLP Message Scam Classification Model."""
    print("\n==================================================")
    print(" [TRAIN] NLP SCAM MESSAGE CLASSIFIER  ")
    print("==================================================")
    
    msg_csv = os.path.join(Config.DATA_DIR, 'message_dataset.csv')
    if not os.path.exists(msg_csv):
        generate_message_dataset()
        
    df = pd.read_csv(msg_csv)
    print(f"[DATA] Loaded {len(df)} message samples from dataset.")
    
    # Preprocess text
    cleaned_texts = [preprocess_message(msg) for msg in df['message']]
    y = df['label'].values
    
    # Fit TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X = vectorizer.fit_transform(cleaned_texts)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Model: Random Forest
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    
    print(f"[EVAL] Accuracy:  {acc:.4f}")
    print(f"[EVAL] Precision: {prec:.4f}")
    print(f"[EVAL] Recall:    {rec:.4f}")
    print(f"[EVAL] F1-Score:  {f1:.4f}")
    
    os.makedirs(Config.MODEL_DIR, exist_ok=True)
    model_path = os.path.join(Config.MODEL_DIR, 'message_classifier.pkl')
    vec_path = os.path.join(Config.MODEL_DIR, 'vectorizer.pkl')
    
    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vec_path)
    
    print(f"[EXPORT] Saved Message classifier to {model_path}")
    print(f"[EXPORT] Saved TF-IDF Vectorizer to {vec_path}")
    
    return model, vectorizer


if __name__ == '__main__':
    train_url_model()
    train_message_model()
    print("\n[SUCCESS] All machine learning & NLP models successfully trained and stored!")

