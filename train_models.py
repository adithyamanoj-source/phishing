"""
🛡️ PhishGuard AI — ML Model Training Pipeline

Trains two production classifiers:
  1. URL Phishing Classifier — 20 lexical features → Random Forest vs Gradient Boosting
  2. NLP Scam Message Classifier — TF-IDF (5,000 features, 1-2 n-grams) → Random Forest

Models are evaluated with train/test split (80/20) and the best performer is saved.
Feature importance rankings are printed for explainability.
"""

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score, f1_score, precision_score, recall_score

from config import Config
from data.generate_training_data import generate_url_dataset, generate_message_dataset
from utils.feature_extraction import extract_url_features, FEATURE_NAMES
from utils.preprocessing import preprocess_message


def train_url_model():
    """Trains and evaluates the URL Phishing Classification Model (20 features)."""
    print("\n" + "=" * 60)
    print("  [TRAIN] URL PHISHING CLASSIFIER — 20 Lexical Features  ")
    print("=" * 60)

    url_csv = os.path.join(Config.DATA_DIR, 'url_dataset.csv')
    if not os.path.exists(url_csv):
        generate_url_dataset()

    df = pd.read_csv(url_csv)
    print(f"[DATA] Loaded {len(df)} URL samples from dataset.")
    print(f"[DATA] Distribution: {(df['label'] == 0).sum()} legitimate / {(df['label'] == 1).sum()} phishing")

    # Feature extraction using the upgraded 20-feature engine
    print("[FEAT] Extracting 20 lexical features per URL...")
    X = np.array([extract_url_features(url) for url in df['url']])
    y = df['label'].values

    print(f"[FEAT] Feature matrix shape: {X.shape}")
    print(f"[FEAT] Feature names: {FEATURE_NAMES}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Model 1: Random Forest
    print("\n[MODEL] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_f1 = f1_score(y_test, rf_preds)
    rf_acc = accuracy_score(y_test, rf_preds)

    # Model 2: Gradient Boosting
    print("[MODEL] Training Gradient Boosting Classifier...")
    gb_model = GradientBoostingClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        min_samples_split=5,
        random_state=42
    )
    gb_model.fit(X_train, y_train)
    gb_preds = gb_model.predict(X_test)
    gb_f1 = f1_score(y_test, gb_preds)
    gb_acc = accuracy_score(y_test, gb_preds)

    print(f"\n[EVAL] Random Forest       — F1: {rf_f1:.4f} | Accuracy: {rf_acc:.4f}")
    print(f"[EVAL] Gradient Boosting   — F1: {gb_f1:.4f} | Accuracy: {gb_acc:.4f}")

    # Select best model
    best_model = rf_model if rf_f1 >= gb_f1 else gb_model
    best_name = "Random Forest" if rf_f1 >= gb_f1 else "Gradient Boosting"
    best_preds = rf_preds if rf_f1 >= gb_f1 else gb_preds
    print(f"\n[SELECT] Best URL Model: {best_name}")

    # Print full classification report
    print(f"\n[REPORT] Classification Report ({best_name}):")
    print(classification_report(y_test, best_preds, target_names=['Legitimate', 'Phishing']))

    # Print feature importances
    print("\n[IMPORTANCE] Top Feature Rankings:")
    importances = best_model.feature_importances_
    feat_imp = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    for rank, (name, imp) in enumerate(feat_imp, 1):
        bar = '#' * int(imp * 50)
        print(f"  {rank:2d}. {name:<28s} {imp:.4f} {bar}")

    # Cross-validation score
    print(f"\n[CV] 5-Fold Cross-Validation F1 Score:")
    cv_scores = cross_val_score(best_model, X, y, cv=5, scoring='f1')
    print(f"  Mean: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Save model
    os.makedirs(Config.MODEL_DIR, exist_ok=True)
    model_path = os.path.join(Config.MODEL_DIR, 'url_classifier.pkl')
    joblib.dump(best_model, model_path)
    print(f"\n[EXPORT] Saved URL classifier model to {model_path}")

    return best_model


def train_message_model():
    """Trains and evaluates the NLP Message Scam Classification Model."""
    print("\n" + "=" * 60)
    print("  [TRAIN] NLP SCAM MESSAGE CLASSIFIER  ")
    print("=" * 60)

    msg_csv = os.path.join(Config.DATA_DIR, 'message_dataset.csv')
    if not os.path.exists(msg_csv):
        generate_message_dataset()

    df = pd.read_csv(msg_csv)
    print(f"[DATA] Loaded {len(df)} message samples from dataset.")
    print(f"[DATA] Distribution: {(df['label'] == 0).sum()} safe / {(df['label'] == 1).sum()} scam")

    # Preprocess text
    cleaned_texts = [preprocess_message(msg) for msg in df['message']]
    y = df['label'].values

    # Fit TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X = vectorizer.fit_transform(cleaned_texts)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Model: Random Forest
    print("\n[MODEL] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=3,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    preds = model.predict(X_test)

    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)

    print(f"\n[EVAL] Accuracy:  {acc:.4f}")
    print(f"[EVAL] Precision: {prec:.4f}")
    print(f"[EVAL] Recall:    {rec:.4f}")
    print(f"[EVAL] F1-Score:  {f1:.4f}")

    print(f"\n[REPORT] Classification Report:")
    print(classification_report(y_test, preds, target_names=['Safe', 'Scam']))

    # Top TF-IDF features
    print("\n[TOP-FEATURES] Most important TF-IDF terms:")
    feature_names = vectorizer.get_feature_names_out()
    importances = model.feature_importances_
    top_indices = importances.argsort()[-15:][::-1]
    for rank, idx in enumerate(top_indices, 1):
        print(f"  {rank:2d}. \"{feature_names[idx]}\" — importance: {importances[idx]:.4f}")

    # Save models
    os.makedirs(Config.MODEL_DIR, exist_ok=True)
    model_path = os.path.join(Config.MODEL_DIR, 'message_classifier.pkl')
    vec_path = os.path.join(Config.MODEL_DIR, 'vectorizer.pkl')

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vec_path)

    print(f"\n[EXPORT] Saved Message classifier to {model_path}")
    print(f"[EXPORT] Saved TF-IDF Vectorizer to {vec_path}")

    return model, vectorizer


if __name__ == '__main__':
    train_url_model()
    train_message_model()
    print("\n" + "=" * 60)
    print("  [SUCCESS] All ML/NLP models trained and exported!  ")
    print("=" * 60)
