# 🛡️ PhishGuard AI — Production Flask Backend Server

import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from utils.database import (
    init_db, get_db, close_db, create_user, get_user_by_email,
    update_last_login, save_url_scan, save_message_scan,
    get_user_scans, delete_user_scan, get_user_stats,
    get_admin_overview_stats, get_all_users, toggle_user_status,
    toggle_user_role, get_global_scans, delete_scan_as_admin, get_system_health_info
)
from utils.auth import User, hash_password, verify_password, admin_required
from utils.validators import validate_url, validate_message, validate_email, validate_password
from utils.feature_extraction import extract_url_features, get_url_explanation, rule_based_phishing_score, FEATURE_NAMES
from utils.link_verifier import deep_link_analysis
from utils.preprocessing import preprocess_message, detect_message_patterns
from utils.model_loader import load_url_model, load_message_model
from utils.logging_config import setup_logging

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Structured Logger
logger = setup_logging(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please sign in to access security analysis tools."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))

# Initialize Flask-Limiter for Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Teardown database connection after request
app.teardown_appcontext(close_db)

# Security Headers & Middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Context Processor for Templates
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

# --- PAGE ROUTING ---

@app.route('/')
def index():
    return render_template('index.html', active_page='home')

@app.route('/analyze')
def analyze():
    return render_template('analyze.html', active_page='analyze')

@app.route('/history')
def history():
    return render_template('history.html', active_page='history')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', active_page='dashboard')

# --- AUTHENTICATION ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('analyze'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        valid_e, msg_e = validate_email(email)
        if not valid_e:
            flash(msg_e, "error")
            return render_template('login.html', active_page='login')

        user = User.get_by_email(email)
        if user and verify_password(password, user.password_hash):
            login_user(user, remember=True)
            update_last_login(user.id)
            logger.info(f"Successful login for user_id={user.id}")
            flash(f"Welcome back! Logged in as {user.email}", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('analyze'))
        else:
            logger.warning(f"Failed login attempt for email={email}")
            flash("Invalid email or password credentials.", "error")

    return render_template('login.html', active_page='login')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('analyze'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        if password != password_confirm:
            flash("Passwords do not match!", "error")
            return render_template('register.html', active_page='register')

        valid_e, msg_e = validate_email(email)
        if not valid_e:
            flash(msg_e, "error")
            return render_template('register.html', active_page='register')

        valid_p, msg_p = validate_password(password)
        if not valid_p:
            flash(msg_p, "error")
            return render_template('register.html', active_page='register')

        if get_user_by_email(email):
            flash("An account with this email already exists.", "error")
            return render_template('register.html', active_page='register')

        try:
            pwd_hash = hash_password(password)
            user_id = create_user(email, pwd_hash)
            logger.info(f"Created new user_id={user_id} email={email}")
            flash("Registration successful! Please sign in with your credentials.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            flash("System error creating account. Please try again.", "error")

    return render_template('register.html', active_page='register')

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logger.info(f"User user_id={current_user.id} logged out")
        logout_user()
    flash("You have successfully signed out.", "success")
    return redirect(url_for('index'))

# --- REAL ML/NLP API ENDPOINTS ---

@app.route('/api/analyze-url', methods=['POST'])
@limiter.limit("50 per hour")
def api_analyze_url():
    data = request.get_json() or {}
    url = data.get('url', '').strip()

    valid, msg = validate_url(url)
    if not valid:
        return jsonify({"status": "error", "message": msg}), 400

    # ─── Tier 1: Extract 20 Lexical Features ───
    features = extract_url_features(url)
    model = load_url_model()

    if model is not None:
        try:
            prob = float(model.predict_proba([features])[0][1])
            score = round(prob * 100, 2)
        except Exception as e:
            logger.error(f"URL model prediction error: {e}")
            score = rule_based_phishing_score(features)
    else:
        # Fallback to rule-based weighted scoring if model file missing
        score = rule_based_phishing_score(features)

    # ─── Tier 1: Generate Lexical Explanations ───
    explanation = get_url_explanation(url, features, score / 100.0)

    # ─── Tier 2-3: Deep Analysis for Borderline Scores ───
    deep_analysis = None
    if 25 < score < 75:
        try:
            deep_result = deep_link_analysis(url)
            deep_analysis = {
                'ssl': deep_result.get('ssl', {}),
                'dns': deep_result.get('dns', {}),
                'redirects': deep_result.get('redirects', {}),
            }
            # Extend explanations with deep indicators
            explanation.extend(deep_result.get('deep_indicators', []))
            # Adjust score based on deep analysis
            adjustment = deep_result.get('deep_risk_adjustment', 0.0)
            score = round(max(0, min(100, score + adjustment)), 2)
        except Exception as e:
            logger.warning(f"Deep link analysis failed for {url}: {e}")

    # ─── Classification ───
    if score > 70:
        classification = 'Phishing'
        risk_level = 'High'
    elif score > 30:
        classification = 'Suspicious'
        risk_level = 'Medium'
    else:
        classification = 'Legitimate'
        risk_level = 'Low'

    # ─── Feature Breakdown (for detailed UI display) ───
    feature_breakdown = []
    for i, (name, value) in enumerate(zip(FEATURE_NAMES, features)):
        feature_breakdown.append({
            'name': name,
            'value': float(value),
            'index': i
        })

    scan_id = None
    if current_user.is_authenticated:
        try:
            scan_id = save_url_scan(current_user.id, url, classification, score, risk_level, explanation)
        except Exception as e:
            logger.error(f"Failed to save URL scan to database: {e}")

    return jsonify({
        "status": "success",
        "type": "url",
        "content": url,
        "classification": classification,
        "risk_score": score,
        "risk_level": risk_level,
        "explanation": explanation,
        "feature_breakdown": feature_breakdown,
        "deep_analysis": deep_analysis,
        "scan_id": scan_id
    })


@app.route('/api/analyze-message', methods=['POST'])
@limiter.limit("50 per hour")
def api_analyze_message():
    data = request.get_json() or {}
    message = data.get('message', '').strip()

    valid, msg = validate_message(message)
    if not valid:
        return jsonify({"status": "error", "message": msg}), 400

    cleaned_text = preprocess_message(message)
    model, vectorizer = load_message_model()

    if model is not None and vectorizer is not None:
        try:
            vec = vectorizer.transform([cleaned_text])
            prob = float(model.predict_proba(vec)[0][1])
            score = round(prob * 100, 2)
        except Exception as e:
            logger.error(f"Message model prediction error: {e}")
            score = 50.0
    else:
        score = 40.0

    matched_patterns, explanation = detect_message_patterns(message)

    if score > 70 or (matched_patterns and score > 40):
        classification = 'Scam'
        risk_level = 'High'
    elif score > 30 or matched_patterns:
        classification = 'Suspicious'
        risk_level = 'Medium'
    else:
        classification = 'Safe'
        risk_level = 'Low'

    scan_id = None
    if current_user.is_authenticated:
        try:
            preview = message[:495] + '...' if len(message) > 500 else message
            scan_id = save_message_scan(current_user.id, preview, classification, score, matched_patterns)
        except Exception as e:
            logger.error(f"Failed to save Message scan to database: {e}")

    return jsonify({
        "status": "success",
        "type": "message",
        "content": message,
        "classification": classification,
        "risk_score": score,
        "risk_level": risk_level,
        "matched_patterns": matched_patterns,
        "explanation": explanation,
        "scan_id": scan_id
    })


@app.route('/api/scan-history', methods=['GET'])
def api_scan_history():
    if not current_user.is_authenticated:
        return jsonify({"status": "error", "message": "Authentication required", "scans": []}), 401

    scan_type = request.args.get('type', 'all')
    risk_level = request.args.get('risk_level', 'all')
    sort_by = request.args.get('sort_by', 'date_desc')
    limit = int(request.args.get('limit', 50))

    scans = get_user_scans(current_user.id, scan_type, risk_level, sort_by, limit)
    stats = get_user_stats(current_user.id)

    return jsonify({
        "status": "success",
        "scans": scans,
        "total_count": len(scans),
        "stats": stats
    })


@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    if not current_user.is_authenticated:
        return jsonify({"status": "error", "message": "Authentication required"}), 401

    success = delete_user_scan(current_user.id, scan_id)
    if success:
        return jsonify({"status": "success", "message": "Record deleted"})
    else:
        return jsonify({"status": "error", "message": "Record not found or unauthorized"}), 404


@app.route('/api/user-stats', methods=['GET'])
def api_user_stats():
    if not current_user.is_authenticated:
        return jsonify({"status": "success", "stats": {"total_scans": 0, "high_risk_count": 0, "safe_count": 0}})

    stats = get_user_stats(current_user.id)
    return jsonify({"status": "success", "stats": stats})

# --- SOC ADMIN CONTROL CENTER ROUTES ---

@app.route('/admin')
@admin_required
def admin_panel():
    stats = get_admin_overview_stats()
    return render_template('admin.html', active_page='admin', stats=stats)


@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_admin_stats():
    stats = get_admin_overview_stats()
    return jsonify({"status": "success", "stats": stats})


@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    search = request.args.get('search', '').strip()
    users = get_all_users(search=search if search else None)
    return jsonify({"status": "success", "users": users, "total_users": len(users)})


@app.route('/api/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def api_admin_toggle_user_status(user_id):
    if current_user.id == user_id:
        return jsonify({"status": "error", "message": "You cannot disable your own administrator account."}), 400
    res = toggle_user_status(user_id)
    if res.get('success'):
        logger.info(f"Admin {current_user.email} changed user_id={user_id} active status to {res.get('is_active')}")
        return jsonify({"status": "success", "is_active": res.get('is_active'), "message": "User status updated successfully."})
    return jsonify({"status": "error", "message": res.get('message', 'Failed to update user status')}), 400


@app.route('/api/admin/users/<int:user_id>/toggle-role', methods=['POST'])
@admin_required
def api_admin_toggle_user_role(user_id):
    if current_user.id == user_id:
        return jsonify({"status": "error", "message": "You cannot change your own administrator role."}), 400
    res = toggle_user_role(user_id)
    if res.get('success'):
        logger.info(f"Admin {current_user.email} changed user_id={user_id} role to {res.get('role')}")
        return jsonify({"status": "success", "role": res.get('role'), "message": f"User role changed to {res.get('role')}."})
    return jsonify({"status": "error", "message": res.get('message', 'Failed to update user role')}), 400


@app.route('/api/admin/scans', methods=['GET'])
@admin_required
def api_admin_scans():
    scan_type = request.args.get('type', 'all')
    risk_level = request.args.get('risk_level', 'all')
    sort_by = request.args.get('sort_by', 'date_desc')
    search = request.args.get('search', '').strip()
    limit = int(request.args.get('limit', 100))

    scans = get_global_scans(
        scan_type=scan_type,
        risk_level=risk_level,
        sort_by=sort_by,
        limit=limit,
        search=search if search else None
    )
    return jsonify({
        "status": "success",
        "scans": scans,
        "total_count": len(scans)
    })


@app.route('/api/admin/scans/<scan_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_scan(scan_id):
    success = delete_scan_as_admin(scan_id)
    if success:
        logger.info(f"Admin {current_user.email} deleted scan record {scan_id}")
        return jsonify({"status": "success", "message": "Scan record permanently purged from audit logs."})
    return jsonify({"status": "error", "message": "Record not found or already removed."}), 404


@app.route('/api/admin/system-health', methods=['GET'])
@admin_required
def api_admin_system_health():
    url_model = load_url_model()
    msg_model, vec = load_message_model()
    health = get_system_health_info()
    health['url_model_loaded'] = url_model is not None
    health['message_model_loaded'] = msg_model is not None and vec is not None
    return jsonify({"status": "success", "health": health})


# Initialise DB schema on startup
with app.app_context():
    init_db(app)

if __name__ == '__main__':
    import socket
    def get_network_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    lan_ip = get_network_ip()
    print("--------------------------------------------------")
    print("  PhishGuard AI Production Backend Server Online  ")
    print("  Local Access:   http://localhost:5000")
    print(f"  Wi-Fi Network:  http://{lan_ip}:5000")
    print("--------------------------------------------------")
    app.run(host='0.0.0.0', port=5000, debug=False)
