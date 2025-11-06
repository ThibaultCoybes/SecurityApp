# app.py
import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from security.authentication import AuthenticationEnforcer
from security.validation import Validation
from security.audit import SecurityAuditLogger
from security.detection import detect_sql_injection, detect_tool

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret-change-me")

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'mysql_db')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'root')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'security_db')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

auth = AuthenticationEnforcer()
validator = Validation()
audit_logger = SecurityAuditLogger()


def client_info():
    return {
        "ip": request.remote_addr or "0.0.0.0",
        "user_agent": request.headers.get("User-Agent", "")
    }


def check_injections(*fields: str, route: str):
    info = client_info()
    payload_sample = " ".join(fields[:3])
    tool = detect_tool(info["user_agent"], payload_sample)
    
    if any(detect_sql_injection(field) for field in fields if field):
        audit_logger.log_injection_detected(
            user=fields[0] if fields else None,
            ip_address=info["ip"],
            route=route,
            payload=payload_sample,
            tool=tool
        )
        return True, tool
    return False, tool


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('username'):
            info = client_info()
            audit_logger.log_access_violation(
                user=None,
                ip_address=info["ip"],
                route=request.path,
                extra={"reason": "not_authenticated", "ua": info["user_agent"]}
            )
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated


def log_route_visit(event_type: str, route: str):
    info = client_info()
    audit_logger.log_route_visit(
        event_type=event_type,
        user=session.get("username"),
        ip_address=info["ip"],
        route=route,
        user_agent=info["user_agent"]
    )


@app.route('/')
@limiter.limit("100 per day")
def home():
    log_route_visit("VISIT", "/")
    return render_template('login.html')


@app.route('/dashboard')
@require_auth
@limiter.limit("200 per day")
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    info = client_info()
    if request.method == 'GET':
        log_route_visit("VISIT_LOGIN", "/login")
        return render_template('login.html')

    username = (request.form.get('username') or "").strip()
    password = request.form.get('password') or ""

    has_injection, tool = check_injections(username, password, route="/login")
    if has_injection:
        return render_template('login.html', error="Injection suspectée"), 400

    success = auth.authenticate(username, password, mysql)
    audit_logger.log_login_attempt(
        user=username or None,
        ip_address=info["ip"],
        success=success,
        extra={"route": "/login", "tool": tool, "ua": info["user_agent"]}
    )

    if success:
        session['username'] = username
        return redirect(url_for('dashboard'))
    return render_template('login.html', error='Identifiants invalides'), 401


@app.route('/logout')
def logout():
    user = session.get('username')
    info = client_info()
    session.clear()
    audit_logger.log_event("LOGOUT", user, info["ip"], "INFO", {"route": "/logout", "ua": info["user_agent"]})
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    info = client_info()
    if request.method == 'GET':
        log_route_visit("VISIT_REGISTER", "/register")
        return render_template('register.html')

    username = (request.form.get('username') or "").strip()
    email = (request.form.get('email') or "").strip()
    password = request.form.get('password') or ""
    confirm_password = request.form.get('confirm_password') or ""

    has_injection, tool = check_injections(username, email, password, route="/register")
    if has_injection:
        return render_template('register.html', error="Injection suspectée"), 400

    if not (validator.validate_username(username) and validator.validate_email(email)
            and validator.validate_password(password, confirm_password)):
        audit_logger.log_event("REGISTER_VALIDATION_FAILED", username or None, info["ip"], "WARNING",
                              {"route": "/register", "ua": info["user_agent"], "tool": tool})
        return render_template('register.html', error='Champs invalides'), 400

    safe_username = validator.sanitize_html(username)
    safe_email = validator.sanitize_html(email)
    hashed = auth.hash_password(password)
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                   (safe_username, safe_email, hashed))
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        audit_logger.log_db_error(safe_username, info["ip"], "/register", str(e))
        return render_template('register.html', error='Erreur base de données'), 500
    finally:
        cur.close()

    audit_logger.log_event("USER_REGISTERED", safe_username, info["ip"], "INFO",
                          {"route": "/register", "ua": info["user_agent"], "tool": tool})
    session['username'] = safe_username
    return redirect(url_for('dashboard'))


def error_handler(code: int, message: str, severity: str):
    def handler(e):
        info = client_info()
        audit_logger.log_event(f"HTTP_{code}", session.get('username'), info["ip"], severity,
                              {"path": request.path, "ua": info["user_agent"], "error": str(e) if code == 500 else None})
        return message, code
    return handler


app.errorhandler(403)(error_handler(403, "Forbidden", "WARNING"))
app.errorhandler(404)(error_handler(404, "Not Found", "INFO"))
app.errorhandler(500)(error_handler(500, "Internal Server Error", "ERROR"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
