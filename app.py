from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_bcrypt import Bcrypt
import re
from pathlib import Path
import json
import os
import secrets
from functools import wraps

app = Flask(__name__)
# A2: Secret key sécurisée (générée ou depuis env)
if "SECRET_KEY" not in os.environ:
    raise RuntimeError("SECRET_KEY environment variable must be set")
app.secret_key = os.environ.get("SECRET_KEY")

bcrypt = Bcrypt(app)
USERS_FILE = Path(__file__).with_name("users.json")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")
MIN_PASSWORD_LENGTH = 12  # A2: Minimum password length

def login_required(f):
    """A1: Décorateur pour vérifier que l'utilisateur est connecté"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Vous devez être connecté", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def load_users():
    if not USERS_FILE.exists():
        return {}
    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def save_users(users):
    tmp_file = USERS_FILE.with_suffix(".json.tmp")
    tmp_file.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_file.replace(USERS_FILE)

def is_admin_request():
    """A1: Vérifier admin via header sécurisé (pas de query param) + constant-time comparison"""
    if not ADMIN_TOKEN:
        return False
    # A2 & A1: Utiliser uniquement le header, pas de query param exposant le token en URL
    token = request.headers.get("X-Admin-Token")
    if not token:
        return False
    # Comparison en temps constant pour éviter les timing attacks
    return secrets.compare_digest(token, ADMIN_TOKEN)
    
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        users = load_users()
        stored_hash = users.get(username)

        if stored_hash and bcrypt.check_password_hash(stored_hash, password):
            # A1: Créer une session utilisateur au lieu de passer le username
            session['username'] = username
            session.permanent = True
            flash("Vous êtes connecté", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Mauvais identifiant ou mot de passe", "danger")

    return render_template("login.html")

def is_valid_username(username):
    ex = r"^[a-zA-Z0-9_]+$"
    return re.match(ex, username) is not None
def is_valid_password(password):
    ex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(ex, password) is not None

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # A2: Validation du mot de passe
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères", "danger")
            return render_template("register.html")

        if len(username) < 3:
            flash("L'identifiant doit contenir au moins 3 caractères", "danger")
            return render_template("register.html")

        users = load_users()
        if username in users:
            flash("Identifiant déjà existant", "danger")
            return render_template("register.html")

        users[username] = bcrypt.generate_password_hash(password).decode("utf-8")
        save_users(users)

        flash("Compte ajouté avec succès", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/admin", methods=["GET"])
def admin():
    """A1: Vérification admin avec méthode sécurisée"""
    if not ADMIN_TOKEN:
        return "ADMIN_TOKEN not set", 500
    if not is_admin_request():
        # A1: Retourner 403 Forbidden, pas 401
        return "Token invalide", 403
    return render_template("admin.html")


@app.route("/admin/reset", methods=["POST"])
def admin_reset():
    if not is_admin_request():
        return "Unauthorized", 401
    save_users({})
    return "OK", 200


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    if not is_admin_request():
        return "Unauthorized", 401

    username = request.form.get("username", "").strip()
    if not username:
        return "Missing username", 400

    users = load_users()
    if username not in users:
        return "Not found", 404

    users.pop(username)
    save_users(users)
    return "OK", 200

@app.route("/dashboard")
@login_required
def dashboard():
    """A1: Page de bienvenue sécurisée, accessible uniquement si connecté"""
    # A7: Utiliser le username depuis la session, pas depuis les paramètres
    username = session.get('username')
    return render_template("success.html", username=username)

@app.route("/logout")
def logout():
    """A1: Détruire la session lors de la déconnexion"""
    session.clear()
    flash("Vous êtes déconnecté", "info")
    return redirect(url_for("login"))

# Security headers: protection contre le clickjacking
@app.after_request
def set_security_headers(response):
    # Empêche l'inclusion de l'application dans un <frame> externe
    # X-Frame-Options: DENY est un moyen simple et supporté par la plupart des navigateurs
    response.headers.setdefault("X-Frame-Options", "DENY")

    # Content-Security-Policy: utilisez frame-ancestors 'none' pour bloquer l'encadrement
    csp_frame = "frame-ancestors 'none';"
    existing_csp = response.headers.get("Content-Security-Policy")
    if existing_csp:
        if "frame-ancestors" not in existing_csp:
            response.headers["Content-Security-Policy"] = existing_csp + " " + csp_frame
    else:
        response.headers["Content-Security-Policy"] = csp_frame

    return response

if __name__ == "__main__":
    app.run(debug=True)