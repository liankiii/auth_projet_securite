from flask import Flask, render_template, request, redirect, flash, url_for
from flask_bcrypt import Bcrypt
import re
from pathlib import Path
import json
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "cle_super_secrete"

bcrypt = Bcrypt(app)
USERS_FILE = Path(__file__).with_name("users.json")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

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
    if not ADMIN_TOKEN:
        return False
    token = request.args.get("token") or request.headers.get("X-Admin-Token")
    return token == ADMIN_TOKEN
    
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        users = load_users()
        stored_hash = users.get(username)

        if stored_hash and bcrypt.check_password_hash(stored_hash, password):
            flash("Vous êtes connecté", "success")
            return render_template("success.html", username=username)
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
        
        username = request.form["username"].strip()
        if not is_valid_username(username):
            flash("Identifiant invalide, utilisez uniquement des lettres, chiffres et underscores", "danger")
            return redirect(url_for("login"))

        password = request.form["password"]
        if not is_valid_password(password):
            flash("Mot de passe invalide, il doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial", "danger")
            return redirect(url_for("login"))

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
    if not ADMIN_TOKEN:
        return "ADMIN_TOKEN not set"
    token = request.args.get("token") or request.headers.get("X-Admin-Token")
    if token == ADMIN_TOKEN:
        return render_template("admin.html")
    else:
        return "Token invalide"


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

@app.route("/logout")
def logout():
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