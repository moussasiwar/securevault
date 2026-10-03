import os
from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from auth import create_reset_token, reset_password

from auth import register_user, authenticate_user, destroy_session, get_session_user, validate_password, validate_email
from decorators import login_required

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=1800,
)

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day"])


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


@app.route("/")
def index():
    return redirect(url_for("dashboard")) if session.get("sid") else redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not validate_email(email):
            flash("Nom d'utilisateur ou email invalide.")
            return render_template("register.html")

        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.")
            return render_template("register.html")

        error = validate_password(password)
        if error:
            flash(error)
            return render_template("register.html")

        ok, message = register_user(username, email, password)
        flash(message)
        if ok:
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user, error = authenticate_user(username, password, request.remote_addr)

        if error:
            flash(error)
            return render_template("login.html")

        session.clear()
        session["sid"] = user["session_id"]
        session.permanent = True
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    destroy_session(session.get("sid"))
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    reset_link = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        token = create_reset_token(email)
        # Message identique que l'email existe ou non
        flash("Si cet email existe, un lien de réinitialisation a été généré.")
        if token:
            # Pour un projet local sans serveur mail : afficher le lien directement
            reset_link = url_for("reset_password_view", token=token, _external=True)
    return render_template("forgot_password.html", reset_link=reset_link)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_view(token):
    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if new_password != confirm:
            flash("Les mots de passe ne correspondent pas.")
            return render_template("reset_password.html", token=token)
        ok, message = reset_password(token, new_password)
        flash(message)
        if ok:
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_session_user(session.get("sid"))
    return render_template("dashboard.html", user=user)


if __name__ == "__main__":
    app.run(ssl_context="adhoc")