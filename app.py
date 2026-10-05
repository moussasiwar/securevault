import os
from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from auth import create_reset_token, reset_password
from notes import create_note, list_notes, get_note, update_note, delete_note
from decorators import role_required
from admin import list_users, set_user_active, set_user_role, list_audit_logs
from flask import Flask, request, session, redirect, url_for, render_template, flash, abort
from notes import create_note, list_notes, get_note, update_note, delete_note
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


@app.route("/notes")
@login_required
def notes_list():
    user = get_session_user(session.get("sid"))
    notes = list_notes(user["id"])
    return render_template("notes_list.html", notes=notes, user=user)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def notes_new():
    user = get_session_user(session.get("sid"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            flash("Titre et contenu requis.")
            return render_template("note_form.html", user=user)
        create_note(user["id"], title, content)
        return redirect(url_for("notes_list"))
    return render_template("note_form.html", user=user)


@app.route("/notes/<int:note_id>")
@login_required
def notes_view(note_id):
    user = get_session_user(session.get("sid"))
    note = get_note(note_id, user["id"])
    if note is None:
        abort(404)
    return render_template("note_view.html", note=note, user=user)


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def notes_edit(note_id):
    user = get_session_user(session.get("sid"))
    note = get_note(note_id, user["id"])
    if note is None:
        abort(404)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        update_note(note_id, user["id"], title, content)
        return redirect(url_for("notes_view", note_id=note_id))
    return render_template("note_form.html", note=note, user=user)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def notes_delete(note_id):
    user = get_session_user(session.get("sid"))
    delete_note(note_id, user["id"])
    return redirect(url_for("notes_list"))


@app.route("/admin/users")
@role_required("admin")
def admin_users():
    user = get_session_user(session.get("sid"))
    users = list_users()
    return render_template("admin_users.html", users=users, user=user)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@role_required("admin")
def admin_toggle_user(user_id):
    admin = get_session_user(session.get("sid"))
    if user_id == admin["id"]:
        flash("Vous ne pouvez pas désactiver votre propre compte.")
        return redirect(url_for("admin_users"))
    users = {u["id"]: u for u in list_users()}
    target = users.get(user_id)
    if target:
        set_user_active(admin["id"], user_id, not target["is_active"])
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def admin_change_role(user_id):
    admin = get_session_user(session.get("sid"))
    new_role = request.form.get("role")
    if user_id == admin["id"]:
        flash("Vous ne pouvez pas modifier votre propre rôle.")
        return redirect(url_for("admin_users"))
    set_user_role(admin["id"], user_id, new_role)
    return redirect(url_for("admin_users"))


@app.route("/admin/logs")
@role_required("admin")
def admin_logs():
    user = get_session_user(session.get("sid"))
    logs = list_audit_logs()
    return render_template("admin_logs.html", logs=logs, user=user)

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=("securevault.local.pem", "securevault.local-key.pem")
    )