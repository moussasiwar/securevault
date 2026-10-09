import re
import time
import secrets
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from db import get_db

ph = PasswordHasher()  # Argon2id par défaut

SESSION_DURATION_MINUTES = 20
MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION_MINUTES = 15


# ---------- Validation ----------

def validate_password(password: str) -> str | None:
    """Retourne un message d'erreur si le mot de passe est trop faible, sinon None."""
    if len(password) < 12:
        return "Le mot de passe doit contenir au moins 12 caractères."
    if not re.search(r"[A-Z]", password):
        return "Le mot de passe doit contenir au moins une majuscule."
    if not re.search(r"[a-z]", password):
        return "Le mot de passe doit contenir au moins une minuscule."
    if not re.search(r"[0-9]", password):
        return "Le mot de passe doit contenir au moins un chiffre."
    return None


def validate_email(email: str) -> bool:
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


# ---------- Inscription ----------

def register_user(username: str, email: str, password: str):
    db = get_db()
    try:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if existing:
            return False, "Ce nom d'utilisateur ou cet email est déjà utilisé."

        password_hash = ph.hash(password)
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        db.commit()
        log_action(db, None, "REGISTER_OK", f"Nouvel utilisateur: {username}")
        return True, "Compte créé avec succès."
    finally:
        db.close()


# ---------- Connexion ----------

def authenticate_user(username: str, password: str, ip: str = ""):
    db = get_db()
    try:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        generic_error = "Identifiants invalides."

        if user is None:
            log_action(db, None, "LOGIN_FAIL", f"Utilisateur inconnu: {username}", ip)
            return None, generic_error

        # Verrouillage : meme message generique, mais log distinct en interne
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now() < locked_until:
                log_action(db, user["id"], "LOGIN_LOCKED", "Tentative sur compte verrouillé", ip)
                return None, generic_error  # <- plus de message distinct

        if not user["is_active"]:
            log_action(db, user["id"], "LOGIN_DISABLED", "Compte désactivé", ip)
            return None, generic_error

        try:
            ph.verify(user["password_hash"], password)
        except VerifyMismatchError:
            _register_failed_attempt(db, user)
            log_action(db, user["id"], "LOGIN_FAIL", "Mot de passe incorrect", ip)
            return None, generic_error

        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        session_id = create_session(db, user["id"], ip)
        log_action(db, user["id"], "LOGIN_OK", "Connexion réussie", ip)
        db.commit()
        return {"id": user["id"], "username": user["username"], "role": user["role"],
                "session_id": session_id}, None
    finally:
        db.close()


def _register_failed_attempt(db, user):
    attempts = user["failed_attempts"] + 1
    locked_until = None
    if attempts >= MAX_FAILED_ATTEMPTS:
        locked_until = (datetime.now() + timedelta(minutes=LOCK_DURATION_MINUTES)).isoformat()
    db.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (attempts, locked_until, user["id"]),
    )
    db.commit()

    # Delai progressif : 0.5s, 1s, 1.5s, 2s... plafonne a 3s
    delay = min(attempts * 0.5, 3.0)
    time.sleep(delay)


# ---------- Sessions ----------

def create_session(db, user_id: int, ip: str = "") -> str:
    session_id = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(minutes=SESSION_DURATION_MINUTES)).isoformat()
    db.execute(
        "INSERT INTO sessions (id, user_id, expires_at, ip_address) VALUES (?, ?, ?, ?)",
        (session_id, user_id, expires_at, ip),
    )
    db.commit()
    return session_id


def get_session_user(session_id: str):
    if not session_id:
        return None
    db = get_db()
    try:
        row = db.execute(
            """SELECT s.user_id, s.expires_at, u.username, u.role
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.id = ?""",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            db.commit()
            return None
        return {"id": row["user_id"], "username": row["username"], "role": row["role"]}
    finally:
        db.close()


def destroy_session(session_id: str):
    db = get_db()
    try:
        db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        db.commit()
    finally:
        db.close()


# ---------- Journalisation ----------

def log_action(db, user_id, action: str, details: str = "", ip: str = ""):
    db.execute(
        "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, action, details, ip),
    )
    db.commit()
    
RESET_TOKEN_EXPIRY_MINUTES = 30

def create_reset_token(email: str):
    db = get_db()
    try:
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:
            # Ne pas révéler si l'email existe : on retourne toujours un succès apparent
            return None
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES)).isoformat()
        db.execute(
            "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user["id"], token, expires_at),
        )
        db.commit()
        log_action(db, user["id"], "PASSWORD_RESET_REQUESTED", "Jeton généré")
        return token
    finally:
        db.close()


def verify_reset_token(token: str):
    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM password_resets WHERE token = ? AND used = 0", (token,)
        ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            return None
        return row["user_id"]
    finally:
        db.close()


def reset_password(token: str, new_password: str):
    user_id = verify_reset_token(token)
    if user_id is None:
        return False, "Lien invalide ou expiré."

    error = validate_password(new_password)
    if error:
        return False, error

    db = get_db()
    try:
        password_hash = ph.hash(new_password)
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        db.execute("UPDATE password_resets SET used = 1 WHERE token = ?", (token,))
        # Invalider toutes les sessions actives par sécurité
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        db.commit()
        log_action(db, user_id, "PASSWORD_RESET_OK", "Mot de passe modifié")
        return True, "Mot de passe réinitialisé avec succès. Connectez-vous."
    finally:
        db.close()