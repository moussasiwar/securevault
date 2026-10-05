from db import get_db
from auth import log_action


def list_users():
    db = get_db()
    try:
        return db.execute(
            "SELECT id, username, email, role, is_active, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    finally:
        db.close()


def set_user_active(admin_id: int, user_id: int, active: bool):
    db = get_db()
    try:
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id))
        if not active:
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))  # déconnexion forcée
        db.commit()
        log_action(db, admin_id, "ADMIN_SET_ACTIVE", f"user_id={user_id}, active={active}")
    finally:
        db.close()


def set_user_role(admin_id: int, user_id: int, role: str):
    if role not in ("user", "admin"):
        return False
    db = get_db()
    try:
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        db.commit()
        log_action(db, admin_id, "ADMIN_SET_ROLE", f"user_id={user_id}, role={role}")
        return True
    finally:
        db.close()


def list_audit_logs(limit: int = 100):
    db = get_db()
    try:
        return db.execute(
            """SELECT a.id, a.action, a.details, a.ip_address, a.created_at, u.username
               FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
               ORDER BY a.created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    finally:
        db.close()