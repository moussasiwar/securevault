from db import get_db
from crypto_utils import encrypt_note, decrypt_note, compute_hmac, verify_hmac
from auth import log_action


def create_note(owner_id: int, title: str, content: str):
    ciphertext, nonce = encrypt_note(content)
    mac = compute_hmac(ciphertext, nonce)

    db = get_db()
    try:
        db.execute(
            "INSERT INTO notes (owner_id, title, content_enc, nonce, hmac) "
            "VALUES (?, ?, ?, ?, ?)",
            (owner_id, title, ciphertext, nonce, mac),
        )
        db.commit()
        log_action(db, owner_id, "NOTE_CREATED", f"Titre: {title}")
    finally:
        db.close()


def list_notes(owner_id: int):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, title, created_at FROM notes WHERE owner_id = ? ORDER BY created_at DESC",
            (owner_id,),
        ).fetchall()
        return rows
    finally:
        db.close()


def get_note(note_id: int, owner_id: int):
    """Retourne la note déchiffrée, uniquement si elle appartient à owner_id.
    C'est ici que le contrôle d'accès (IDOR) est appliqué."""
    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
            (note_id, owner_id),
        ).fetchone()

        if row is None:
            # Soit la note n'existe pas, soit elle appartient à quelqu'un d'autre.
            # Même réponse dans les deux cas : on ne révèle jamais l'existence
            # d'une ressource appartenant à un autre utilisateur.
            log_action(db, owner_id, "NOTE_ACCESS_DENIED", f"note_id={note_id}")
            return None

        if not verify_hmac(row["content_enc"], row["nonce"], row["hmac"]):
            log_action(db, owner_id, "NOTE_INTEGRITY_FAIL", f"note_id={note_id}")
            return None  # intégrité compromise : on refuse d'afficher

        content = decrypt_note(row["content_enc"], row["nonce"])
        log_action(db, owner_id, "NOTE_VIEWED", f"note_id={note_id}")
        return {"id": row["id"], "title": row["title"], "content": content,
                "created_at": row["created_at"]}
    finally:
        db.close()


def update_note(note_id: int, owner_id: int, title: str, content: str) -> bool:
    db = get_db()
    try:
        existing = db.execute(
            "SELECT id FROM notes WHERE id = ? AND owner_id = ?",
            (note_id, owner_id),
        ).fetchone()
        if existing is None:
            return False

        ciphertext, nonce = encrypt_note(content)
        mac = compute_hmac(ciphertext, nonce)
        db.execute(
            "UPDATE notes SET title = ?, content_enc = ?, nonce = ?, hmac = ? WHERE id = ?",
            (title, ciphertext, nonce, mac, note_id),
        )
        db.commit()
        log_action(db, owner_id, "NOTE_UPDATED", f"note_id={note_id}")
        return True
    finally:
        db.close()


def delete_note(note_id: int, owner_id: int) -> bool:
    db = get_db()
    try:
        cur = db.execute(
            "DELETE FROM notes WHERE id = ? AND owner_id = ?",
            (note_id, owner_id),
        )
        db.commit()
        if cur.rowcount > 0:
            log_action(db, owner_id, "NOTE_DELETED", f"note_id={note_id}")
            return True
        return False
    finally:
        db.close()