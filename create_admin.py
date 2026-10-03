import getpass
from argon2 import PasswordHasher
from db import get_db

ph = PasswordHasher()

def create_admin():
    username = input("Nom d'utilisateur admin : ").strip()
    email = input("Email admin : ").strip()
    password = getpass.getpass("Mot de passe admin : ")
    confirm = getpass.getpass("Confirmer le mot de passe : ")

    if password != confirm:
        print("Erreur : les mots de passe ne correspondent pas.")
        return

    if len(password) < 12:
        print("Erreur : le mot de passe doit contenir au moins 12 caractères.")
        return

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        print("Erreur : cet utilisateur ou cet email existe déjà.")
        db.close()
        return

    password_hash = ph.hash(password)
    db.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
        (username, email, password_hash),
    )
    db.commit()
    db.close()
    print(f"Compte administrateur '{username}' créé avec succès.")

if __name__ == "__main__":
    create_admin()