import os
import sys
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Clé maîtresse AES-256 (32 octets), encodée en base64 dans la variable d'environnement.
# Générée une seule fois avec :
#   python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
_MASTER_KEY_B64 = os.environ.get("SECUREVAULT_MASTER_KEY")

if not _MASTER_KEY_B64:
    sys.exit(
        "ERREUR FATALE: la variable d'environnement SECUREVAULT_MASTER_KEY "
        "n'est pas définie.\n"
        "Générez une clé avec :\n"
        "  python -c \"import os,base64; print(base64.b64encode(os.urandom(32)).decode())\"\n"
        "puis définissez-la avant de lancer l'application, par exemple :\n"
        "  $env:SECUREVAULT_MASTER_KEY = \"votre_cle_generee\"   (PowerShell)\n"
        "L'application refuse de démarrer sans cette clé, afin d'éviter"
        " tout usage accidentel d'une clé par défaut non sécurisée."
    )

try:
    MASTER_KEY = base64.b64decode(_MASTER_KEY_B64, validate=True)
except Exception:
    sys.exit("ERREUR FATALE: SECUREVAULT_MASTER_KEY n'est pas une chaîne base64 valide.")

if len(MASTER_KEY) != 32:
    sys.exit(
        f"ERREUR FATALE: SECUREVAULT_MASTER_KEY doit décoder vers exactement "
        f"32 octets (AES-256), {len(MASTER_KEY)} octet(s) obtenu(s)."
    )

# Clé HMAC dérivée séparément de la clé de chiffrement, pour une défense en
# profondeur indépendante de l'authentification intégrée à AES-GCM.
HMAC_KEY = hashlib.sha256(MASTER_KEY + b"-hmac").digest()


def encrypt_note(plaintext: str) -> tuple[bytes, bytes]:
    """Chiffre le contenu d'une note avec AES-256-GCM.
    Retourne (contenu_chiffré, nonce)."""
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)  # nonce de 96 bits, recommandé pour GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return ciphertext, nonce


def decrypt_note(ciphertext: bytes, nonce: bytes) -> str:
    """Déchiffre le contenu d'une note. Lève une exception si l'intégrité
    AEAD est compromise (donnée altérée ou mauvaise clé)."""
    aesgcm = AESGCM(MASTER_KEY)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def compute_hmac(ciphertext: bytes, nonce: bytes) -> str:
    """Calcule un HMAC-SHA256 sur (nonce + contenu chiffré), pour une
    seconde couche d'intégrité, indépendante de l'authentification GCM."""
    mac = hmac.new(HMAC_KEY, nonce + ciphertext, hashlib.sha256)
    return mac.hexdigest()


def verify_hmac(ciphertext: bytes, nonce: bytes, expected_hmac: str) -> bool:
    """Vérifie le HMAC en temps constant (évite les attaques par timing)."""
    computed = compute_hmac(ciphertext, nonce)
    return hmac.compare_digest(computed, expected_hmac)