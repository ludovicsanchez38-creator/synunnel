"""Primitives de la double authentification et des jetons de récupération.

Aucune dépendance à Flask : ces fonctions ne voient ni la base ni la requête, les règles
d'usage (consommation unique, versions de justificatifs, limites) vivent dans `account.py`.
"""

import base64
import hashlib
import hmac
import re
import secrets
import struct
from urllib.parse import quote

import segno
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1  # un pas avant ou après le pas courant : tolérance d'horloge du téléphone
SECRET_BYTES = 20  # 160 bits, taille recommandée par la RFC 4226 pour HMAC-SHA1
RECOVERY_CODES = 10
RECOVERY_LENGTH = 20  # caractères base32, soit 100 bits
CODE_RE = re.compile(r"[0-9]{6}", re.ASCII)
RECOVERY_RE = re.compile(r"[A-Z2-7]{20}", re.ASCII)
_ENC_PREFIX = "v1:"


class SecretUnavailable(Exception):
    """Secret chiffré illisible (clé absente, changée ou donnée altérée) : refus fermé."""


def parse_key(value: str) -> bytes:
    """Clé de chiffrement des secrets TOTP : 32 octets écrits en 64 caractères hexadécimaux."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value or ""):
        raise ValueError("TOTP_KEY doit contenir 64 caractères hexadécimaux (32 octets aléatoires).")
    return bytes.fromhex(value)


def encrypt_secret(key: bytes, user_id: int, secret: bytes) -> str:
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(key).encrypt(nonce, secret, f"user:{user_id}".encode())
    return _ENC_PREFIX + base64.b64encode(nonce + sealed).decode()


def decrypt_secret(key: bytes, user_id: int, value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith(_ENC_PREFIX):
        raise SecretUnavailable("format inconnu")
    try:
        raw = base64.b64decode(value[len(_ENC_PREFIX):], validate=True)
        return AESGCM(key).decrypt(raw[:12], raw[12:], f"user:{user_id}".encode())
    except (ValueError, InvalidTag) as exc:
        raise SecretUnavailable("déchiffrement impossible") from exc


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def secret_base32(secret: bytes) -> str:
    return base64.b32encode(secret).decode().rstrip("=")


def code_at(secret: bytes, step: int) -> str:
    """HOTP (RFC 4226) au compteur `step` : c'est le TOTP de la RFC 6238 pour ce pas."""
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def current_step(now: float) -> int:
    return int(now) // STEP_SECONDS


def matching_step(secret: bytes, code: str, now: float) -> int | None:
    """Pas reconnu pour ce code, dans la fenêtre ±1. Le pas reconnu (pas le pas courant) est
    celui qu'il faut consommer : un code du pas suivant ne doit plus jamais repasser."""
    if not isinstance(code, str) or not CODE_RE.fullmatch(code):
        return None
    found = None
    center = current_step(now)
    for step in range(center - WINDOW, center + WINDOW + 1):
        # Toutes les comparaisons sont faites : aucun court-circuit selon la position du pas.
        if hmac.compare_digest(code_at(secret, step), code) and found is None:
            found = step
    return found


def otpauth_uri(secret: bytes, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}", safe="@:")
    return (f"otpauth://totp/{label}?secret={secret_base32(secret)}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")


def qr_svg(uri: str) -> str:
    """QR code en SVG inline, généré ici : aucune image externe, aucune relâche de la CSP."""
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#0F172A", light="#FFFFFF", border=2)


def new_recovery_codes() -> list[str]:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return ["".join(secrets.choice(alphabet) for _ in range(RECOVERY_LENGTH)) for _ in range(RECOVERY_CODES)]


def format_recovery(code: str) -> str:
    return "-".join(code[i:i + 5] for i in range(0, len(code), 5))


def normalize_recovery(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.replace("-", "").replace(" ", "").upper()
    return text if RECOVERY_RE.fullmatch(text) else None


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token() -> str:
    """Jeton de réinitialisation, de vérification ou de challenge : 256 bits."""
    return secrets.token_urlsafe(32)
