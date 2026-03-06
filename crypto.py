# api/crypto.py — Misma lógica de encriptación que la app de escritorio
import base64
import os
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_cipher(master_password: str, salt_hex: str) -> Fernet:
    """Genera el cipher Fernet — idéntico al de database.py."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(salt_hex),
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))
    return Fernet(key)


def encrypt_password(plain: str, master_password: str, salt_hex: str) -> str:
    cipher = get_cipher(master_password, salt_hex)
    return cipher.encrypt(plain.encode()).decode()


def decrypt_password(encrypted: str, master_password: str, salt_hex: str) -> str:
    cipher = get_cipher(master_password, salt_hex)
    return cipher.decrypt(encrypted.encode()).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def generate_salt() -> str:
    return os.urandom(16).hex()
