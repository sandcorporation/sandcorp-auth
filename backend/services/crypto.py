"""Secrets at rest: Fernet under `settings.SIGNING_KEY_ENCRYPTION_KEY`.

One key encrypts every stored secret (signing private keys, TOTP secrets).
"""

from cryptography.fernet import Fernet
from django.conf import settings


def _fernet() -> Fernet:
    return Fernet(settings.SIGNING_KEY_ENCRYPTION_KEY)


def encrypt_secret(raw: bytes) -> bytes:
    return _fernet().encrypt(raw)


def decrypt_secret(token: bytes) -> bytes:
    return _fernet().decrypt(token)
