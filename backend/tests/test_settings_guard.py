"""The fast test hasher must never leak into production settings."""

from config import settings


def test_production_password_hasher_is_pbkdf2() -> None:
    hashers = getattr(settings, "PASSWORD_HASHERS", None)
    assert hashers is None or hashers[0] == "django.contrib.auth.hashers.PBKDF2PasswordHasher"
