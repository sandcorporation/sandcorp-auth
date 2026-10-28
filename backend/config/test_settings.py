"""Settings for pytest: the production settings with throwaway secret and encryption keys."""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("SIGNING_KEY_ENCRYPTION_KEY", "dGVzdC1vbmx5LXNpZ25pbmcta2V5LWVuY3J5cHRpb24=")
os.environ.setdefault("TRUST_X_FORWARDED_FOR", "0")
os.environ.setdefault("SITE_URL", "https://auth.sandcorp.co.kr")
# `make db` (docker-compose.yml): local MySQL on 15444.
os.environ.setdefault("DB_PORT", "15444")
# Social login providers on, answered by the autouse `fake_providers` fixture (never the real ones).
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client.apps.googleusercontent.com")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-google-secret")
os.environ.setdefault("KAKAO_CLIENT_ID", "test-kakao-rest-api-key")
os.environ.setdefault("KAKAO_CLIENT_SECRET", "test-kakao-secret")

from config.settings import *  # noqa: E402, F403

# Fast password hashing for tests only (PBKDF2 dominated the suite). Production keeps Django's
# default; tests/test_settings_guard.py pins that.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
