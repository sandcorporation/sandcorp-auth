"""Settings for pytest: the production settings with throwaway secret and encryption keys."""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("SIGNING_KEY_ENCRYPTION_KEY", "dGVzdC1vbmx5LXNpZ25pbmcta2V5LWVuY3J5cHRpb24=")
os.environ.setdefault("TRUST_X_FORWARDED_FOR", "0")
os.environ.setdefault("SITE_URL", "https://auth.sandcorp.co.kr")

from config.settings import *  # noqa: E402, F403
