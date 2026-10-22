"""Django settings. Every deploy-specific value comes from the environment (see /.env.example)."""

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in env(name, default).split(",") if item.strip()]


DEBUG = env("DJANGO_DEBUG", "0") == "1"
SECRET_KEY = env("DJANGO_SECRET_KEY") or ("dev-insecure-key" if DEBUG else "")
if not SECRET_KEY:
    raise RuntimeError("DJANGO_SECRET_KEY is required when DJANGO_DEBUG is not 1")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
# NPMplus terminates TLS and forwards X-Forwarded-Proto.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "accounts",
    "oauth",
    "audit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "accounts.middleware.TotpEnrollmentMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", "sandcorp_auth"),
        "USER": env("POSTGRES_USER", "sandcorp_auth"),
        "PASSWORD": env("POSTGRES_PASSWORD", "sandcorp_auth"),
        "HOST": env("POSTGRES_HOST", "127.0.0.1"),
        "PORT": env("POSTGRES_PORT", "15444"),
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LANGUAGE_CODE = "ko-kr"
TIME_ZONE = "Asia/Seoul"
USE_I18N = True
USE_TZ = True

# The service's absolute base URL; later the JWT `iss`.
SITE_URL = env("SITE_URL", "https://auth.sandcorp.co.kr").rstrip("/")
# Fernet key that encrypts signing private keys at rest (see /.env.example for how to make one).
SIGNING_KEY_ENCRYPTION_KEY = env("SIGNING_KEY_ENCRYPTION_KEY") or (
    "ZGV2LWluc2VjdXJlLXNpZ25pbmcta2V5LTMyYnl0ZXM=" if DEBUG else ""
)
if not SIGNING_KEY_ENCRYPTION_KEY:
    raise RuntimeError("SIGNING_KEY_ENCRYPTION_KEY is required when DJANGO_DEBUG is not 1")
# Access token lifetime; a rotated-out signing key stays in the JWKS this long.
ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
AUTHORIZATION_CODE_LIFETIME = timedelta(minutes=5)
REFRESH_TOKEN_LIFETIME = timedelta(days=90)

# Owner login (accounts app). Django `login()` happens only after password + TOTP.
LOGIN_URL = "/login"
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]
# Sessions end after SESSION_AGE_SECONDS (default 12 h) or when the browser closes.
SESSION_COOKIE_AGE = int(env("SESSION_AGE_SECONDS", str(12 * 60 * 60)))
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG

# Request limiting (services/throttle.py): per rule name, `limit` failures within
# `window_seconds` block the key for `block_seconds`.
THROTTLE: dict[str, dict[str, int | str]] = {
    # Login failures per IP: 5 in 15 minutes block that address for 15 minutes.
    "login": {"limit": 5, "window_seconds": 15 * 60, "block_seconds": 15 * 60},
    # Dynamic client registration: every request counts, 10 per hour per IP.
    "register": {"limit": 10, "window_seconds": 3600, "block_seconds": 3600},
    # Token endpoint: every request counts, 60 per minute per IP.
    "token": {"limit": 60, "window_seconds": 60, "block_seconds": 60},
    # Login failures per account: no lock (anyone knows the username), only a growing delay
    # of 1, 2, 4 ... up to 60 seconds; forgotten after 15 minutes without a failure.
    "login_account": {"mode": "backoff", "max_delay_seconds": 60, "window_seconds": 15 * 60},
}
# Behind NPMplus the caller's address is the first X-Forwarded-For entry. Set 0 when the app is
# reached directly (then REMOTE_ADDR is used).
TRUST_X_FORWARDED_FOR = env("TRUST_X_FORWARDED_FOR", "1") == "1"

# Django admin lives on a hard-to-guess path in production.
ADMIN_PATH = env("DJANGO_ADMIN_PATH", "admin/").strip("/") + "/"

# Static files: whitenoise serves the collectstatic output (Django admin).
STATIC_URL = "/static/"
STATIC_ROOT = Path(env("DJANGO_STATIC_ROOT", str(BASE_DIR / "staticfiles")))
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": env("DJANGO_LOG_LEVEL", "INFO")},
}
