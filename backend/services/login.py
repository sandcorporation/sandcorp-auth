"""Login decisions, gathered here so request limiting and audit logging (#6) hook in one place.

The views only translate these answers into redirects; they never judge credentials themselves.
"""

from django.contrib.auth import authenticate
from django.contrib.auth.models import User

from services.totp import accept_code, confirmed_device, enrollment_device


def check_password_step(username: str, password: str) -> User | None:
    """First step: the owner whose username and password match, else None."""
    user = authenticate(None, username=username, password=password)
    return user if isinstance(user, User) else None


def check_totp_step(user: User, code: str) -> bool:
    """Second step for an enrolled owner: a fresh, correct TOTP code."""
    device = confirmed_device(user)
    return device is not None and accept_code(device, code)


def check_totp_enrollment(user: User, code: str) -> bool:
    """Enrollment: the first correct code confirms the device (and completes the login)."""
    device = enrollment_device(user)
    return device.confirmed_at is None and accept_code(device, code)
