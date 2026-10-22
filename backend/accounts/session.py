"""The "half-authenticated" session state: password passed, TOTP not yet.

Django `login()` is called only after TOTP, so `request.user.is_authenticated` means both steps.
"""

from django.contrib.auth.models import User
from django.http import HttpRequest
from django.utils.http import url_has_allowed_host_and_scheme

PENDING_USER_KEY = "accounts.pending_user_id"
NEXT_KEY = "accounts.next"


def pending_user(request: HttpRequest) -> User | None:
    user_id = request.session.get(PENDING_USER_KEY)
    if not isinstance(user_id, int):
        return None
    return User.objects.filter(pk=user_id, is_active=True).first()


def safe_next(request: HttpRequest, candidate: str | None) -> str | None:
    """`candidate` if it is a relative path on this host, else None."""
    if not candidate or not candidate.startswith("/") or candidate.startswith("//"):
        return None
    if not url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return None
    return candidate
