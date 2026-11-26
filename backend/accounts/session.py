"""The "half-authenticated" session state: password passed, TOTP not yet.

Django `login()` is called only after TOTP, so for a password login `request.user.is_authenticated`
means both steps. The owner may also sign in with a linked social login (#100): whether the
session passed password + TOTP is `services.step_up.has_strong_auth`.
"""

from django.contrib.auth.models import User
from django.http import HttpRequest
from django.utils.http import url_has_allowed_host_and_scheme

OWNER_ENROLLMENT_NOTICE = (
    "대표 계정은 비밀번호와 OTP 등록을 먼저 마쳐야 합니다. 비밀번호로 로그인해 OTP를 등록해 주세요."
)
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
