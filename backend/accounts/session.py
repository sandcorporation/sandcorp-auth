"""The "half-authenticated" session state: password passed, TOTP not yet.

Django `login()` is called only after TOTP, so for a password login `request.user.is_authenticated`
means both steps. The owner may also sign in with a linked social login (#100): whether the
session passed password + TOTP is `services.step_up.has_strong_auth`.
"""

import inspect
from collections.abc import Callable
from typing import Final
from urllib.parse import urlsplit

from django.contrib.auth.models import User
from django.http import HttpRequest
from django.urls import Resolver404, resolve
from django.utils.http import url_has_allowed_host_and_scheme

OWNER_ENROLLMENT_NOTICE = (
    "대표 계정은 비밀번호와 OTP 등록을 먼저 마쳐야 합니다. 비밀번호로 로그인해 OTP를 등록해 주세요."
)
PENDING_USER_KEY = "accounts.pending_user_id"
NEXT_KEY = "accounts.next"
# Views that answer POST only without a `require_POST` wrapper to see: the admin's logout runs
# Django's `LogoutView` (POST only) inside a plain `AdminSite.logout` method (#145).
POST_ONLY_VIEW_NAMES: Final = frozenset({"admin:logout"})


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


def same_origin_referer(request: HttpRequest) -> str | None:
    """The path and query of the Referer when it is this site (same scheme and host)."""
    referer = urlsplit(request.headers.get("referer", ""))
    if referer.scheme != request.scheme or referer.netloc != request.get_host():
        return None
    return safe_next(request, referer.path + (f"?{referer.query}" if referer.query else ""))


def allows_get(path: str) -> bool:
    """Whether the view at `path` answers GET: False for an unknown path, a view behind
    `require_POST` (or `require_http_methods` without GET), a class view without `get`, or one
    of `POST_ONLY_VIEW_NAMES`."""
    try:
        match = resolve(path)
    except Resolver404:
        return False
    if match.view_name in POST_ONLY_VIEW_NAMES:
        return False
    view: object = match.func
    view_class = getattr(view, "view_class", None)
    if view_class is not None:
        return "get" in view_class.http_method_names and hasattr(view_class, "get")
    while callable(view):
        methods = _allowed_methods(view)
        if methods is not None:
            return "GET" in methods
        view = getattr(view, "__wrapped__", None)
    return True


def _allowed_methods(view: Callable[..., object]) -> list[str] | None:
    """`request_method_list` of a `django.views.decorators.http.require_http_methods` wrapper."""
    try:
        methods = inspect.getclosurevars(view).nonlocals.get("request_method_list")
    except TypeError:  # a builtin or a callable object, not a plain function
        return None
    return methods if isinstance(methods, list) else None
