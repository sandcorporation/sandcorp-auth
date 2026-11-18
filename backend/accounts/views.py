"""Owner login: password → (TOTP setup | TOTP code) → Django login → `next`."""

import math
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_http_methods, require_POST

from accounts.models import ExternalIdentity
from accounts.session import NEXT_KEY, PENDING_USER_KEY, pending_user, safe_next
from accounts.social_views import social_buttons
from core.http import client_ip
from services import audit
from services.login import (
    check_password_step,
    check_totp_enrollment,
    check_totp_step,
    login_blocked,
    login_failed,
    login_succeeded,
)
from services.step_up import is_weak_owner_session, mark_strong
from services.totp import enrollment_device, is_enrolled, provisioning_uri, qr_svg, secret_of

BACKEND = "django.contrib.auth.backends.ModelBackend"


def _locked_message(seconds: int) -> str:
    when = f"{seconds}초" if seconds < 120 else f"약 {math.ceil(seconds / 60)}분"
    return f"로그인 시도가 너무 많습니다. {when} 뒤 다시 시도하세요."


def _finish(request: HttpRequest, user: User, *, enrolled_now: bool = False) -> HttpResponse:
    login_succeeded(user, client_ip(request), enrolled_now=enrolled_now)
    target = request.session.get(NEXT_KEY)
    login(request, user, backend=BACKEND)
    mark_strong(request)  # password + TOTP: the admin and owner-only grants open (#100)
    request.session.pop(PENDING_USER_KEY, None)
    request.session.pop(NEXT_KEY, None)
    return redirect(target if isinstance(target, str) else "accounts:home")


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    next_url = safe_next(request, request.POST.get("next") or request.GET.get("next"))
    # A social login session of the owner stays here: password + TOTP again (step-up, #100).
    if (
        request.user.is_authenticated
        and request.method == "GET"
        and not is_weak_owner_session(request)
    ):
        return redirect(next_url or "accounts:home")
    step_up = is_weak_owner_session(request)
    error = None
    username = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        ip = client_ip(request)
        wait = login_blocked(username, ip)
        user = None if wait else check_password_step(username, request.POST.get("password", ""))
        if user is not None:
            logout(request)  # a fresh session for the new attempt
            request.session[PENDING_USER_KEY] = user.pk
            if next_url:
                request.session[NEXT_KEY] = next_url
            if is_enrolled(user):
                return redirect("accounts:login_totp")
            return redirect("accounts:totp_setup")
        if not wait:
            wait = login_failed(audit.LOGIN_PASSWORD_FAILED, username, ip, "password")
        error = _locked_message(wait) if wait else "아이디 또는 비밀번호가 맞지 않습니다."
    context = {
        "error": error,
        "username": username,
        "next": next_url or "",
        "step_up": step_up,
        "social": [] if step_up else social_buttons(next_url),
    }
    return render(request, "accounts/login.html", context)


@require_http_methods(["GET", "POST"])
def login_totp_view(request: HttpRequest) -> HttpResponse:
    user = pending_user(request)
    if user is None or not is_enrolled(user):
        return redirect("accounts:login")
    error = None
    if request.method == "POST":
        username, ip = user.get_username(), client_ip(request)
        wait = login_blocked(username, ip)
        if not wait and check_totp_step(user, request.POST.get("code", "")):
            return _finish(request, user)
        if not wait:
            wait = login_failed(audit.LOGIN_TOTP_FAILED, username, ip, "totp")
        error = (
            _locked_message(wait)
            if wait
            else "인증 코드가 맞지 않습니다. 앱에 새로 뜬 코드를 넣어 주세요."
        )
    return render(request, "accounts/login_totp.html", {"error": error})


@require_http_methods(["GET", "POST"])
def totp_setup_view(request: HttpRequest) -> HttpResponse:
    user = pending_user(request)
    if user is None or is_enrolled(user):
        return redirect("accounts:login")
    device = enrollment_device(user)
    error = None
    if request.method == "POST":
        username, ip = user.get_username(), client_ip(request)
        wait = login_blocked(username, ip)
        if not wait and check_totp_enrollment(user, request.POST.get("code", "")):
            return _finish(request, user, enrolled_now=True)
        if not wait:
            wait = login_failed(audit.LOGIN_TOTP_FAILED, username, ip, "enrollment")
        error = (
            _locked_message(wait)
            if wait
            else "인증 코드가 맞지 않습니다. 시계가 맞는지 확인하고 새 코드를 넣어 주세요."
        )
    uri = provisioning_uri(device)
    context = {
        "error": error,
        "qr_svg": mark_safe(qr_svg(uri)),  # our own generated SVG, no user input
        "secret": secret_of(device),
        "username": user.get_username(),
    }
    return render(request, "accounts/totp_setup.html", context)


@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        audit.record(audit.LOGOUT, actor=request.user.get_username(), ip=client_ip(request))
    logout(request)
    target = request.POST.get("next", "")
    # Internal paths only: "/x" yes, "//host" and "/\\host" no.
    if target.startswith("/") and not target.startswith(("//", "/\\")):
        return redirect(target)
    return redirect("accounts:login")


@login_required
def home_view(request: HttpRequest) -> HttpResponse:
    return render(request, "accounts/home.html", {"admin_path": "/" + settings.ADMIN_PATH})


def _mask_email(email: str) -> str:
    """`ab***@example.com`: keep the first two characters of the local part."""
    local, at, domain = email.partition("@")
    if not at:
        return ""
    return local[:2] + "***" + at + domain


def admin_login_redirect(request: HttpRequest) -> HttpResponse:
    """Replaces the Django admin login screen with this service's login. A signed-in member
    is not staff: /login would send it straight back (a redirect loop), so show a 403 page whose
    button ends the member session and goes to /login (#95)."""
    admin_path = "/" + settings.ADMIN_PATH
    if request.user.is_authenticated:
        user = request.user
        if user.is_staff:
            return redirect(admin_path)
        who = ""
        if isinstance(user, User):
            identity = user.identities.order_by("id").first()
            who = _mask_email(user.email) or (
                ExternalIdentity.Provider(identity.provider).label if identity else ""
            )
        context = {"who": who, "relogin_next": "/login?" + urlencode({"next": admin_path})}
        return render(request, "accounts/admin_forbidden.html", context, status=403)
    next_url = safe_next(request, request.GET.get("next")) or admin_path
    return redirect("/login?" + urlencode({"next": next_url}))


def csrf_failure(request: HttpRequest, reason: str = "") -> HttpResponse:
    """`CSRF_FAILURE_VIEW`: a page-expired screen; retry is a plain GET of the same path."""
    path = request.path
    retry = path if path.startswith("/") and not path.startswith(("//", "/\\")) else "/"
    return render(request, "accounts/csrf_failed.html", {"retry": retry}, status=403)


def forbidden(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    """`handler403`: no bare "Forbidden" (an owner on a member-only screen, etc.)."""
    return render(request, "accounts/forbidden.html", status=403)
