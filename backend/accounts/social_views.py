"""Social login screens (#36): start, provider callback, the same-email notice, and the member's
「내 계정」 page (linked social logins, email, connected apps). Rules are in
`services/social.py`; this module only keeps the in-between state in the session and picks
the screen.
"""

from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from accounts.models import ExternalIdentity
from accounts.session import OWNER_ENROLLMENT_NOTICE, safe_next
from adapters.clock import get_clock
from core.http import client_ip
from services import audit, throttle
from services.consents import connected_apps, disconnect_app
from services.login import IP_RULE, locked_message
from services.members import (
    EmailTaken,
    ExternalProfile,
    IdentityTaken,
    InvalidEmail,
    is_member,
    member_email_verified,
    set_member_email,
)
from services.social import (
    ACCOUNT_HOME,
    PENDING_SECONDS,
    IdentityNotFound,
    LastIdentity,
    NotAMember,
    Purpose,
    account_login_next,
    begin,
    complete,
    link_identity,
    may_link,
    pending_signup,
    provider_named,
    providers_with_email,
    read_pending,
    read_pending_signup,
    sign_in,
    social_login_allowed,
    unlink_identity,
)
from services.social_providers import SocialLoginFailed, SocialProvider, configured_providers
from services.step_up import drop_strong, is_weak_owner_session
from services.terms import needs_terms
from services.totp import is_enrolled
from services.withdrawal import CONFIRM_PHRASE, withdraw_member

BACKEND = "django.contrib.auth.backends.ModelBackend"
PENDING_SOCIAL_KEY = "accounts.social_pending"
PENDING_SIGNUP_KEY = "accounts.social_signup"
# Where the login that just finished was headed, kept as long as a pending login lives, so a
# second callback (back button, picking again) lands there instead of on a failure page (#123).
JUST_SIGNED_IN_KEY = "accounts.social_signed_in"
# Where the last pending sign-in was headed, kept 10 minutes after it is taken out, so a
# callback with no pending login (back button after a cancel) still leads to that app's login
# screen (#144). Dropped at the end of a login; a logout flushes the session.
RECENT_NEXT_KEY = "accounts.social_recent_next"
# Provider answers that mean "the person said no", not an attack: no throttle count.
CANCELLED = frozenset({"access_denied", "consent_required", "interaction_required"})


def social_login_target(next_url: str) -> tuple[Purpose, str] | None:
    """The kind of social login a login screen for `next_url` offers, and where it lands:
    sign in (or up) for an app that allows members, sign in to 「내 계정」 with no app (#126),
    or none."""
    if social_login_allowed(next_url):
        return "login", next_url
    account_next = account_login_next(next_url)
    return ("account", account_next) if account_next else None


def social_buttons(next_url: str | None) -> list[dict[str, str]]:
    """Buttons for the login screen (see `social_login_target`)."""
    target = social_login_target(next_url or "")
    if target is None:
        return []
    query = urlencode({"next": target[1]})
    return [
        {"name": p.name, "label": p.label, "url": f"/login/{p.name}?{query}"}
        for p in configured_providers().values()
    ]


def _provider_or_404(name: str) -> SocialProvider:
    provider = provider_named(name)
    if provider is None:
        raise Http404("no such login provider")
    return provider


def _login_url(next_url: str) -> str:
    return "/login?" + urlencode({"next": next_url}) if next_url else "/login"


def _sign_into(request: HttpRequest, user: User, next_url: str) -> HttpResponse:
    request.session.pop(PENDING_SIGNUP_KEY, None)
    if not is_member(user) and not is_enrolled(user):
        # The owner before TOTP enrollment: enrolling needs the password, never a social
        # session. Say so on the login screen instead of signing in and out silently (#110).
        messages.info(request, OWNER_ENROLLMENT_NOTICE)
        return redirect(_login_url(next_url))
    login(request, user, backend=BACKEND)  # also sets last_login, the ID token's auth_time
    drop_strong(request)  # a social login never opens the owner's admin and grants (#100)
    request.session.pop(RECENT_NEXT_KEY, None)
    request.session[JUST_SIGNED_IN_KEY] = _note(next_url)
    if needs_terms(user):  # a new account, or a new version of the terms (#37)
        return (
            redirect("/terms?" + urlencode({"next": next_url})) if next_url else redirect("/terms")
        )
    return redirect(next_url or "accounts:home")


def _note(next_url: str) -> dict[str, str | float]:
    return {"next": next_url, "at": get_clock().now().timestamp()}


def _noted_next(request: HttpRequest, key: str) -> str:
    """The `next` noted under `key` in the last 10 minutes (see `_note`), or ""."""
    note = request.session.get(key)
    if not isinstance(note, dict):
        return ""
    started, target = note.get("at"), note.get("next")
    if not isinstance(started, int | float) or not isinstance(target, str):
        return ""
    age = get_clock().now().timestamp() - started
    if not 0 <= age <= PENDING_SECONDS:
        return ""
    return safe_next(request, target) or ""


def _failed(
    request: HttpRequest,
    provider: str,
    reason: str,
    next_url: str,
    *,
    status: int = 400,
    wait: int = 0,
) -> HttpResponse:
    context = {
        "login_url": _login_url(next_url),
        "reason": reason,
        "status": status,
        "locked_message": locked_message(wait) if wait else "",
    }
    return render(request, "accounts/social_failed.html", context, status=status)


@require_GET
def social_start(request: HttpRequest, provider: str) -> HttpResponse:
    social = _provider_or_404(provider)
    next_url = safe_next(request, request.GET.get("next")) or ""
    if request.user.is_authenticated:
        return redirect(next_url or "accounts:home")
    target = social_login_target(next_url)
    if target is None:
        return redirect(_login_url(next_url))
    purpose, next_url = target
    url, pending = begin(social, purpose, next_url=next_url)
    request.session[PENDING_SOCIAL_KEY] = dict(pending)
    return redirect(url)


@require_GET
def social_callback(request: HttpRequest, provider: str) -> HttpResponse:
    social = _provider_or_404(provider)
    ip = client_ip(request)
    raw = request.session.pop(PENDING_SOCIAL_KEY, None)  # one callback per start
    if raw is None and request.user.is_authenticated:
        # The login already finished (back button, picking again): not a failure (#123).
        # A link flow noted 「내 계정」 when it started (#144).
        return redirect(_noted_next(request, JUST_SIGNED_IN_KEY) or "accounts:home")
    if isinstance(raw, dict):
        next_url = raw.get("next", "")
        next_url = next_url if isinstance(next_url, str) else ""
        if raw.get("purpose") != "link":
            request.session[RECENT_NEXT_KEY] = _note(next_url)
    else:  # no pending login: the one taken out a moment ago, if any (#144)
        next_url = _noted_next(request, RECENT_NEXT_KEY)
    ip_key = f"ip:{ip}"
    wait = throttle.check(IP_RULE, ip_key).retry_after
    if wait:
        audit.record(audit.LOGIN_LOCKED, ip=ip, detail={"refused": True, "provider": provider})
        return _failed(request, provider, "locked", next_url, status=429, wait=wait)
    provider_error = request.GET.get("error", "")
    try:
        pending = read_pending(raw, provider)
        if provider_error:
            raise SocialLoginFailed(
                "cancelled" if provider_error in CANCELLED else "provider_error"
            )
        profile = complete(
            social, pending, state=request.GET.get("state", ""), code=request.GET.get("code", "")
        )
    except SocialLoginFailed as error:
        audit.record(
            audit.SOCIAL_LOGIN_FAILED, ip=ip, detail={"provider": provider, "reason": error.reason}
        )
        if error.reason != "cancelled":
            throttle.hit(IP_RULE, ip_key)
        return _failed(request, provider, error.reason, next_url)

    if pending["purpose"] == "link":
        return _finish_link(request, pending["user_id"], profile, ip)
    try:
        result = sign_in(profile, ip=ip, create=pending["purpose"] != "account")
    except SocialLoginFailed as error:
        audit.record(
            audit.SOCIAL_LOGIN_FAILED, ip=ip, detail={"provider": provider, "reason": error.reason}
        )
        if error.reason == "no_account":
            context = {"login_url": _login_url(pending["next"])}  # withdrawn or never seen
            return render(request, "accounts/social_no_account.html", context)
        return _failed(request, provider, error.reason, next_url, status=403)
    if result.user is None:
        waiting = pending_signup(
            profile, pending["next"], may_create=pending["purpose"] != "account"
        )
        request.session[PENDING_SIGNUP_KEY] = dict(waiting)
        return redirect("accounts:signup_confirm")
    return _sign_into(request, result.user, pending["next"])


def _finish_link(
    request: HttpRequest, user_id: int, profile: ExternalProfile, ip: str
) -> HttpResponse:
    user = request.user
    if not isinstance(user, User) or not user.is_authenticated or user.pk != user_id:
        audit.record(audit.SOCIAL_LOGIN_FAILED, ip=ip, detail={"reason": "link_session_changed"})
        return _failed(request, "", "link_session_changed", "")
    if is_weak_owner_session(request):  # the step-up ran out between start and callback
        return _step_up()
    try:
        linked = link_identity(user, profile, ip=ip)
    except IdentityTaken:
        messages.error(request, "이 로그인은 이미 다른 Sandcorp 계정에 연결되어 있습니다.")
    except NotAMember as error:
        raise PermissionDenied("only members and the owner link social logins") from error
    else:
        label = ExternalIdentity.Provider(profile.provider).label
        if linked:
            messages.success(request, f"{label} 로그인을 연결했습니다.")
        else:
            messages.info(request, f"{label} 로그인은 이미 이 계정에 연결되어 있습니다.")
    return redirect("accounts:account")


@require_http_methods(["GET", "POST"])
def signup_confirm(request: HttpRequest) -> HttpResponse:
    """「이전에 <제공자>로 가입하셨습니다」: sign in with that login, or make a new account."""
    waiting = read_pending_signup(request.session.get(PENDING_SIGNUP_KEY))
    if waiting is None:
        request.session.pop(PENDING_SIGNUP_KEY, None)
        return redirect("accounts:login")
    profile, next_url = waiting.profile, waiting.next
    if request.method == "POST":
        if not waiting.may_create:  # a login without an app makes no account (#135)
            return redirect("accounts:signup_confirm")
        try:
            result = sign_in(profile, ip=client_ip(request), force_new=True)
        except SocialLoginFailed as error:
            return _failed(request, profile.provider, error.reason, next_url, status=403)
        assert result.user is not None
        return _sign_into(request, result.user, next_url)
    query = urlencode({"next": next_url})
    labels = providers_with_email(profile)
    choices = [
        {"name": p.name, "label": p.label, "url": f"/login/{p.name}?{query}"}
        for p in configured_providers().values()
        if p.label in labels
    ]
    choices.sort(key=lambda c: labels.index(c["label"]))  # the order they were linked (#144)
    context = {
        "existing": " · ".join(labels),
        "choices": choices,
        "provider": ExternalIdentity.Provider(profile.provider).label,
        "email": profile.email,
        "may_create": waiting.may_create,
        "login_url": _login_url(next_url),
    }
    return render(request, "accounts/signup_confirm.html", context)


class _StepUp(Exception):
    """The owner without a recent password + TOTP: ask for it, then come back."""


def _holder_or_403(request: HttpRequest) -> User:
    """A member, or the owner after a recent password + TOTP (raises _StepUp otherwise)."""
    user = request.user
    if not isinstance(user, User) or not may_link(user):
        raise PermissionDenied("for members and the owner only")
    if is_weak_owner_session(request):
        raise _StepUp
    return user


def _step_up() -> HttpResponse:
    return redirect("/login?" + urlencode({"next": "/account"}))


def _member_or_403(request: HttpRequest) -> User:
    user = request.user
    if not isinstance(user, User) or not is_member(user):
        raise PermissionDenied("for members only")
    return user


@login_required
@require_GET
def account(request: HttpRequest) -> HttpResponse:
    """「내 계정」: the member's sign-in methods (link / unlink), account email, connected apps
    (disconnect) and the way into withdrawal (#39). The owner (#100) sees only its sign-in
    methods, after a recent password + TOTP."""
    try:
        user = _holder_or_403(request)
    except _StepUp:
        return _step_up()
    is_owner = not is_member(user)
    linked = list(ExternalIdentity.objects.filter(user_id=user.pk).order_by("linked_at", "pk"))
    linked_providers = {identity.provider for identity in linked}
    context = {
        "display_name": user.first_name,
        "email": user.email,
        "email_verified": member_email_verified(user),
        "identities": [
            {"pk": i.pk, "label": i.get_provider_display(), "email": i.email} for i in linked
        ],
        "can_unlink": is_owner or len(linked) > 1,
        "is_owner": is_owner,
        "link_choices": [
            {"name": p.name, "label": p.label}
            for p in configured_providers().values()
            if p.name not in linked_providers
        ],
        "apps": [] if is_owner else connected_apps(user),
    }
    return render(request, "accounts/account.html", context)


@login_required
@require_POST
def set_email(request: HttpRequest) -> HttpResponse:
    user = _member_or_403(request)
    try:
        set_member_email(user, request.POST.get("email", ""), ip=client_ip(request))
    except InvalidEmail:
        messages.error(request, "이메일 주소 형식이 맞지 않습니다.")
    except EmailTaken:
        messages.error(request, "이미 다른 계정에서 쓰는 이메일입니다.")
    else:
        messages.success(request, "이메일을 저장했습니다.")
    return redirect("accounts:account")


@login_required
@require_POST
def disconnect(request: HttpRequest, client_pk: int) -> HttpResponse:
    user = _member_or_403(request)
    if disconnect_app(user, client_pk, ip=client_ip(request)):
        messages.success(request, "앱 연결을 끊었습니다.")
    else:
        messages.info(request, "이미 연결이 끊어진 앱입니다.")
    return redirect("accounts:account")


@login_required
@require_POST
def link_start(request: HttpRequest, provider: str) -> HttpResponse:
    social = _provider_or_404(provider)
    try:
        user = _holder_or_403(request)
    except _StepUp:
        return _step_up()
    url, pending = begin(social, "link", user_id=user.pk)
    request.session[PENDING_SOCIAL_KEY] = dict(pending)
    # A repeated callback of this flow (finished or cancelled) lands on 「내 계정」, not on the
    # app of an earlier login (#144).
    request.session[JUST_SIGNED_IN_KEY] = _note(ACCOUNT_HOME)
    return redirect(url)


@login_required
@require_POST
def unlink(request: HttpRequest, identity_id: int) -> HttpResponse:
    try:
        user = _holder_or_403(request)
    except _StepUp:
        return _step_up()
    try:
        provider = unlink_identity(user, identity_id, ip=client_ip(request))
    except IdentityNotFound as error:
        raise Http404("no such linked login") from error
    except LastIdentity:
        messages.error(request, "마지막 남은 로그인은 해제할 수 없습니다.")
    except NotAMember as error:
        raise PermissionDenied("for members only") from error
    else:
        messages.success(
            request, f"{ExternalIdentity.Provider(provider).label} 로그인 연결을 해제했습니다."
        )
    return redirect("accounts:account")


@login_required
@require_http_methods(["GET", "POST"])
def withdraw(request: HttpRequest) -> HttpResponse:
    """탈퇴 (#39, ADR 0004): GET shows what happens, POST with the confirmation phrase withdraws,
    signs out and shows the 「탈퇴했습니다」 page. A wrong phrase is 400 with the same page."""
    user = _member_or_403(request)
    context = {"phrase": CONFIRM_PHRASE, "apps": [app.name for app in connected_apps(user)]}
    if request.method == "GET":
        return render(request, "accounts/withdraw.html", context)
    if request.POST.get("confirm", "").strip() != CONFIRM_PHRASE:
        context["error"] = f"「{CONFIRM_PHRASE}」를 정확히 입력하세요."
        return render(request, "accounts/withdraw.html", context, status=400)
    withdraw_member(user)
    logout(request)
    return render(request, "accounts/withdrawn.html")
