from collections.abc import Callable
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.shortcuts import redirect
from django.urls import reverse

from accounts.session import pending_user
from services.members import is_member
from services.step_up import is_weak_owner_session
from services.totp import is_enrolled


class TotpEnrollmentMiddleware:
    """An owner before TOTP enrollment reaches nothing but the setup screen (and logout).

    A logged-in session whose device was reset (`owner reset-totp`) is logged out first.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = request.user
        if (
            isinstance(user, User)
            and user.is_authenticated
            and not is_enrolled(user)
            and not is_member(user)  # members sign in with a social login, no TOTP
        ):
            logout(request)
        pending = pending_user(request)
        if pending is not None and not is_enrolled(pending):
            allowed = {reverse("accounts:totp_setup"), reverse("accounts:logout")}
            if request.path not in allowed and not request.path.startswith(settings.STATIC_URL):
                return redirect("accounts:totp_setup")
        return self.get_response(request)


class OwnerStepUpMiddleware:
    """The admin screens need a recent password + TOTP (#100). The owner signed in with a social
    login is sent to the password + TOTP screen first and comes back afterwards. Anyone else
    (a member, nobody) goes on to the admin's own refusal (`admin_login_redirect`, #95)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        admin_path = "/" + settings.ADMIN_PATH
        if request.path.startswith(admin_path) and is_weak_owner_session(request):
            target = request.get_full_path() if request.method == "GET" else admin_path
            return redirect("/login?" + urlencode({"next": target}))
        return self.get_response(request)


class MethodNotAllowedPageMiddleware:
    """A browser that GETs a POST-only path (`/logout`, `/account/email`, ...) gets a page in the
    service's look instead of Django's empty 405 (#106). Status and `Allow` stay; a client
    that does not ask for HTML (the token endpoint's callers) keeps the bare response."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        if (
            not isinstance(response, HttpResponseNotAllowed)
            or response.content
            or "text/html" not in request.headers.get("accept", "")
        ):
            return response
        from accounts.views import method_not_allowed

        page = method_not_allowed(request)
        page["Allow"] = response["Allow"]
        return page
