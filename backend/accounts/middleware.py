from collections.abc import Callable

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

from accounts.session import pending_user
from services.totp import is_enrolled


class TotpEnrollmentMiddleware:
    """An account before TOTP enrollment reaches nothing but the setup screen (and logout).

    A logged-in session whose device was reset (`owner reset-totp`) is logged out first.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = request.user
        if isinstance(user, User) and user.is_authenticated and not is_enrolled(user):
            logout(request)
        pending = pending_user(request)
        if pending is not None and not is_enrolled(pending):
            allowed = {reverse("accounts:totp_setup"), reverse("accounts:logout")}
            if request.path not in allowed and not request.path.startswith(settings.STATIC_URL):
                return redirect("accounts:totp_setup")
        return self.get_response(request)
