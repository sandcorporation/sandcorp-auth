"""The owner's two kinds of session (#100).

The owner may sign in with a password + TOTP (the login screen) or, since #100, with a social
login linked to the owner account. A session is *strong* when it passed password + TOTP within
`STEP_UP_SECONDS`; the mark lives in the session (`mark_strong`), set only by the password +
TOTP login and dropped by a social login.

Without a strong session the owner gets only what a member could get: a member-level grant
(`member_level`: a client that allows members, scopes within `member_scopes(resource)`).
Everything else — the admin screens, owner-only clients and scopes — sends the owner to the
password + TOTP screen first (step-up) and back afterwards. Codes and refresh tokens issued in
such a session are marked `via_social`, and their tokens carry `amr: ["fed"]`.
"""

from typing import Final

from django.conf import settings
from django.contrib.auth.models import User
from django.http import HttpRequest

from adapters.clock import get_clock
from oauth.models import Client, Resource
from services.members import is_member, member_scopes

STRONG_AUTH_KEY: Final = "accounts.strong_auth_at"
# RFC 8176 "fed": the sign-in was a federated (social) login.
SOCIAL_AMR: Final = ("fed",)


def step_up_seconds() -> int:
    return int(getattr(settings, "STEP_UP_SECONDS", settings.SESSION_COOKIE_AGE))


def mark_strong(request: HttpRequest) -> None:
    """Call right after `login()` of a password + TOTP sign-in."""
    request.session[STRONG_AUTH_KEY] = int(get_clock().now().timestamp())


def drop_strong(request: HttpRequest) -> None:
    request.session.pop(STRONG_AUTH_KEY, None)


def has_strong_auth(request: HttpRequest) -> bool:
    at = request.session.get(STRONG_AUTH_KEY)
    if not isinstance(at, int) or isinstance(at, bool):
        return False
    age = get_clock().now().timestamp() - at
    return 0 <= age <= step_up_seconds()


def is_weak_owner_session(request: HttpRequest) -> bool:
    """The signed-in owner without a recent password + TOTP (a social login session)."""
    user = request.user
    return (
        isinstance(user, User)
        and user.is_authenticated
        and not is_member(user)
        and not has_strong_auth(request)
    )


def member_level(client: Client, scopes: list[str], resource: Resource) -> bool:
    """True when a member could get exactly this grant: the client allows members and every
    scope is a member scope for `resource`."""
    return client.allows_members and set(scopes) <= member_scopes(resource)
