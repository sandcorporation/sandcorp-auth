"""The social login flow (#36, spec #34): start, callback, account resolution, link and unlink.

Views keep the in-between state in the session and turn these answers into screens; the rules
live here.

- `begin` makes a fresh `state`, `nonce` and PKCE verifier (`get_randomness()`), returns the
  provider URL and a `PendingSocial` for the session. It is good for `PENDING_SECONDS` and one
  callback only.
- `complete` checks the callback against it (provider, age, `state` in constant time) before
  any code is exchanged, then asks the provider for the profile (`social_providers`).
- `sign_in`: a known identity signs into its account. A new one becomes a member (status
  「동의 대기」 until the terms ticket, #37) unless its verified email already belongs to another
  member: then nothing is made and the caller shows 「이전에 <제공자>로 가입하셨습니다」 first;
  only `force_new=True` (the person chose 「그래도 새 계정」) makes the account. Nothing is merged.
- `link_identity` / `unlink_identity` (members and the owner, #100): an identity that belongs
  to another account is refused, and the last identity of a member cannot be removed (the
  owner keeps its password + TOTP, so it may remove all). The owner's views ask for a recent
  password + TOTP first (`services.step_up`).
- Social buttons show where `social_login_allowed(next)`: the login is for an `/authorize`
  request of a client that allows members (spec 7). They also show with no app (#126, #138):
  any other `next` on this host but `/authorize` (`account_login_next`). That login has
  purpose "account" and signs into existing accounts only — a new identity gets no account
  (`create=False`); one whose verified email an account already has gets the same-email
  notice, which then offers only that account's login (#135, `PendingSignup.may_create`).
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Final, Literal, TypedDict
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.db.models.functions import Lower

from accounts.models import ExternalIdentity, Member
from accounts.session import allows_get
from adapters.clock import get_clock
from adapters.randomness import get_randomness
from oauth.models import Client
from services import audit
from services.clients import find_client
from services.locks import lock_account
from services.members import ExternalProfile, IdentityTaken, create_member, is_member
from services.social_providers import (
    AuthorizationRequest,
    SocialLoginFailed,
    SocialProvider,
    configured_providers,
)

PENDING_SECONDS: Final = 10 * 60

# "login": through an app's /authorize (may sign up); "link": add a login to the signed-in
# account; "account": straight to 「내 계정」, existing accounts only (#126).
type Purpose = Literal["login", "link", "account"]

ACCOUNT_HOME: Final = "/account"
# The login's own screens: a login without an app that was headed there lands on 「내 계정」.
LOGIN_PATHS: Final = frozenset({"", "/", "/login", "/logout", "/signup/confirm"})


class PendingSocial(TypedDict):
    provider: str
    purpose: Purpose
    state: str
    nonce: str
    verifier: str
    next: str
    # The account being linked to (purpose "link"); 0 for a login.
    user_id: int
    started_at: float


class PendingSignup(TypedDict):
    """A new identity waiting on the same-email notice."""

    provider: str
    provider_sub: str
    email: str
    email_verified: bool
    display_name: str
    next: str
    # False for a login without an app (#135): the notice cannot make a new account.
    may_create: bool
    started_at: float


@dataclass(frozen=True)
class WaitingSignup:
    profile: ExternalProfile
    next: str
    may_create: bool


class NotAMember(Exception):
    """Only members link or unlink social logins (the owner signs in with password + TOTP)."""


class LastIdentity(Exception):
    """The account's only social login cannot be removed (it could no longer sign in)."""


class IdentityNotFound(Exception):
    pass


@dataclass(frozen=True)
class SignInResult:
    """`user` is signed in, or (None) the email belongs to accounts that use `existing`."""

    user: User | None
    created: bool = False
    existing: list[str] = field(default_factory=list)


def _random_token(n: int = 32) -> str:
    return base64.urlsafe_b64encode(get_randomness().token_bytes(n)).rstrip(b"=").decode()


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def callback_uri(provider_name: str) -> str:
    return f"{settings.SITE_URL}/login/{provider_name}/callback"


def provider_named(name: str) -> SocialProvider | None:
    return configured_providers().get(name)


def begin(
    provider: SocialProvider, purpose: Purpose, *, next_url: str = "", user_id: int = 0
) -> tuple[str, PendingSocial]:
    pending = PendingSocial(
        provider=provider.name,
        purpose=purpose,
        state=_random_token(),
        nonce=_random_token(),
        verifier=_random_token(),
        next=next_url,
        user_id=user_id,
        started_at=get_clock().now().timestamp(),
    )
    url = provider.authorization_url(
        AuthorizationRequest(
            redirect_uri=callback_uri(provider.name),
            state=pending["state"],
            nonce=pending["nonce"],
            code_challenge=_s256(pending["verifier"]),
        )
    )
    return url, pending


def _fresh(started_at: object) -> bool:
    if not isinstance(started_at, int | float):
        return False
    age = get_clock().now().timestamp() - started_at
    return 0 <= age <= PENDING_SECONDS


def read_pending(value: object, provider_name: str) -> PendingSocial:
    """The session's pending login for this provider callback, or SocialLoginFailed."""
    if not isinstance(value, dict):
        raise SocialLoginFailed("no_pending_login")
    text_keys = ("provider", "purpose", "state", "nonce", "verifier", "next")
    if not all(isinstance(value.get(key), str) for key in text_keys) or not isinstance(
        value.get("user_id"), int
    ):
        raise SocialLoginFailed("no_pending_login")
    if value["provider"] != provider_name:
        raise SocialLoginFailed("provider_mismatch")
    if not _fresh(value.get("started_at")):
        raise SocialLoginFailed("pending_login_expired")
    purpose: Purpose = "link" if value["purpose"] == "link" else "login"
    if value["purpose"] == "account":
        purpose = "account"
    return PendingSocial(
        provider=value["provider"],
        purpose=purpose,
        state=value["state"],
        nonce=value["nonce"],
        verifier=value["verifier"],
        next=value["next"],
        user_id=value["user_id"],
        started_at=float(value["started_at"]),
    )


def complete(
    provider: SocialProvider, pending: PendingSocial, *, state: str, code: str
) -> ExternalProfile:
    """Check the callback's `state` against the pending login, then exchange `code`."""
    if not state or not hmac.compare_digest(state.encode(), pending["state"].encode()):
        raise SocialLoginFailed("state_mismatch")
    if not code:
        raise SocialLoginFailed("no_code")
    profile = provider.fetch_profile(
        code=code,
        redirect_uri=callback_uri(provider.name),
        code_verifier=pending["verifier"],
        nonce=pending["nonce"],
    )
    if not profile.provider_sub:
        raise SocialLoginFailed("no_subject")
    return profile


def identity_owner(profile: ExternalProfile) -> User | None:
    identity = (
        ExternalIdentity.objects.select_related("user")
        .filter(provider=profile.provider, provider_sub=profile.provider_sub)
        .first()
    )
    return identity.user if identity is not None else None


def providers_with_email(profile: ExternalProfile) -> list[str]:
    """Provider keys (`ExternalIdentity.provider`) of the social logins of the members that
    already have this verified email (as their account email or an identity's email), first
    linked first. Empty for an unverified email."""
    email = profile.email.strip()
    if not email or not profile.email_verified:
        return []
    # Compared lower-cased: `iexact` is LIKE, case-sensitive under the as_cs collation.
    wanted = email.lower()
    member_users = Member.objects.values("user_id")
    by_account = User.objects.alias(e=Lower("email")).filter(e=wanted).values("pk")
    by_identity = (
        ExternalIdentity.objects.alias(e=Lower("email")).filter(e=wanted).values("user_id")
    )
    # A withdrawn account is never pointed to (ADR 0004: no 「이전 계정」 notice).
    users = User.objects.filter(pk__in=member_users, is_active=True).filter(
        Q(pk__in=by_account) | Q(pk__in=by_identity)
    )
    # In the order they were linked, first linked first (#144).
    providers = ExternalIdentity.objects.filter(user__in=users).order_by("linked_at", "pk")
    return list(dict.fromkeys(i.provider for i in providers.only("provider")))


def sign_in(
    profile: ExternalProfile, *, ip: str, force_new: bool = False, create: bool = True
) -> SignInResult:
    """`create=False` (a login without an app, #126): a new identity never signs up — it
    gets the same-email answer (#135) or SocialLoginFailed("no_account")."""
    user = identity_owner(profile)
    created = False
    if user is None:
        if not force_new or not create:
            existing = providers_with_email(profile)
            if existing:
                return SignInResult(user=None, existing=existing)
        if not create:
            raise SocialLoginFailed("no_account")
        try:
            user = create_member(profile)
            created = True
            audit.record(
                audit.MEMBER_CREATED,
                actor=user.get_username(),
                ip=ip,
                detail={"provider": profile.provider},
            )
        except IdentityTaken:
            # Someone (this person, in another tab) linked it a moment ago: use that account.
            user = identity_owner(profile)
            if user is None:
                raise
    if not user.is_active:
        raise SocialLoginFailed("account_inactive")
    audit.record(
        audit.SOCIAL_LOGIN_SUCCEEDED,
        actor=user.get_username(),
        ip=ip,
        detail={"provider": profile.provider, "created": created},
    )
    return SignInResult(user=user, created=created)


def may_link(user: User) -> bool:
    """Members and the owner (#100) have social logins; nobody else does."""
    return is_member(user) or (user.is_superuser and user.is_active)


def link_identity(user: User, profile: ExternalProfile, *, ip: str) -> bool:
    """Link `profile` to the member or the owner `user`. True if newly linked, False if it
    already was. Raises NotAMember, IdentityTaken (it belongs to another account)."""
    if not may_link(user):
        raise NotAMember(user.get_username())
    owner = identity_owner(profile)
    if owner is not None:
        if owner.pk == user.pk:
            return False
        raise IdentityTaken(f"{profile.provider} identity belongs to another account")
    email = profile.email.strip()
    name = profile.display_name.strip()[:150]
    try:
        with transaction.atomic():
            ExternalIdentity.objects.create(
                user=user,
                provider=profile.provider,
                provider_sub=profile.provider_sub,
                email=email,
                email_verified=bool(email) and profile.email_verified,
                display_name=name,
                linked_at=get_clock().now(),
            )
    except IntegrityError as error:
        owner = identity_owner(profile)
        if owner is not None and owner.pk == user.pk:
            return False
        raise IdentityTaken(f"{profile.provider} identity belongs to another account") from error
    audit.record(
        audit.IDENTITY_LINKED,
        actor=user.get_username(),
        ip=ip,
        detail={"provider": profile.provider},
    )
    return True


def unlink_identity(user: User, identity_id: int, *, ip: str) -> str:
    """Remove one of the account's social logins. Raises NotAMember, IdentityNotFound,
    LastIdentity (members only: the owner signs in with its password + TOTP). Returns the provider
    key of the removed login. The account row
    is locked so two removals at once cannot both pass the "not the last one" check."""
    if not may_link(user):
        raise NotAMember(user.get_username())
    member = is_member(user)
    with transaction.atomic():
        lock_account(user.pk)
        identities = list(ExternalIdentity.objects.filter(user_id=user.pk))
        target = next((i for i in identities if i.pk == identity_id), None)
        if target is None:
            raise IdentityNotFound(str(identity_id))
        if member and len(identities) <= 1:
            raise LastIdentity(user.get_username())
        target.delete()
    audit.record(
        audit.IDENTITY_UNLINKED,
        actor=user.get_username(),
        ip=ip,
        detail={"provider": target.provider},
    )
    return target.provider


def authorize_client(next_url: str | None) -> Client | None:
    """The active client of an `/authorize` request `next_url` (one `client_id`), else None."""
    if not next_url:
        return None
    parts = urlsplit(next_url)
    if parts.path != "/authorize":
        return None
    client_ids = parse_qs(parts.query).get("client_id", [])
    if len(client_ids) != 1:
        return None
    return find_client(client_ids[0])


def social_login_allowed(next_url: str | None) -> bool:
    """True when `next_url` is an `/authorize` request of an active client that allows
    members: only then may a person sign in (or up) with a social login."""
    return members_may_sign_in(authorize_client(next_url))


def members_may_sign_in(app: Client | None) -> bool:
    """`social_login_allowed` for the `authorize_client` already looked up."""
    return app is not None and app.allows_members


def account_login_next(next_url: str | None) -> str | None:
    """Where a social login without an app lands (#126, #138), for a `next` already checked
    by `safe_next`: None (no such login) for `/authorize` — an app's login is
    `social_login_allowed` or none; 「내 계정」 for no `next`, the login's own screens and a
    path that does not open with GET; else `next_url` itself."""
    path = urlsplit(next_url or "").path
    if path == "/authorize" or path.startswith("/" + settings.ADMIN_PATH):
        return None  # the admin signs in with the password + TOTP only (#144)
    if not next_url or path in LOGIN_PATHS or path.startswith("/login/"):
        return ACCOUNT_HOME
    return next_url if allows_get(path) else ACCOUNT_HOME


def pending_signup(
    profile: ExternalProfile, next_url: str, *, may_create: bool = True
) -> PendingSignup:
    return PendingSignup(
        provider=profile.provider,
        provider_sub=profile.provider_sub,
        email=profile.email,
        email_verified=profile.email_verified,
        display_name=profile.display_name,
        next=next_url,
        may_create=may_create,
        started_at=get_clock().now().timestamp(),
    )


def read_pending_signup(value: object) -> WaitingSignup | None:
    """The waiting profile, its `next` and whether it may sign up; None when there is none or
    it is too old."""
    if not isinstance(value, dict) or not _fresh(value.get("started_at")):
        return None
    text_keys = ("provider", "provider_sub", "email", "display_name", "next")
    if not all(isinstance(value.get(key), str) for key in text_keys):
        return None
    if not isinstance(value.get("email_verified"), bool):
        return None
    if not isinstance(value.get("may_create"), bool):
        return None
    profile = ExternalProfile(
        provider=value["provider"],
        provider_sub=value["provider_sub"],
        email=value["email"],
        email_verified=value["email_verified"],
        display_name=value["display_name"],
    )
    return WaitingSignup(profile=profile, next=value["next"], may_create=value["may_create"])
