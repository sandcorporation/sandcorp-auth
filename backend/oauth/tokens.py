"""What the token endpoint hands out and keeps.

`SandcorpTokenGenerator` builds the token response: the access token is #4's signed JWT with
`aud` = the resource bound to the grant (RFC 8707, which authlib's generators cannot carry, so
the server passes `resource` explicitly), the refresh token is an opaque random value (a
rotated one is derived from the token it replaces, `successor_refresh_token`). Refresh tokens
are stored as SHA-256 hashes in the live family of the consent they descend from.
With the `openid` scope the response also carries an OpenID Connect ID token
(`services.oidc`); the access token then keeps only its resource's own scopes.
"""

import hashlib
from datetime import datetime
from typing import NotRequired, TypedDict

import jwt
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import User
from django.db import transaction
from django.utils.crypto import salted_hmac

from adapters.clock import get_clock
from oauth.models import (
    AuthorizationCode,
    Client,
    Consent,
    RefreshToken,
    RefreshTokenFamily,
    Resource,
)
from services import audit
from services.machine_clients import MACHINE, machine_sub
from services.members import (
    MEMBER,
    MemberClientRefused,
    MemberInactive,
    MemberScopeRefused,
    MemberTermsPending,
    check_member_grant,
    is_member,
)
from services.oidc import OPENID, issue_id_token
from services.signing import b64url, random_token
from services.step_up import SOCIAL_AMR, member_level
from services.tokens import issue_access_token

REFRESH_TOKEN_BYTES = 32
SUCCESSOR_SALT = "sandcorp.oauth.refresh-successor"


class TokenResponse(TypedDict):
    """RFC 6749 5.1 fields, plus `id_token` (OpenID Connect Core 3.1.3.3) with `openid`."""

    access_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: NotRequired[str]
    id_token: NotRequired[str]


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def find_refresh_token(raw: str) -> RefreshToken | None:
    """The stored refresh token with this value (live or not), or None."""
    return (
        RefreshToken.objects.select_related("family__client", "family__user", "family__resource")
        .filter(token_hash=hash_refresh_token(raw))
        .first()
    )


def successor_refresh_token(presented: str) -> str:
    """The refresh token that replaces `presented` on rotation: HMAC(SECRET_KEY, presented).
    Deterministic, so a refresh in the grace window gets the very same successor again without
    the raw value being stored; unguessable without both the presented token and the key."""
    return b64url(salted_hmac(SUCCESSOR_SALT, presented, algorithm="sha256").digest())


def graced_successor(
    spent: RefreshToken, presented: str, *, lock: bool = False
) -> RefreshToken | None:
    """The successor to hand out again when `spent` (the token whose value is `presented`) comes
    back: it was rotated, not revoked, at most REFRESH_TOKEN_REUSE_GRACE ago, and its successor
    is still the live, unexpired tip of a live family and is the one derived from `presented`.
    The caller has checked the client. None means it is reuse. `lock` locks the successor row
    so it cannot be rotated while it is handed out again."""
    grace = settings.REFRESH_TOKEN_REUSE_GRACE
    if not grace or spent.replaced_by_id is None or spent.revoked_at is not None:
        return None
    rows = RefreshToken.objects.filter(
        pk=spent.replaced_by_id,
        family_id=spent.family_id,
        token_hash=hash_refresh_token(successor_refresh_token(presented)),
        replaced_by__isnull=True,
        revoked_at__isnull=True,
        family__revoked_at__isnull=True,
    )
    successor = (rows.select_for_update() if lock else rows).first()
    if successor is None or successor.is_expired():
        return None
    if get_clock().now() - successor.issued_at > grace:
        return None
    return successor


def access_token_jti(access_token: str) -> str:
    """The `jti` of an access token this server just signed (not verified: it is ours)."""
    claims: dict[str, object] = jwt.decode(access_token, options={"verify_signature": False})
    return str(claims["jti"])


class SandcorpTokenGenerator(BearerTokenGenerator):  # type: ignore[misc]  # no stubs
    def __init__(self) -> None:
        super().__init__(access_token_generator=None)

    def generate(
        self,
        grant_type: str,
        client: Client,
        user: AbstractBaseUser | None = None,
        scope: str | None = None,
        expires_in: int | None = None,
        include_refresh_token: bool = True,
        *,
        resource: Resource | None = None,
        auth_time: datetime | None = None,
        nonce: str | None = None,
        via_social: bool = False,
    ) -> TokenResponse:
        """`auth_time` (the owner's login) and `nonce` go into the ID token, which is made
        only when the scope has `openid`. `via_social` (the owner's social login session,
        #100): only a member-level grant, and `amr: ["fed"]` in the access and ID tokens.
        A machine client (#76) gets a token for itself: no account,
        `sub` = `client:<client_id>`, `acct` = `machine`, never a refresh token."""
        if client.kind == Client.Kind.MACHINE:
            return self._machine_token(client, scope, resource, user)
        if not isinstance(user, User) or resource is None:
            raise RuntimeError("an access token needs an account and a resource (its audience)")
        allowed: str = self.get_allowed_scope(client, scope)
        granted = allowed.split()
        member = is_member(user)
        if member:
            # Last line (ADR 0003): /authorize and /token checked already; never sign past it.
            try:
                check_member_grant(user, client, granted, resource)
            except (
                MemberInactive,
                MemberClientRefused,
                MemberScopeRefused,
                MemberTermsPending,
            ) as error:
                raise RuntimeError(f"refusing a member token: {error!r}") from error
        social = via_social and not member
        if social and not member_level(client, granted, resource):
            raise RuntimeError("refusing an owner-only grant from a social login session")
        own = set(resource.scopes.filter(name__in=granted).values_list("name", flat=True))
        token = TokenResponse(
            access_token=issue_access_token(
                sub=user.get_username(),
                audience=resource.url,
                client_id=client.client_id,
                scopes=[name for name in granted if name in own],
                acct=MEMBER if member else None,
                amr=SOCIAL_AMR if social else None,
            ),
            token_type="Bearer",
            expires_in=int(settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
            scope=allowed,
        )
        if include_refresh_token:
            token["refresh_token"] = random_token(REFRESH_TOKEN_BYTES)
        if OPENID in granted:
            if auth_time is None:
                raise RuntimeError("an ID token needs the owner's login time")
            token["id_token"] = issue_id_token(
                user=user,
                client_id=client.client_id,
                scopes=granted,
                auth_time=auth_time,
                nonce=nonce,
                amr=SOCIAL_AMR if social else None,
            )
        return token

    @staticmethod
    def _machine_token(
        client: Client, scope: str | None, resource: Resource | None, user: object
    ) -> TokenResponse:
        if user is not None or resource is None or resource != client.machine_resource:
            raise RuntimeError("a machine token has no account and only the client's resource")
        scopes = sorted(set((scope or "").split()))
        if not scopes or not set(scopes) <= set(client.machine_scopes):
            raise RuntimeError("a machine token carries only the client's bound scopes")
        return TokenResponse(
            access_token=issue_access_token(
                sub=machine_sub(client),
                audience=resource.url,
                client_id=client.client_id,
                scopes=scopes,
                acct=MACHINE,
            ),
            token_type="Bearer",
            expires_in=int(settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
            scope=" ".join(scopes),
        )


def live_family(consent: Consent) -> RefreshTokenFamily:
    """The consent's live refresh token family, opened on first use (one live per consent).
    The consent row is locked while the family is found or opened, so a family is never opened
    on a consent `services.consents.revoke_consent` has revoked (it takes the same row first)."""
    with transaction.atomic():
        if not lock_live_consent(consent):
            raise RuntimeError("a refresh token family needs a live consent")
        family, _ = RefreshTokenFamily.objects.get_or_create(
            consent=consent,
            revoked_at=None,
            defaults={
                "client_id": consent.client_id,
                "user_id": consent.user_id,
                "resource_id": consent.resource_id,
                "created_at": get_clock().now(),
            },
        )
    return family


def lock_live_consent(consent: Consent) -> bool:
    """Lock `consent`'s account, then its row, until the transaction ends; False when it is
    already revoked or no longer that account's (a merge moved it).

    Account before consent is the one lock order (#145): a withdrawal and a member merge lock
    the account first and then revoke or move its consents. Taking the consent first here
    deadlocked them, since the family a code exchange stores also takes the account row."""
    User.objects.select_for_update().filter(pk=consent.user_id).exists()
    return (
        Consent.objects.select_for_update()
        .filter(pk=consent.pk, user_id=consent.user_id, revoked_at__isnull=True)
        .exists()
    )


def store_refresh_token(
    family: RefreshTokenFamily,
    raw: str,
    scope: str,
    jti: str = "",
    auth_time: datetime | None = None,
    via_social: bool = False,
) -> RefreshToken:
    now = get_clock().now()
    return RefreshToken.objects.create(
        family=family,
        token_hash=hash_refresh_token(raw),
        scope=scope,
        jti=jti,
        auth_time=auth_time,
        via_social=via_social,
        issued_at=now,
        expires_at=now + settings.REFRESH_TOKEN_LIFETIME,
    )


def revoke_family(family: RefreshTokenFamily, reason: str) -> None:
    RefreshTokenFamily.objects.filter(pk=family.pk, revoked_at__isnull=True).update(
        revoked_at=get_clock().now(), revoked_reason=reason
    )


def report_code_reuse(code: AuthorizationCode, ip: str) -> None:
    """A used code came back: whoever holds it is not to be trusted with what it bought.
    Revoke the live family of the code's consent and record it."""
    family = RefreshTokenFamily.objects.filter(
        consent=code.consent, revoked_at__isnull=True
    ).first()
    if family is not None:
        revoke_family(family, "code_reuse")
    audit.record(
        audit.TOKEN_CODE_REUSE_DETECTED,
        actor=code.user.get_username(),
        client_id=code.client.client_id,
        ip=ip,
        detail={"resource": code.resource.url, "family": family.pk if family else None},
    )
