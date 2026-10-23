"""What the token endpoint hands out and keeps.

`SandcorpTokenGenerator` builds the token response: the access token is #4's signed JWT with
`aud` = the resource bound to the grant (RFC 8707, which authlib's generators cannot carry, so
the server passes `resource` explicitly), the refresh token is an opaque random value. Refresh
tokens are stored as SHA-256 hashes in the live family of the consent they descend from.
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
from services.oidc import OPENID, issue_id_token
from services.signing import random_token
from services.tokens import issue_access_token

REFRESH_TOKEN_BYTES = 32


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
    ) -> TokenResponse:
        """`auth_time` (the owner's login) and `nonce` go into the ID token, which is made
        only when the scope has `openid`."""
        if not isinstance(user, User) or resource is None:
            raise RuntimeError("an access token needs an owner and a resource (its audience)")
        allowed: str = self.get_allowed_scope(client, scope)
        granted = allowed.split()
        own = set(resource.scopes.filter(name__in=granted).values_list("name", flat=True))
        token = TokenResponse(
            access_token=issue_access_token(
                sub=user.get_username(),
                audience=resource.url,
                client_id=client.client_id,
                scopes=[name for name in granted if name in own],
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
            )
        return token


def live_family(consent: Consent) -> RefreshTokenFamily:
    """The consent's live refresh token family, opened on first use (one live per consent)."""
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


def store_refresh_token(
    family: RefreshTokenFamily,
    raw: str,
    scope: str,
    jti: str = "",
    auth_time: datetime | None = None,
) -> RefreshToken:
    now = get_clock().now()
    return RefreshToken.objects.create(
        family=family,
        token_hash=hash_refresh_token(raw),
        scope=scope,
        jti=jti,
        auth_time=auth_time,
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
