"""OpenID Connect on top of the OAuth layer: login info scopes, ID tokens, userinfo claims.

Login info scopes (`openid`, `profile`, `email`) are not resource scopes. Asked for without a
`resource`, the grant is bound to the internal resource `USERINFO_RESOURCE` (registered by
migration 0007), which becomes the access token's `aud`: such a token is good only at
`/userinfo`. Asked for together with a `resource`, the access token is that resource's as
always (with its own scopes only) and the ID token comes alongside. Either way the token
response carries an `id_token` whose `aud` is the client.

The ID token is signed like access tokens (the active Ed25519 key, `EdDSA`, header `kid`).
No `at_hash`: OpenID Connect defines none for EdDSA. Claims are never made up: `name` only when
the account has one, `email`/`email_verified` only when it has an email.

A member (ADR 0003) also gets `acct: "member"` in userinfo and the ID token (the owner gets no
`acct`), no `preferred_username` (its username is the opaque `sub`), and `email_verified` as the
member's own flag (a typed-in email is not verified).
"""

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from typing import Final, NotRequired, TypedDict

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.contrib.auth.models import User

from accounts.models import Member
from adapters.clock import get_clock
from services.signing import ALGORITHM, active_signing_key, published_jwks

OPENID: Final = "openid"
LOGIN_INFO_SCOPES: Final = frozenset({OPENID, "profile", "email"})
USERINFO_RESOURCE: Final = "https://auth.sandcorp.co.kr/userinfo"
CLAIMS_SUPPORTED: Final = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "name",
    "preferred_username",
    "email",
    "email_verified",
]


class IdentityClaims(TypedDict):
    sub: str
    acct: NotRequired[str]
    name: NotRequired[str]
    preferred_username: NotRequired[str]
    email: NotRequired[str]
    email_verified: NotRequired[bool]


class IdTokenClaims(IdentityClaims):
    iss: str
    aud: str
    iat: int
    exp: int
    auth_time: int
    nonce: NotRequired[str]


def identity_claims(user: User, scopes: Collection[str]) -> IdentityClaims:
    """`sub` and what `scopes` allow of the account's profile (userinfo and the ID token)."""
    claims = IdentityClaims(sub=user.get_username())
    member = Member.objects.filter(user_id=user.pk).first()
    if member is not None:
        claims["acct"] = "member"
    if "profile" in scopes:
        if member is None:
            claims["preferred_username"] = user.get_username()
        name = user.get_full_name()
        if name:
            claims["name"] = name
    if "email" in scopes and user.email:
        claims["email"] = user.email
        claims["email_verified"] = True if member is None else member.email_verified
    return claims


def issue_id_token(
    *,
    user: User,
    client_id: str,
    scopes: Collection[str],
    auth_time: datetime,
    nonce: str | None,
) -> str:
    """Sign an ID token for `client_id`. Lives as long as an access token."""
    key = active_signing_key()
    iat = int(get_clock().now().timestamp())
    identity = identity_claims(user, scopes)
    claims = IdTokenClaims(
        sub=identity["sub"],
        iss=settings.SITE_URL,
        aud=client_id,
        iat=iat,
        exp=iat + int(settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
        auth_time=int(auth_time.timestamp()),
    )
    if "acct" in identity:
        claims["acct"] = identity["acct"]
    if "name" in identity:
        claims["name"] = identity["name"]
    if "preferred_username" in identity:
        claims["preferred_username"] = identity["preferred_username"]
    if "email" in identity:
        claims["email"] = identity["email"]
    if "email_verified" in identity:
        claims["email_verified"] = identity["email_verified"]
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(
        dict(claims), key.private_key, algorithm=ALGORITHM, headers={"kid": key.kid, "typ": "JWT"}
    )


class UserinfoTokenRejected(Exception):
    """The bearer token is not a live access token of this server for `USERINFO_RESOURCE`."""


@dataclass(frozen=True)
class UserinfoGrant:
    user: User
    scopes: frozenset[str]


def verify_userinfo_token(raw: str) -> UserinfoGrant:
    """Check an access token presented to /userinfo: our signature (a published key), our
    issuer, `aud` = `USERINFO_RESOURCE`, not expired (by `get_clock()`), owner still there."""
    try:
        kid = jwt.get_unverified_header(raw).get("kid")
    except jwt.InvalidTokenError as error:
        raise UserinfoTokenRejected("malformed") from error
    key = next((jwk for jwk in published_jwks()["keys"] if jwk["kid"] == kid), None)
    if key is None:
        raise UserinfoTokenRejected("unknown kid")
    public_key = Ed25519PublicKey.from_public_bytes(jwt.utils.base64url_decode(key["x"]))
    try:
        claims: dict[str, object] = jwt.decode(
            raw,
            public_key,
            algorithms=[ALGORITHM],
            audience=USERINFO_RESOURCE,
            issuer=settings.SITE_URL,
            options={"require": ["iss", "sub", "aud", "exp", "scope"], "verify_exp": False},
        )
    except jwt.InvalidTokenError as error:
        raise UserinfoTokenRejected(str(error)) from error
    exp = claims["exp"]
    if not isinstance(exp, int) or exp <= get_clock().now().timestamp():
        raise UserinfoTokenRejected("expired")
    user = User.objects.filter(username=str(claims["sub"]), is_active=True).first()
    if user is None:
        raise UserinfoTokenRejected("unknown subject")
    return UserinfoGrant(user=user, scopes=frozenset(str(claims["scope"]).split()))
