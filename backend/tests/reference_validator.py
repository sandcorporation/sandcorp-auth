"""Reference access-token validator for the resource servers (portfolio, news).

This file implements docs/resource-server-token-validation.md rule for rule, with plain PyJWT
and no Django, so the two sites can copy it. When the rules change, change both together.

Injected: `fetch_jwks` (GET https://auth.sandcorp.co.kr/.well-known/jwks.json, parsed JSON)
and `clock` (anything with `now() -> aware datetime`).
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, NotRequired, Protocol, TypedDict

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ISSUER = "https://auth.sandcorp.co.kr"
JWKS_URL = "https://auth.sandcorp.co.kr/.well-known/jwks.json"
ALGORITHM = "EdDSA"
JWKS_TTL_SECONDS = 600
JWKS_MIN_REFETCH_SECONDS = 60
EXP_LEEWAY_SECONDS = 30
REQUIRED_CLAIMS = ["iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope"]


class Clock(Protocol):
    def now(self) -> datetime: ...


class Jwk(TypedDict):
    kty: str
    crv: str
    x: str
    kid: str
    alg: NotRequired[str]
    use: NotRequired[str]


class JwkSet(TypedDict):
    keys: list[Jwk]


class TokenRejected(Exception):
    """401 with `error="invalid_token"`."""


class InsufficientScope(Exception):
    """403 with `error="insufficient_scope"`."""

    def __init__(self, required_scope: str) -> None:
        super().__init__(required_scope)
        self.required_scope = required_scope


@dataclass(frozen=True)
class AccessToken:
    sub: str
    client_id: str
    scopes: frozenset[str]
    jti: str
    iat: int
    exp: int


class JwksCache:
    """Public keys by `kid` (rules J1-J5 in the document).

    - fetch when the cache is empty or older than JWKS_TTL_SECONDS;
    - on an unknown `kid` fetch once more at once, but at most once per JWKS_MIN_REFETCH_SECONDS;
    - a failed fetch keeps the old keys and is not retried for JWKS_MIN_REFETCH_SECONDS.
    """

    def __init__(self, fetch_jwks: Callable[[], JwkSet], clock: Clock) -> None:
        self._fetch = fetch_jwks
        self._clock = clock
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at: float | None = None
        self._failed_at: float | None = None
        self._unknown_kid_refetch_at: float | None = None

    def key_for(self, kid: str) -> Ed25519PublicKey | None:
        now = self._clock.now().timestamp()
        stale = self._fetched_at is None or now - self._fetched_at >= JWKS_TTL_SECONDS
        if stale and not _within(self._failed_at, now):
            self._refresh(now)
        elif kid not in self._keys and not _within(self._unknown_kid_refetch_at, now):
            self._unknown_kid_refetch_at = now
            self._refresh(now)
        return self._keys.get(kid)

    def _refresh(self, now: float) -> None:
        try:
            jwk_set = self._fetch()
        except Exception:  # network/JSON failure: keep serving the keys we already have
            self._failed_at = now
            return
        keys: dict[str, Ed25519PublicKey] = {}
        for jwk in jwk_set.get("keys", []):
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            if jwk.get("alg", ALGORITHM) != ALGORITHM or jwk.get("use", "sig") != "sig":
                continue
            key = jwt.PyJWK(dict(jwk), algorithm=ALGORITHM).key
            if isinstance(key, Ed25519PublicKey):
                keys[jwk["kid"]] = key
        self._keys = keys
        self._fetched_at = now
        self._failed_at = None


def _within(moment: float | None, now: float) -> bool:
    return moment is not None and now - moment < JWKS_MIN_REFETCH_SECONDS


def validate_access_token(
    token: str,
    *,
    jwks: JwksCache,
    audience: str,
    owner_sub: str,
    required_scope: str,
    clock: Clock,
) -> AccessToken:
    """Return the verified token, or raise TokenRejected (401) / InsufficientScope (403)."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise TokenRejected("malformed token") from exc
    kid = header.get("kid")
    if header.get("alg") != ALGORITHM or not isinstance(kid, str):
        raise TokenRejected("alg must be EdDSA and kid must be present")
    key = jwks.key_for(kid)
    if key is None:
        raise TokenRejected("unknown kid")
    try:
        claims: dict[str, object] = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            options={
                "require": REQUIRED_CLAIMS,
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.InvalidTokenError as exc:
        raise TokenRejected("bad signature or missing claim") from exc

    sub, client_id, jti, scope = (claims[n] for n in ("sub", "client_id", "jti", "scope"))
    iat, exp = claims["iat"], claims["exp"]
    if not (
        isinstance(sub, str)
        and isinstance(client_id, str)
        and isinstance(jti, str)
        and isinstance(scope, str)
        and isinstance(iat, int)
        and isinstance(exp, int)
    ):
        raise TokenRejected("claim has the wrong type")
    if claims["iss"] != ISSUER:
        raise TokenRejected("wrong issuer")
    if claims["aud"] != audience:  # a string, exactly equal; lists are rejected
        raise TokenRejected("wrong audience")
    if clock.now().timestamp() > exp + EXP_LEEWAY_SECONDS:
        raise TokenRejected("expired")
    if sub != owner_sub:
        raise TokenRejected("not the owner")

    scopes = frozenset(scope.split(" ")) - {""}
    if required_scope not in scopes:
        raise InsufficientScope(required_scope)
    return AccessToken(sub=sub, client_id=client_id, scopes=scopes, jti=jti, iat=iat, exp=exp)


def www_authenticate(
    site_origin: str,
    *,
    error: Literal["invalid_token", "insufficient_scope"] | None = None,
    scope: str | None = None,
) -> str:
    """`WWW-Authenticate` value: 401 without/with `invalid_token`, or 403 `insufficient_scope`."""
    if error == "insufficient_scope":
        return f'Bearer error="insufficient_scope", scope="{scope}"'
    value = f'Bearer resource_metadata="{site_origin}/.well-known/oauth-protected-resource"'
    if error == "invalid_token":
        value += ', error="invalid_token"'
    return value
