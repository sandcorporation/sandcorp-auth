"""Access-token validation for Sandcorp resource servers (no web framework here).

The rules are sandcorp-auth `docs/resource-server-token-validation.md` §3–§4 (T1–T10, S1,
J1–J5) and §10 (A1–A3). Where the four sites' copies differed, the strictest one is the
default here; see the package README for the comparison.

Everything a site configures (issuer, its resource URL, the scope an endpoint needs, how to
fetch the JWKS, the clock) is a function argument — this module never reads settings.
Site-specific account rules (owner only, owner or member) plug in through
`extra_claims_hook`; `owner_only` and `owner_or_member` are the two the auth server defines.
"""

import json
import re
import threading
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Protocol, TypeIs

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALGORITHM = "EdDSA"
JWKS_TTL_SECONDS = 600
JWKS_MIN_REFETCH_SECONDS = 60
JWKS_FETCH_TIMEOUT_SECONDS = 5.0
JWKS_MAX_BYTES = 64 * 1024
EXP_LEEWAY_SECONDS = 30
REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope")
ACCOUNT_KIND_CLAIM = "acct"
MEMBER_SUB = re.compile(r"m_[0-7][0-9A-HJKMNP-TV-Z]{25}")


class Clock(Protocol):
    def now(self) -> datetime:
        """An aware datetime."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class TokenRejected(Exception):
    """401 with `error="invalid_token"`. The message is for the server log only."""


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
    acct: str | None = None
    """The `acct` claim when it is a string (`"member"` on member tokens), else None.
    Only meaningful after a hook such as `owner_or_member` has checked it."""


type JwksFetcher = Callable[[], object]
"""Returns the parsed JWKS document. Its shape is checked before use, so `object`."""

type ClaimsHook = Callable[[Mapping[str, object]], None]
"""Runs after T1–T10 and before S1 with the verified claims (read-only).
Raise `TokenRejected` to turn the token away with 401."""


class JwksCache:
    """Public keys by `kid` (rules J1–J5).

    - fetch when the cache is empty or older than `ttl_seconds`;
    - on an unknown `kid` fetch once more at once, but at most once per `min_refetch_seconds`;
    - a failed fetch keeps the old keys and is not retried for `min_refetch_seconds`;
    - a successful fetch replaces the whole cache (keys dropped from the JWKS are dropped here).
    One instance per process; it is thread-safe.
    """

    def __init__(
        self,
        fetch_jwks: JwksFetcher,
        clock: Clock,
        *,
        ttl_seconds: float = JWKS_TTL_SECONDS,
        min_refetch_seconds: float = JWKS_MIN_REFETCH_SECONDS,
    ) -> None:
        self._fetch = fetch_jwks
        self._clock = clock
        self._ttl = ttl_seconds
        self._min_refetch = min_refetch_seconds
        self._lock = threading.Lock()
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at: float | None = None
        self._failed_at: float | None = None
        self._unknown_kid_refetch_at: float | None = None

    def key_for(self, kid: str) -> Ed25519PublicKey | None:
        with self._lock:
            now = self._clock.now().timestamp()
            stale = self._fetched_at is None or now - self._fetched_at >= self._ttl
            if stale and not self._within(self._failed_at, now):
                self._refresh(now)
            elif kid not in self._keys and not self._within(self._unknown_kid_refetch_at, now):
                self._unknown_kid_refetch_at = now
                self._refresh(now)
            return self._keys.get(kid)

    def _within(self, moment: float | None, now: float) -> bool:
        return moment is not None and now - moment < self._min_refetch

    def _refresh(self, now: float) -> None:
        try:
            keys = _usable_keys(self._fetch())
        except Exception:  # network/JSON/shape failure: keep serving the keys we already have
            self._failed_at = now
            return
        self._keys = keys
        self._fetched_at = now
        self._failed_at = None


def _usable_keys(document: object) -> dict[str, Ed25519PublicKey]:
    """J3: only OKP/Ed25519 keys whose `alg` (if any) is EdDSA and `use` (if any) is sig.
    A document that is not `{"keys": [...]}` is a failed fetch (ValueError)."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("not a JWK set")
    keys: dict[str, Ed25519PublicKey] = {}
    for jwk in document["keys"]:
        if not isinstance(jwk, dict) or not isinstance(jwk.get("kid"), str):
            continue
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        if jwk.get("alg", ALGORITHM) != ALGORITHM or jwk.get("use", "sig") != "sig":
            continue
        try:
            key = jwt.PyJWK(dict(jwk), algorithm=ALGORITHM).key
        except jwt.PyJWTError:
            continue
        if isinstance(key, Ed25519PublicKey):
            keys[jwk["kid"]] = key
    return keys


def http_jwks_fetcher(
    url: str,
    *,
    timeout: float = JWKS_FETCH_TIMEOUT_SECONDS,
    max_bytes: int = JWKS_MAX_BYTES,
) -> JwksFetcher:
    """A `JwksFetcher` that GETs `url` (J1: 5 s timeout). Any failure raises, which
    `JwksCache` treats as J4. Bodies over `max_bytes` are failures too."""
    if not url.startswith(("https://", "http://")):
        raise ValueError("JWKS URL must be http(s)")

    def fetch() -> object:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("JWKS response too large")
        parsed: object = json.loads(body)
        return parsed

    return fetch


def validate_access_token(
    token: str,
    *,
    issuer: str,
    audience: str,
    required_scope: str,
    jwks: JwksCache,
    clock: Clock,
    extra_claims_hook: ClaimsHook | None = None,
) -> AccessToken:
    """Return the verified token, or raise TokenRejected (401) / InsufficientScope (403).

    `issuer` and `audience` are compared as exact strings (T8, T9): no trailing-slash or
    case leniency, and an `aud` list is rejected even if it contains `audience`.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
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
                "require": list(REQUIRED_CLAIMS),
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise TokenRejected("bad signature or missing claim") from exc

    sub, client_id, jti, scope = (claims[n] for n in ("sub", "client_id", "jti", "scope"))
    iat, exp = claims["iat"], claims["exp"]
    if not (
        isinstance(sub, str)
        and isinstance(client_id, str)
        and isinstance(jti, str)
        and isinstance(scope, str)
        and _is_int(iat)
        and _is_int(exp)
    ):
        raise TokenRejected("claim has the wrong type")
    if claims["iss"] != issuer:
        raise TokenRejected("wrong issuer")
    if claims["aud"] != audience:  # a string, exactly equal; lists are rejected
        raise TokenRejected("wrong audience")
    if clock.now().timestamp() > exp + EXP_LEEWAY_SECONDS:
        raise TokenRejected("expired")
    if extra_claims_hook is not None:
        extra_claims_hook(MappingProxyType(claims))

    scopes = frozenset(scope.split(" ")) - {""}
    if required_scope not in scopes:
        raise InsufficientScope(required_scope)
    acct = claims.get(ACCOUNT_KIND_CLAIM)
    return AccessToken(
        sub=sub,
        client_id=client_id,
        scopes=scopes,
        jti=jti,
        iat=iat,
        exp=exp,
        acct=acct if isinstance(acct, str) else None,
    )


def _is_int(value: object) -> TypeIs[int]:
    """JSON integers only: `true`/`false` are not timestamps."""
    return isinstance(value, int) and not isinstance(value, bool)


def owner_only(owner_sub: str) -> ClaimsHook:
    """T11 for sites that take only the owner: `sub` must equal `owner_sub` exactly, and an
    owner token never carries `acct` (§10 A1), so a token with `acct` is rejected too.
    An empty `owner_sub` (setting not filled in) rejects every token."""

    def hook(claims: Mapping[str, object]) -> None:
        if ACCOUNT_KIND_CLAIM in claims:
            raise TokenRejected("not an owner token")
        if not owner_sub or claims["sub"] != owner_sub:
            raise TokenRejected("not the owner")

    return hook


def owner_or_member(owner_sub: str) -> ClaimsHook:
    """§10 A1–A3 for sites that also take members: no `acct` means the owner (sub must be
    `owner_sub`); otherwise `acct` must be exactly "member" and `sub` must be `m_` + ULID.
    An empty `owner_sub` rejects every owner token; members still pass."""

    def hook(claims: Mapping[str, object]) -> None:
        if ACCOUNT_KIND_CLAIM not in claims:
            if not owner_sub or claims["sub"] != owner_sub:
                raise TokenRejected("not the owner")
            return
        if claims[ACCOUNT_KIND_CLAIM] != "member":
            raise TokenRejected("unknown account kind")
        sub = claims["sub"]
        if not isinstance(sub, str) or MEMBER_SUB.fullmatch(sub) is None:
            raise TokenRejected("not a member sub")

    return hook
