"""Test doubles for the sites' suites: signing keys, a fake JWKS endpoint, a fixed clock and a
fake sandcorp-auth (`/authorize` approval + `/token`). No network, no Django.

They replace the sites' own `fake_jwks.py` / `resource_token_fakes.py` /
`operator_login_fakes.py`. Only the external boundaries are faked — the real validator, JWKS
cache and login code run against them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .login import TokenRequest, TransportResponse
from .tokens import ALGORITHM, Clock, JwksCache

ISSUER = "https://auth.sandcorp.co.kr"
OWNER_SUB = "farrar142"
MEMBER_SUB = "m_01JB2Z3Y4X5W6V7T8S9R0Q1P2N"
"""A well-formed member `sub` (`m_` + ULID)."""
DEFAULT_START = datetime(2026, 1, 1, tzinfo=UTC)
TOKEN_LIFETIME_SECONDS = 600

type Claims = dict[str, object]


class FixedClock:
    """A `tokens.Clock` that only moves when told to."""

    def __init__(self, moment: datetime = DEFAULT_START) -> None:
        if moment.tzinfo is None:
            raise ValueError("FixedClock needs an aware datetime")
        self.moment = moment

    def now(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


def public_jwk(private_key: Ed25519PrivateKey, kid: str) -> dict[str, str]:
    """The JWK sandcorp-auth publishes for an Ed25519 key."""
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        "kid": kid,
        "alg": ALGORITHM,
        "use": "sig",
    }


@dataclass
class SigningKey:
    kid: str = "test-key"
    private: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    def jwk(self) -> dict[str, str]:
        return public_jwk(self.private, self.kid)

    def sign(
        self, claims: Mapping[str, object], *, headers: Mapping[str, object] | None = None
    ) -> str:
        """EdDSA-sign `claims`. `headers` replaces the default `{"kid", "typ"}` header as a
        whole (so a test can drop `kid` or set another one)."""
        header = dict(headers) if headers is not None else {"kid": self.kid, "typ": "JWT"}
        return jwt.encode(dict(claims), self.private, algorithm=ALGORITHM, headers=header)


def _without_none(claims: Claims, overrides: Mapping[str, object]) -> Claims:
    """Apply `overrides`; an override of None drops that claim (the sites' fakes' rule)."""
    merged = {**claims, **overrides}
    return {name: value for name, value in merged.items() if value is not None}


def access_token_claims(
    clock: Clock,
    *,
    audience: str,
    issuer: str | None = ISSUER,
    sub: str | None = OWNER_SUB,
    scope: str | None = "admin login",
    client_id: str | None = "test-client",
    acct: str | None = None,
    jti: str | None = None,
    lifetime: int = TOKEN_LIFETIME_SECONDS,
    **overrides: object,
) -> Claims:
    """Claims shaped like sandcorp-auth's (backend/services/tokens.py) at `clock.now()`.
    `acct="member"` makes a member token; owner tokens carry no `acct`. None drops a claim
    (`jti=None` generates one)."""
    iat = int(clock.now().timestamp())
    claims: Claims = {
        "iss": issuer,
        "sub": sub,
        "aud": audience,
        "client_id": client_id,
        "scope": scope,
        "iat": iat,
        "exp": iat + lifetime,
        "jti": jti or secrets.token_hex(8),
    }
    claims["acct"] = acct
    return _without_none(claims, overrides)


def id_token_claims(
    clock: Clock,
    *,
    client_id: str,
    nonce: str,
    issuer: str | None = ISSUER,
    sub: str | None = OWNER_SUB,
    acct: str | None = None,
    lifetime: int = TOKEN_LIFETIME_SECONDS,
    **overrides: object,
) -> Claims:
    """ID-token claims as sandcorp-auth issues them (services/oidc.py): `aud` = client_id."""
    iat = int(clock.now().timestamp())
    claims: Claims = {
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "iat": iat,
        "exp": iat + lifetime,
        "auth_time": iat,
        "nonce": nonce,
    }
    claims["acct"] = acct
    return _without_none(claims, overrides)


class FakeJwks:
    """sandcorp-auth's JWKS endpoint as a `JwksFetcher`. Serves `document`, counts `fetches`,
    raises `OSError` while `failing` is set. Signs with `key` (the newest)."""

    def __init__(self, *keys: SigningKey) -> None:
        self.keys: list[SigningKey] = list(keys) or [SigningKey()]
        self.key: SigningKey = self.keys[-1]
        self.document: object = {"keys": [k.jwk() for k in self.keys]}
        self.fetches = 0
        self.failing = False

    def __call__(self) -> object:
        self.fetches += 1
        if self.failing:
            raise OSError("JWKS unreachable")
        return self.document

    def serve(self, *keys: SigningKey) -> None:
        """Publish exactly `keys` (drop the rest). Signing stays with `key`."""
        self.keys = list(keys)
        self.document = {"keys": [k.jwk() for k in keys]}

    def rotate(self, kid: str) -> SigningKey:
        """sandcorp-auth `signing_keys rotate`: a new key signs from now on and the old ones stay
        published."""
        self.key = SigningKey(kid=kid)
        self.serve(*self.keys, self.key)
        return self.key

    def cache(self, clock: Clock) -> JwksCache:
        return JwksCache(self, clock)

    def issue_access_token(
        self,
        clock: Clock,
        *,
        audience: str,
        key: SigningKey | None = None,
        headers: Mapping[str, object] | None = None,
        **claims: object,
    ) -> str:
        """A signed access token: `access_token_claims` defaults, then `claims` by claim name
        (`sub=`, `scope=`, `acct="member"`, `exp=`; None drops one). `key` signs with another
        (e.g. unpublished) key; `headers` replaces the JWT header."""
        body = _without_none(access_token_claims(clock, audience=audience), claims)
        return (key or self.key).sign(body, headers=headers)

    def issue_id_token(
        self,
        clock: Clock,
        *,
        client_id: str,
        nonce: str,
        key: SigningKey | None = None,
        headers: Mapping[str, object] | None = None,
        **claims: object,
    ) -> str:
        """A signed ID token: `id_token_claims` defaults, then `claims` by claim name."""
        body = _without_none(id_token_claims(clock, client_id=client_id, nonce=nonce), claims)
        return (key or self.key).sign(body, headers=headers)


def bearer_header(token: str) -> dict[str, str]:
    """`{"Authorization": "Bearer …"}` for `headers=` of Django's test client and
    RequestFactory (Django ≥ 4.2) and of ninja's TestClient."""
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Grant:
    """One approved `/authorize` request, waiting for its code to be exchanged."""

    client_id: str
    redirect_uri: str
    code_challenge: str
    scope: str
    resource: str
    nonce: str | None
    sub: str
    acct: str | None
    access_overrides: dict[str, object]
    id_token_overrides: dict[str, object]


@dataclass
class FakeTokenEndpoint:
    """sandcorp-auth for the operator login: `approve()` plays `/authorize`, and the object is a
    `login.TokenTransport` that plays `POST /token` with the real checks (client_secret_basic,
    one-time code, same `redirect_uri`, PKCE S256). Every request lands in `requests`.

    `respond(status, body)` / `fail(exc)` make the next exchange return that instead.
    """

    jwks: FakeJwks
    clock: Clock
    client_id: str = "test-client"
    client_secret: str = "test-client-secret"
    issuer: str = ISSUER
    codes: dict[str, Grant] = field(default_factory=dict)
    requests: list[TokenRequest] = field(default_factory=list)
    _next: TransportResponse | BaseException | None = None

    # ── /authorize ──

    def approve(
        self,
        authorize_url: str,
        *,
        sub: str = OWNER_SUB,
        acct: str | None = None,
        scope: str | None = None,
        access_overrides: Mapping[str, object] | None = None,
        id_token_overrides: Mapping[str, object] | None = None,
    ) -> dict[str, str]:
        """Approve the request in `authorize_url` and return the callback query
        (`{"code", "state"}`). `scope` is what the token carries (default: what was asked)."""
        params = _query(authorize_url)
        if params.get("response_type") != "code":
            raise AssertionError("response_type must be code")
        if params.get("client_id") != self.client_id:
            raise AssertionError("unknown client_id")
        if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
            raise AssertionError("PKCE S256 is required")
        for name in ("redirect_uri", "state", "resource", "scope"):
            if not params.get(name):
                raise AssertionError(f"{name} is required")
        code = secrets.token_urlsafe(16)
        self.codes[code] = Grant(
            client_id=params["client_id"],
            redirect_uri=params["redirect_uri"],
            code_challenge=params["code_challenge"],
            scope=scope if scope is not None else params["scope"],
            resource=params["resource"],
            nonce=params.get("nonce"),
            sub=sub,
            acct=acct,
            access_overrides=dict(access_overrides or {}),
            id_token_overrides=dict(id_token_overrides or {}),
        )
        return {"code": code, "state": params["state"]}

    def approve_member(
        self, authorize_url: str, *, sub: str = MEMBER_SUB, scope: str | None = None
    ) -> dict[str, str]:
        """`approve` for a member (`acct="member"`, member sub)."""
        return self.approve(authorize_url, sub=sub, acct="member", scope=scope)

    def deny(self, authorize_url: str, error: str = "access_denied") -> dict[str, str]:
        """The callback query when the owner refuses (or auth refuses) the request."""
        return {"error": error, "state": _query(authorize_url).get("state", "")}

    # ── /token ──

    def respond(self, status: int, body: bytes | Mapping[str, object]) -> None:
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self._next = TransportResponse(status=status, body=payload)

    def fail(self, exc: BaseException) -> None:
        self._next = exc

    def __call__(self, request: TokenRequest) -> TransportResponse:
        self.requests.append(request)
        upcoming, self._next = self._next, None
        if isinstance(upcoming, BaseException):
            raise upcoming
        if upcoming is not None:
            return upcoming
        if not self._client_authenticated(request.headers.get("Authorization", "")):
            return _error(401, "invalid_client")
        form = request.form
        if form.get("grant_type") != "authorization_code":
            return _error(400, "unsupported_grant_type")
        grant = self.codes.pop(form.get("code", ""), None)  # a code works once
        if grant is None or grant.redirect_uri != form.get("redirect_uri"):
            return _error(400, "invalid_grant")
        verifier = form.get("code_verifier", "")
        if not hmac.compare_digest(_s256(verifier), grant.code_challenge):
            return _error(400, "invalid_grant")
        return TransportResponse(status=200, body=json.dumps(self._tokens(grant)).encode())

    def _client_authenticated(self, header: str) -> bool:
        scheme, _, encoded = header.partition(" ")
        if scheme != "Basic":
            return False
        try:
            raw = base64.b64decode(encoded, validate=True).decode()
        except binascii.Error, UnicodeDecodeError:
            return False
        client_id, sep, secret = raw.partition(":")
        return bool(sep) and (
            urllib.parse.unquote_plus(client_id) == self.client_id
            and hmac.compare_digest(urllib.parse.unquote_plus(secret), self.client_secret)
        )

    def _tokens(self, grant: Grant) -> dict[str, object]:
        access_claims = access_token_claims(
            self.clock,
            audience=grant.resource,
            issuer=self.issuer,
            sub=grant.sub,
            scope=grant.scope,
            client_id=grant.client_id,
            acct=grant.acct,
        )
        body: dict[str, object] = {
            "access_token": self.jwks.key.sign(
                _without_none(access_claims, grant.access_overrides)
            ),
            "token_type": "Bearer",
            "expires_in": TOKEN_LIFETIME_SECONDS,
            "refresh_token": secrets.token_urlsafe(16),
            "scope": grant.scope,
        }
        if "openid" in grant.scope.split(" "):
            id_claims = id_token_claims(
                self.clock,
                client_id=grant.client_id,
                nonce=grant.nonce or "",
                issuer=self.issuer,
                sub=grant.sub,
                acct=grant.acct,
            )
            body["id_token"] = self.jwks.key.sign(
                _without_none(id_claims, grant.id_token_overrides)
            )
        return body


def _query(url: str) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii", "replace")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _error(status: int, error: str) -> TransportResponse:
    return TransportResponse(status=status, body=json.dumps({"error": error}).encode())
