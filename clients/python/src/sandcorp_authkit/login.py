"""Operator (admin-screen) login as a confidential client of sandcorp-auth:
`/authorize` with state + PKCE S256 + nonce → callback → `POST /token` (client_secret_basic) →
access token checked by the §3 rules → ID token checked (§10, when present).

Rules: docs/resource-server-token-validation.md §7 and §10. No Django: the attempt store is an
interface (`SessionAttemptStore` adapts a Django session), the HTTP call is an injectable
`TokenTransport`, and every setting is an argument (`LoginConfig`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field
from typing import Literal, NotRequired, Protocol, TypedDict, TypeIs

import jwt

from .tokens import (
    ACCOUNT_KIND_CLAIM,
    ALGORITHM,
    EXP_LEEWAY_SECONDS,
    AccessToken,
    ClaimsHook,
    Clock,
    InsufficientScope,
    JwksCache,
    TokenRejected,
    validate_access_token,
)

logger = logging.getLogger(__name__)

ATTEMPT_MAX_AGE_SECONDS = 600
TOKEN_TIMEOUT_SECONDS = 5.0
TOKEN_MAX_BYTES = 64 * 1024
LOGIN_SCOPE = "login"
ID_TOKEN_REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat", "nonce")

type RejectReason = Literal["config", "state", "expired", "denied", "exchange", "token"]
"""Why a login failed — for logs and for the site to pick a page. Never show it in a URL."""


class LoginRejected(Exception):
    def __init__(self, reason: RejectReason) -> None:
        super().__init__(reason)
        self.reason: RejectReason = reason


class TokenExchangeFailed(Exception):
    """`POST /token` did not give a usable response. The message is for the server log."""


class IdTokenRejected(Exception):
    """The ID token failed a §10 check. The message is for the server log."""


@dataclass(frozen=True)
class LoginConfig:
    """The site's confidential-client registration. Build it from settings in the adapter."""

    client_id: str
    client_secret: str
    redirect_uri: str
    """Exactly as registered (a trailing slash matters, §7)."""
    authorize_url: str
    token_url: str
    issuer: str
    resource: str
    """This site's resource URL: the access token's `aud`."""
    scope: str = LOGIN_SCOPE
    """What `/authorize` asks for. With `openid` in it the ID token becomes mandatory."""

    @property
    def complete(self) -> bool:
        return all(
            (
                self.client_id,
                self.client_secret,
                self.redirect_uri,
                self.authorize_url,
                self.token_url,
                self.issuer,
                self.resource,
                self.scope,
            )
        )

    @property
    def wants_id_token(self) -> bool:
        return "openid" in self.scope.split(" ")


# ── attempts ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LoginAttempt:
    state: str
    code_verifier: str
    nonce: str
    started_at: int
    """Unix seconds on the login clock."""
    extra: Mapping[str, str] = field(default_factory=dict)
    """The site's own values carried through the login (`next`, an invite, the entry)."""

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "code_verifier": self.code_verifier,
            "nonce": self.nonce,
            "started_at": self.started_at,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: object) -> LoginAttempt | None:
        """None for anything that is not a dict `to_dict` wrote."""
        if not isinstance(data, dict):
            return None
        state, verifier, nonce = data.get("state"), data.get("code_verifier"), data.get("nonce")
        started, extra = data.get("started_at"), data.get("extra", {})
        if not (
            isinstance(state, str)
            and isinstance(verifier, str)
            and isinstance(nonce, str)
            and isinstance(started, int)
            and not isinstance(started, bool)
            and isinstance(extra, dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in extra.items())
        ):
            return None
        return cls(state, verifier, nonce, started, dict(extra))


class AttemptStore(Protocol):
    """Where the attempt waits for its callback — server-side (§7: never the URL; the
    `code_verifier` should not ride in a readable cookie). One slot: a newer `save` replaces
    the older attempt."""

    def save(self, attempt: LoginAttempt) -> None: ...

    def take(self) -> LoginAttempt | None:
        """Return the attempt and forget it, so a callback can run only once."""
        ...


class SessionAttemptStore:
    """An `AttemptStore` over a session mapping (Django's `request.session` works as is)."""

    def __init__(
        self, session: MutableMapping[str, object], key: str = "sandcorp_authkit.login"
    ) -> None:
        self.session = session
        self.key = key

    def save(self, attempt: LoginAttempt) -> None:
        self.session[self.key] = attempt.to_dict()

    def take(self) -> LoginAttempt | None:
        return LoginAttempt.from_dict(self.session.pop(self.key, None))


# ── the token endpoint (external boundary) ─────────────────────────────────────


@dataclass(frozen=True)
class TokenRequest:
    url: str
    headers: Mapping[str, str]
    form: Mapping[str, str]
    timeout: float
    max_bytes: int

    @property
    def body(self) -> bytes:
        return urllib.parse.urlencode(self.form).encode()


@dataclass(frozen=True)
class TransportResponse:
    status: int
    body: bytes


type TokenTransport = Callable[[TokenRequest], TransportResponse]
"""Sends a `TokenRequest`. Network failures raise `OSError`; any HTTP status is a response.
Should read at most `max_bytes + 1` bytes."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None  # a redirect from /token is a failure, not something to follow


_opener = urllib.request.build_opener(_NoRedirects)


def urllib_transport(request: TokenRequest) -> TransportResponse:
    """The default transport: standard-library `urllib`, no redirects followed."""
    http_request = urllib.request.Request(
        request.url, data=request.body, method="POST", headers=dict(request.headers)
    )
    try:
        with _opener.open(http_request, timeout=request.timeout) as response:
            return TransportResponse(response.status, response.read(request.max_bytes + 1))
    except urllib.error.HTTPError as exc:  # 4xx/5xx (and unfollowed 3xx) still have a body
        with exc:
            return TransportResponse(exc.code, exc.read(request.max_bytes + 1))


class TokenResponse(TypedDict):
    access_token: str
    token_type: str
    id_token: NotRequired[str]
    scope: NotRequired[str]
    refresh_token: NotRequired[str]
    expires_in: NotRequired[int]


def _form_quote(value: str) -> str:
    # RFC 6749 2.3.1 form-encodes id and secret before Basic. Percent-encoding everything
    # (no `+` for space) decodes the same under unquote and unquote_plus.
    return urllib.parse.quote(value, safe="")


def exchange_code(
    config: LoginConfig,
    *,
    code: str,
    code_verifier: str,
    transport: TokenTransport | None = None,
    timeout: float = TOKEN_TIMEOUT_SECONDS,
    max_bytes: int = TOKEN_MAX_BYTES,
) -> TokenResponse:
    """`POST /token` with client_secret_basic (§7). Raises `TokenExchangeFailed` on a network
    error, a status other than 200, a body over `max_bytes`, non-JSON, or no usable
    `access_token`/`token_type: Bearer`."""
    credentials = f"{_form_quote(config.client_id)}:{_form_quote(config.client_secret)}"
    request = TokenRequest(
        url=config.token_url,
        headers={
            "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        form={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirect_uri,
            "code_verifier": code_verifier,
        },
        timeout=timeout,
        max_bytes=max_bytes,
    )
    try:
        response = (transport or urllib_transport)(request)
    except (OSError, http.client.HTTPException, ValueError) as exc:  # ValueError: bad URL
        raise TokenExchangeFailed(f"token endpoint unreachable: {exc!r}") from exc
    if len(response.body) > max_bytes:
        raise TokenExchangeFailed("token response too large")
    if response.status != 200:
        raise TokenExchangeFailed(f"token endpoint said {response.status}: {_error_code(response)}")
    try:
        payload: object = json.loads(response.body)
    except ValueError as exc:  # also UnicodeDecodeError
        raise TokenExchangeFailed("token response is not JSON") from exc
    if not isinstance(payload, dict):
        raise TokenExchangeFailed("token response is not an object")
    access, token_type = payload.get("access_token"), payload.get("token_type")
    if not isinstance(access, str) or not access:
        raise TokenExchangeFailed("no access_token")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise TokenExchangeFailed("token_type is not Bearer")
    result = TokenResponse(access_token=access, token_type=token_type)
    if (id_token := _optional_str(payload, "id_token")) is not None:
        result["id_token"] = id_token
    if (scope := _optional_str(payload, "scope")) is not None:
        result["scope"] = scope
    if (refresh := _optional_str(payload, "refresh_token")) is not None:
        result["refresh_token"] = refresh
    return result


def _optional_str(payload: Mapping[str, object], name: str) -> str | None:
    value = payload.get(name)
    if name in payload and not isinstance(value, str):
        raise TokenExchangeFailed(f"{name} is not a string")
    return value if isinstance(value, str) else None


def _error_code(response: TransportResponse) -> str:
    try:
        payload = json.loads(response.body)
    except ValueError:
        return "(no JSON body)"
    error = payload.get("error") if isinstance(payload, dict) else None
    return error if isinstance(error, str) else "(no error code)"


# ── ID token (§10) ─────────────────────────────────────────────────────────────


class IdentityClaims(TypedDict):
    sub: str
    name: NotRequired[str]
    email: NotRequired[str]
    email_verified: NotRequired[bool]


def verify_id_token(
    id_token: str,
    *,
    issuer: str,
    client_id: str,
    nonce: str,
    access: AccessToken,
    jwks: JwksCache,
    clock: Clock,
) -> IdentityClaims:
    """§10 ID-token checks, flow's variant tightened: EdDSA and a `kid` from the same JWKS;
    `iss` exactly `issuer`; `aud` exactly `client_id` (a string — lists are refused); `azp`,
    if present, is `client_id`; `exp` with the 30 s leeway; `iat` an integer; `nonce` equal
    (constant time); `sub` and `acct` the same as the access token's.

    `at_hash` is not checked: OIDC defines none for EdDSA, and sandcorp-auth issues none."""
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise IdTokenRejected("malformed ID token") from exc
    kid = header.get("kid")
    if header.get("alg") != ALGORITHM or not isinstance(kid, str):
        raise IdTokenRejected("alg must be EdDSA and kid must be present")
    key = jwks.key_for(kid)
    if key is None:
        raise IdTokenRejected("unknown kid")
    try:
        claims: dict[str, object] = jwt.decode(
            id_token,
            key,
            algorithms=[ALGORITHM],
            options={
                "require": list(ID_TOKEN_REQUIRED_CLAIMS),
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise IdTokenRejected("bad signature or missing claim") from exc
    sub, exp, iat, claim_nonce = claims["sub"], claims["exp"], claims["iat"], claims["nonce"]
    if not (
        isinstance(sub, str) and _is_int(exp) and _is_int(iat) and isinstance(claim_nonce, str)
    ):
        raise IdTokenRejected("claim has the wrong type")
    if claims["iss"] != issuer:
        raise IdTokenRejected("wrong issuer")
    if claims["aud"] != client_id:
        raise IdTokenRejected("wrong audience")
    if "azp" in claims and claims["azp"] != client_id:
        raise IdTokenRejected("wrong azp")
    if clock.now().timestamp() > exp + EXP_LEEWAY_SECONDS:
        raise IdTokenRejected("expired")
    if not hmac.compare_digest(claim_nonce.encode(), nonce.encode()):
        raise IdTokenRejected("nonce mismatch")
    if sub != access.sub:
        raise IdTokenRejected("sub differs from the access token")
    if claims.get(ACCOUNT_KIND_CLAIM) != access.acct:
        raise IdTokenRejected("acct differs from the access token")

    identity = IdentityClaims(sub=sub)
    name, email, verified = claims.get("name"), claims.get("email"), claims.get("email_verified")
    if isinstance(name, str):
        identity["name"] = name
    if isinstance(email, str):
        identity["email"] = email
    if isinstance(verified, bool):
        identity["email_verified"] = verified
    return identity


def _is_int(value: object) -> TypeIs[int]:
    return isinstance(value, int) and not isinstance(value, bool)


# ── the flow ───────────────────────────────────────────────────────────────────


def code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def start_login(
    config: LoginConfig,
    store: AttemptStore,
    *,
    clock: Clock,
    extra: Mapping[str, str] | None = None,
) -> str:
    """Make a fresh state, PKCE verifier and nonce, save the attempt, and return the
    `/authorize` URL to redirect to. `LoginRejected("config")` if the config is incomplete."""
    if not config.complete:
        raise LoginRejected("config")
    attempt = LoginAttempt(
        state=secrets.token_urlsafe(32),
        code_verifier=secrets.token_urlsafe(64),  # 86 characters: RFC 7636 wants 43–128
        nonce=secrets.token_urlsafe(32),
        started_at=int(clock.now().timestamp()),
        extra=dict(extra or {}),
    )
    store.save(attempt)
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": config.scope,
            "resource": config.resource,
            "state": attempt.state,
            "nonce": attempt.nonce,
            "code_challenge": code_challenge(attempt.code_verifier),
            "code_challenge_method": "S256",
        }
    )
    return f"{config.authorize_url}?{query}"


@dataclass(frozen=True)
class LoginResult:
    access: AccessToken
    """The verified access token: `sub`, `scopes`, `acct`. Do not store the raw token."""
    identity: IdentityClaims | None
    """From the ID token when one came (always, with `openid` in the scope)."""
    extra: Mapping[str, str]
    """What `start_login(extra=…)` carried."""


def complete_login(
    query: Mapping[str, str],
    config: LoginConfig,
    store: AttemptStore,
    *,
    jwks: JwksCache,
    clock: Clock,
    required_scope: str = LOGIN_SCOPE,
    extra_claims_hook: ClaimsHook | None = None,
    transport: TokenTransport | None = None,
) -> LoginResult:
    """Check the callback `query` end to end, or raise `LoginRejected(reason)`.

    Order: config → the attempt is taken (gone even if what follows fails) → `state`
    (constant time) → attempt age ≤ 600 s → `error` → `code` → exchange → access token by the
    §3 rules (`aud` = `config.resource`, `required_scope`, the hook — e.g. `owner_only`) and
    `client_id` = this client → ID token (§10) if `openid` was asked or one came anyway.
    What the site does with the account (admin scope, member vs owner entry) is its own check.
    """
    if not config.complete:
        raise LoginRejected("config")
    attempt = store.take()
    state = query.get("state", "")
    if attempt is None or not hmac.compare_digest(state.encode(), attempt.state.encode()):
        logger.info("operator login: no attempt or state mismatch")
        raise LoginRejected("state")
    if clock.now().timestamp() > attempt.started_at + ATTEMPT_MAX_AGE_SECONDS:
        logger.info("operator login: attempt expired")
        raise LoginRejected("expired")
    if query.get("error"):
        logger.info("operator login: authorization server refused (%s)", query.get("error"))
        raise LoginRejected("denied")
    code = query.get("code")
    if not code:
        raise LoginRejected("exchange")
    try:
        tokens = exchange_code(
            config, code=code, code_verifier=attempt.code_verifier, transport=transport
        )
    except TokenExchangeFailed as exc:
        logger.info("operator login: code exchange failed (%s)", exc)
        raise LoginRejected("exchange") from exc
    try:
        access = validate_access_token(
            tokens["access_token"],
            issuer=config.issuer,
            audience=config.resource,
            required_scope=required_scope,
            jwks=jwks,
            clock=clock,
            extra_claims_hook=extra_claims_hook,
        )
    except (TokenRejected, InsufficientScope) as exc:
        logger.info("operator login: access token refused (%r)", exc)
        raise LoginRejected("token") from exc
    if access.client_id != config.client_id:
        logger.info("operator login: the access token belongs to another client")
        raise LoginRejected("token")

    identity: IdentityClaims | None = None
    id_token = tokens.get("id_token")
    if id_token is None and config.wants_id_token:
        logger.info("operator login: openid asked but no ID token")
        raise LoginRejected("token")
    if id_token is not None:
        try:
            identity = verify_id_token(
                id_token,
                issuer=config.issuer,
                client_id=config.client_id,
                nonce=attempt.nonce,
                access=access,
                jwks=jwks,
                clock=clock,
            )
        except IdTokenRejected as exc:
            logger.info("operator login: ID token refused (%s)", exc)
            raise LoginRejected("token") from exc
    return LoginResult(access=access, identity=identity, extra=attempt.extra)
