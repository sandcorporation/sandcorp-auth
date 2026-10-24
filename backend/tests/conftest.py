"""Shared fixtures for backend HTTP-boundary tests.

Fake adapters get registered here as they appear: `frozen_clock`, `recording_randomness`,
`fake_http` (documents by URL, host addresses by name), `fake_providers` (autouse: Google and
Kakao at the HTTP boundary, see `FakeProviders`).
`signing_key` gives a test an active token signing key.
`owner` is the owner account (before TOTP enrollment); `logged_in_client` is a test client that
finished password + TOTP (Django `login()` done), with `frozen_clock` running.
`make_member()` makes a Sandcorp member account the way a social login will (#36); `member` is
one with a Google identity, `member_client` a test client logged in as that member.
"""

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone
from jwt.algorithms import RSAAlgorithm

from adapters.clock import set_clock
from adapters.http import FetchedDocument, FetchError, set_http_client
from adapters.randomness import set_randomness
from adapters.social_http import set_provider_http
from oauth.models import Client as OAuthClient
from oauth.models import SigningKey
from services.members import ExternalProfile, create_member
from services.owner import create_owner
from services.signing import create_signing_key
from services.totp import current_code, enrollment_device

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

if TYPE_CHECKING:  # the test client's response type exists only in django-stubs
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

OWNER_USERNAME = "farrar142"
OWNER_PASSWORD = "correct horse battery staple"


class FrozenClock:
    """A clock that only moves when the test says so."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[FrozenClock]:
    """Freeze `get_clock().now()` at 2026-01-01T00:00:00Z; `advance(seconds)` moves it.

    Django's own `timezone.now()` (session expiry, last_login) follows the same clock.
    """
    clock = FrozenClock(datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(timezone, "now", clock.now)
    previous = set_clock(clock)
    yield clock
    set_clock(previous)


class RecordingRandomness:
    """Deterministic, distinct bytes per call; remembers everything it handed out."""

    def __init__(self) -> None:
        self.issued: list[bytes] = []

    def token_bytes(self, n: int) -> bytes:
        block = hashlib.sha256(len(self.issued).to_bytes(4, "big")).digest()
        out = (block * (n // len(block) + 1))[:n]
        self.issued.append(out)
        return out


@pytest.fixture
def recording_randomness() -> Iterator[RecordingRandomness]:
    """Install a deterministic randomness source whose outputs the test can inspect."""
    randomness = RecordingRandomness()
    previous = set_randomness(randomness)
    yield randomness
    set_randomness(previous)


@pytest.fixture
def signing_key(db: None) -> SigningKey:
    """An active signing key (same as `manage.py signing_keys create`)."""
    return create_signing_key()


@pytest.fixture
def owner(db: None) -> User:
    """The owner account, as `manage.py owner create` makes it (TOTP not enrolled yet)."""
    return create_owner(OWNER_USERNAME, OWNER_PASSWORD)


def totp_code(user: User) -> str:
    """The code the owner's authenticator shows at `get_clock().now()`."""
    return current_code(enrollment_device(user))


@pytest.fixture
def logged_in_client(client: Client, owner: User, frozen_clock: FrozenClock) -> Client:
    """A client logged in with password + TOTP (enrolled on the way). The code's time step is
    used up: advance the clock 30 s before asking for another code."""
    client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    client.post("/totp/setup", {"code": totp_code(owner)})
    return client


MEMBER_NAME = "김회원"
MEMBER_EMAIL = "member@example.com"


def make_member(
    provider: str = "google",
    provider_sub: str = "108234567890123456789",
    *,
    email: str = MEMBER_EMAIL,
    email_verified: bool = True,
    name: str = MEMBER_NAME,
) -> User:
    """A member account with one external identity (the login flow itself comes in #36)."""
    return create_member(
        ExternalProfile(
            provider=provider,
            provider_sub=provider_sub,
            email=email,
            email_verified=email_verified,
            display_name=name,
        )
    )


@pytest.fixture
def member(db: None) -> User:
    """A member who signed up with Google (verified email, display name)."""
    return make_member()


@pytest.fixture
def member_client(client: Client, member: User, frozen_clock: "FrozenClock") -> Client:
    """A test client whose session is the member's (Django `login()` done)."""
    client.force_login(member)
    return client


class FakeHttp:
    """Answers `fetch_json` from documents the test put in, and `resolve` from a host table
    (every host resolves to a public address unless the test says otherwise)."""

    PUBLIC_ADDRESS = "93.184.215.14"

    def __init__(self) -> None:
        self.documents: dict[str, FetchedDocument] = {}
        self.addresses: dict[str, list[str]] = {}
        # Answers for successive `resolve` calls of one host, consumed before `addresses`
        # (a DNS rebinding: public at check time, private afterwards).
        self.rebinding: dict[str, list[list[str]]] = {}
        self.resolved: list[str] = []
        self.fetched: list[str] = []
        # The address each fetch was pinned to, parallel to `fetched`.
        self.fetched_addresses: list[str] = []

    def put_json(
        self,
        url: str,
        document: object,
        *,
        cache_control: str | None = None,
        content_type: str = "application/json",
    ) -> None:
        headers = {"content-type": content_type}
        if cache_control is not None:
            headers["cache-control"] = cache_control
        body = document if isinstance(document, bytes) else json.dumps(document).encode()
        self.documents[url] = FetchedDocument(200, headers, body)

    def resolve(self, host: str) -> list[str]:
        self.resolved.append(host)
        if self.rebinding.get(host):
            return self.rebinding[host].pop(0)
        return self.addresses.get(host, [self.PUBLIC_ADDRESS])

    def fetch_json(
        self, url: str, *, address: str, max_bytes: int, timeout: float
    ) -> FetchedDocument:
        self.fetched.append(url)
        self.fetched_addresses.append(address)
        if url not in self.documents:
            raise FetchError(f"no fake document at {url}")
        document = self.documents[url]
        return FetchedDocument(document.status, document.headers, document.body[: max_bytes + 1])


@pytest.fixture
def fake_http() -> Iterator[FakeHttp]:
    """Install a fake HTTP client; `put_json(url, doc)` registers a document, `fetched` records
    every fetch (`fetched_addresses` the address it was pinned to), `addresses[host] = [...]`
    overrides name resolution, `resolved` records every resolution."""
    fake = FakeHttp()
    previous = set_http_client(fake)
    yield fake
    set_http_client(previous)


def cimd_document(url: str, **overrides: object) -> dict[str, object]:
    """A valid client metadata document published at `url`."""
    document: dict[str, object] = {
        "client_id": url,
        "client_name": "Example MCP client",
        "redirect_uris": ["https://app.example/callback", "http://localhost:3000/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    document.update(overrides)
    return document


CIMD_URL = "https://app.example/client.json"


def register(client: Client, **metadata: object) -> tuple[int, dict[str, object]]:
    """POST /register with a valid public-client body, overridden by `metadata`."""
    body: dict[str, object] = {
        "client_name": "Claude Code",
        "redirect_uris": ["http://localhost:33418/callback"],
    }
    body.update(metadata)
    response = client.post("/register", json.dumps(body), content_type="application/json")
    payload: dict[str, object] = response.json()
    return response.status_code, payload


@pytest.fixture
def dcr_client(client: Client, db: None) -> OAuthClient:
    """A public client registered through POST /register (redirect_uri
    http://localhost:33418/callback)."""
    status, payload = register(client)
    assert status == 201, payload
    return OAuthClient.objects.get(client_id=payload["client_id"])


@pytest.fixture
def cimd_client(fake_http: FakeHttp, frozen_clock: FrozenClock, db: None) -> OAuthClient:
    """A CIMD client (client_id `CIMD_URL`) fetched through the fake HTTP adapter at the
    frozen clock's start; cached for an hour."""
    from oauth.server import server

    fake_http.put_json(CIMD_URL, cimd_document(CIMD_URL))
    found: OAuthClient | None = server.query_client(CIMD_URL)
    assert found is not None
    return found


PORTFOLIO = "https://sandcorp.co.kr/mcp"


class FakeProviders:
    """Stands in for Google and Kakao at the HTTP boundary (`adapters.social_http`), so the
    real id_token checks run against tokens signed by a test RSA key.

    A test registers what the provider will say for a code: `google_codes[code] = claims`
    (signed with the test key; a `str` is sent as the id_token as it is) and
    `kakao_codes[code] = user` (the `/v2/user/me` document). Codes are single use. `posted`
    records every form post (url, data); anything else raises FetchError."""

    def __init__(self) -> None:
        self.google_codes: dict[str, dict[str, object] | str] = {}
        self.kakao_codes: dict[str, dict[str, object]] = {}
        self.kakao_tokens: dict[str, dict[str, object]] = {}
        self.posted: list[tuple[str, dict[str, str]]] = []
        self.requested: list[str] = []

    @staticmethod
    def sign(claims: dict[str, object], *, key: "RSAPrivateKey | None" = None) -> str:
        return jwt.encode(
            claims, key or _google_key(), algorithm="RS256", headers={"kid": GOOGLE_KID}
        )

    @staticmethod
    def _json(document: object, status: int = 200) -> FetchedDocument:
        return FetchedDocument(
            status, {"content-type": "application/json"}, json.dumps(document).encode()
        )

    def post_form(self, url: str, data: "Mapping[str, str]") -> FetchedDocument:
        from services.social_providers import GOOGLE_TOKEN_URL, KAKAO_TOKEN_URL

        self.posted.append((url, dict(data)))
        code = data.get("code", "")
        if url == GOOGLE_TOKEN_URL:
            claims = self.google_codes.pop(code, None)
            if claims is None:
                return self._json({"error": "invalid_grant"}, 400)
            token = claims if isinstance(claims, str) else self.sign(claims)
            return self._json({"access_token": "ya29.fake", "id_token": token})
        if url == KAKAO_TOKEN_URL:
            user = self.kakao_codes.pop(code, None)
            if user is None:
                return self._json({"error": "invalid_grant"}, 400)
            access_token = f"kakao-at-{len(self.kakao_tokens)}"
            self.kakao_tokens[access_token] = user
            return self._json({"access_token": access_token, "token_type": "bearer"})
        raise FetchError(f"no fake provider at {url}")

    def get(self, url: str, *, headers: "Mapping[str, str]") -> FetchedDocument:
        from services.social_providers import GOOGLE_JWKS_URL, KAKAO_USER_URL

        self.requested.append(url)
        if url == GOOGLE_JWKS_URL:
            jwk = json.loads(RSAAlgorithm.to_jwk(_google_key().public_key()))
            return self._json({"keys": [{**jwk, "kid": GOOGLE_KID, "alg": "RS256", "use": "sig"}]})
        if url == KAKAO_USER_URL:
            token = headers.get("Authorization", "").removeprefix("Bearer ")
            if token not in self.kakao_tokens:
                return self._json({"msg": "this access token does not exist", "code": -401}, 401)
            return self._json(self.kakao_tokens[token])
        raise FetchError(f"no fake provider at {url}")


GOOGLE_KID = "test-google-kid"
_GOOGLE_KEYS: "list[RSAPrivateKey]" = []


def _google_key() -> "RSAPrivateKey":
    """One RSA key per test run (generating one is slow)."""
    if not _GOOGLE_KEYS:
        _GOOGLE_KEYS.append(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    return _GOOGLE_KEYS[0]


@pytest.fixture(autouse=True)
def fake_providers() -> Iterator[FakeProviders]:
    """Every test talks to fake Google/Kakao (never the real ones)."""
    fake = FakeProviders()
    previous = set_provider_http(fake)
    yield fake
    set_provider_http(previous)


NEWS = "https://news.sandcorp.co.kr/mcp"
PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-padding-for-43-chars"


def use_https(client: Client) -> Client:
    """Make every later request of `client` arrive over https (as behind NPMplus): authlib
    refuses OAuth requests over plain http."""
    client.defaults["HTTP_X_FORWARDED_PROTO"] = "https"
    return client


def authorize_query(oauth_client: OAuthClient, **overrides: str | None) -> str:
    """A valid /authorize query for `oauth_client` (its first redirect URI, the portfolio
    resource, scope `admin`, S256 challenge of `PKCE_VERIFIER`). An override of None drops
    that parameter."""
    from authlib.oauth2.rfc7636 import create_s256_code_challenge

    params: dict[str, str | None] = {
        "response_type": "code",
        "client_id": oauth_client.client_id,
        "redirect_uri": oauth_client.redirect_uris[0],
        "state": "xyz",
        "code_challenge": create_s256_code_challenge(PKCE_VERIFIER),
        "code_challenge_method": "S256",
        "resource": PORTFOLIO,
        "scope": "admin",
    }
    params.update(overrides)
    return urlencode({key: value for key, value in params.items() if value is not None})


def obtain_authorization_code(
    client: Client, oauth_client: OAuthClient, **overrides: str | None
) -> tuple[str, str]:
    """Run /authorize as the logged-in owner (allowing on the consent screen if it shows) and
    return `(code, code_verifier)` from the redirect."""
    use_https(client)
    url = "/authorize?" + authorize_query(oauth_client, **overrides)
    response = client.get(url)
    if response.status_code == 200:
        response = client.post(url, {"decision": "allow"})
    assert response.status_code == 302, response.content
    query = parse_qs(urlsplit(response["Location"]).query)
    return query["code"][0], PKCE_VERIFIER


TOKEN_FIELDS = {"access_token", "token_type", "expires_in", "refresh_token", "scope"}


def exchange_code(
    client: Client, oauth_client: OAuthClient, code: str, verifier: str, /, **overrides: str | None
) -> "TestResponse":
    """POST /token with `grant_type=authorization_code` for `oauth_client` (a public client:
    `client_id` in the form). An override of None drops that field."""
    use_https(client)
    form: dict[str, str | None] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": oauth_client.redirect_uris[0],
        "client_id": oauth_client.client_id,
        "code_verifier": verifier,
    }
    form.update(overrides)
    return client.post("/token", {key: value for key, value in form.items() if value is not None})


def obtain_tokens(
    client: Client, oauth_client: OAuthClient, **authorize_overrides: str | None
) -> dict[str, str | int]:
    """Authorize as the logged-in owner, exchange the code, and return the token response
    (`access_token`, `token_type`, `expires_in`, `refresh_token`, `scope`)."""
    code, verifier = obtain_authorization_code(client, oauth_client, **authorize_overrides)
    response = exchange_code(client, oauth_client, code, verifier)
    assert response.status_code == 200, response.content
    tokens: dict[str, str | int] = response.json()
    return tokens


def refresh(
    client: Client, oauth_client: OAuthClient, refresh_token: str, /, **overrides: str | None
) -> "TestResponse":
    """POST /token with `grant_type=refresh_token` for `oauth_client` (a public client:
    `client_id` in the form). An override of None drops that field."""
    use_https(client)
    form: dict[str, str | None] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": oauth_client.client_id,
    }
    form.update(overrides)
    return client.post("/token", {key: value for key, value in form.items() if value is not None})
