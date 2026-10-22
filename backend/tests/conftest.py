"""Shared fixtures for backend HTTP-boundary tests.

Fake adapters get registered here as they appear: `frozen_clock`, `recording_randomness`,
`fake_http` (documents by URL, host addresses by name).
`signing_key` gives a test an active token signing key.
`owner` is the owner account (before TOTP enrollment); `logged_in_client` is a test client that
finished password + TOTP (Django `login()` done), with `frozen_clock` running.
"""

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from adapters.clock import set_clock
from adapters.http import FetchedDocument, FetchError, set_http_client
from adapters.randomness import set_randomness
from oauth.models import Client as OAuthClient
from oauth.models import SigningKey
from services.owner import create_owner
from services.signing import create_signing_key
from services.totp import current_code, enrollment_device

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


class FakeHttp:
    """Answers `fetch_json` from documents the test put in, and `resolve` from a host table
    (every host resolves to a public address unless the test says otherwise)."""

    PUBLIC_ADDRESS = "93.184.215.14"

    def __init__(self) -> None:
        self.documents: dict[str, FetchedDocument] = {}
        self.addresses: dict[str, list[str]] = {}
        self.fetched: list[str] = []

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
        return self.addresses.get(host, [self.PUBLIC_ADDRESS])

    def fetch_json(self, url: str, *, max_bytes: int, timeout: float) -> FetchedDocument:
        self.fetched.append(url)
        if url not in self.documents:
            raise FetchError(f"no fake document at {url}")
        document = self.documents[url]
        return FetchedDocument(document.status, document.headers, document.body[: max_bytes + 1])


@pytest.fixture
def fake_http() -> Iterator[FakeHttp]:
    """Install a fake HTTP client; `put_json(url, doc)` registers a document, `fetched` records
    every fetch, `addresses[host] = [...]` overrides name resolution."""
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
