"""Confidential clients: the sites' admin screens log in through the code flow with
`client_secret_basic` (or `client_secret_post`), PKCE still required, `scope=login`."""

import base64
import io
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import SigningKey
from services.confidential_clients import create_confidential_client
from tests.conftest import (
    NEWS,
    OWNER_USERNAME,
    PORTFOLIO,
    TOKEN_FIELDS,
    FrozenClock,
    authorize_query,
    obtain_authorization_code,
    use_https,
)
from tests.reference_validator import JwksCache, validate_access_token
from tests.test_signing_keys import jwks_fetcher

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db

PORTFOLIO_CALLBACK = "https://sandcorp.co.kr/x7q/oauth/callback/"
NEWS_CALLBACK = "https://news.sandcorp.co.kr/auth/callback"

ConfidentialClient = tuple[OAuthClient, str]


@pytest.fixture
def owner_client(logged_in_client: Client, signing_key: SigningKey) -> Client:
    return logged_in_client


@pytest.fixture
def portfolio_site_client(db: None) -> ConfidentialClient:
    """The portfolio site's admin login client (trailing slash in its callback), and its
    secret."""
    issued = create_confidential_client("sandcorp.co.kr 관리", [PORTFOLIO_CALLBACK], actor="test")
    return issued.client, issued.secret


@pytest.fixture
def news_site_client(db: None) -> ConfidentialClient:
    """The news site's admin login client (no trailing slash), and its secret."""
    issued = create_confidential_client("뉴스 관리", [NEWS_CALLBACK], actor="test")
    return issued.client, issued.secret


def basic(client_id: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


def post_token(
    client: Client, form: dict[str, str | None], authorization: str | None = None
) -> "TestResponse":
    """POST /token over https; `authorization` is the Authorization header, None for none."""
    use_https(client)
    body = {key: value for key, value in form.items() if value is not None}
    if authorization is None:
        return client.post("/token", body)
    return client.post("/token", body, HTTP_AUTHORIZATION=authorization)


def code_form(oauth_client: OAuthClient, code: str, verifier: str) -> dict[str, str | None]:
    """The authorization_code form a site sends with Basic auth: no `client_id`."""
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": oauth_client.redirect_uris[0],
        "code_verifier": verifier,
    }


def login_code(client: Client, oauth_client: OAuthClient, resource: str) -> tuple[str, str]:
    return obtain_authorization_code(client, oauth_client, resource=resource, scope="login")


def login_tokens(
    client: Client, site: ConfidentialClient, resource: str = PORTFOLIO
) -> dict[str, str | int]:
    oauth_client, secret = site
    code, verifier = login_code(client, oauth_client, resource)
    response = post_token(
        client, code_form(oauth_client, code, verifier), basic(oauth_client.client_id, secret)
    )
    assert response.status_code == 200, response.content
    tokens: dict[str, str | int] = response.json()
    return tokens


def refresh_form(refresh_token: str | int) -> dict[str, str | None]:
    return {"grant_type": "refresh_token", "refresh_token": str(refresh_token)}


def oauth_error(response: "TestResponse", status: int) -> str:
    """The RFC 6749 5.2 error code, after checking the status and the body's shape."""
    assert response.status_code == status, response.content
    body = response.json()
    assert set(body) == {"error", "error_description"}, body
    error: str = body["error"]
    return error


@pytest.mark.parametrize(
    ("site_fixture", "resource"),
    [("portfolio_site_client", PORTFOLIO), ("news_site_client", NEWS)],
)
def test_site_admin_login_with_client_secret_basic(
    owner_client: Client,
    frozen_clock: FrozenClock,
    request: pytest.FixtureRequest,
    site_fixture: str,
    resource: str,
) -> None:
    site: ConfidentialClient = request.getfixturevalue(site_fixture)

    tokens = login_tokens(owner_client, site, resource)

    assert set(tokens) == TOKEN_FIELDS
    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == "login"
    verified = validate_access_token(
        str(tokens["access_token"]),
        jwks=JwksCache(jwks_fetcher(owner_client), frozen_clock),
        audience=resource,
        owner_sub=OWNER_USERNAME,
        required_scope="login",
        clock=frozen_clock,
    )
    assert verified is not None


def test_client_secret_post_is_accepted(
    owner_client: Client, portfolio_site_client: ConfidentialClient
) -> None:
    oauth_client, secret = portfolio_site_client
    code, verifier = login_code(owner_client, oauth_client, PORTFOLIO)
    form = code_form(oauth_client, code, verifier)
    form |= {"client_id": oauth_client.client_id, "client_secret": secret}

    response = post_token(owner_client, form)

    assert response.status_code == 200, response.content
    assert response.json()["scope"] == "login"


def test_wrong_secret_is_invalid_client_with_basic_challenge(
    owner_client: Client, portfolio_site_client: ConfidentialClient
) -> None:
    oauth_client, _ = portfolio_site_client
    code, verifier = login_code(owner_client, oauth_client, PORTFOLIO)

    response = post_token(
        owner_client, code_form(oauth_client, code, verifier), basic(oauth_client.client_id, "x")
    )

    assert oauth_error(response, 401) == "invalid_client"
    challenge = response["WWW-Authenticate"]
    assert challenge.startswith('Basic realm="')
    assert 'error="invalid_client"' in challenge
    assert response["Cache-Control"] == "no-store"


@pytest.mark.parametrize("auth", ["form_client_id_only", "basic_empty_secret"])
def test_missing_secret_is_invalid_client(
    owner_client: Client, portfolio_site_client: ConfidentialClient, auth: str
) -> None:
    oauth_client, _ = portfolio_site_client
    code, verifier = login_code(owner_client, oauth_client, PORTFOLIO)
    form = code_form(oauth_client, code, verifier)
    if auth == "form_client_id_only":  # token_endpoint_auth_method "none"
        response = post_token(owner_client, form | {"client_id": oauth_client.client_id})
    else:
        response = post_token(owner_client, form, basic(oauth_client.client_id, ""))

    assert oauth_error(response, 401) == "invalid_client"


def test_redirect_uri_must_match_exactly_on_authorize(
    owner_client: Client, portfolio_site_client: ConfidentialClient
) -> None:
    oauth_client, _ = portfolio_site_client
    use_https(owner_client)
    query = authorize_query(
        oauth_client, redirect_uri=PORTFOLIO_CALLBACK.rstrip("/"), scope="login"
    )

    response = owner_client.get("/authorize?" + query)

    assert response.status_code == 400
    assert "Location" not in response


def test_redirect_uri_must_match_exactly_on_exchange(
    owner_client: Client, portfolio_site_client: ConfidentialClient
) -> None:
    oauth_client, secret = portfolio_site_client
    code, verifier = login_code(owner_client, oauth_client, PORTFOLIO)
    form = code_form(oauth_client, code, verifier) | {
        "redirect_uri": PORTFOLIO_CALLBACK.rstrip("/")
    }

    response = post_token(owner_client, form, basic(oauth_client.client_id, secret))

    assert oauth_error(response, 400) == "invalid_grant"


def test_pkce_is_required_for_confidential_clients(
    owner_client: Client, portfolio_site_client: ConfidentialClient
) -> None:
    oauth_client, _ = portfolio_site_client
    use_https(owner_client)
    query = authorize_query(
        oauth_client, scope="login", code_challenge=None, code_challenge_method=None
    )

    response = owner_client.get("/authorize?" + query)

    assert response.status_code == 302
    redirected = parse_qs(urlsplit(response["Location"]).query)
    assert redirected["error"] == ["invalid_request"]
    assert "code" not in redirected


def test_confidential_client_refreshes_with_basic(
    owner_client: Client, news_site_client: ConfidentialClient
) -> None:
    oauth_client, secret = news_site_client
    tokens = login_tokens(owner_client, news_site_client, NEWS)

    response = post_token(
        owner_client,
        refresh_form(tokens["refresh_token"]),
        basic(oauth_client.client_id, secret),
    )

    assert response.status_code == 200, response.content
    assert set(response.json()) == TOKEN_FIELDS


def test_rotate_secret_command_replaces_the_secret(
    owner_client: Client, portfolio_site_client: ConfidentialClient
) -> None:
    oauth_client, old_secret = portfolio_site_client
    tokens = login_tokens(owner_client, portfolio_site_client)
    out = io.StringIO()

    call_command("clients", "rotate-secret", "--client-id", oauth_client.client_id, stdout=out)

    new_secret = printed_secret(out.getvalue())
    assert new_secret != old_secret
    old = post_token(
        owner_client,
        refresh_form(tokens["refresh_token"]),
        basic(oauth_client.client_id, old_secret),
    )
    assert oauth_error(old, 401) == "invalid_client"
    new = post_token(
        owner_client,
        refresh_form(tokens["refresh_token"]),
        basic(oauth_client.client_id, new_secret),
    )
    assert new.status_code == 200, new.content
    event = AuditEvent.objects.get(kind="client.secret_rotated")
    assert event.detail == {"client_id": oauth_client.client_id, "name": oauth_client.name}


def printed_secret(output: str) -> str:
    lines = [line for line in output.splitlines() if line.startswith("client_secret: ")]
    assert len(lines) == 1, output
    return lines[0].removeprefix("client_secret: ")


def test_create_command_shows_the_secret_once_and_stores_a_hash(db: None) -> None:
    out = io.StringIO()

    call_command(
        "clients",
        "create-confidential",
        "--name",
        "뉴스 관리",
        "--redirect-uri",
        NEWS_CALLBACK,
        stdout=out,
    )

    output = out.getvalue()
    secret = printed_secret(output)
    assert output.count(secret) == 1
    created = OAuthClient.objects.get()
    assert f"client_id: {created.client_id}" in output
    assert created.kind == OAuthClient.Kind.CONFIDENTIAL
    assert created.registered_via == OAuthClient.Via.ADMIN
    assert created.redirect_uris == [NEWS_CALLBACK]
    assert secret not in created.secret_hash
    assert check_password(secret, created.secret_hash)
    event = AuditEvent.objects.get(kind="client.created")
    assert event.detail == {"client_id": created.client_id, "name": "뉴스 관리"}

    listing = io.StringIO()
    call_command("clients", "list", stdout=listing)
    assert created.client_id in listing.getvalue()
    assert secret not in listing.getvalue()


@pytest.mark.parametrize(
    "uri", ["http://localhost:8000/callback", "http://sandcorp.co.kr/cb", "https://x/cb#frag"]
)
def test_create_command_accepts_only_https_redirect_uris(db: None, uri: str) -> None:
    with pytest.raises(CommandError):
        call_command(
            "clients",
            "create-confidential",
            "--name",
            "x",
            "--redirect-uri",
            uri,
            stdout=io.StringIO(),
        )
    assert not OAuthClient.objects.exists()


ADMIN_CLIENTS = f"/{settings.ADMIN_PATH}oauth/client/"


def test_admin_adds_a_confidential_client_and_shows_the_secret_once(
    owner_client: Client,
) -> None:
    response = owner_client.post(
        ADMIN_CLIENTS + "add/",
        {"name": "sandcorp.co.kr 관리", "redirect_uris_text": PORTFOLIO_CALLBACK + "\n"},
        follow=True,
    )

    assert response.status_code == 200
    created = OAuthClient.objects.get()
    assert created.kind == OAuthClient.Kind.CONFIDENTIAL
    assert created.registered_via == OAuthClient.Via.ADMIN
    assert created.redirect_uris == [PORTFOLIO_CALLBACK]
    shown = [str(message) for message in response.context["messages"]]
    secrets = [m.split("client_secret: ")[1].split()[0] for m in shown if "client_secret: " in m]
    assert len(secrets) == 1
    secret = secrets[0]
    assert check_password(secret, created.secret_hash)
    assert AuditEvent.objects.filter(kind="client.created").count() == 1

    again = owner_client.get(f"{ADMIN_CLIENTS}{created.pk}/change/")
    assert again.status_code == 200
    page = again.content.decode()
    assert secret not in page
    assert "시크릿 재발급" in page

    rotated = owner_client.post(f"{ADMIN_CLIENTS}{created.pk}/rotate-secret/", follow=True)
    new_messages = [str(message) for message in rotated.context["messages"]]
    new_secret = new_messages[0].split("client_secret: ")[1].split()[0]
    created.refresh_from_db()
    assert not check_password(secret, created.secret_hash)
    assert check_password(new_secret, created.secret_hash)
    assert (
        new_secret not in owner_client.get(f"{ADMIN_CLIENTS}{created.pk}/change/").content.decode()
    )


def test_admin_add_form_rejects_http_redirect_uris(owner_client: Client) -> None:
    response = owner_client.post(
        ADMIN_CLIENTS + "add/",
        {"name": "x", "redirect_uris_text": "http://sandcorp.co.kr/cb"},
    )

    assert response.status_code == 200
    assert "https여야" in response.content.decode()
    assert not OAuthClient.objects.exists()


def test_admin_rotate_secret_needs_post(
    owner_client: Client, portfolio_site_client: ConfidentialClient
) -> None:
    oauth_client, secret = portfolio_site_client

    response = owner_client.get(f"{ADMIN_CLIENTS}{oauth_client.pk}/rotate-secret/")

    assert response.status_code == 405
    oauth_client.refresh_from_db()
    assert check_password(secret, oauth_client.secret_hash)


def test_metadata_declares_the_client_auth_methods(client: Client) -> None:
    metadata = client.get("/.well-known/oauth-authorization-server").json()

    methods = {"none", "client_secret_basic", "client_secret_post"}
    assert set(metadata["token_endpoint_auth_methods_supported"]) == methods
    assert set(metadata["revocation_endpoint_auth_methods_supported"]) == methods


def test_public_client_sending_a_secret_is_invalid_client(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(owner_client, dcr_client)
    form = code_form(dcr_client, code, verifier)

    response = post_token(owner_client, form, basic(dcr_client.client_id, "anything"))

    assert oauth_error(response, 401) == "invalid_client"


@pytest.mark.parametrize("path", ["/end-session", "/oauth/logout", "/connect/endsession"])
def test_there_is_no_end_session_endpoint(client: Client, path: str) -> None:
    assert client.get(path).status_code == 404
