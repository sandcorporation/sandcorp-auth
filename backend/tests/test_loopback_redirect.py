"""Loopback redirect URIs ignore the port (RFC 8252 §7.3); every other URI matches exactly.

MCP clients (Claude Code) register `http://localhost:<port>/callback` once and pick a new free
port on every later login."""

from urllib.parse import parse_qs, urlsplit

import pytest
from django.test import Client

from oauth.models import AuthorizationCode
from oauth.models import Client as OAuthClient
from services.redirect_uris import redirect_uri_matches
from tests.conftest import (
    authorize_query as query_for,
)
from tests.conftest import (
    exchange_code,
    obtain_authorization_code,
    register,
    use_https,
)

pytestmark = pytest.mark.django_db

OTHER_PORT = "http://localhost:41235/callback"


@pytest.mark.parametrize(
    ("requested", "registered", "matches"),
    [
        # loopback http: the port is free, everything else is exact
        ("http://localhost:41235/callback", "http://localhost:33418/callback", True),
        ("http://localhost:41235/callback", "http://localhost/callback", True),
        ("http://localhost/callback", "http://localhost:33418/callback", True),
        ("http://127.0.0.1:5555/cb", "http://127.0.0.1:1234/cb", True),
        ("http://[::1]:5555/cb", "http://[::1]:1234/cb", True),
        ("http://localhost:41235/cb?a=1", "http://localhost:1/cb?a=1", True),
        ("http://localhost:41235/other", "http://localhost:33418/callback", False),
        ("http://localhost:41235/callback/", "http://localhost:33418/callback", False),
        ("http://localhost:41235/cb?a=2", "http://localhost:1/cb?a=1", False),
        ("http://localhost:41235/cb", "http://localhost:1/cb?a=1", False),
        ("http://127.0.0.1:41235/callback", "http://localhost:33418/callback", False),
        ("http://[::1]:41235/callback", "http://localhost:33418/callback", False),
        ("http://LOCALHOST:41235/callback", "http://localhost:33418/callback", False),
        ("http://evil@localhost:41235/callback", "http://localhost:33418/callback", False),
        ("http://localhost.evil.example:1/callback", "http://localhost:2/callback", False),
        ("http://localhost:41235/callback#x", "http://localhost:33418/callback", False),
        ("http://localhost:41235/callback#", "http://localhost:33418/callback", False),
        ("HTTP://localhost:41235/callback", "http://localhost:33418/callback", False),
        ("http://localhost:99999/callback", "http://localhost:33418/callback", False),
        ("http://localhost:/callback", "http://localhost:33418/callback", False),
        ("https://localhost:41235/callback", "https://localhost:33418/callback", False),
        ("https://localhost:41235/callback", "http://localhost:33418/callback", False),
        # everything else: exact match only
        ("https://app.example:8443/cb", "https://app.example/cb", False),
        ("https://app.example/cb", "https://app.example/cb", True),
        ("http://localhost:33418/callback", "http://localhost:33418/callback", True),
    ],
)
def test_redirect_uri_matching_rule(requested: str, registered: str, matches: bool) -> None:
    assert redirect_uri_matches(requested, registered) is matches


@pytest.mark.usefixtures("signing_key")
def test_other_loopback_port_gets_a_code_and_tokens(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(
        logged_in_client, dcr_client, redirect_uri=OTHER_PORT
    )

    stored = AuthorizationCode.objects.get()
    assert stored.redirect_uri == OTHER_PORT  # the port actually used, not the registered one
    response = exchange_code(logged_in_client, dcr_client, code, verifier, redirect_uri=OTHER_PORT)
    assert response.status_code == 200, response.content
    assert "access_token" in response.json()


def test_other_loopback_port_redirects_back_to_that_port(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    use_https(logged_in_client)
    url = "/authorize?" + query_for(dcr_client, redirect_uri=OTHER_PORT)

    page = logged_in_client.get(url)
    response = logged_in_client.post(url, {"decision": "allow"})

    assert page.status_code == 200
    assert response.status_code == 302
    assert response["Location"].startswith(OTHER_PORT + "?")
    assert "code" in parse_qs(urlsplit(response["Location"]).query)


def test_errors_go_back_to_the_requested_loopback_port(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    use_https(logged_in_client)
    url = "/authorize?" + query_for(dcr_client, redirect_uri=OTHER_PORT, scope="nonexistent")

    response = logged_in_client.get(url)

    assert response.status_code == 302
    assert response["Location"].startswith(OTHER_PORT + "?")


@pytest.mark.parametrize(
    "token_redirect_uri",
    ["http://localhost:33418/callback", "http://localhost:41236/callback", None],
)
def test_token_exchange_needs_the_exact_uri_of_the_authorize_request(
    logged_in_client: Client, dcr_client: OAuthClient, token_redirect_uri: str | None
) -> None:
    code, verifier = obtain_authorization_code(
        logged_in_client, dcr_client, redirect_uri=OTHER_PORT
    )

    response = exchange_code(
        logged_in_client, dcr_client, code, verifier, redirect_uri=token_redirect_uri
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://localhost:41235/other",
        "http://127.0.0.1:41235/callback",
        "http://[::1]:41235/callback",
        "http://evil@localhost:41235/callback",
        "https://localhost:41235/callback",
    ],
)
def test_loopback_with_other_host_path_or_scheme_is_refused(
    logged_in_client: Client, dcr_client: OAuthClient, redirect_uri: str
) -> None:
    use_https(logged_in_client)
    url = "/authorize?" + query_for(dcr_client, redirect_uri=redirect_uri)

    response = logged_in_client.get(url)

    assert response.status_code == 400
    assert "Location" not in response
    assert not AuthorizationCode.objects.exists()


def test_https_client_port_must_match_exactly(client: Client, logged_in_client: Client) -> None:
    status, payload = register(client, redirect_uris=["https://app.example/cb"])
    assert status == 201, payload
    https_client = OAuthClient.objects.get(client_id=payload["client_id"])
    use_https(logged_in_client)

    other_port = logged_in_client.get(
        "/authorize?" + query_for(https_client, redirect_uri="https://app.example:8443/cb")
    )
    exact = logged_in_client.get("/authorize?" + query_for(https_client))

    assert other_port.status_code == 400
    assert exact.status_code == 200


@pytest.mark.usefixtures("signing_key")
def test_ipv6_loopback_registers_and_ignores_the_port(
    client: Client, logged_in_client: Client
) -> None:
    status, payload = register(client, redirect_uris=["http://[::1]:33418/callback"])
    assert status == 201, payload
    v6_client = OAuthClient.objects.get(client_id=payload["client_id"])

    code, verifier = obtain_authorization_code(
        logged_in_client, v6_client, redirect_uri="http://[::1]:50000/callback"
    )
    response = exchange_code(
        logged_in_client, v6_client, code, verifier, redirect_uri="http://[::1]:50000/callback"
    )

    assert response.status_code == 200, response.content
