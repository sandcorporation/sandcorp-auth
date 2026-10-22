"""Resources, scopes and clients: initial data, authorization server metadata (RFC 8414) and
Dynamic Client Registration (RFC 7591), at the HTTP boundary with a frozen clock."""

import pytest
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from django.conf import settings
from django.test import Client

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import Scope
from tests.conftest import FrozenClock, register

pytestmark = pytest.mark.django_db

SITE = "https://auth.sandcorp.co.kr"


def test_initial_data_has_the_five_documented_scopes() -> None:
    scopes = {(s.resource.url, s.name) for s in Scope.objects.select_related("resource")}
    assert scopes == {
        ("https://sandcorp.co.kr/mcp", "admin"),
        ("https://sandcorp.co.kr/mcp", "login"),
        ("https://news.sandcorp.co.kr/mcp", "admin"),
        ("https://news.sandcorp.co.kr/mcp", "editor"),
        ("https://news.sandcorp.co.kr/mcp", "login"),
    }
    assert all(s.description for s in Scope.objects.all())


def test_metadata_declares_endpoints_features_and_cimd(client: Client) -> None:
    response = client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    assert response["Cache-Control"] == "public, max-age=3600"
    metadata = response.json()
    assert metadata == {
        "issuer": SITE,
        "authorization_endpoint": f"{SITE}/authorize",
        "token_endpoint": f"{SITE}/token",
        "registration_endpoint": f"{SITE}/register",
        "revocation_endpoint": f"{SITE}/revoke",
        "jwks_uri": f"{SITE}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
        ],
        "revocation_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
        ],
        "scopes_supported": ["admin", "editor", "login"],
        "client_id_metadata_document_supported": True,
    }
    AuthorizationServerMetadata(metadata).validate()


def test_scopes_supported_follows_the_database(client: Client) -> None:
    Scope.objects.create(
        resource=Scope.objects.first().resource,  # type: ignore[union-attr]
        name="reader",
        description="읽기",
    )
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["scopes_supported"] == ["admin", "editor", "login", "reader"]


def test_dcr_registers_a_public_client_that_admin_lists(
    logged_in_client: Client, frozen_clock: FrozenClock
) -> None:
    status, payload = register(
        logged_in_client,
        client_name="Claude",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        application_type="web",
    )

    assert status == 201
    client_id = payload["client_id"]
    assert isinstance(client_id, str) and client_id
    assert payload["client_id_issued_at"] == int(frozen_clock.now().timestamp())
    assert payload["client_name"] == "Claude"
    assert payload["redirect_uris"] == ["https://claude.ai/api/mcp/auth_callback"]
    assert payload["grant_types"] == ["authorization_code", "refresh_token"]
    assert payload["response_types"] == ["code"]
    assert payload["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in payload

    stored = OAuthClient.objects.get(client_id=client_id)
    assert stored.registered_via == "dcr"
    assert stored.kind == "public"
    assert stored.active
    assert stored.secret_hash == ""
    assert stored.created_at == frozen_clock.now()

    event = AuditEvent.objects.get(kind="client.registered")
    assert event.client_id == client_id
    assert event.ip == "127.0.0.1"

    listing = logged_in_client.get(f"/{settings.ADMIN_PATH}oauth/client/")
    assert listing.status_code == 200
    assert client_id in listing.content.decode()
    detail = logged_in_client.get(f"/{settings.ADMIN_PATH}oauth/client/{stored.pk}/change/")
    assert detail.status_code == 200


def test_admin_revokes_a_client(logged_in_client: Client, dcr_client: OAuthClient) -> None:
    response = logged_in_client.post(
        f"/{settings.ADMIN_PATH}oauth/client/",
        {"action": "deactivate", "_selected_action": [dcr_client.pk]},
    )
    assert response.status_code == 302
    dcr_client.refresh_from_db()
    assert not dcr_client.active

    from oauth.server import server

    assert server.query_client(dcr_client.client_id) is None


def test_admin_edits_resources_and_scopes(logged_in_client: Client) -> None:
    assert logged_in_client.get(f"/{settings.ADMIN_PATH}oauth/resource/").status_code == 200
    resource = Scope.objects.first().resource  # type: ignore[union-attr]
    page = logged_in_client.get(f"/{settings.ADMIN_PATH}oauth/resource/{resource.pk}/change/")
    assert page.status_code == 200
    assert "기사 작성·편집" in page.content.decode() or "관리 화면 로그인" in page.content.decode()


@pytest.mark.parametrize(
    "redirect_uris",
    [
        ["http://example.com/callback"],
        ["https://app.example/cb#frag"],
        ["ftp://app.example/cb"],
        [],
        "https://app.example/cb",
    ],
)
def test_dcr_rejects_bad_redirect_uris(client: Client, redirect_uris: object) -> None:
    status, payload = register(client, redirect_uris=redirect_uris)
    assert status == 400
    assert payload["error"] == "invalid_redirect_uri"
    assert not OAuthClient.objects.exists()


def test_dcr_accepts_loopback_http(client: Client) -> None:
    status, _ = register(client, redirect_uris=["http://127.0.0.1:5555/cb", "http://localhost/cb"])
    assert status == 201


@pytest.mark.parametrize(
    "metadata",
    [
        {"grant_types": ["client_credentials"]},
        {"grant_types": ["authorization_code", "implicit"]},
        {"response_types": ["token"]},
        {"token_endpoint_auth_method": "client_secret_basic"},
        {"token_endpoint_auth_method": "client_secret_post"},
        {"client_name": ""},
    ],
)
def test_dcr_rejects_unsupported_metadata(client: Client, metadata: dict[str, object]) -> None:
    status, payload = register(client, **metadata)
    assert status == 400
    assert payload["error"] == "invalid_client_metadata"
    assert not OAuthClient.objects.exists()


def test_dcr_rejects_a_body_that_is_not_a_json_object(client: Client) -> None:
    response = client.post("/register", "[1, 2]", content_type="application/json")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    response = client.post("/register", "{nope", content_type="application/json")
    assert response.status_code == 400


def test_dcr_limits_requests_per_ip(client: Client, frozen_clock: FrozenClock) -> None:
    for _ in range(10):
        status, _ = register(client)
        assert status == 201

    response = client.post("/register", "{}", content_type="application/json")
    assert response.status_code == 429
    assert response.json() == {"error": "too_many_requests"}
    assert int(response["Retry-After"]) == 3600

    # Another address is not affected; the first one is free again after the block.
    other = client.post(
        "/register",
        '{"client_name": "x", "redirect_uris": ["https://a.example/cb"]}',
        content_type="application/json",
        REMOTE_ADDR="10.9.9.9",
    )
    assert other.status_code == 201
    frozen_clock.advance(3600)
    status, _ = register(client)
    assert status == 201
