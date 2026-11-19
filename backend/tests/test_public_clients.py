"""Public clients the owner registers for a program on one PC (#102, ADR 0007):
`manage.py clients create-public [--login-info]`, loopback redirect, PKCE, no client secret."""

import io
from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import Client

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import SigningKey
from services.public_clients import create_public_client
from tests.conftest import (
    FrozenClock,
    authorize_query,
    exchange_code,
    obtain_authorization_code,
    use_https,
)
from tests.test_members import redirect_error
from tests.test_oidc import OWNER_EMAIL, set_profile, verify_id_token

pytestmark = pytest.mark.django_db

CALLBACK = "http://127.0.0.1:8090/auth/callback"
LOGIN_INFO = "openid email profile"


def create_public(*args: str) -> tuple[OAuthClient, str]:
    out = io.StringIO()
    call_command(
        "clients", "create-public", "--name", "app", "--redirect-uri", CALLBACK, *args, stdout=out
    )
    client = OAuthClient.objects.get(name="app")
    return client, out.getvalue()


@pytest.fixture
def owner_client(logged_in_client: Client, signing_key: SigningKey) -> Client:
    return logged_in_client


@pytest.fixture
def app() -> OAuthClient:
    return create_public("--login-info")[0]


def login_info_query(oauth_client: OAuthClient, **overrides: str | None) -> str:
    return authorize_query(oauth_client, resource=None, scope=LOGIN_INFO, **overrides)


def test_marked_client_logs_in_with_pkce_and_gets_email_in_the_id_token(
    owner_client: Client, owner: User, app: OAuthClient, frozen_clock: FrozenClock
) -> None:
    set_profile(owner, email=OWNER_EMAIL, name="샌드링")
    code, verifier = obtain_authorization_code(owner_client, app, resource=None, scope=LOGIN_INFO)
    response = exchange_code(owner_client, app, code, verifier)  # no secret: client_id only

    assert response.status_code == 200, response.content
    tokens = response.json()
    assert tokens["scope"] == "email openid profile"
    claims = verify_id_token(owner_client, tokens["id_token"], app.client_id)
    assert claims["email"] == OWNER_EMAIL
    assert claims["email_verified"] is True
    assert claims["sub"] == owner.username


def test_marked_client_without_the_code_verifier_gets_no_token(
    owner_client: Client, app: OAuthClient
) -> None:
    code, _ = obtain_authorization_code(owner_client, app, resource=None, scope=LOGIN_INFO)
    response = exchange_code(owner_client, app, code, "x" * 64)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_marked_client_shows_the_consent_screen_every_time(
    owner_client: Client, app: OAuthClient
) -> None:
    obtain_authorization_code(owner_client, app, resource=None, scope=LOGIN_INFO)
    response = owner_client.get("/authorize?" + login_info_query(app))
    assert response.status_code == 200  # consent screen again, no code issued silently
    assert b"app" in response.content


def test_marked_client_matches_the_redirect_uri_with_its_port(
    owner_client: Client, app: OAuthClient
) -> None:
    use_https(owner_client)
    other_port = CALLBACK.replace(":8090", ":8091")
    response = owner_client.get("/authorize?" + login_info_query(app, redirect_uri=other_port))
    assert response.status_code == 400
    assert "Location" not in response


def test_unmarked_admin_public_client_is_invalid_scope(owner_client: Client) -> None:
    plain, _ = create_public()
    use_https(owner_client)
    response = owner_client.get("/authorize?" + login_info_query(plain))
    assert redirect_error(response) == "invalid_scope"


def test_cimd_public_client_still_cannot_ask_for_login_info(
    owner_client: Client, cimd_client: OAuthClient
) -> None:
    # DCR: tests/test_oidc.py::test_public_clients_cannot_ask_for_login_info
    use_https(owner_client)
    response = owner_client.get("/authorize?" + login_info_query(cimd_client))
    assert redirect_error(response) == "invalid_scope"


def test_the_mark_is_only_for_admin_public_clients(dcr_client: OAuthClient) -> None:
    dcr_client.allows_login_info = True
    with pytest.raises(IntegrityError), transaction.atomic():
        dcr_client.save(update_fields=["allows_login_info"])


def test_members_need_the_members_mark(member_client: Client, app: OAuthClient) -> None:
    use_https(member_client)
    url = "/authorize?" + login_info_query(app)
    assert redirect_error(member_client.get(url)) == "access_denied"


def test_marked_client_with_allow_members_logs_a_member_in(
    member_client: Client, member: User, signing_key: SigningKey
) -> None:
    app = create_public("--login-info", "--allow-members")[0]
    code, verifier = obtain_authorization_code(member_client, app, resource=None, scope=LOGIN_INFO)
    response = exchange_code(member_client, app, code, verifier)
    assert response.status_code == 200, response.content
    claims = verify_id_token(member_client, response.json()["id_token"], app.client_id)
    assert claims["sub"] == member.username
    assert claims["acct"] == "member"


def test_create_public_prints_the_client_and_records_client_created() -> None:
    app, out = create_public("--login-info")

    assert app.kind == OAuthClient.Kind.PUBLIC
    assert app.registered_via == OAuthClient.Via.ADMIN
    assert app.secret_hash == ""
    assert app.allows_members is False
    assert f"client_id: {app.client_id}" in out
    assert "login_info: on" in out
    assert "client_secret" not in out
    event = AuditEvent.objects.get(kind="client.created", client_id=app.client_id)
    assert event.detail == {
        "client_id": app.client_id,
        "name": "app",
        "kind": "public",
        "login_info": True,
    }
    listed = io.StringIO()
    call_command("clients", "list", stdout=listed)
    assert "login_info=on" in listed.getvalue()


@pytest.mark.parametrize(
    "uri",
    [
        "http://localhost:8090/auth/callback",  # not an IP literal (RFC 8252 §8.3)
        "http://127.0.0.1/auth/callback",  # no port to match exactly
        "https://app.example/auth/callback",
        "http://app.example:8090/auth/callback",
        "http://127.0.0.1:8090/auth/callback#x",
    ],
)
def test_create_public_takes_only_loopback_ip_uris_with_a_port(uri: str) -> None:
    with pytest.raises(CommandError):
        call_command("clients", "create-public", "--name", "x", "--redirect-uri", uri)
    assert not OAuthClient.objects.filter(name="x").exists()


def test_ipv6_loopback_is_accepted() -> None:
    client = create_public_client(
        "v6", ["http://[::1]:8090/auth/callback"], login_info=True, actor="test"
    )
    assert client.redirect_uris == ["http://[::1]:8090/auth/callback"]


def test_redirect_carries_the_code_to_the_registered_port(
    owner_client: Client, app: OAuthClient
) -> None:
    use_https(owner_client)
    url = "/authorize?" + login_info_query(app)
    response = owner_client.post(url, {"decision": "allow"})
    assert response.status_code == 302
    location = urlsplit(response["Location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == CALLBACK
    assert "code" in parse_qs(location.query)
