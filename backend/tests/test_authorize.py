"""The authorization endpoint: PKCE S256 and `resource` required, consent screen, codes."""

from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.test import Client

from audit.models import AuditEvent
from oauth.grants import find_authorization_code, hash_code
from oauth.models import AuthorizationCode, Consent
from oauth.models import Client as OAuthClient
from tests.conftest import (
    NEWS,
    PORTFOLIO,
    FrozenClock,
    authorize_query,
    obtain_authorization_code,
    use_https,
)

pytestmark = pytest.mark.django_db


def authorize(client: Client, oauth_client: OAuthClient, **overrides: str | None) -> str:
    use_https(client)
    return "/authorize?" + authorize_query(oauth_client, **overrides)


def redirect_query(location: str) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}


def test_anonymous_request_goes_to_login_and_keeps_the_query(
    client: Client, dcr_client: OAuthClient
) -> None:
    url = authorize(client, dcr_client)

    response = client.get(url)

    assert response.status_code == 302
    location = urlsplit(response["Location"])
    assert location.path == "/login"
    assert parse_qs(location.query)["next"] == [url]


def test_login_then_returns_to_authorize(
    client: Client, dcr_client: OAuthClient, logged_in_client: Client
) -> None:
    # `logged_in_client` logged in without `next`; the login view sends a logged-in visitor
    # straight to `next`.
    url = authorize(client, dcr_client)

    response = logged_in_client.get("/login?" + urlencode({"next": url}))

    assert response.status_code == 302
    assert response["Location"] == url


def test_consent_screen_shows_client_resource_and_scopes(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    response = logged_in_client.get(authorize(logged_in_client, dcr_client, scope="admin login"))

    assert response.status_code == 200
    page = response.content.decode()
    assert "Claude Code" in page
    assert "portfolio" in page and PORTFOLIO in page
    assert "포트폴리오 관리: 제안서·포트폴리오 항목 읽기와 쓰기" in page
    assert "sandcorp.co.kr 관리 화면 로그인" in page
    assert "localhost:33418" in page
    assert response["Cache-Control"] == "no-store"
    assert not AuthorizationCode.objects.exists()


def test_allow_issues_a_hashed_code_bound_to_a_consent(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    url = authorize(logged_in_client, dcr_client)

    response = logged_in_client.post(url, {"decision": "allow"})

    assert response.status_code == 302
    assert response["Location"].startswith("http://localhost:33418/callback?")
    query = redirect_query(response["Location"])
    assert query["state"] == "xyz"
    consent = Consent.objects.get()
    assert consent.client == dcr_client
    assert consent.resource.url == PORTFOLIO
    assert consent.scopes == ["admin"]
    assert consent.revoked_at is None
    code = AuthorizationCode.objects.get()
    assert code.code_hash == hash_code(query["code"])
    assert not AuthorizationCode.objects.filter(code_hash=query["code"]).exists()
    assert (code.consent, code.resource, code.scope) == (consent, consent.resource, "admin")
    assert code.redirect_uri == "http://localhost:33418/callback"
    assert code.code_challenge_method == "S256"
    kinds = list(AuditEvent.objects.order_by("id").values_list("kind", flat=True))
    assert kinds[-2:] == ["consent.granted", "authorization_code.issued"]
    issued = AuditEvent.objects.get(kind="authorization_code.issued")
    assert issued.client_id == dcr_client.client_id
    assert issued.detail == {"resource": PORTFOLIO, "scope": "admin"}
    assert query["code"] not in str(issued.detail)


def test_live_consent_is_reused_without_asking(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    obtain_authorization_code(logged_in_client, dcr_client, scope="admin login")

    response = logged_in_client.get(authorize(logged_in_client, dcr_client, scope="login"))

    assert response.status_code == 302
    assert "code" in redirect_query(response["Location"])
    assert Consent.objects.count() == 1
    assert AuthorizationCode.objects.count() == 2


def test_wider_scope_asks_again_and_replaces_the_consent(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    obtain_authorization_code(logged_in_client, dcr_client, scope="login")
    url = authorize(logged_in_client, dcr_client, scope="admin")

    page = logged_in_client.get(url)
    assert page.status_code == 200
    assert "포트폴리오 관리" in page.content.decode()
    logged_in_client.post(url, {"decision": "allow"})

    old, new = Consent.objects.order_by("id")
    assert old.revoked_at is not None
    assert new.revoked_at is None
    assert new.scopes == ["admin", "login"]


def test_deny_redirects_with_access_denied(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    response = logged_in_client.post(authorize(logged_in_client, dcr_client), {"decision": "deny"})

    assert response.status_code == 302
    query = redirect_query(response["Location"])
    assert (query["error"], query["state"]) == ("access_denied", "xyz")
    assert "code" not in query
    assert not Consent.objects.exists()
    assert AuditEvent.objects.filter(kind="consent.denied").count() == 1


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge_method": None}, "invalid_request"),
        ({"code_challenge": None, "code_challenge_method": None}, "invalid_request"),
        ({"resource": None}, "invalid_target"),
        ({"resource": "https://evil.example/mcp"}, "invalid_target"),
        ({"resource": PORTFOLIO + "/"}, "invalid_target"),
        ({"resource": NEWS, "scope": "admin editor"}, None),
        ({"scope": "editor"}, "invalid_scope"),
        ({"scope": None}, "invalid_scope"),
    ],
)
def test_bad_parameters_go_back_to_the_client_as_errors(
    logged_in_client: Client,
    dcr_client: OAuthClient,
    overrides: dict[str, str | None],
    error: str | None,
) -> None:
    response = logged_in_client.get(authorize(logged_in_client, dcr_client, **overrides))

    if error is None:  # control: the same shape with valid values reaches the consent screen
        assert response.status_code == 200
        return
    assert response.status_code == 302
    location = response["Location"]
    assert location.startswith("http://localhost:33418/callback?")
    query = redirect_query(location)
    assert (query["error"], query["state"]) == (error, "xyz")
    assert not AuthorizationCode.objects.exists()


def test_two_resources_are_refused(logged_in_client: Client, dcr_client: OAuthClient) -> None:
    url = authorize(logged_in_client, dcr_client) + "&resource=" + NEWS

    response = logged_in_client.get(url)

    assert redirect_query(response["Location"])["error"] == "invalid_target"


@pytest.mark.parametrize(
    "overrides",
    [
        {"redirect_uri": "http://localhost:33418/other"},
        {"client_id": "unknown-client"},
        {"client_id": None},
    ],
)
def test_bad_client_or_redirect_uri_shows_an_error_page(
    logged_in_client: Client, dcr_client: OAuthClient, overrides: dict[str, str | None]
) -> None:
    response = logged_in_client.get(authorize(logged_in_client, dcr_client, **overrides))

    assert response.status_code == 400
    assert "Location" not in response
    assert "잘못된 인가 요청" in response.content.decode()


def test_bad_redirect_uri_on_post_is_not_followed(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    url = authorize(logged_in_client, dcr_client, redirect_uri="https://evil.example/cb")

    response = logged_in_client.post(url, {"decision": "allow"})

    assert response.status_code == 400
    assert not Consent.objects.exists()


def test_cimd_client_consent_screen_shows_document_name_and_url(
    logged_in_client: Client, cimd_client: OAuthClient
) -> None:
    response = logged_in_client.get(authorize(logged_in_client, cimd_client))

    assert response.status_code == 200
    page = response.content.decode()
    assert "Example MCP client" in page
    assert "https://app.example/client.json" in page
    assert "app.example" in page


def test_code_expires_after_five_minutes_and_is_single_use(
    logged_in_client: Client, dcr_client: OAuthClient, frozen_clock: FrozenClock
) -> None:
    code, _ = obtain_authorization_code(logged_in_client, dcr_client)
    found = find_authorization_code(code, dcr_client)
    assert found is not None

    frozen_clock.advance(5 * 60 - 1)
    assert find_authorization_code(code, dcr_client) is not None
    frozen_clock.advance(2)
    assert find_authorization_code(code, dcr_client) is None


def test_used_code_or_other_client_finds_nothing(
    logged_in_client: Client,
    dcr_client: OAuthClient,
    cimd_client: OAuthClient,
    frozen_clock: FrozenClock,
) -> None:
    code, _ = obtain_authorization_code(logged_in_client, dcr_client)
    assert find_authorization_code(code, cimd_client) is None

    AuthorizationCode.objects.update(used_at=frozen_clock.now())

    assert find_authorization_code(code, dcr_client) is None
