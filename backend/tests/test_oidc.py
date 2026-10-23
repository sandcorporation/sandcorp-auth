"""OpenID Connect on top of the OAuth layer: discovery, login info scopes (`openid`, `profile`,
`email`), the ID token, and userinfo. The resource scope flow stays as it was."""

import io
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client

from oauth.models import Client as OAuthClient
from oauth.models import SigningKey
from services.confidential_clients import create_confidential_client
from services.oidc import USERINFO_RESOURCE
from tests.conftest import (
    NEWS,
    OWNER_USERNAME,
    FrozenClock,
    authorize_query,
    obtain_authorization_code,
    use_https,
)
from tests.reference_validator import JwksCache, validate_access_token
from tests.test_confidential_clients import basic, code_form, post_token, refresh_form
from tests.test_signing_keys import jwks_fetcher

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db

SITE = "https://auth.sandcorp.co.kr"
PROXY_CALLBACK = "https://app.sandcorp.co.kr/oauth2/callback"
OWNER_EMAIL = "owner@sandcorp.co.kr"

Proxy = tuple[OAuthClient, str]
Claims = dict[str, object]


@pytest.fixture
def owner_client(logged_in_client: Client, signing_key: SigningKey) -> Client:
    return logged_in_client


@pytest.fixture
def proxy(db: None) -> Proxy:
    """A forward auth proxy (oauth2-proxy) as a confidential client, and its secret."""
    issued = create_confidential_client("oauth2-proxy", [PROXY_CALLBACK], actor="test")
    return issued.client, issued.secret


def oidc_tokens(
    client: Client, proxy: Proxy, *, scope: str = "openid", **overrides: str | None
) -> dict[str, str | int]:
    """Authorize `scope` without a resource (unless overridden) and exchange the code."""
    oauth_client, secret = proxy
    code, verifier = obtain_authorization_code(
        client, oauth_client, resource=overrides.pop("resource", None), scope=scope, **overrides
    )
    response = post_token(
        client, code_form(oauth_client, code, verifier), basic(oauth_client.client_id, secret)
    )
    assert response.status_code == 200, response.content
    tokens: dict[str, str | int] = response.json()
    return tokens


def verify_id_token(client: Client, raw: str | int, client_id: str) -> Claims:
    """Verify an ID token with the published JWKS (EdDSA, by `kid`) and return its claims."""
    kid = jwt.get_unverified_header(str(raw))["kid"]
    jwk = next(key for key in jwks_fetcher(client)()["keys"] if key["kid"] == kid)
    claims: Claims = jwt.decode(
        str(raw),
        jwt.PyJWK(dict(jwk)).key,
        algorithms=["EdDSA"],
        audience=client_id,
        issuer=SITE,
        options={"verify_exp": False, "verify_iat": False},  # the test clock is frozen
    )
    return claims


def unverified(raw: str | int) -> Claims:
    claims: Claims = jwt.decode(str(raw), options={"verify_signature": False})
    return claims


def userinfo(client: Client, token: str | int | None, method: str = "get") -> "TestResponse":
    headers = {} if token is None else {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    response: TestResponse = getattr(client, method)("/userinfo", **headers)
    return response


def set_profile(user: User, *, email: str = "", name: str = "") -> None:
    User.objects.filter(pk=user.pk).update(email=email, first_name=name)


# --- discovery -----------------------------------------------------------------------------


def test_discovery_and_rfc8414_metadata_are_the_same_document(client: Client) -> None:
    discovery = client.get("/.well-known/openid-configuration")
    assert discovery.status_code == 200
    body = discovery.json()
    assert body == client.get("/.well-known/oauth-authorization-server").json()
    assert body["issuer"] == SITE
    assert body["authorization_endpoint"] == SITE + "/authorize"
    assert body["token_endpoint"] == SITE + "/token"
    assert body["userinfo_endpoint"] == SITE + "/userinfo"
    assert body["jwks_uri"] == SITE + "/.well-known/jwks.json"
    assert body["response_types_supported"] == ["code"]
    assert body["subject_types_supported"] == ["public"]
    assert body["id_token_signing_alg_values_supported"] == ["EdDSA"]
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert {"openid", "profile", "email", "admin", "editor", "login"} <= set(
        body["scopes_supported"]
    )
    assert "client_secret_basic" in body["token_endpoint_auth_methods_supported"]
    assert set(body["grant_types_supported"]) == {"authorization_code", "refresh_token"}


# --- authorize → token ---------------------------------------------------------------------


def test_openid_without_resource_gives_an_id_token_and_a_userinfo_access_token(
    owner_client: Client, owner: User, proxy: Proxy, frozen_clock: FrozenClock
) -> None:
    set_profile(owner, email=OWNER_EMAIL, name="샌드링")
    tokens = oidc_tokens(owner_client, proxy, scope="openid profile email")
    owner.refresh_from_db()

    assert tokens["scope"] == "email openid profile"
    access = unverified(tokens["access_token"])
    assert access["aud"] == USERINFO_RESOURCE
    assert access["scope"] == "email openid profile"

    oauth_client = proxy[0]
    claims = verify_id_token(owner_client, tokens["id_token"], oauth_client.client_id)
    assert owner.last_login is not None
    now = int(frozen_clock.now().timestamp())
    assert claims == {
        "iss": SITE,
        "sub": OWNER_USERNAME,
        "aud": oauth_client.client_id,
        "iat": now,
        "exp": now + 600,
        "auth_time": int(owner.last_login.timestamp()),
        "name": "샌드링",
        "preferred_username": OWNER_USERNAME,
        "email": OWNER_EMAIL,
        "email_verified": True,
    }
    assert "at_hash" not in claims


def test_nonce_from_authorize_is_in_the_id_token(owner_client: Client, proxy: Proxy) -> None:
    tokens = oidc_tokens(owner_client, proxy, nonce="n-0S6_WzA2Mj")
    assert unverified(tokens["id_token"])["nonce"] == "n-0S6_WzA2Mj"
    assert "nonce" not in unverified(oidc_tokens(owner_client, proxy)["id_token"])


def test_too_long_nonce_is_refused(owner_client: Client, proxy: Proxy) -> None:
    use_https(owner_client)
    query = authorize_query(proxy[0], resource=None, scope="openid", nonce="n" * 256)
    response = owner_client.get("/authorize?" + query)
    assert response.status_code == 302
    assert parse_qs(urlsplit(response["Location"]).query)["error"] == ["invalid_request"]


def test_claims_the_owner_has_not_got_are_left_out(
    owner_client: Client, owner: User, proxy: Proxy
) -> None:
    tokens = oidc_tokens(owner_client, proxy, scope="openid profile email")
    claims = unverified(tokens["id_token"])
    assert claims["preferred_username"] == OWNER_USERNAME
    assert not {"email", "email_verified", "name"} & set(claims)


def test_openid_alone_carries_no_profile_or_email(
    owner_client: Client, owner: User, proxy: Proxy
) -> None:
    set_profile(owner, email=OWNER_EMAIL, name="샌드링")
    claims = unverified(oidc_tokens(owner_client, proxy)["id_token"])
    assert not {"email", "email_verified", "name", "preferred_username"} & set(claims)


def test_refresh_reissues_the_id_token_with_the_original_auth_time(
    owner_client: Client, owner: User, proxy: Proxy, frozen_clock: FrozenClock
) -> None:
    oauth_client, secret = proxy
    tokens = oidc_tokens(owner_client, proxy, scope="openid email", nonce="abc")
    first = unverified(tokens["id_token"])
    frozen_clock.advance(300)
    response = post_token(
        owner_client, refresh_form(tokens["refresh_token"]), basic(oauth_client.client_id, secret)
    )
    assert response.status_code == 200, response.content
    refreshed = response.json()
    claims = verify_id_token(owner_client, refreshed["id_token"], oauth_client.client_id)
    assert claims["iat"] == int(str(first["iat"])) + 300
    assert claims["auth_time"] == first["auth_time"]
    assert "nonce" not in claims  # OpenID Connect Core 12.2
    assert unverified(refreshed["access_token"])["aud"] == USERINFO_RESOURCE


def test_resource_and_openid_together(
    owner_client: Client, owner: User, proxy: Proxy, frozen_clock: FrozenClock
) -> None:
    """The access token is the resource's (its own scopes only, valid by the resource server
    rules); the ID token comes alongside."""
    oauth_client, secret = proxy
    use_https(owner_client)
    query = authorize_query(oauth_client, resource=NEWS, scope="openid email login")
    screen = owner_client.get("/authorize?" + query)
    assert screen.status_code == 200
    assert "로그인 정보(이름·이메일) 제공" in screen.content.decode()

    tokens = oidc_tokens(owner_client, proxy, resource=NEWS, scope="openid email login")
    assert tokens["scope"] == "email login openid"
    access = unverified(tokens["access_token"])
    assert access["aud"] == NEWS
    assert access["scope"] == "login"
    validate_access_token(
        str(tokens["access_token"]),
        jwks=JwksCache(jwks_fetcher(owner_client), frozen_clock),
        audience=NEWS,
        owner_sub=OWNER_USERNAME,
        required_scope="login",
        clock=frozen_clock,
    )
    assert verify_id_token(owner_client, tokens["id_token"], oauth_client.client_id)["sub"] == (
        OWNER_USERNAME
    )


def test_without_openid_there_is_no_id_token(owner_client: Client, proxy: Proxy) -> None:
    tokens = oidc_tokens(owner_client, proxy, resource=NEWS, scope="login")
    assert "id_token" not in tokens


@pytest.mark.parametrize(
    ("resource", "scope"),
    [
        (None, "profile"),  # no openid: no resource to bind to
        (NEWS, "profile login"),  # profile without openid
        (NEWS, "openid"),  # nothing of the resource itself
        (USERINFO_RESOURCE, "openid login"),  # login is not a login info scope
    ],
)
def test_bad_login_info_scope_requests(
    owner_client: Client, proxy: Proxy, resource: str | None, scope: str
) -> None:
    use_https(owner_client)
    query = authorize_query(proxy[0], resource=resource, scope=scope)
    response = owner_client.get("/authorize?" + query)
    assert response.status_code == 302, response.content
    error = parse_qs(urlsplit(response["Location"]).query)["error"]
    assert error in (["invalid_scope"], ["invalid_target"])


def test_public_clients_cannot_ask_for_login_info(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    use_https(owner_client)
    query = authorize_query(dcr_client, resource=None, scope="openid")
    response = owner_client.get("/authorize?" + query)
    assert response.status_code == 302
    assert parse_qs(urlsplit(response["Location"]).query)["error"] == ["invalid_scope"]


# --- userinfo ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("openid", {"sub": OWNER_USERNAME}),
        (
            "openid profile",
            {"sub": OWNER_USERNAME, "name": "샌드링", "preferred_username": OWNER_USERNAME},
        ),
        (
            "openid email",
            {"sub": OWNER_USERNAME, "email": OWNER_EMAIL, "email_verified": True},
        ),
    ],
)
@pytest.mark.parametrize("method", ["get", "post"])
def test_userinfo_answers_by_scope(
    owner_client: Client,
    owner: User,
    proxy: Proxy,
    scope: str,
    expected: Claims,
    method: str,
) -> None:
    set_profile(owner, email=OWNER_EMAIL, name="샌드링")
    tokens = oidc_tokens(owner_client, proxy, scope=scope)
    response = userinfo(owner_client, tokens["access_token"], method)
    assert response.status_code == 200, response.content
    assert response.json() == expected
    assert response["Cache-Control"] == "no-store"


def test_userinfo_refuses_a_resource_access_token(owner_client: Client, proxy: Proxy) -> None:
    tokens = oidc_tokens(owner_client, proxy, resource=NEWS, scope="openid login")
    response = userinfo(owner_client, tokens["access_token"])
    assert response.status_code == 401
    assert (
        response["WWW-Authenticate"] == 'Bearer realm="auth.sandcorp.co.kr", error="invalid_token"'
    )


def test_userinfo_refuses_missing_expired_and_forged_tokens(
    owner_client: Client, proxy: Proxy, frozen_clock: FrozenClock
) -> None:
    missing = userinfo(owner_client, None)
    assert missing.status_code == 401
    assert missing["WWW-Authenticate"] == 'Bearer realm="auth.sandcorp.co.kr"'

    access = str(oidc_tokens(owner_client, proxy)["access_token"])
    assert userinfo(owner_client, access + "x").status_code == 401
    assert userinfo(owner_client, "not-a-jwt").status_code == 401
    frozen_clock.advance(601)
    assert userinfo(owner_client, access).status_code == 401


# --- owner profile -------------------------------------------------------------------------


def test_owner_set_email_and_set_name(owner: User) -> None:
    out = io.StringIO()
    call_command("owner", "set-email", "--email", OWNER_EMAIL, stdout=out)
    call_command("owner", "set-name", "--name", " 샌드링 ", stdout=out)
    owner.refresh_from_db()
    assert (owner.email, owner.get_full_name()) == (OWNER_EMAIL, "샌드링")
    with pytest.raises(CommandError):
        call_command("owner", "set-email", "--email", "not-an-email")
    with pytest.raises(CommandError):
        call_command("owner", "set-name")
    call_command("owner", "set-email", "--email", "", stdout=out)
    owner.refresh_from_db()
    assert owner.email == ""
