"""Bearer auth for Django views and django-ninja (§3, §5, §6).

Cases carried over from portfolio/metrics `tests/test_resource_auth.py`, news
`tests/test_resource_auth.py` and flow `tests/test_operator_resource_token.py`.
Django is configured by `conftest.pytest_configure`.
"""

import dataclasses
import itertools
import json
from collections.abc import Callable

import pytest
from conftest import ISSUER, OWNER, RESOURCE, START
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory
from ninja import NinjaAPI
from ninja.testing import TestClient

from sandcorp_authkit.django import (
    AuthNotConfigured,
    BearerAuth,
    BearerConfig,
    BearerDenied,
    MissingToken,
    authenticate,
    deny,
    install_bearer_errors,
    metadata_response,
    require_bearer,
)
from sandcorp_authkit.testing import (
    MEMBER_SUB,
    FakeJwks,
    FixedClock,
    access_token_claims,
    bearer_header,
)
from sandcorp_authkit.tokens import (
    AccessToken,
    InsufficientScope,
    TokenRejected,
    owner_only,
    owner_or_member,
)

METADATA = "https://sandcorp.co.kr/.well-known/oauth-protected-resource"
CHALLENGE = f'Bearer resource_metadata="{METADATA}"'
INVALID = f'{CHALLENGE}, error="invalid_token"'
_namespaces = itertools.count()


class Site:
    def __init__(self, *, owner_sub: str = OWNER, issuer: str = ISSUER) -> None:
        self.clock = FixedClock(START)
        self.fake_jwks = FakeJwks()
        self.config = BearerConfig(
            issuer=issuer,
            audience=RESOURCE,
            resource_metadata_url=METADATA,
            jwks=self.fake_jwks.cache(self.clock),
            clock=self.clock,
            extra_claims_hook=owner_only(owner_sub),
        )

    def token(self, **claims: object) -> str:
        body = {**access_token_claims(self.clock, audience=RESOURCE), **claims}
        return self.fake_jwks.key.sign({k: v for k, v in body.items() if v is not None})


@pytest.fixture
def site() -> Site:
    return Site()


rf = RequestFactory()


def body(response: HttpResponse) -> object:
    return json.loads(response.content)


# ── require_bearer ──


def view_for(site: Site, scope: str = "admin") -> Callable[..., HttpResponse]:
    @require_bearer(scope, config=site.config)
    def view(request: HttpRequest, token: AccessToken, item: str = "") -> HttpResponse:
        assert request.access_token is token  # type: ignore[attr-defined]
        return JsonResponse({"sub": token.sub, "item": item})

    return view


def call(view: Callable[..., HttpResponse], headers: dict[str, str] | None = None) -> HttpResponse:
    response = view(rf.get("/mcp", headers=headers), item="x")
    assert isinstance(response, HttpResponse)
    return response


def test_valid_token_passes(site: Site) -> None:
    response = call(view_for(site), bearer_header(site.token()))
    assert response.status_code == 200
    assert body(response) == {"sub": OWNER, "item": "x"}


def test_bearer_scheme_is_case_insensitive(site: Site) -> None:
    for scheme in ("bearer", "BEARER", "BeArEr"):
        response = call(view_for(site), {"Authorization": f"{scheme} {site.token()}"})
        assert response.status_code == 200


def test_no_token_is_401_with_resource_metadata_and_no_error(site: Site) -> None:
    for headers in (
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer"},
    ):
        response = call(view_for(site), headers)
        assert response.status_code == 401
        assert response["WWW-Authenticate"] == CHALLENGE
        assert body(response) == {"error": "unauthorized"}
        assert response["Content-Type"] == "application/json"


def test_token_in_query_string_is_ignored(site: Site) -> None:
    view = view_for(site)
    response = view(rf.get(f"/mcp?access_token={site.token()}"))
    assert response.status_code == 401
    assert response["WWW-Authenticate"] == CHALLENGE


@pytest.mark.parametrize(
    "make",
    [
        lambda s: "garbage",
        lambda s: s.token(iss="https://evil.example"),
        lambda s: s.token(aud="https://other/mcp"),
        lambda s: s.token(sub="intruder"),
        lambda s: s.token(acct="member", sub=MEMBER_SUB),
        lambda s: s.token(exp=int(START.timestamp()) - 31),
        lambda s: " " + s.token(),  # "Bearer  <token>": the token is sent as is
    ],
    ids=["garbage", "issuer", "audience", "owner", "member", "expired", "double-space"],
)
def test_bad_tokens_are_401_invalid_token(site: Site, make: Callable[[Site], str]) -> None:
    token = make(site)
    response = call(view_for(site), {"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response["WWW-Authenticate"] == INVALID
    assert body(response) == {"error": "unauthorized"}


def test_expiry_allows_30_seconds_of_leeway(site: Site) -> None:
    token = site.token(exp=int(START.timestamp()) - 30)
    assert call(view_for(site), bearer_header(token)).status_code == 200


def test_missing_scope_is_403_insufficient_scope(site: Site) -> None:
    response = call(view_for(site, "editor"), bearer_header(site.token(scope="admin login")))
    assert response.status_code == 403
    assert response["WWW-Authenticate"] == 'Bearer error="insufficient_scope", scope="editor"'
    assert body(response) == {"error": "forbidden"}


def test_someone_elses_token_is_401_even_without_the_scope(site: Site) -> None:
    response = call(view_for(site, "editor"), bearer_header(site.token(sub="intruder")))
    assert response.status_code == 401


def test_without_owner_setting_is_503_before_the_header_is_read() -> None:
    def config() -> BearerConfig:
        raise AuthNotConfigured("AUTH_OWNER_SUB is empty")

    @require_bearer("admin", config=config)
    def view(request: HttpRequest, token: AccessToken) -> HttpResponse:
        raise AssertionError("must not run")

    for headers in ({}, {"Authorization": "Bearer x"}):
        response = view(rf.get("/mcp", headers=headers))
        assert response.status_code == 503
        assert body(response) == {"error": "auth_not_configured"}
        assert "WWW-Authenticate" not in response


@pytest.mark.parametrize("blank", ["issuer", "audience", "resource_metadata_url"])
def test_blank_config_values_are_503(site: Site, blank: str) -> None:
    blanks: dict[str, BearerConfig] = {
        "issuer": dataclasses.replace(site.config, issuer=""),
        "audience": dataclasses.replace(site.config, audience=""),
        "resource_metadata_url": dataclasses.replace(site.config, resource_metadata_url=""),
    }
    config = blanks[blank]

    @require_bearer("admin", config=config)
    def view(request: HttpRequest, token: AccessToken) -> HttpResponse:
        raise AssertionError("must not run")

    assert view(rf.get("/mcp", headers=bearer_header(site.token()))).status_code == 503


def test_config_function_is_read_per_request(site: Site) -> None:
    current = {"config": site.config}
    view = view_for_source(lambda: current["config"])
    assert call(view, bearer_header(site.token())).status_code == 200
    other = Site(owner_sub="someone")
    current["config"] = other.config
    assert call(view, bearer_header(other.token())).status_code == 401


def view_for_source(source: Callable[[], BearerConfig]) -> Callable[..., HttpResponse]:
    @require_bearer("admin", config=source)
    def view(request: HttpRequest, token: AccessToken, item: str = "") -> HttpResponse:
        return HttpResponse(token.sub)

    return view


def test_member_site_takes_member_tokens() -> None:
    site = Site()
    config = BearerConfig(
        issuer=ISSUER,
        audience=RESOURCE,
        resource_metadata_url=METADATA,
        jwks=site.config.jwks,
        clock=site.clock,
        extra_claims_hook=owner_or_member(OWNER),
    )
    token = site.token(sub=MEMBER_SUB, acct="member", scope="login")
    request = rf.get("/mcp", headers=bearer_header(token))
    access = authenticate(request, "login", config)
    assert (access.sub, access.acct) == (MEMBER_SUB, "member")


def test_authenticate_raises_the_plain_exceptions(site: Site) -> None:
    with pytest.raises(MissingToken):
        authenticate(rf.get("/"), "admin", site.config)
    with pytest.raises(TokenRejected):
        authenticate(rf.get("/", headers={"Authorization": "Bearer x"}), "admin", site.config)
    with pytest.raises(InsufficientScope):
        authenticate(
            rf.get("/", headers=bearer_header(site.token(scope="login"))), "admin", site.config
        )


def test_deny_shapes() -> None:
    request = rf.get("/")
    scoped = deny(request, InsufficientScope("admin"), resource_metadata_url=METADATA, scope="x")
    assert scoped["WWW-Authenticate"] == 'Bearer error="insufficient_scope", scope="x"'
    assert deny(request, MissingToken(), resource_metadata_url=METADATA).status_code == 401
    assert deny(request, AuthNotConfigured(), resource_metadata_url=METADATA).status_code == 503


# ── django-ninja ──


def ninja_client(site: Site, scope: str = "admin") -> TestClient:
    api = NinjaAPI(urls_namespace=f"authkit-test-{next(_namespaces)}")
    install_bearer_errors(api)

    @api.get("/whoami", auth=BearerAuth(scope, config=site.config))
    def whoami(request: HttpRequest) -> dict[str, str]:
        token = request.auth  # type: ignore[attr-defined]
        assert isinstance(token, AccessToken)
        return {"sub": token.sub}

    return TestClient(api)


def test_ninja_valid_token_sets_request_auth(site: Site) -> None:
    response = ninja_client(site).get(
        "/whoami", headers={"Authorization": f"Bearer {site.token()}"}
    )
    assert response.status_code == 200
    assert response.json() == {"sub": OWNER}


def test_ninja_missing_token_is_401_with_challenge(site: Site) -> None:
    response = ninja_client(site).get("/whoami")
    assert response.status_code == 401
    assert response["WWW-Authenticate"] == CHALLENGE
    assert response.json() == {"error": "unauthorized"}


def test_ninja_bad_token_is_401_invalid_token(site: Site) -> None:
    response = ninja_client(site).get("/whoami", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401
    assert response["WWW-Authenticate"] == INVALID


def test_ninja_missing_scope_is_403(site: Site) -> None:
    token = site.token(scope="login")
    response = ninja_client(site).get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response["WWW-Authenticate"] == 'Bearer error="insufficient_scope", scope="admin"'
    assert response.json() == {"error": "forbidden"}


def test_ninja_not_configured_is_503(site: Site) -> None:
    def config() -> BearerConfig:
        raise AuthNotConfigured("no owner")

    api = NinjaAPI(urls_namespace=f"authkit-test-{next(_namespaces)}")
    install_bearer_errors(api)

    @api.get("/x", auth=BearerAuth("admin", config=config))
    def x(request: HttpRequest) -> dict[str, str]:
        return {}

    response = TestClient(api).get("/x", headers={"Authorization": f"Bearer {site.token()}"})
    assert response.status_code == 503
    assert response.json() == {"error": "auth_not_configured"}


def test_bearer_auth_raises_bearer_denied_with_the_refusal(site: Site) -> None:
    auth = BearerAuth("admin", config=site.config)
    with pytest.raises(BearerDenied) as caught:
        auth(rf.get("/"))
    assert isinstance(caught.value.error, MissingToken)
    assert caught.value.response.status_code == 401


def test_ninja_openapi_names_bearer() -> None:
    auth = BearerAuth("admin", config=Site().config)
    assert auth.openapi_security_schema == {"type": "http", "scheme": "bearer"}


# ── metadata ──


def test_metadata_response_is_cross_origin_json() -> None:
    response = metadata_response(RESOURCE, ISSUER, ["admin", "login"], resource_name="Sandcorp")
    assert response["Access-Control-Allow-Origin"] == "*"
    assert body(response) == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["admin", "login"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Sandcorp",
    }
