"""The token endpoint: authorization code exchange for a JWT access token and a refresh token."""

from datetime import timedelta

import jwt
import pytest
from django.test import Client

from audit.models import AuditEvent
from oauth.models import AuthorizationCode, RefreshToken, RefreshTokenFamily, SigningKey
from oauth.models import Client as OAuthClient
from oauth.tokens import hash_refresh_token
from tests.conftest import (
    NEWS,
    OWNER_USERNAME,
    PORTFOLIO,
    TOKEN_FIELDS,
    FrozenClock,
    exchange_code,
    obtain_authorization_code,
    obtain_tokens,
    use_https,
)
from tests.reference_validator import JwksCache, TokenRejected, validate_access_token
from tests.test_signing_keys import jwks_fetcher

pytestmark = pytest.mark.django_db


def validate(client: Client, raw: str, clock: FrozenClock) -> object:
    return validate_access_token(
        raw,
        jwks=JwksCache(jwks_fetcher(client), clock),
        audience=PORTFOLIO,
        owner_sub=OWNER_USERNAME,
        required_scope="admin",
        clock=clock,
    )


@pytest.fixture
def owner_client(logged_in_client: Client, signing_key: SigningKey) -> Client:
    return logged_in_client


def test_code_exchange_end_to_end(
    owner_client: Client, dcr_client: OAuthClient, frozen_clock: FrozenClock
) -> None:
    metadata = owner_client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["token_endpoint"].endswith("/token")
    code, verifier = obtain_authorization_code(owner_client, dcr_client)

    response = exchange_code(owner_client, dcr_client, code, verifier)

    assert response.status_code == 200, response.content
    body = response.json()
    assert set(body) == TOKEN_FIELDS
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 600
    assert body["scope"] == "admin"
    verified = validate_access_token(
        body["access_token"],
        jwks=JwksCache(jwks_fetcher(owner_client), frozen_clock),
        audience=PORTFOLIO,
        owner_sub=OWNER_USERNAME,
        required_scope="admin",
        clock=frozen_clock,
    )
    assert verified.client_id == dcr_client.client_id
    assert verified.scopes == frozenset({"admin"})
    # The audience is the resource bound to the code, not merely accepted by the validator.
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    issued = AuthorizationCode.objects.get()
    assert claims["aud"] == issued.resource.url == PORTFOLIO
    assert issued.used_at is not None
    event = AuditEvent.objects.get(kind="token.issued")
    assert event.client_id == dcr_client.client_id
    assert event.detail["resource"] == PORTFOLIO
    assert event.detail["jti"] == claims["jti"]


def test_tokens_are_not_cached(owner_client: Client, dcr_client: OAuthClient) -> None:
    code, verifier = obtain_authorization_code(owner_client, dcr_client)
    ok = exchange_code(owner_client, dcr_client, code, verifier)
    failed = exchange_code(owner_client, dcr_client, "nope", verifier)

    for response in (ok, failed):
        assert response["Cache-Control"] == "no-store"
        assert response["Pragma"] == "no-cache"
    assert failed.status_code == 400


def test_reused_code_is_refused_and_revokes_the_family(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(owner_client, dcr_client)
    assert exchange_code(owner_client, dcr_client, code, verifier).status_code == 200

    replay = exchange_code(owner_client, dcr_client, code, verifier)

    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    family = RefreshTokenFamily.objects.get()
    assert family.revoked_at is not None
    assert family.revoked_reason == "code_reuse"
    assert RefreshToken.objects.get().is_revoked()
    event = AuditEvent.objects.get(kind="token.code_reuse_detected")
    assert event.detail == {"resource": PORTFOLIO, "family": family.pk}


def test_next_exchange_after_reuse_opens_a_new_family(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(owner_client, dcr_client)
    exchange_code(owner_client, dcr_client, code, verifier)
    exchange_code(owner_client, dcr_client, code, verifier)  # replay: family revoked

    obtain_tokens(owner_client, dcr_client)  # same live consent, no screen

    assert RefreshTokenFamily.objects.filter(revoked_at__isnull=True).count() == 1
    assert RefreshTokenFamily.objects.count() == 2


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"code_verifier": "x" * 43}, "invalid_grant"),
        ({"redirect_uri": "http://localhost:33418/other"}, "invalid_grant"),
        ({"resource": NEWS}, "invalid_target"),
        ({"code": "not-a-code"}, "invalid_grant"),
        ({"code_verifier": None}, "invalid_request"),
    ],
)
def test_bad_exchange_is_refused(
    owner_client: Client,
    dcr_client: OAuthClient,
    overrides: dict[str, str | None],
    error: str,
) -> None:
    code, verifier = obtain_authorization_code(owner_client, dcr_client)

    response = exchange_code(owner_client, dcr_client, code, verifier, **overrides)

    assert response.status_code == 400, response.content
    assert response.json()["error"] == error
    assert not RefreshToken.objects.exists()


def test_matching_resource_is_accepted(owner_client: Client, dcr_client: OAuthClient) -> None:
    code, verifier = obtain_authorization_code(owner_client, dcr_client)

    response = exchange_code(owner_client, dcr_client, code, verifier, resource=PORTFOLIO)

    assert response.status_code == 200, response.content


def test_news_code_gives_a_news_audience(owner_client: Client, dcr_client: OAuthClient) -> None:
    tokens = obtain_tokens(owner_client, dcr_client, resource=NEWS, scope="editor")

    claims = jwt.decode(str(tokens["access_token"]), options={"verify_signature": False})
    assert claims["aud"] == NEWS
    assert RefreshTokenFamily.objects.get().resource.url == NEWS


def test_access_token_expires_after_ten_minutes(
    owner_client: Client, dcr_client: OAuthClient, frozen_clock: FrozenClock
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)
    raw = str(tokens["access_token"])
    validate(owner_client, raw, frozen_clock)

    frozen_clock.advance(631)

    with pytest.raises(TokenRejected):
        validate(owner_client, raw, frozen_clock)


def test_refresh_token_is_stored_as_hash_in_the_consent_family(
    owner_client: Client, dcr_client: OAuthClient, frozen_clock: FrozenClock
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)
    obtain_tokens(owner_client, dcr_client)  # a second code under the same consent

    raw = str(tokens["refresh_token"])
    first = RefreshToken.objects.get(token_hash=hash_refresh_token(raw))
    assert not RefreshToken.objects.filter(token_hash=raw).exists()
    family = RefreshTokenFamily.objects.get()  # one consent, one family
    assert family.tokens.count() == 2
    assert first.family == family
    assert family.consent == AuthorizationCode.objects.first().consent  # type: ignore[union-attr]
    assert first.scope == "admin"
    assert first.issued_at == frozen_clock.now()
    assert first.expires_at == first.issued_at + timedelta(days=90)
    claims = jwt.decode(str(tokens["access_token"]), options={"verify_signature": False})
    assert first.jti == claims["jti"]


def test_cimd_client_can_exchange(owner_client: Client, cimd_client: OAuthClient) -> None:
    tokens = obtain_tokens(owner_client, cimd_client)

    assert set(tokens) == TOKEN_FIELDS


@pytest.mark.parametrize("grant_type", ["password"])  # client_credentials: test_machine_clients
def test_other_grant_types_are_unsupported(
    owner_client: Client, dcr_client: OAuthClient, grant_type: str
) -> None:
    response = exchange_code(owner_client, dcr_client, "c", "v", grant_type=grant_type)

    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_token_requests_are_limited_per_ip(client: Client, dcr_client: OAuthClient) -> None:
    use_https(client)
    form = {"grant_type": "authorization_code", "code": "c", "client_id": dcr_client.client_id}
    responses = [client.post("/token", form, REMOTE_ADDR="10.9.9.9") for _ in range(61)]

    assert [r.status_code for r in responses[:60]] == [400] * 60
    limited = responses[60]
    assert limited.status_code == 429
    assert limited.json() == {"error": "too_many_requests"}
    assert int(limited["Retry-After"]) > 0
    assert limited["Cache-Control"] == "no-store"
    # Another address is not affected.
    assert client.post("/token", form, REMOTE_ADDR="10.9.9.8").status_code == 400
