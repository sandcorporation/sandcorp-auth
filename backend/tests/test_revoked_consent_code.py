"""A code issued before its consent was revoked (「연결 끊기」, admin, withdrawal) is dead:
/token refuses it with invalid_grant and opens no new refresh token family."""

from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth.models import User
from django.test import Client

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import Consent, RefreshTokenFamily, SigningKey
from oauth.tokens import live_family
from services import audit
from services.confidential_clients import create_confidential_client
from services.consents import revoke_consent
from services.withdrawal import withdraw_member
from tests.conftest import (
    PKCE_VERIFIER,
    authorize_query,
    exchange_code,
    obtain_authorization_code,
    obtain_tokens,
    use_https,
)

pytestmark = pytest.mark.django_db


@pytest.fixture
def members_proxy(db: None, signing_key: SigningKey) -> tuple[OAuthClient, str]:
    issued = create_confidential_client(
        "Foresight", ["https://news.sandcorp.co.kr/callback"], actor="test"
    )
    OAuthClient.objects.filter(pk=issued.client.pk).update(allows_members=True)
    issued.client.refresh_from_db()
    return issued.client, issued.secret


def member_code(member_client: Client, app: OAuthClient) -> str:
    use_https(member_client)
    url = "/authorize?" + authorize_query(app, scope="openid profile email", resource=None)
    response = member_client.get(url)
    if response.status_code == 200:
        response = member_client.post(url, {"decision": "allow"})
    assert response.status_code == 302, response.content
    return parse_qs(urlsplit(response["Location"]).query)["code"][0]


def test_member_code_is_dead_after_disconnect(
    member_client: Client, member: User, members_proxy: tuple[OAuthClient, str]
) -> None:
    app, secret = members_proxy
    code = member_code(member_client, app)
    response = member_client.post(f"/account/apps/{app.pk}/disconnect")
    assert response.status_code == 302
    assert not Consent.objects.filter(user=member, revoked_at__isnull=True).exists()

    response = exchange_code(member_client, app, code, PKCE_VERIFIER, client_secret=secret)

    assert response.status_code == 400, response.content
    assert response.json()["error"] == "invalid_grant"
    assert not RefreshTokenFamily.objects.filter(user=member, revoked_at__isnull=True).exists()


def test_owner_code_is_dead_after_consent_revoked(
    logged_in_client: Client, owner: User, signing_key: SigningKey, dcr_client: OAuthClient
) -> None:
    obtain_tokens(logged_in_client, dcr_client)  # the consent now exists
    code, verifier = obtain_authorization_code(logged_in_client, dcr_client)
    consent = Consent.objects.get(user=owner, client=dcr_client, revoked_at__isnull=True)
    revoke_consent(consent, reason="consent_revoked", actor="admin", ip="")

    response = exchange_code(logged_in_client, dcr_client, code, verifier)

    assert response.status_code == 400, response.content
    assert response.json()["error"] == "invalid_grant"
    assert not RefreshTokenFamily.objects.filter(user=owner, revoked_at__isnull=True).exists()


def test_no_family_opens_on_a_revoked_consent(
    logged_in_client: Client, owner: User, signing_key: SigningKey, dcr_client: OAuthClient
) -> None:
    obtain_tokens(logged_in_client, dcr_client)
    consent = Consent.objects.get(user=owner, client=dcr_client, revoked_at__isnull=True)
    revoke_consent(consent, reason="consent_revoked", actor="admin", ip="")

    with pytest.raises(RuntimeError):
        live_family(consent)
    assert not RefreshTokenFamily.objects.filter(user=owner, revoked_at__isnull=True).exists()


def test_a_dead_code_is_not_taken_for_reuse(
    logged_in_client: Client, owner: User, signing_key: SigningKey, dcr_client: OAuthClient
) -> None:
    obtain_tokens(logged_in_client, dcr_client)
    code, verifier = obtain_authorization_code(logged_in_client, dcr_client)
    consent = Consent.objects.get(user=owner, client=dcr_client, revoked_at__isnull=True)
    revoke_consent(consent, reason="consent_revoked", actor="admin", ip="")

    exchange_code(logged_in_client, dcr_client, code, verifier)

    assert not AuditEvent.objects.filter(kind=audit.TOKEN_CODE_REUSE_DETECTED).exists()


def test_member_code_is_dead_after_withdrawal(
    member_client: Client, member: User, members_proxy: tuple[OAuthClient, str]
) -> None:
    app, secret = members_proxy
    code = member_code(member_client, app)
    withdraw_member(member)

    response = exchange_code(member_client, app, code, PKCE_VERIFIER, client_secret=secret)

    assert response.status_code == 400, response.content
    assert response.json()["error"] == "invalid_grant"
    assert not RefreshTokenFamily.objects.filter(user=member, revoked_at__isnull=True).exists()
