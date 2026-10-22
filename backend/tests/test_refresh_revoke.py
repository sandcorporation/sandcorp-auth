"""Refresh token rotation and reuse detection, revocation (RFC 7009), and consent revocation."""

from datetime import timedelta
from typing import TYPE_CHECKING

import jwt
import pytest
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from oauth.grants import SandcorpRefreshTokenGrant
from oauth.models import Client as OAuthClient
from oauth.models import Consent, RefreshToken, RefreshTokenFamily, SigningKey
from oauth.tokens import hash_refresh_token, store_refresh_token
from tests.conftest import (
    NEWS,
    PORTFOLIO,
    TOKEN_FIELDS,
    FrozenClock,
    authorize_query,
    obtain_tokens,
    refresh,
    use_https,
)

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db


@pytest.fixture
def owner_client(logged_in_client: Client, signing_key: SigningKey) -> Client:
    return logged_in_client


def stored(raw: str | int) -> RefreshToken:
    return RefreshToken.objects.get(token_hash=hash_refresh_token(str(raw)))


def error_of(response: "TestResponse") -> str:
    assert response.status_code in (400, 401), response.content
    error: str = response.json()["error"]
    return error


def claims(access_token: str | int) -> dict[str, object]:
    decoded: dict[str, object] = jwt.decode(str(access_token), options={"verify_signature": False})
    return decoded


def revoke(client: Client, oauth_client: OAuthClient, token: str, **extra: str) -> "TestResponse":
    use_https(client)
    return client.post("/revoke", {"token": token, "client_id": oauth_client.client_id, **extra})


def test_refresh_rotates_the_refresh_token(owner_client: Client, dcr_client: OAuthClient) -> None:
    first = obtain_tokens(owner_client, dcr_client)

    response = refresh(owner_client, dcr_client, str(first["refresh_token"]))

    assert response.status_code == 200, response.content
    body = response.json()
    assert set(body) == TOKEN_FIELDS
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "admin"
    assert body["refresh_token"] != first["refresh_token"]
    assert body["access_token"] != first["access_token"]
    access = claims(body["access_token"])
    assert access["aud"] == PORTFOLIO
    assert access["client_id"] == dcr_client.client_id
    old, new = stored(first["refresh_token"]), stored(body["refresh_token"])
    assert old.replaced_by == new
    assert old.family == new.family
    assert new.jti == access["jti"]
    event = AuditEvent.objects.get(kind="token.refreshed")
    assert event.client_id == dcr_client.client_id
    assert event.detail == {
        "client_id": dcr_client.client_id,
        "resource": PORTFOLIO,
        "scope": "admin",
        "jti": access["jti"],
        "family": new.family.pk,
    }


def test_reused_refresh_token_revokes_the_family(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    first = obtain_tokens(owner_client, dcr_client)
    second = refresh(owner_client, dcr_client, str(first["refresh_token"])).json()

    assert error_of(refresh(owner_client, dcr_client, str(first["refresh_token"]))) == (
        "invalid_grant"
    )

    family = RefreshTokenFamily.objects.get()
    assert family.revoked_at is not None
    assert family.revoked_reason == "refresh_reuse"
    # The latest token of the family is dead too.
    assert error_of(refresh(owner_client, dcr_client, second["refresh_token"])) == "invalid_grant"
    event = AuditEvent.objects.get(kind="token.reuse_detected")
    assert event.client_id == dcr_client.client_id
    assert event.detail == {"resource": PORTFOLIO, "family": family.pk}


def test_new_authorization_after_reuse_opens_a_new_family(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    first = obtain_tokens(owner_client, dcr_client)
    refresh(owner_client, dcr_client, str(first["refresh_token"]))
    refresh(owner_client, dcr_client, str(first["refresh_token"]))  # reuse: family revoked

    again = obtain_tokens(owner_client, dcr_client)
    response = refresh(owner_client, dcr_client, str(again["refresh_token"]))

    assert response.status_code == 200, response.content
    assert RefreshTokenFamily.objects.count() == 2
    live = RefreshTokenFamily.objects.get(revoked_at__isnull=True)
    assert stored(response.json()["refresh_token"]).family == live


def test_refresh_is_bound_to_the_family_resource(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)
    raw = str(tokens["refresh_token"])

    assert error_of(refresh(owner_client, dcr_client, raw, resource=NEWS)) == "invalid_target"

    response = refresh(owner_client, dcr_client, raw, resource=PORTFOLIO)
    assert response.status_code == 200, response.content
    assert claims(response.json()["access_token"])["aud"] == PORTFOLIO


def test_news_family_refreshes_to_a_news_audience(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client, resource=NEWS, scope="editor")

    response = refresh(owner_client, dcr_client, str(tokens["refresh_token"]))

    assert response.status_code == 200, response.content
    assert claims(response.json()["access_token"])["aud"] == NEWS


def test_scope_may_narrow_but_not_widen(owner_client: Client, dcr_client: OAuthClient) -> None:
    tokens = obtain_tokens(owner_client, dcr_client, scope="admin login")

    wider = refresh(owner_client, dcr_client, str(tokens["refresh_token"]), scope="admin editor")
    assert error_of(wider) == "invalid_scope"

    narrower = refresh(owner_client, dcr_client, str(tokens["refresh_token"]), scope="login")
    assert narrower.status_code == 200, narrower.content
    body = narrower.json()
    assert body["scope"] == "login"
    assert claims(body["access_token"])["scope"] == "login"
    # The new refresh token keeps the scope of the one it replaced (RFC 6749 6).
    assert stored(body["refresh_token"]).scope == "admin login"
    back = refresh(owner_client, dcr_client, body["refresh_token"])
    assert back.json()["scope"] == "admin login"


def test_other_client_cannot_use_the_refresh_token(
    owner_client: Client, dcr_client: OAuthClient, cimd_client: OAuthClient
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)

    stolen = refresh(owner_client, cimd_client, str(tokens["refresh_token"]))

    assert error_of(stolen) == "invalid_grant"
    assert RefreshTokenFamily.objects.get().revoked_at is None  # nothing happens to the family
    assert refresh(owner_client, dcr_client, str(tokens["refresh_token"])).status_code == 200


def test_refresh_token_expires_after_ninety_days(
    owner_client: Client, dcr_client: OAuthClient, frozen_clock: FrozenClock
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)

    frozen_clock.advance(timedelta(days=90).total_seconds() + 1)

    assert error_of(refresh(owner_client, dcr_client, str(tokens["refresh_token"]))) == (
        "invalid_grant"
    )


def test_refresh_just_before_ninety_days_works(
    owner_client: Client, dcr_client: OAuthClient, frozen_clock: FrozenClock
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)

    frozen_clock.advance(timedelta(days=90).total_seconds() - 1)

    assert refresh(owner_client, dcr_client, str(tokens["refresh_token"])).status_code == 200


def test_unknown_refresh_token_is_invalid_grant(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    assert error_of(refresh(owner_client, dcr_client, "not-a-token")) == "invalid_grant"


def test_losing_a_concurrent_rotation_is_not_reuse(
    owner_client: Client, dcr_client: OAuthClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two refreshes with one token: the one that finds it already rotated after validating it
    (the other committed in between) gets invalid_grant, and the family lives on."""
    tokens = obtain_tokens(owner_client, dcr_client)
    original = SandcorpRefreshTokenGrant.validate_token_request

    def winner_commits_in_between(grant: SandcorpRefreshTokenGrant) -> None:
        original(grant)
        token: RefreshToken = grant.request.refresh_token
        winner = store_refresh_token(token.family, "winner", token.scope)
        RefreshToken.objects.filter(pk=token.pk).update(replaced_by=winner)

    monkeypatch.setattr(
        SandcorpRefreshTokenGrant, "validate_token_request", winner_commits_in_between
    )

    loser = refresh(owner_client, dcr_client, str(tokens["refresh_token"]))

    assert error_of(loser) == "invalid_grant"
    assert RefreshTokenFamily.objects.get().revoked_at is None
    assert not AuditEvent.objects.filter(kind="token.reuse_detected").exists()
    assert RefreshToken.objects.count() == 2  # the original and the winner's, nothing more


def test_revoking_a_refresh_token_revokes_its_family(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)
    second = refresh(owner_client, dcr_client, str(tokens["refresh_token"])).json()

    response = revoke(owner_client, dcr_client, second["refresh_token"])

    assert response.status_code == 200
    family = RefreshTokenFamily.objects.get()
    assert family.revoked_at is not None
    assert family.revoked_reason == "revoked_by_client"
    assert error_of(refresh(owner_client, dcr_client, second["refresh_token"])) == "invalid_grant"
    event = AuditEvent.objects.get(kind="token.revoked")
    assert event.client_id == dcr_client.client_id
    assert event.detail == {
        "resource": PORTFOLIO,
        "family": family.pk,
        "reason": "revoked_by_client",
    }
    # Revoking it again (or with a misleading hint) is still fine.
    again = revoke(
        owner_client, dcr_client, second["refresh_token"], token_type_hint="access_token"
    )
    assert again.status_code == 200


@pytest.mark.parametrize("hint", [None, "access_token", "refresh_token"])
def test_revoking_unknown_or_access_tokens_is_200(
    owner_client: Client, dcr_client: OAuthClient, hint: str | None
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)
    extra = {"token_type_hint": hint} if hint else {}

    for value in ["not-a-token", str(tokens["access_token"])]:
        response = revoke(owner_client, dcr_client, value, **extra)
        assert response.status_code == 200, response.content

    assert RefreshTokenFamily.objects.get().revoked_at is None
    assert not AuditEvent.objects.filter(kind="token.revoked").exists()
    assert refresh(owner_client, dcr_client, str(tokens["refresh_token"])).status_code == 200


def test_other_client_cannot_revoke_the_refresh_token(
    owner_client: Client, dcr_client: OAuthClient, cimd_client: OAuthClient
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)

    response = revoke(owner_client, cimd_client, str(tokens["refresh_token"]))

    assert error_of(response) == "invalid_grant"  # authlib's answer (RFC 7009 2.1: refused)
    assert RefreshTokenFamily.objects.get().revoked_at is None


def test_revocation_needs_a_known_client_and_a_token(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    use_https(owner_client)
    unknown = owner_client.post("/revoke", {"token": "x", "client_id": "nobody"})
    assert error_of(unknown) == "invalid_client"
    missing = owner_client.post("/revoke", {"client_id": dcr_client.client_id})
    assert error_of(missing) == "invalid_request"


def test_admin_consent_revocation_cuts_the_family_and_asks_again(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)
    consent = Consent.objects.get()

    response = owner_client.post(
        reverse("admin:oauth_consent_changelist"),
        {"action": "revoke", "_selected_action": [consent.pk]},
    )

    assert response.status_code == 302, response.content
    consent.refresh_from_db()
    assert consent.revoked_at is not None
    family = RefreshTokenFamily.objects.get()
    assert family.revoked_reason == "consent_revoked"
    assert error_of(refresh(owner_client, dcr_client, str(tokens["refresh_token"]))) == (
        "invalid_grant"
    )
    event = AuditEvent.objects.get(kind="consent.revoked")
    assert event.actor == "farrar142"
    assert event.client_id == dcr_client.client_id
    assert event.detail == {
        "resource": PORTFOLIO,
        "scope": "admin",
        "reason": "consent_revoked",
        "families": [family.pk],
    }
    screen = owner_client.get("/authorize?" + authorize_query(dcr_client))
    assert screen.status_code == 200  # the consent screen again


def test_admin_family_revocation(owner_client: Client, dcr_client: OAuthClient) -> None:
    tokens = obtain_tokens(owner_client, dcr_client)
    family = RefreshTokenFamily.objects.get()

    response = owner_client.post(
        reverse("admin:oauth_refreshtokenfamily_changelist"),
        {"action": "revoke", "_selected_action": [family.pk]},
    )

    assert response.status_code == 302, response.content
    family.refresh_from_db()
    assert family.revoked_reason == "revoked_by_admin"
    assert error_of(refresh(owner_client, dcr_client, str(tokens["refresh_token"]))) == (
        "invalid_grant"
    )
    event = AuditEvent.objects.get(kind="token.revoked")
    assert event.actor == "farrar142"
    assert event.detail["reason"] == "revoked_by_admin"
    assert Consent.objects.get().revoked_at is None  # the consent stays: no screen next time
    assert owner_client.get("/authorize?" + authorize_query(dcr_client)).status_code == 302


def test_admin_lists_refresh_tokens_without_hashes(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    obtain_tokens(owner_client, dcr_client)
    token = RefreshToken.objects.get()

    page = owner_client.get(reverse("admin:oauth_refreshtoken_change", args=[token.pk]))

    assert page.status_code == 200
    assert token.token_hash not in page.content.decode()


def test_wider_consent_revokes_the_old_family(
    owner_client: Client, dcr_client: OAuthClient
) -> None:
    old = obtain_tokens(owner_client, dcr_client, scope="login")

    new = obtain_tokens(owner_client, dcr_client, scope="admin")  # consent screen, then allow

    old_consent, new_consent = Consent.objects.order_by("id")
    old_family = RefreshTokenFamily.objects.get(consent=old_consent)
    assert old_family.revoked_reason == "consent_replaced"
    assert error_of(refresh(owner_client, dcr_client, str(old["refresh_token"]))) == (
        "invalid_grant"
    )
    response = refresh(owner_client, dcr_client, str(new["refresh_token"]))
    assert response.status_code == 200, response.content
    assert stored(response.json()["refresh_token"]).family.consent == new_consent
    event = AuditEvent.objects.get(kind="consent.revoked")
    assert event.actor == "farrar142"
    assert event.detail["reason"] == "consent_replaced"
    assert event.detail["families"] == [old_family.pk]
