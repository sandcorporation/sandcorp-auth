"""The owner's social login (#100): linking, the social session's limits (member-level grants
only, `amr: ["fed"]`), the password + TOTP step-up for the admin and owner-only grants, and
`members merge`."""

import hashlib
import hmac
import json
from io import StringIO
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.test import Client, override_settings

from accounts.models import ExternalIdentity, Member, TermsAgreement
from audit.models import AuditEvent
from oauth.models import AuthorizationCode, Consent, RefreshToken, RefreshTokenFamily, SigningKey
from oauth.models import Client as OAuthClient
from services import audit
from services.merge import MergeRefused, merge_member_into_owner
from services.webhooks import deliver_due, set_webhook
from tests.conftest import (
    OWNER_PASSWORD,
    OWNER_USERNAME,
    FakeProviders,
    FakeWebhooks,
    FrozenClock,
    authorize_query,
    exchange_code,
    make_member,
    obtain_authorization_code,
    refresh,
    totp_code,
    use_https,
)
from tests.test_oidc import unverified
from tests.test_social_login import callback, kakao_login, kakao_user, session_user

pytestmark = pytest.mark.django_db

OWNER_KAKAO_ID = 3900000001
MEMBER_KAKAO_ID = 4123456789
HOOK_URL = "https://flow.sandcorp.co.kr/hooks/auth"
ADMIN = "/" + settings.ADMIN_PATH


@pytest.fixture
def members_app(dcr_client: OAuthClient, signing_key: SigningKey) -> OAuthClient:
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    return dcr_client


def member_level_url(app: OAuthClient, **overrides: str) -> str:
    return "/authorize?" + authorize_query(app, **({"scope": "login"} | overrides))


def link_owner_kakao(owner: User) -> ExternalIdentity:
    return ExternalIdentity.objects.create(
        user=owner,
        provider="kakao",
        provider_sub=str(OWNER_KAKAO_ID),
        linked_at=owner.date_joined,
    )


@pytest.fixture
def social_owner(
    logged_in_client: Client,
    owner: User,
    members_app: OAuthClient,
    fake_providers: FakeProviders,
    frozen_clock: FrozenClock,
) -> Client:
    """The owner (TOTP enrolled, Kakao linked) signed in again with Kakao only."""
    link_owner_kakao(owner)
    logged_in_client.post("/logout")
    use_https(logged_in_client)
    response = kakao_login(
        logged_in_client, fake_providers, member_level_url(members_app), kakao_user(OWNER_KAKAO_ID)
    )
    assert response.status_code == 302, response.content
    assert session_user(logged_in_client) == owner
    return logged_in_client


def step_up(client: Client, owner: User, frozen_clock: FrozenClock, next_url: str) -> str:
    """Password + TOTP from the social session; where it lands."""
    frozen_clock.advance(30)  # a fresh TOTP time step
    response = client.post(
        "/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD, "next": next_url}
    )
    assert response.status_code == 302, response.content
    response = client.post("/login/totp", {"code": totp_code(owner)})
    assert response.status_code == 302, response.content
    return str(response["Location"])


# --- linking -------------------------------------------------------------------------------


def test_owner_links_kakao_from_the_account_page(
    logged_in_client: Client, owner: User, fake_providers: FakeProviders
) -> None:
    page = logged_in_client.get("/account")
    assert page.status_code == 200
    html = page.content.decode()
    assert 'data-slot="identities"' in html
    assert 'data-slot="withdraw"' not in html and 'data-slot="email"' not in html
    response = logged_in_client.post("/account/identities/link/kakao")
    assert response.status_code == 302
    query = {k: v[0] for k, v in parse_qs(urlsplit(response["Location"]).query).items()}
    fake_providers.kakao_codes["the-code"] = kakao_user(OWNER_KAKAO_ID)
    assert callback(logged_in_client, "kakao", query)["Location"] == "/account"
    identity = ExternalIdentity.objects.get(provider="kakao")
    assert (identity.user_id, identity.provider_sub) == (owner.pk, str(OWNER_KAKAO_ID))
    # The owner keeps its password + TOTP, so its last social login may go too.
    assert logged_in_client.post(f"/account/identities/{identity.pk}/unlink").status_code == 302
    assert not ExternalIdentity.objects.filter(user=owner).exists()


def test_social_session_must_step_up_before_changing_sign_in_methods(
    social_owner: Client,
) -> None:
    to_login = "/login?" + urlencode({"next": "/account"})
    assert social_owner.get("/account")["Location"] == to_login
    assert social_owner.post("/account/identities/link/github")["Location"] == to_login
    identity = ExternalIdentity.objects.get(provider="kakao")
    unlink = social_owner.post(f"/account/identities/{identity.pk}/unlink")
    assert unlink["Location"] == to_login
    assert ExternalIdentity.objects.filter(pk=identity.pk).exists()


# --- the social session --------------------------------------------------------------------


def test_kakao_owner_gets_member_level_tokens_as_the_owner_marked_fed(
    social_owner: Client, members_app: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(social_owner, members_app, scope="login")
    assert AuthorizationCode.objects.get().via_social
    response = exchange_code(social_owner, members_app, code, verifier)
    assert response.status_code == 200, response.content
    tokens = response.json()
    claims = unverified(tokens["access_token"])
    assert claims["sub"] == OWNER_USERNAME
    assert "acct" not in claims
    assert claims["amr"] == ["fed"]
    assert claims["scope"] == "login"
    again = refresh(social_owner, members_app, tokens["refresh_token"])
    assert again.status_code == 200, again.content
    assert unverified(again.json()["access_token"])["amr"] == ["fed"]
    assert all(token.via_social for token in RefreshToken.objects.all())


def test_password_totp_tokens_carry_no_amr(
    logged_in_client: Client, members_app: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(logged_in_client, members_app, scope="admin")
    response = exchange_code(logged_in_client, members_app, code, verifier)
    assert response.status_code == 200, response.content
    assert "amr" not in unverified(response.json()["access_token"])
    assert not AuthorizationCode.objects.get().via_social


@pytest.mark.parametrize("allows_members, scope", [(True, "admin"), (False, "login")])
def test_owner_only_grants_send_the_social_session_to_password_totp(
    social_owner: Client,
    owner: User,
    members_app: OAuthClient,
    frozen_clock: FrozenClock,
    allows_members: bool,
    scope: str,
) -> None:
    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=allows_members)
    url = member_level_url(members_app, scope=scope)
    for response in (social_owner.get(url), social_owner.post(url, {"decision": "allow"})):
        assert response.status_code == 302
        assert response["Location"] == "/login?" + urlencode({"next": url})
    assert not AuthorizationCode.objects.exists()
    login_page = social_owner.get("/login?" + urlencode({"next": url}))
    html = login_page.content.decode()
    assert login_page.status_code == 200
    assert 'data-slot="step-up"' in html and 'data-slot="social-login"' not in html
    # After password + TOTP the request comes back and goes through without `amr`.
    assert step_up(social_owner, owner, frozen_clock, url) == url
    code, verifier = obtain_authorization_code(social_owner, members_app, scope=scope)
    response = exchange_code(social_owner, members_app, code, verifier)
    assert response.status_code == 200, response.content
    assert "amr" not in unverified(response.json()["access_token"])


def test_social_code_is_refused_at_token_once_the_grant_is_no_longer_member_level(
    social_owner: Client, members_app: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(social_owner, members_app, scope="login")
    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=False)
    response = exchange_code(social_owner, members_app, code, verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_social_refresh_is_refused_once_the_grant_is_no_longer_member_level(
    social_owner: Client, members_app: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(social_owner, members_app, scope="login")
    tokens = exchange_code(social_owner, members_app, code, verifier).json()
    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=False)
    response = refresh(social_owner, members_app, tokens["refresh_token"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_social_session_steps_up_before_the_admin(
    social_owner: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    for path in (ADMIN, ADMIN + "oauth/client/", ADMIN + "login/"):
        response = social_owner.get(path)
        assert response.status_code == 302, path
        assert response["Location"] == "/login?" + urlencode({"next": path})
    assert step_up(social_owner, owner, frozen_clock, ADMIN) == ADMIN
    assert social_owner.get(ADMIN).status_code == 200


def test_password_totp_session_opens_the_admin(logged_in_client: Client) -> None:
    assert logged_in_client.get(ADMIN).status_code == 200


@override_settings(STEP_UP_SECONDS=600)
def test_step_up_runs_out(logged_in_client: Client, frozen_clock: FrozenClock) -> None:
    frozen_clock.advance(601)
    response = logged_in_client.get(ADMIN)
    assert response.status_code == 302
    assert response["Location"] == "/login?" + urlencode({"next": ADMIN})


# --- members merge -------------------------------------------------------------------------


@pytest.fixture
def merge_case(
    owner: User, members_app: OAuthClient, signing_key: SigningKey, frozen_clock: FrozenClock
) -> tuple[User, str]:
    """A Kakao member with a live consent (and refresh tokens) at a client with a webhook."""
    secret = set_webhook(members_app, url=HOOK_URL, rotate_secret=False, actor="test")
    assert secret is not None
    member = make_member("kakao", str(MEMBER_KAKAO_ID))
    client = Client()
    client.force_login(member)
    code, verifier = obtain_authorization_code(client, members_app, scope="login")
    assert exchange_code(client, members_app, code, verifier).status_code == 200
    return member, secret


def test_merge_dry_run_only_counts(merge_case: tuple[User, str]) -> None:
    member, _ = merge_case
    out = StringIO()
    call_command(
        "members",
        "merge",
        "--from",
        member.username,
        "--into",
        OWNER_USERNAME,
        "--dry-run",
        stdout=out,
    )
    text = out.getvalue()
    assert "소셜 로그인 1개 kakao" in text
    assert "앱 동의 옮김 1건" in text
    assert "리프레시 토큰 패밀리 폐기 1건" in text
    assert "user.merged 웹훅 1건" in text
    assert User.objects.filter(pk=member.pk).exists()
    assert ExternalIdentity.objects.get(provider="kakao").user_id == member.pk


def test_merge_moves_identities_and_consents_and_announces_user_merged(
    logged_in_client: Client,  # the owner has TOTP enrolled
    merge_case: tuple[User, str],
    owner: User,
    members_app: OAuthClient,
    fake_webhooks: FakeWebhooks,
    fake_providers: FakeProviders,
) -> None:
    member, secret = merge_case
    sub = member.username
    family = RefreshTokenFamily.objects.get(user=member)
    session = Client()
    session.force_login(member)
    report = merge_member_into_owner(sub, OWNER_USERNAME)
    assert (report.identities, report.consents_moved, report.families_revoked) == (["kakao"], 1, 1)
    assert report.sessions_deleted == 2  # the fixture's and this one
    assert not User.objects.filter(pk=member.pk).exists()
    assert not Member.objects.exists() and not TermsAgreement.objects.exists()
    assert ExternalIdentity.objects.get(provider="kakao").user_id == owner.pk
    consent = Consent.objects.get(revoked_at__isnull=True)
    assert (consent.user_id, consent.client_id, consent.scopes) == (
        owner.pk,
        members_app.pk,
        ["login"],
    )
    assert not RefreshTokenFamily.objects.filter(pk=family.pk).exists()  # gone with the member
    assert session.get("/account").status_code == 302  # signed out
    event = AuditEvent.objects.get(kind=audit.MEMBER_MERGED)
    assert event.detail["from_sub"] == sub and len(event.detail["terms_agreed"]) == 2

    deliver_due()
    ((url, body, headers),) = fake_webhooks.sent
    assert url == HOOK_URL
    payload = json.loads(body)
    assert set(payload) == {"id", "type", "from_sub", "to_sub"}
    assert (payload["type"], payload["from_sub"], payload["to_sub"]) == (
        "user.merged",
        sub,
        OWNER_USERNAME,
    )
    assert headers["X-Sandcorp-Event"] == "user.merged"
    stamp, mac = (part.split("=", 1)[1] for part in headers["X-Sandcorp-Signature"].split(","))
    expected = hmac.new(secret.encode(), f"{stamp}.".encode() + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(mac, expected)
    assert not any(json.loads(b)["type"] == "user.deleted" for _, b, _ in fake_webhooks.sent)

    # The owner now signs in with that Kakao and gets the app without a new consent screen.
    owner_client = Client()
    use_https(owner_client)
    landed = kakao_login(
        owner_client, fake_providers, member_level_url(members_app), kakao_user(MEMBER_KAKAO_ID)
    )
    assert landed.status_code == 302
    assert session_user(owner_client) == owner
    code, verifier = obtain_authorization_code(owner_client, members_app, scope="login")
    tokens = exchange_code(owner_client, members_app, code, verifier).json()
    assert unverified(tokens["access_token"])["sub"] == OWNER_USERNAME


def test_merge_adds_scopes_to_a_consent_the_owner_already_has(
    merge_case: tuple[User, str], owner: User, members_app: OAuthClient
) -> None:
    member, _ = merge_case
    Consent.objects.create(
        user=owner,
        client=members_app,
        resource=Consent.objects.get(user=member).resource,
        scopes=["admin"],
        granted_at=owner.date_joined,
    )
    report = merge_member_into_owner(member.username, OWNER_USERNAME)
    assert (report.consents_moved, report.consents_combined) == (0, 1)
    assert Consent.objects.get(revoked_at__isnull=True).scopes == ["admin", "login"]


def test_merge_stops_when_the_owner_already_has_that_provider(
    merge_case: tuple[User, str], owner: User, fake_webhooks: FakeWebhooks
) -> None:
    member, _ = merge_case
    ExternalIdentity.objects.create(
        user=owner, provider="kakao", provider_sub="999", linked_at=owner.date_joined
    )
    with pytest.raises(CommandError, match="already has a login of kakao"):
        call_command("members", "merge", "--from", member.username, "--into", OWNER_USERNAME)
    assert User.objects.filter(pk=member.pk).exists()
    assert RefreshTokenFamily.objects.get(user=member).revoked_at is None
    deliver_due()
    assert fake_webhooks.sent == []


@pytest.mark.parametrize(
    "source, target", [("owner", "owner"), ("owner", "member"), ("member", "member")]
)
def test_merge_takes_a_member_into_the_owner_only(
    merge_case: tuple[User, str], source: str, target: str
) -> None:
    member, _ = merge_case
    names = {"owner": OWNER_USERNAME, "member": member.username}
    with pytest.raises(MergeRefused):
        merge_member_into_owner(names[source], names[target])
