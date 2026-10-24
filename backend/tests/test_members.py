"""Sandcorp members (#35, ADR 0003): a second kind of account next to the owner.

A member signs in with a social login only (the flow is #36; here `make_member()` stands in).
Its `sub` is an opaque `m_` + ULID, its tokens carry `acct=member`, it never gets the owner's
resource scopes (`admin`, `editor`), and only clients marked "allows members" may get a code
or a token for it. The owner's tokens and the existing sites' rule (T11) stay as they were.
"""

import io
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import Client

from accounts.models import ExternalIdentity, Member
from audit.models import AuditEvent
from oauth.models import AuthorizationCode, Consent, Resource, SigningKey
from oauth.models import Client as OAuthClient
from oauth.tokens import SandcorpTokenGenerator
from services.confidential_clients import create_confidential_client
from services.members import (
    MEMBER_SUB_PATTERN,
    ExternalProfile,
    IdentityTaken,
    account_kind,
    create_member,
)
from services.owner import create_owner, get_owner
from tests.conftest import (
    MEMBER_EMAIL,
    MEMBER_NAME,
    NEWS,
    OWNER_PASSWORD,
    OWNER_USERNAME,
    PORTFOLIO,
    FrozenClock,
    authorize_query,
    exchange_code,
    make_member,
    obtain_authorization_code,
    refresh,
    use_https,
)
from tests.reference_validator import (
    AccessToken,
    JwksCache,
    TokenRejected,
    validate_access_token,
    validate_account_access_token,
)
from tests.test_confidential_clients import basic, code_form, post_token
from tests.test_oidc import PROXY_CALLBACK, SITE, unverified, userinfo, verify_id_token
from tests.test_signing_keys import jwks_fetcher

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db

Proxy = tuple[OAuthClient, str]


@pytest.fixture
def members_app(dcr_client: OAuthClient, signing_key: SigningKey) -> OAuthClient:
    """A public client that allows members."""
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    return dcr_client


@pytest.fixture
def members_proxy(db: None, signing_key: SigningKey) -> Proxy:
    """A confidential client (an app that signs members in with OpenID Connect)."""
    issued = create_confidential_client("Sandcorp Flow", [PROXY_CALLBACK], actor="test")
    OAuthClient.objects.filter(pk=issued.client.pk).update(allows_members=True)
    issued.client.refresh_from_db()
    return issued.client, issued.secret


def redirect_error(response: "TestResponse") -> str:
    """The `error` an /authorize response sent back to the client's redirect URI."""
    assert response.status_code == 302, response.content
    query = parse_qs(urlsplit(response["Location"]).query)
    assert "code" not in query
    return query["error"][0]


def oidc_tokens(client: Client, proxy: Proxy, scope: str) -> dict[str, str | int]:
    oauth_client, secret = proxy
    code, verifier = obtain_authorization_code(client, oauth_client, resource=None, scope=scope)
    response = post_token(
        client, code_form(oauth_client, code, verifier), basic(oauth_client.client_id, secret)
    )
    assert response.status_code == 200, response.content
    tokens: dict[str, str | int] = response.json()
    return tokens


# --- the account ---------------------------------------------------------------------------


def test_member_sub_is_an_opaque_ulid_not_made_from_the_profile(member: User) -> None:
    assert re.fullmatch(MEMBER_SUB_PATTERN, member.username)
    assert re.fullmatch(r"m_[0-7][0-9A-HJKMNP-TV-Z]{25}", member.username)
    assert "member" not in member.username.lower()
    assert not member.has_usable_password()
    assert not member.is_staff and not member.is_superuser
    assert account_kind(member) == "member"
    identity = ExternalIdentity.objects.get(user=member)
    assert (identity.provider, identity.provider_sub) == ("google", "108234567890123456789")
    assert (identity.email, identity.email_verified) == (MEMBER_EMAIL, True)
    assert identity.display_name == MEMBER_NAME
    assert Member.objects.get(user=member).email_verified is True


def test_each_member_gets_its_own_sub(db: None) -> None:
    first = make_member("google", "1")
    second = make_member("kakao", "1")  # same provider sub, other provider: another account
    assert first.username != second.username
    assert {account_kind(first), account_kind(second)} == {"member"}


def test_one_identity_belongs_to_one_account(member: User) -> None:
    with pytest.raises(IdentityTaken):
        make_member("google", "108234567890123456789", email="other@example.com")
    assert User.objects.filter(member__isnull=False).count() == 1


def test_an_account_may_have_several_identities_but_the_pair_is_unique(member: User) -> None:
    ExternalIdentity.objects.create(
        user=member, provider="kakao", provider_sub="42", linked_at=member.date_joined
    )
    assert member.identities.count() == 2
    with pytest.raises(IntegrityError), transaction.atomic():
        ExternalIdentity.objects.create(
            user=member, provider="kakao", provider_sub="42", linked_at=member.date_joined
        )


def test_unknown_provider_is_refused(db: None) -> None:
    with pytest.raises(ValueError):
        create_member(ExternalProfile(provider="naver", provider_sub="1"))


def test_members_do_not_count_as_a_second_owner(db: None) -> None:
    member = make_member()
    owner = create_owner(OWNER_USERNAME, OWNER_PASSWORD)
    assert get_owner() == owner
    assert account_kind(owner) == "owner"
    assert account_kind(member) == "member"


def test_a_member_shaped_username_cannot_be_the_owner(db: None) -> None:
    with pytest.raises(ValueError):
        create_owner("m_01JB0000000000000000000000", OWNER_PASSWORD)


def test_member_is_refused_by_the_admin_without_a_redirect_loop(member_client: Client) -> None:
    response = member_client.get(f"/{settings.ADMIN_PATH}", follow=True)
    assert response.status_code == 403
    assert len(response.redirect_chain) <= 2


def test_member_session_is_not_sent_to_totp(member_client: Client) -> None:
    response = member_client.get("/")
    assert response.status_code == 200
    assert "_auth_user_id" in member_client.session


# --- authorize: allowed clients and scopes -------------------------------------------------


def test_member_on_a_client_that_does_not_allow_members_is_access_denied(
    member_client: Client, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    use_https(member_client)
    url = "/authorize?" + authorize_query(dcr_client, scope="login")
    assert redirect_error(member_client.get(url)) == "access_denied"
    assert redirect_error(member_client.post(url, {"decision": "allow"})) == "access_denied"
    assert not Consent.objects.exists()
    assert not AuthorizationCode.objects.exists()


@pytest.mark.parametrize(
    ("resource", "scope"),
    [(PORTFOLIO, "admin"), (PORTFOLIO, "admin login"), (NEWS, "editor"), (NEWS, "login editor")],
)
def test_member_never_gets_admin_or_editor(
    member_client: Client, members_app: OAuthClient, resource: str, scope: str
) -> None:
    use_https(member_client)
    url = "/authorize?" + authorize_query(members_app, resource=resource, scope=scope)
    assert redirect_error(member_client.get(url)) == "invalid_scope"
    assert redirect_error(member_client.post(url, {"decision": "allow"})) == "invalid_scope"
    assert not Consent.objects.exists()


def test_member_on_an_allowing_client_gets_a_member_access_token(
    member_client: Client, members_app: OAuthClient, member: User, frozen_clock: FrozenClock
) -> None:
    code, verifier = obtain_authorization_code(member_client, members_app, scope="login")
    response = exchange_code(member_client, members_app, code, verifier)
    assert response.status_code == 200, response.content
    tokens = response.json()
    claims = unverified(tokens["access_token"])
    assert claims["sub"] == member.username
    assert claims["acct"] == "member"
    assert claims["scope"] == "login"
    assert claims["aud"] == PORTFOLIO

    jwks = JwksCache(jwks_fetcher(member_client), frozen_clock)
    verified = validate_account_access_token(
        tokens["access_token"],
        jwks=jwks,
        audience=PORTFOLIO,
        owner_sub=OWNER_USERNAME,
        required_scope="login",
        clock=frozen_clock,
    )
    assert (verified.sub, verified.acct) == (member.username, "member")
    # An existing site (T11, owner only) turns the same token away.
    with pytest.raises(TokenRejected):
        validate_access_token(
            tokens["access_token"],
            jwks=jwks,
            audience=PORTFOLIO,
            owner_sub=OWNER_USERNAME,
            required_scope="login",
            clock=frozen_clock,
        )

    refreshed = refresh(member_client, members_app, tokens["refresh_token"])
    assert refreshed.status_code == 200, refreshed.content
    assert unverified(refreshed.json()["access_token"])["acct"] == "member"


def test_member_id_token_and_userinfo(
    member_client: Client, members_proxy: Proxy, member: User, frozen_clock: FrozenClock
) -> None:
    tokens = oidc_tokens(member_client, members_proxy, "openid profile email")
    oauth_client = members_proxy[0]
    claims = verify_id_token(member_client, tokens["id_token"], oauth_client.client_id)
    member.refresh_from_db()
    assert member.last_login is not None
    now = int(frozen_clock.now().timestamp())
    assert claims == {
        "iss": SITE,
        "sub": member.username,
        "aud": oauth_client.client_id,
        "iat": now,
        "exp": now + 600,
        "auth_time": int(member.last_login.timestamp()),
        "acct": "member",
        "name": MEMBER_NAME,
        "email": MEMBER_EMAIL,
        "email_verified": True,
    }
    assert unverified(tokens["access_token"])["acct"] == "member"
    response = userinfo(member_client, tokens["access_token"])
    assert response.status_code == 200, response.content
    assert response.json() == {
        "sub": member.username,
        "acct": "member",
        "name": MEMBER_NAME,
        "email": MEMBER_EMAIL,
        "email_verified": True,
    }


def test_member_without_email_has_no_email_claims(
    client: Client, members_proxy: Proxy, frozen_clock: FrozenClock
) -> None:
    kakao = make_member("kakao", "3141592", email="", email_verified=False, name="")
    client.force_login(kakao)
    tokens = oidc_tokens(client, members_proxy, "openid profile email")
    claims = verify_id_token(client, tokens["id_token"], members_proxy[0].client_id)
    assert claims["acct"] == "member"
    assert not {"email", "email_verified", "name", "preferred_username"} & set(claims)
    assert userinfo(client, tokens["access_token"]).json() == {
        "sub": kakao.username,
        "acct": "member",
    }


def test_unverified_member_email_says_so(
    client: Client, members_proxy: Proxy, frozen_clock: FrozenClock
) -> None:
    kakao = make_member("kakao", "2718", email="k@example.com", email_verified=False)
    client.force_login(kakao)
    tokens = oidc_tokens(client, members_proxy, "openid email")
    claims = verify_id_token(client, tokens["id_token"], members_proxy[0].client_id)
    assert (claims["email"], claims["email_verified"]) == ("k@example.com", False)


# --- token endpoint: the client's mark is checked again ------------------------------------


def test_code_is_refused_if_the_client_stopped_allowing_members(
    member_client: Client, members_app: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(member_client, members_app, scope="login")
    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=False)
    response = exchange_code(member_client, members_app, code, verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_refresh_is_refused_if_the_client_stopped_allowing_members(
    member_client: Client, members_app: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(member_client, members_app, scope="login")
    tokens = exchange_code(member_client, members_app, code, verifier).json()
    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=False)
    response = refresh(member_client, members_app, tokens["refresh_token"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_token_generator_never_signs_owner_scopes_for_a_member(
    member: User, members_app: OAuthClient, signing_key: SigningKey
) -> None:
    resource = Resource.objects.get(url=PORTFOLIO)
    with pytest.raises(RuntimeError):
        SandcorpTokenGenerator().generate(
            "authorization_code", members_app, member, "admin", resource=resource
        )
    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=False)
    members_app.refresh_from_db()
    with pytest.raises(RuntimeError):
        SandcorpTokenGenerator().generate(
            "authorization_code", members_app, member, "login", resource=resource
        )


# --- the owner is untouched ----------------------------------------------------------------


def test_owner_tokens_carry_no_account_claim(
    logged_in_client: Client, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    code, verifier = obtain_authorization_code(logged_in_client, dcr_client)
    tokens = exchange_code(logged_in_client, dcr_client, code, verifier).json()
    claims = unverified(tokens["access_token"])
    assert set(claims) == {"iss", "sub", "aud", "client_id", "scope", "iat", "exp", "jti"}
    assert claims["sub"] == OWNER_USERNAME


def test_account_validator_takes_the_owner_only_by_owner_sub(
    logged_in_client: Client,
    dcr_client: OAuthClient,
    signing_key: SigningKey,
    frozen_clock: FrozenClock,
) -> None:
    code, verifier = obtain_authorization_code(logged_in_client, dcr_client, scope="login")
    token = exchange_code(logged_in_client, dcr_client, code, verifier).json()["access_token"]
    jwks = JwksCache(jwks_fetcher(logged_in_client), frozen_clock)

    def check(owner_sub: str) -> AccessToken:
        return validate_account_access_token(
            token,
            jwks=jwks,
            audience=PORTFOLIO,
            owner_sub=owner_sub,
            required_scope="login",
            clock=frozen_clock,
        )

    verified = check(OWNER_USERNAME)
    assert (verified.sub, verified.acct) == (OWNER_USERNAME, "owner")
    with pytest.raises(TokenRejected):
        check("someone-else")


# --- managing the mark ---------------------------------------------------------------------


def test_clients_command_turns_members_on_and_off(dcr_client: OAuthClient) -> None:
    out = io.StringIO()
    call_command("clients", "members", f"--client-id={dcr_client.client_id}", "--allow", stdout=out)
    dcr_client.refresh_from_db()
    assert dcr_client.allows_members is True
    event = AuditEvent.objects.get(kind="client.members_changed")
    assert event.detail == {"client_id": dcr_client.client_id, "allows_members": True}

    call_command("clients", "members", f"--client-id={dcr_client.client_id}", "--deny", stdout=out)
    dcr_client.refresh_from_db()
    assert dcr_client.allows_members is False

    listing = io.StringIO()
    call_command("clients", "list", stdout=listing)
    assert "members=off" in listing.getvalue()


def test_create_confidential_can_allow_members(db: None) -> None:
    out = io.StringIO()
    call_command(
        "clients",
        "create-confidential",
        "--name",
        "Sandcorp Flow",
        "--redirect-uri",
        "https://flow.sandcorp.co.kr/auth/callback",
        "--allow-members",
        stdout=out,
    )
    created = OAuthClient.objects.get(name="Sandcorp Flow")
    assert created.allows_members is True
    assert "allows_members: on" in out.getvalue()


def test_new_clients_do_not_allow_members(dcr_client: OAuthClient) -> None:
    assert dcr_client.allows_members is False
    issued = create_confidential_client("x", ["https://x.example/cb"], actor="test")
    assert issued.client.allows_members is False


def test_admin_change_form_has_the_members_switch(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    response = logged_in_client.get(f"/{settings.ADMIN_PATH}oauth/client/{dcr_client.pk}/change/")
    assert response.status_code == 200
    assert b'name="allows_members"' in response.content
