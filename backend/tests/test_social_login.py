"""Google and Kakao sign-in (#36): the provider checks, the account a callback signs into, the
same-email notice, linking and unlinking. Providers are faked at the HTTP boundary
(`fake_providers`), so the real state / PKCE / id_token checks run."""

import base64
import hashlib
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, override_settings

from accounts.models import ExternalIdentity, Member
from adapters.clock import get_clock
from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import SigningKey
from services import audit
from services.social_providers import (
    GITHUB_EMAILS_URL,
    GITHUB_TOKEN_URL,
    GITHUB_USER_URL,
    GOOGLE_TOKEN_URL,
    KAKAO_TOKEN_URL,
)
from tests.conftest import (
    MEMBER_EMAIL,
    FakeProviders,
    FrozenClock,
    authorize_query,
    ensure_terms_documents,
    exchange_code,
    make_member,
    obtain_authorization_code,
)
from tests.test_oidc import unverified

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db

GOOGLE_SUB = "108234567890123456789"  # the `member` fixture's Google identity
NEW_GOOGLE_SUB = "117000000000000000001"


@pytest.fixture
def members_app(dcr_client: OAuthClient, signing_key: SigningKey) -> OAuthClient:
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    return dcr_client


@pytest.fixture
def next_url(members_app: OAuthClient) -> str:
    return "/authorize?" + authorize_query(members_app, scope="login")


def start(client: Client, provider: str, next_url: str) -> dict[str, str]:
    """Press the provider button; the query the provider's authorization URL carries."""
    response = client.get(f"/login/{provider}?" + urlencode({"next": next_url}))
    assert response.status_code == 302, response.content
    location = urlsplit(response["Location"])
    assert location.scheme == "https"
    return {key: values[0] for key, values in parse_qs(location.query).items()}


def google_claims(query: dict[str, str], **overrides: object) -> dict[str, object]:
    now = int(get_clock().now().timestamp())
    claims: dict[str, object] = {
        "iss": "https://accounts.google.com",
        "aud": settings.GOOGLE_CLIENT_ID,
        "sub": NEW_GOOGLE_SUB,
        "email": "new@example.com",
        "email_verified": True,
        "name": "새 회원",
        "iat": now,
        "exp": now + 3600,
        "nonce": query["nonce"],
    }
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def callback(client: Client, provider: str, query: dict[str, str], **params: str) -> TestResponse:
    values = {"state": query["state"], "code": "the-code", **params}
    return client.get(f"/login/{provider}/callback?" + urlencode(values))


def google_login(
    client: Client, fake: FakeProviders, next_url: str, **overrides: object
) -> TestResponse:
    query = start(client, "google", next_url)
    fake.google_codes["the-code"] = google_claims(query, **overrides)
    return callback(client, "google", query)


def kakao_user(kakao_id: int = 4123456789, **account: object) -> dict[str, object]:
    return {
        "id": kakao_id,
        "kakao_account": {"profile": {"nickname": "카카오회원"}, **account},
    }


def kakao_login(
    client: Client, fake: FakeProviders, next_url: str, user: dict[str, object]
) -> TestResponse:
    query = start(client, "kakao", next_url)
    fake.kakao_codes["the-code"] = user
    return callback(client, "kakao", query)


def github_answer(
    github_id: int = 583231, emails: list[dict[str, object]] | None = None, **user: object
) -> dict[str, object]:
    """What GitHub says for one code: the `/user` document and the `/user/emails` list."""
    return {
        "user": {"id": github_id, "login": "octocat", "name": "모나 리자", **user},
        "emails": emails if emails is not None else [],
    }


def github_email(address: str, *, primary: bool, verified: bool) -> dict[str, object]:
    return {"email": address, "primary": primary, "verified": verified, "visibility": None}


def github_login(
    client: Client, fake: FakeProviders, next_url: str, answer: dict[str, object]
) -> TestResponse:
    query = start(client, "github", next_url)
    fake.github_codes["the-code"] = answer
    return callback(client, "github", query)


def terms_url(next_url: str) -> str:
    """Where a new account (or one behind on the terms) goes after signing in (#37)."""
    return "/terms?" + urlencode({"next": next_url})


def agree_to_terms(client: Client) -> None:
    ensure_terms_documents()
    page = client.get("/terms")
    documents = [str(d.pk) for d in page.context["documents"]]
    assert client.post("/terms", {"document": documents, "age_14": "on"}).status_code == 302


def session_user(client: Client) -> User | None:
    user_id = client.session.get("_auth_user_id")
    return User.objects.filter(pk=user_id).first() if user_id else None


def assert_refused(response: TestResponse, fake: FakeProviders) -> None:
    assert response.status_code == 400, response.content
    assert "_auth_user_id" not in response.client.session
    assert not ExternalIdentity.objects.filter(provider_sub=NEW_GOOGLE_SUB).exists()


# --- signing in ----------------------------------------------------------------------------


def test_first_google_login_makes_a_member_and_the_next_one_signs_into_it(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    assert query["scope"] == "openid email profile"
    assert query["redirect_uri"] == "https://auth.sandcorp.co.kr/login/google/callback"
    assert query["code_challenge_method"] == "S256"
    assert query["state"] and query["nonce"] and query["state"] != query["nonce"]
    fake_providers.google_codes["the-code"] = google_claims(query)
    response = callback(client, "google", query)

    assert response.status_code == 302
    assert response["Location"] == terms_url(next_url)  # a new account agrees first (#37)
    user = session_user(client)
    assert user is not None and user.username.startswith("m_")
    assert user.email == "new@example.com" and user.first_name == "새 회원"
    assert Member.objects.get(user=user).status == Member.Status.PENDING_TERMS
    # PKCE: the verifier sent to Google's token endpoint matches the challenge.
    url, form = fake_providers.posted[-1]
    assert url == GOOGLE_TOKEN_URL
    digest = hashlib.sha256(form["code_verifier"].encode()).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == query["code_challenge"]
    assert AuditEvent.objects.filter(kind=audit.MEMBER_CREATED, actor=user.username).exists()

    client.post("/logout")
    again = google_login(client, fake_providers, next_url)
    assert again.status_code == 302
    assert session_user(client) == user
    assert User.objects.filter(member__isnull=False).count() == 1


def test_signed_in_member_gets_a_member_token_for_the_authorize_request(
    client: Client,
    fake_providers: FakeProviders,
    members_app: OAuthClient,
    next_url: str,
    frozen_clock: FrozenClock,
) -> None:
    google_login(client, fake_providers, next_url)
    user = session_user(client)
    assert user is not None
    agree_to_terms(client)
    code, verifier = obtain_authorization_code(client, members_app, scope="login")
    response = exchange_code(client, members_app, code, verifier)
    assert response.status_code == 200, response.content
    claims = unverified(response.json()["access_token"])
    assert (claims["sub"], claims["acct"]) == (user.username, "member")


def test_kakao_login_without_email(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    response = kakao_login(client, fake_providers, next_url, kakao_user())
    assert response.status_code == 302 and response["Location"] == terms_url(next_url)
    identity = ExternalIdentity.objects.get(provider="kakao")
    assert identity.provider_sub == "4123456789"
    assert identity.display_name == "카카오회원"
    assert identity.user.email == "" and identity.email == ""
    url, form = fake_providers.posted[-1]
    assert url == KAKAO_TOKEN_URL and form["code_verifier"]


def test_kakao_email_counts_as_verified_only_when_kakao_says_so(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    kakao_login(
        client,
        fake_providers,
        next_url,
        kakao_user(email="k@example.com", is_email_valid=True, is_email_verified=False),
    )
    identity = ExternalIdentity.objects.get(provider="kakao")
    assert identity.email == "k@example.com" and identity.email_verified is False


def test_github_login_keeps_the_numeric_id_and_the_primary_verified_email(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "github", next_url)
    assert query["scope"] == "read:user user:email"
    assert query["code_challenge_method"] == "S256" and query["code_challenge"]
    assert "nonce" not in query  # OAuth 2.0 only, no id_token
    fake_providers.github_codes["the-code"] = github_answer(
        emails=[
            github_email("old@example.com", primary=False, verified=True),
            github_email("Mona@Example.com", primary=True, verified=True),
        ]
    )
    response = callback(client, "github", query)
    assert response.status_code == 302 and response["Location"] == terms_url(next_url)
    identity = ExternalIdentity.objects.get(provider="github")
    assert identity.provider_sub == "583231"
    assert identity.email == "Mona@Example.com" and identity.email_verified is True
    assert identity.display_name == "모나 리자"
    url, form = fake_providers.posted[-1]
    assert url == GITHUB_TOKEN_URL and form["code_verifier"] and form["code"] == "the-code"
    assert fake_providers.requested[-2:] == [GITHUB_USER_URL, GITHUB_EMAILS_URL]


@pytest.mark.parametrize(
    "emails",
    [
        [],
        [github_email("p@example.com", primary=True, verified=False)],
        [
            github_email("p@example.com", primary=True, verified=False),
            github_email("other@example.com", primary=False, verified=True),
        ],
    ],
)
def test_github_without_a_verified_primary_email_has_no_email(
    client: Client, fake_providers: FakeProviders, next_url: str, emails: list[dict[str, object]]
) -> None:
    response = github_login(
        client, fake_providers, next_url, github_answer(emails=emails, name=None)
    )
    assert response.status_code == 302 and response["Location"] == terms_url(next_url)
    identity = ExternalIdentity.objects.get(provider="github")
    assert identity.email == "" and identity.email_verified is False
    assert identity.display_name == "octocat"  # no name: the login


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        ({"user": {"id": True}, "emails": []}, "github_no_id"),
        ({"user": {"login": "octocat"}, "emails": []}, "github_no_id"),
        ({"user": {"id": 1}, "emails": {"email": "x@example.com"}}, "github_emails_not_list"),
        ({"user": {"id": 1}, "emails": "denied"}, "github_emails_status_403"),
        ({"token_error": "bad_verification_code"}, "github_no_access_token"),
    ],
)
def test_github_answers_that_cannot_be_used_are_refused(
    client: Client,
    fake_providers: FakeProviders,
    next_url: str,
    answer: dict[str, object],
    reason: str,
) -> None:
    response = github_login(client, fake_providers, next_url, answer)
    assert response.status_code == 400, response.content
    assert "_auth_user_id" not in client.session
    assert not ExternalIdentity.objects.exists()
    assert AuditEvent.objects.get(kind=audit.SOCIAL_LOGIN_FAILED).detail["reason"] == reason


def test_a_verified_github_email_of_another_account_shows_the_notice_first(
    client: Client, fake_providers: FakeProviders, next_url: str, member: User
) -> None:
    emails = [github_email(MEMBER_EMAIL, primary=True, verified=True)]
    response = github_login(client, fake_providers, next_url, github_answer(emails=emails))
    assert response.status_code == 302 and response["Location"] == "/signup/confirm"
    assert not ExternalIdentity.objects.filter(provider="github").exists()
    assert "이전에 Google로 가입하셨습니다" in client.get("/signup/confirm").content.decode()


# --- what the callback refuses -------------------------------------------------------------


def test_state_mismatch_is_refused_before_the_code_is_exchanged(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)
    response = callback(client, "google", {**query, "state": "forged"})
    assert_refused(response, fake_providers)
    assert fake_providers.posted == []
    event = AuditEvent.objects.get(kind=audit.SOCIAL_LOGIN_FAILED)
    assert event.detail == {"provider": "google", "reason": "state_mismatch"}


def test_a_callback_without_a_started_login_is_refused(
    client: Client, fake_providers: FakeProviders, members_app: OAuthClient
) -> None:
    response = client.get("/login/google/callback?state=x&code=the-code")
    assert_refused(response, fake_providers)
    assert fake_providers.posted == []


def test_a_callback_is_good_once(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)
    assert callback(client, "google", query).status_code == 302
    client.post("/logout")
    fake_providers.google_codes["the-code"] = google_claims(query)
    assert callback(client, "google", query).status_code == 400


def test_a_second_callback_after_the_login_went_through_returns_to_the_app(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    """Back button to the provider and picking again: no failure page, the app's `next`."""
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)
    assert callback(client, "google", query).status_code == 302
    again = callback(client, "google", query)
    assert again.status_code == 302
    assert again["Location"] == next_url
    assert not AuditEvent.objects.filter(kind=audit.SOCIAL_LOGIN_FAILED).exists()


def test_the_replayed_callback_does_not_count_against_the_address(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)
    callback(client, "google", query)
    for _ in range(10):
        assert callback(client, "google", query).status_code == 302


def test_a_replayed_callback_goes_home_once_the_note_is_old(
    client: Client, fake_providers: FakeProviders, next_url: str, frozen_clock: FrozenClock
) -> None:
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)
    callback(client, "google", query)
    frozen_clock.advance(10 * 60 + 1)
    again = callback(client, "google", query)
    assert again.status_code == 302
    assert again["Location"] == "/"


def test_a_callback_nobody_started_says_to_start_over_not_that_time_ran_out(
    client: Client, fake_providers: FakeProviders, members_app: OAuthClient
) -> None:
    response = client.get("/login/google/callback?state=x&code=the-code")
    assert "처음부터 다시 시작" in response.content.decode()
    assert "시간이 지났" not in response.content.decode()


def test_a_started_login_that_ran_out_says_time_ran_out(
    client: Client, fake_providers: FakeProviders, next_url: str, frozen_clock: FrozenClock
) -> None:
    query = start(client, "google", next_url)
    frozen_clock.advance(10 * 60 + 1)
    response = callback(client, "google", query)
    assert "시간이 지났" in response.content.decode()


def test_a_started_login_expires(
    client: Client, fake_providers: FakeProviders, next_url: str, frozen_clock: FrozenClock
) -> None:
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)
    frozen_clock.advance(10 * 60 + 1)
    assert_refused(callback(client, "google", query), fake_providers)


def test_a_callback_for_another_provider_is_refused(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    fake_providers.kakao_codes["the-code"] = kakao_user()
    response = callback(client, "kakao", query)
    assert response.status_code == 400
    assert not ExternalIdentity.objects.exists()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"nonce": "another-nonce"}, "id_token_nonce"),
        ({"nonce": None}, "id_token_nonce"),
        ({"aud": "someone-else.apps.googleusercontent.com"}, "id_token_aud"),
        ({"iss": "https://evil.example"}, "id_token_iss"),
        ({"exp": 1}, "id_token_expired"),
    ],
)
def test_id_tokens_google_would_not_vouch_for_are_refused(
    client: Client,
    fake_providers: FakeProviders,
    next_url: str,
    overrides: dict[str, object],
    reason: str,
) -> None:
    response = google_login(client, fake_providers, next_url, **overrides)
    assert_refused(response, fake_providers)
    assert AuditEvent.objects.get(kind=audit.SOCIAL_LOGIN_FAILED).detail["reason"] == reason


def test_expiry_is_judged_by_the_service_clock(
    client: Client, fake_providers: FakeProviders, next_url: str, frozen_clock: FrozenClock
) -> None:
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)  # exp = now + 1 hour
    frozen_clock.advance(9 * 60)
    assert callback(client, "google", query).status_code == 302
    client.post("/logout")
    query = start(client, "google", next_url)
    now = int(frozen_clock.now().timestamp())
    fake_providers.google_codes["the-code"] = google_claims(query, iat=now - 7200, exp=now - 61)
    assert callback(client, "google", query).status_code == 400


def test_an_id_token_signed_by_another_key_is_refused(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    forger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_providers.google_codes["the-code"] = FakeProviders.sign(google_claims(query), key=forger)
    assert_refused(callback(client, "google", query), fake_providers)


def test_too_many_failed_callbacks_block_the_address(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    for _ in range(5):
        query = start(client, "google", next_url)
        assert callback(client, "google", {**query, "state": "forged"}).status_code == 400
    query = start(client, "google", next_url)
    fake_providers.google_codes["the-code"] = google_claims(query)
    assert callback(client, "google", query).status_code == 429
    assert fake_providers.posted == []


def test_cancelling_at_the_provider_is_not_counted_as_an_attack(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    for _ in range(6):
        query = start(client, "google", next_url)
        response = callback(client, "google", query, error="access_denied", code="")
        assert response.status_code == 400
        assert "취소" in response.content.decode()
    assert fake_providers.posted == []


# --- which login screen shows the buttons --------------------------------------------------


def test_social_buttons_show_only_for_a_client_that_allows_members(
    client: Client, members_app: OAuthClient, next_url: str
) -> None:
    page = client.get("/login?" + urlencode({"next": next_url})).content.decode()
    assert 'data-provider="google"' in page and 'data-provider="kakao"' in page
    assert 'data-provider="github"' in page
    assert 'name="password"' in page  # the owner's login stays

    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=False)
    page = client.get("/login?" + urlencode({"next": next_url})).content.decode()
    assert "data-provider" not in page
    assert 'name="password"' in page
    assert "data-provider" not in client.get("/login").content.decode()


def test_the_start_route_refuses_a_client_that_does_not_allow_members(
    client: Client, fake_providers: FakeProviders, members_app: OAuthClient, next_url: str
) -> None:
    OAuthClient.objects.filter(pk=members_app.pk).update(allows_members=False)
    response = client.get("/login/google?" + urlencode({"next": next_url}))
    assert response.status_code == 302
    assert response["Location"].startswith("/login?")
    assert client.get("/login/google").status_code == 302  # no next: back to /login


@pytest.mark.parametrize(
    ("provider", "empty"),
    [
        ("kakao", "KAKAO_CLIENT_SECRET"),
        ("github", "GITHUB_CLIENT_ID"),
        ("github", "GITHUB_CLIENT_SECRET"),
    ],
)
def test_a_provider_without_its_settings_is_hidden_and_404(
    client: Client, next_url: str, provider: str, empty: str
) -> None:
    with override_settings(**{empty: ""}):
        page = client.get("/login?" + urlencode({"next": next_url})).content.decode()
        assert 'data-provider="google"' in page and f'data-provider="{provider}"' not in page
        assert client.get(f"/login/{provider}?" + urlencode({"next": next_url})).status_code == 404
        assert client.get(f"/login/{provider}/callback?state=x&code=y").status_code == 404


# --- same email ----------------------------------------------------------------------------


def test_a_verified_email_of_another_account_shows_the_notice_first(
    client: Client, fake_providers: FakeProviders, next_url: str, member: User
) -> None:
    response = kakao_login(
        client,
        fake_providers,
        next_url,
        kakao_user(email=MEMBER_EMAIL.upper(), is_email_valid=True, is_email_verified=True),
    )
    assert response.status_code == 302 and response["Location"] == "/signup/confirm"
    assert not ExternalIdentity.objects.filter(provider="kakao").exists()
    assert "_auth_user_id" not in client.session

    page = client.get("/signup/confirm").content.decode()
    assert "이전에 Google로 가입하셨습니다" in page
    assert "/login/google?" in page  # sign in with that login instead
    assert "로그인을 연결할 수 있습니다" in page and "합칠" not in page

    created = client.post("/signup/confirm")
    assert created.status_code == 302 and created["Location"] == terms_url(next_url)
    user = session_user(client)
    assert user is not None and user != member
    assert ExternalIdentity.objects.get(provider="kakao").user == user  # nothing merged
    assert client.get("/signup/confirm").status_code == 302  # the choice is used up


def test_an_unverified_email_shows_no_notice(
    client: Client, fake_providers: FakeProviders, next_url: str, member: User
) -> None:
    response = google_login(
        client, fake_providers, next_url, email=MEMBER_EMAIL, email_verified=False
    )
    assert response["Location"] == terms_url(next_url)
    assert session_user(client) not in (None, member)


def test_the_notice_expires(
    client: Client,
    fake_providers: FakeProviders,
    next_url: str,
    member: User,
    frozen_clock: FrozenClock,
) -> None:
    google_login(client, fake_providers, next_url, email=MEMBER_EMAIL)
    frozen_clock.advance(10 * 60 + 1)
    response = client.post("/signup/confirm")
    assert response.status_code == 302 and response["Location"] == "/login"
    assert User.objects.filter(member__isnull=False).count() == 1


# --- linking and unlinking -----------------------------------------------------------------


def link(client: Client, fake: FakeProviders, provider: str, **profile: object) -> TestResponse:
    response = client.post(f"/account/identities/link/{provider}")
    assert response.status_code == 302, response.content
    query = {k: v[0] for k, v in parse_qs(urlsplit(response["Location"]).query).items()}
    if provider == "google":
        fake.google_codes["the-code"] = google_claims(query, **profile)
    elif provider == "github":
        fake.github_codes["the-code"] = github_answer(**profile)  # type: ignore[arg-type]
    else:
        fake.kakao_codes["the-code"] = kakao_user(**profile)  # type: ignore[arg-type]
    return callback(client, provider, query)


def test_a_member_links_another_login(
    member_client: Client, fake_providers: FakeProviders, member: User
) -> None:
    response = link(member_client, fake_providers, "kakao")
    assert response.status_code == 302 and response["Location"] == "/account"
    assert sorted(member.identities.values_list("provider", flat=True)) == ["google", "kakao"]
    assert session_user(member_client) == member
    assert AuditEvent.objects.filter(kind=audit.IDENTITY_LINKED, actor=member.username).exists()
    page = member_client.get("/account/identities").content.decode()
    assert "Kakao 로그인을 연결했습니다" in page


def test_a_member_links_github_and_sees_it_in_the_account_page(
    member_client: Client, fake_providers: FakeProviders, member: User
) -> None:
    page = member_client.get("/account").content.decode()
    assert 'action="/account/identities/link/github"' in page
    response = link(member_client, fake_providers, "github")
    assert response.status_code == 302 and response["Location"] == "/account"
    page = member_client.get("/account").content.decode()
    assert "GitHub 로그인을 연결했습니다" in page
    assert '<span class="sc-list-title">GitHub</span>' in page
    assert 'action="/account/identities/link/github"' not in page


def test_linking_a_login_of_another_account_is_refused(
    member_client: Client, fake_providers: FakeProviders, member: User
) -> None:
    other = make_member("kakao", "999", email="", name="다른 사람")
    response = link(member_client, fake_providers, "kakao", kakao_id=999)
    assert response.status_code == 302
    assert ExternalIdentity.objects.get(provider="kakao").user == other
    assert member.identities.count() == 1
    page = member_client.get("/account/identities").content.decode()
    assert "이미 다른 Sandcorp 계정에 연결되어" in page


def test_relinking_your_own_login_changes_nothing(
    member_client: Client, fake_providers: FakeProviders, member: User
) -> None:
    response = link(member_client, fake_providers, "google", sub=GOOGLE_SUB)
    assert response.status_code == 302
    assert member.identities.count() == 1


def test_a_link_callback_after_the_session_changed_is_refused(
    member_client: Client, fake_providers: FakeProviders, member: User
) -> None:
    response = member_client.post("/account/identities/link/kakao")
    query = {k: v[0] for k, v in parse_qs(urlsplit(response["Location"]).query).items()}
    other = make_member("google", "777", email="", name="다른 사람")
    session = member_client.session
    pending = session["accounts.social_pending"]
    member_client.force_login(other)
    session = member_client.session
    session["accounts.social_pending"] = pending
    session.save()
    fake_providers.kakao_codes["the-code"] = kakao_user()
    assert callback(member_client, "kakao", query).status_code == 400
    assert not ExternalIdentity.objects.filter(provider="kakao").exists()


def test_the_last_login_cannot_be_unlinked(member_client: Client, member: User) -> None:
    identity = member.identities.get()
    response = member_client.post(f"/account/identities/{identity.pk}/unlink")
    assert response.status_code == 302
    assert member.identities.count() == 1
    page = member_client.get("/account/identities").content.decode()
    assert "마지막 남은 로그인은 해제할 수 없습니다" in page
    assert "/unlink" not in page


def test_a_member_with_two_logins_unlinks_one(
    member_client: Client, fake_providers: FakeProviders, member: User
) -> None:
    link(member_client, fake_providers, "kakao")
    google = member.identities.get(provider="google")
    page = member_client.get("/account/identities").content.decode()
    assert 'aria-label="Google 로그인 해제"' in page
    assert 'aria-label="Kakao 로그인 해제"' in page
    response = member_client.post(f"/account/identities/{google.pk}/unlink")
    assert response.status_code == 302
    assert list(member.identities.values_list("provider", flat=True)) == ["kakao"]
    assert (
        "Google 로그인 연결을 해제했습니다."
        in member_client.get("/account/identities").content.decode()
    )
    event = AuditEvent.objects.get(kind=audit.IDENTITY_UNLINKED)
    assert event.detail == {"provider": "google"}


def test_a_kakao_member_links_github_signs_in_with_it_and_unlinks_it(
    client: Client, fake_providers: FakeProviders, next_url: str, frozen_clock: FrozenClock
) -> None:
    kakao_member = make_member("kakao", "4123456789", email="", name="카카오회원")
    client.force_login(kakao_member)
    assert link(client, fake_providers, "github", github_id=99).status_code == 302
    assert sorted(kakao_member.identities.values_list("provider", flat=True)) == [
        "github",
        "kakao",
    ]

    client.logout()
    response = github_login(client, fake_providers, next_url, github_answer(github_id=99))
    assert response.status_code == 302 and response["Location"] == next_url
    assert session_user(client) == kakao_member  # the same member, no new account
    assert User.objects.filter(member__isnull=False).count() == 1

    github = kakao_member.identities.get(provider="github")
    assert client.post(f"/account/identities/{github.pk}/unlink").status_code == 302
    assert list(kakao_member.identities.values_list("provider", flat=True)) == ["kakao"]
    page = client.get("/account").content.decode()
    assert 'action="/account/identities/link/github"' in page  # can be linked again


def test_another_accounts_login_cannot_be_unlinked(member_client: Client, member: User) -> None:
    other = make_member("kakao", "999", email="", name="다른 사람")
    identity = other.identities.get()
    assert member_client.post(f"/account/identities/{identity.pk}/unlink").status_code == 404
    assert other.identities.count() == 1


def test_the_owner_has_a_social_logins_page(logged_in_client: Client) -> None:
    """#100: the owner (after password + TOTP) links social logins too; `test_owner_social`."""
    assert logged_in_client.get("/account/identities").status_code == 200
    linking = logged_in_client.post("/account/identities/link/google")
    assert linking.status_code == 302 and linking["Location"].startswith("https://")


def test_the_logins_page_needs_a_session(client: Client) -> None:
    response = client.get("/account/identities")
    assert response.status_code == 302 and response["Location"].startswith("/login")
