"""Social login flow details (#144): where a repeated or failed callback leads, the no-account
and same-email screens, and no social buttons on the admin's login."""

from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.http.response import HttpResponseBase
from django.test import Client, override_settings

from accounts.models import ExternalIdentity
from adapters.clock import get_clock
from services import throttle
from services.login import IP_RULE
from tests.conftest import MEMBER_EMAIL, FakeProviders, FrozenClock, make_member
from tests.test_social_login import (
    GOOGLE_SUB,
    callback,
    github_answer,
    github_email,
    github_login,
    google_login,
    kakao_user,
    members_app,
    next_url,
    start,
)

__all__ = ["members_app", "next_url"]  # fixtures

pytestmark = pytest.mark.django_db


def login_link(next_url: str) -> str:
    return 'href="/login?' + urlencode({"next": next_url}) + '"'


def body(response: HttpResponseBase) -> str:
    return str(response.content.decode()).replace("&amp;", "&")  # type: ignore[attr-defined]


# --- 1. a link flow that finished goes back to 「내 계정」 ------------------------------------


def test_picking_the_linked_provider_again_after_linking_goes_to_my_account(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    make_member()
    assert google_login(client, fake_providers, next_url, sub=GOOGLE_SUB)["Location"] == next_url

    started = client.post("/account/identities/link/kakao")
    query = {k: v[0] for k, v in parse_qs(urlsplit(started["Location"]).query).items()}
    fake_providers.kakao_codes["the-code"] = kakao_user()
    assert callback(client, "kakao", query)["Location"] == "/account"

    again = callback(client, "kakao", query)  # back button, the same provider again
    assert again.status_code == 302 and again["Location"] == "/account"


# --- 2. after a cancel, the failure page still leads back to the app ----------------------


def test_a_callback_after_a_cancel_leads_to_the_apps_login(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    cancelled = callback(client, "google", query, error="access_denied", code="")
    assert login_link(next_url) in body(cancelled)

    again = callback(client, "google", query)  # back button, picking someone again
    assert again.status_code == 400
    assert "진행 중인 로그인이 없습니다" in body(again)
    assert login_link(next_url) in body(again)


def test_the_locked_page_after_a_cancel_leads_to_the_apps_login(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    callback(client, "google", query, error="access_denied", code="")
    for _ in range(5):
        throttle.hit(IP_RULE, "ip:127.0.0.1")
    again = callback(client, "google", query)
    assert again.status_code == 429
    assert login_link(next_url) in body(again)


def test_the_kept_next_lasts_ten_minutes(
    client: Client, fake_providers: FakeProviders, next_url: str, frozen_clock: FrozenClock
) -> None:
    query = start(client, "google", next_url)
    callback(client, "google", query, error="access_denied", code="")
    frozen_clock.advance(10 * 60 + 1)
    again = callback(client, "google", query)
    assert 'href="/login"' in body(again) and next_url not in body(again)


def test_a_logout_drops_the_kept_next(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    callback(client, "google", query, error="access_denied", code="")
    client.post("/logout")
    assert 'href="/login"' in body(callback(client, "google", query))


def test_a_login_drops_the_kept_next(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    query = start(client, "google", next_url)
    callback(client, "google", query, error="access_denied", code="")
    assert "accounts.social_recent_next" in client.session
    google_login(client, fake_providers, next_url)
    assert "accounts.social_recent_next" not in client.session


# --- 3. no account: the same words for a withdrawn and an unknown login -------------------


def test_no_account_page_does_not_say_not_yet(
    client: Client, fake_providers: FakeProviders, frozen_clock: FrozenClock
) -> None:
    page = body(google_login(client, fake_providers, "/account"))
    assert "이 로그인 수단으로 연결된 계정이 없습니다" in page
    assert "아직" not in page


# --- 4, 5. the same-email notice -----------------------------------------------------------


def same_email_member() -> User:
    """A member that linked Kakao first and Google later (not alphabetical)."""
    user = make_member("kakao", "4000000001")
    ExternalIdentity.objects.create(
        user=user,
        provider="google",
        provider_sub="109000000000000000001",
        email=MEMBER_EMAIL,
        linked_at=get_clock().now() + timedelta(days=1),
    )
    return user


def github_same_email(client: Client, fake: FakeProviders, next_url: str) -> str:
    answer = github_answer(emails=[github_email(MEMBER_EMAIL, primary=True, verified=True)])
    assert github_login(client, fake, next_url, answer)["Location"] == "/signup/confirm"
    return body(client.get("/signup/confirm"))


def test_the_notice_lists_logins_in_the_order_they_were_linked(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    same_email_member()
    page = github_same_email(client, fake_providers, next_url)
    assert "이전에 Kakao · Google로 가입하셨습니다" in page
    assert page.index('data-provider="kakao"') < page.index('data-provider="google"')


def test_the_notice_without_an_app_hides_unset_providers_and_leads_to_the_login(
    client: Client, fake_providers: FakeProviders
) -> None:
    same_email_member()
    with override_settings(KAKAO_CLIENT_ID=""):
        page = github_same_email(client, fake_providers, "/account")
    assert 'data-provider="kakao"' not in page and 'data-provider="google"' in page
    assert login_link("/account") in page


def test_the_notice_for_an_app_also_leads_to_the_login(
    client: Client, fake_providers: FakeProviders, next_url: str
) -> None:
    same_email_member()
    page = github_same_email(client, fake_providers, next_url)
    assert login_link(next_url) in page


# --- 6. the admin's login has no social buttons ---------------------------------------------


@pytest.mark.parametrize("path", ["", "auth/user/"])
def test_no_social_buttons_on_the_admins_login(client: Client, path: str) -> None:
    admin_next = "/" + settings.ADMIN_PATH + path
    page = client.get("/login?" + urlencode({"next": admin_next})).content.decode()
    assert "data-provider" not in page
    assert 'name="password"' in page
    started = client.get("/login/google?" + urlencode({"next": admin_next}))
    assert started.status_code == 302 and started["Location"].startswith("/login?")
