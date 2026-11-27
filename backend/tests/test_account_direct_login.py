"""Signing in to 「내 계정」 with a social login and no app (#126): existing accounts only."""

from typing import Literal
from urllib.parse import urlencode

import pytest
from django.contrib.auth.models import User
from django.test import Client

from accounts.models import ExternalIdentity
from audit.models import AuditEvent
from services import audit
from services.withdrawal import withdraw_member
from tests.conftest import MEMBER_EMAIL, FakeProviders, FrozenClock, make_member
from tests.test_owner_social import OWNER_KAKAO_ID, link_owner_kakao
from tests.test_social_login import (
    GOOGLE_SUB,
    NEW_GOOGLE_SUB,
    google_login,
    kakao_login,
    kakao_user,
    session_user,
)

pytestmark = pytest.mark.django_db

type Who = Literal["member", "new", "new_same_email", "owner", "withdrawn"]

NO_ACCOUNT = "이 로그인 수단으로 연결된 계정이 없습니다"


@pytest.mark.parametrize(
    ("who", "next_url", "button_next"),
    [
        ("member", "", "/account"),
        ("member", "/", "/account"),
        ("member", "/account", "/account"),
        ("member", "https://evil.example/account", "/account"),
        ("new", "", "/account"),
        ("new", "/account", "/account"),
        ("new_same_email", "", "/account"),
        ("owner", "", "/account"),
        ("withdrawn", "", "/account"),
        ("withdrawn", "/account", "/account"),
        # Any other screen of this service (#138): back there, or 「내 계정」 when it is
        # POST only or the login itself.
        ("member", "/terms", "/terms"),
        ("member", "/terms?next=%2Faccount", "/terms?next=%2Faccount"),
        ("member", "/account/email", "/account"),
        ("member", "/login", "/account"),
        ("member", "/logout", "/account"),
        ("member", "/login/google", "/account"),
        ("new", "/terms", "/terms"),
        ("new_same_email", "/terms", "/terms"),
        ("owner", "/terms", "/terms"),
    ],
)
def test_social_login_without_an_app_signs_in_existing_accounts_only(
    client: Client,
    fake_providers: FakeProviders,
    frozen_clock: FrozenClock,
    owner: User,
    request: pytest.FixtureRequest,
    who: Who,
    next_url: str,
    button_next: str,
) -> None:
    login_page = "/login?" + urlencode({"next": next_url}) if next_url else "/login"
    page = client.get(login_page).content.decode()
    button = "/login/google?" + urlencode({"next": button_next})
    assert f'href="{button}"' in page.replace("&amp;", "&")
    assert 'name="password"' in page  # the owner's form stays
    assert "처음이면 계정이 만들어집니다" not in page
    users_before = User.objects.count()

    if who == "owner":
        request.getfixturevalue("logged_in_client")  # TOTP enrolled, then signed out
        client.post("/logout")
        link_owner_kakao(owner)
        response = kakao_login(client, fake_providers, button_next, kakao_user(OWNER_KAKAO_ID))
    else:
        if who in ("member", "withdrawn"):
            member = make_member()
            if who == "withdrawn":
                withdraw_member(member)
        if who == "new_same_email":
            make_member("kakao", "4000000001")
        sub = GOOGLE_SUB if who in ("member", "withdrawn") else NEW_GOOGLE_SUB
        email = MEMBER_EMAIL if who == "new_same_email" else "new@example.com"
        response = google_login(client, fake_providers, button_next, sub=sub, email=email)
        users_before = User.objects.count()

    if who in ("member", "owner"):
        assert response.status_code == 302, response.content
        assert response["Location"] == button_next
        signed_in = session_user(client)
        assert signed_in is not None
        if who == "owner":
            assert signed_in == owner
            # A social session of the owner is weak: 「내 계정」 asks for password + TOTP.
            assert client.get("/account")["Location"] == "/login?next=%2Faccount"
        else:
            assert client.get("/account").status_code == 200
        return

    if who == "new_same_email":
        # The same-email notice, as through an app, but it only leads to the existing login.
        assert response.status_code == 302, response.content
        assert response["Location"] == "/signup/confirm"
        body = client.get("/signup/confirm").content.decode().replace("&amp;", "&")
        assert "이전에 Kakao로 가입하셨습니다" in body
        assert 'href="/login/kakao?' + urlencode({"next": button_next}) + '"' in body
        assert 'data-slot="new-account"' not in body
        assert "_auth_user_id" not in client.session
        assert User.objects.count() == users_before
        return

    assert response.status_code == 200, response.content
    body = response.content.decode()
    assert NO_ACCOUNT in body
    assert 'href="/login?' + urlencode({"next": button_next}) + '"' in body
    assert "_auth_user_id" not in client.session
    assert User.objects.count() == users_before
    assert not ExternalIdentity.objects.filter(provider_sub=NEW_GOOGLE_SUB).exists()
    assert "accounts.social_signup" not in client.session  # no same-email notice either
    assert AuditEvent.objects.filter(kind=audit.SOCIAL_LOGIN_FAILED).exists()


def test_owner_home_has_a_way_into_my_account(logged_in_client: Client) -> None:
    page = logged_in_client.get("/").content.decode()
    assert 'href="/account"' in page


def test_apps_that_refuse_members_show_no_buttons(client: Client) -> None:
    for next_url in ("/authorize?client_id=nope", "/authorize"):
        page = client.get("/login?" + urlencode({"next": next_url})).content.decode()
        assert "data-provider" not in page
        response = client.get("/login/google?" + urlencode({"next": next_url}))
        assert response["Location"].startswith("/login?")


def test_signed_out_member_is_sent_to_the_login_with_buttons(client: Client) -> None:
    for path in ("/", "/account"):
        response = client.get(path)
        assert response.status_code == 302
        page = client.get(response["Location"]).content.decode()
        assert 'data-provider="google"' in page


def test_no_new_account_from_the_same_email_notice_without_an_app(
    client: Client, fake_providers: FakeProviders, frozen_clock: FrozenClock
) -> None:
    make_member("kakao", "4000000001")
    google_login(client, fake_providers, "/account", sub=NEW_GOOGLE_SUB, email=MEMBER_EMAIL)
    users_before = User.objects.count()
    created_before = AuditEvent.objects.filter(kind=audit.MEMBER_CREATED).count()

    response = client.post("/signup/confirm")

    assert response.status_code == 302
    assert response["Location"] == "/signup/confirm"
    assert User.objects.count() == users_before
    assert not ExternalIdentity.objects.filter(provider_sub=NEW_GOOGLE_SUB).exists()
    assert "_auth_user_id" not in client.session
    assert AuditEvent.objects.filter(kind=audit.MEMBER_CREATED).count() == created_before
    # The notice is still there, with the existing login.
    assert "이전에 Kakao로 가입하셨습니다" in client.get("/signup/confirm").content.decode()
