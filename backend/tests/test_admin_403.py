"""#95: a member session on the admin path gets a way out, and CSRF failures get a retry screen."""

from urllib.parse import urlencode

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, RequestFactory

from accounts.views import _masked_email, csrf_failure
from tests.conftest import MEMBER_EMAIL, FrozenClock

ADMIN = "/" + settings.ADMIN_PATH
ADMIN_LOGIN = ADMIN + "login/"
RELOGIN_TARGET = "/login?" + urlencode({"next": ADMIN})


def test_member_session_on_the_admin_gets_the_relogin_screen(member_client: Client) -> None:
    response = member_client.get(ADMIN, follow=True)

    assert response.status_code == 403
    assert len(response.redirect_chain) <= 2
    page = response.content.decode()
    assert "관리자 계정으로 다시 로그인" in page
    assert 'method="post"' in page and "csrfmiddlewaretoken" in page
    assert "Google" in page
    assert _masked_email(MEMBER_EMAIL) in page
    assert MEMBER_EMAIL not in page


def test_relogin_button_ends_the_member_session_and_goes_to_owner_login(
    member: User, frozen_clock: FrozenClock
) -> None:
    browser = Client(enforce_csrf_checks=True)
    browser.force_login(member)
    browser.get(ADMIN_LOGIN)
    token = browser.cookies[settings.CSRF_COOKIE_NAME].value

    response = browser.post(
        ADMIN_LOGIN + "?next=https://evil.example/",
        {"csrfmiddlewaretoken": token, "next": "https://evil.example/"},
    )

    assert response.status_code == 302
    assert response["Location"] == RELOGIN_TARGET
    assert "_auth_user_id" not in browser.session
    assert browser.get(ADMIN)["Location"].startswith(ADMIN_LOGIN)


def test_relogin_post_without_csrf_token_is_refused(member: User) -> None:
    browser = Client(enforce_csrf_checks=True)
    browser.force_login(member)

    response = browser.post(ADMIN_LOGIN)

    assert response.status_code == 403
    assert "페이지가 만료됐습니다" in response.content.decode()
    assert "_auth_user_id" in browser.session


def test_anonymous_admin_still_goes_to_login(client: Client, db: None) -> None:
    response = client.get(ADMIN_LOGIN, {"next": ADMIN})
    assert response.status_code == 302
    assert response["Location"] == RELOGIN_TARGET


def test_owner_reaches_the_admin(logged_in_client: Client) -> None:
    assert logged_in_client.get(ADMIN).status_code == 200
    assert logged_in_client.get(ADMIN_LOGIN)["Location"] == ADMIN


def test_csrf_failure_shows_expired_screen_with_same_path_retry(client: Client, db: None) -> None:
    browser = Client(enforce_csrf_checks=True)

    response = browser.post("/login?next=%2Faccount", {"username": "x", "password": "y"})

    assert response.status_code == 403
    page = response.content.decode()
    assert "페이지가 만료됐습니다" in page
    assert 'href="/login?next=%2Faccount"' in page


@pytest.mark.parametrize("path", ["//evil.example/x", "/\\evil.example/x"])
def test_csrf_retry_link_never_leaves_the_site(path: str, db: None) -> None:
    request = RequestFactory().post(path)
    page = csrf_failure(request).content.decode()
    assert 'href="/"' in page
    assert "evil.example" not in page


def test_token_endpoint_is_not_behind_csrf(db: None) -> None:
    browser = Client(enforce_csrf_checks=True)
    response = browser.post("/token", {"grant_type": "authorization_code"}, secure=True)
    assert response.status_code != 403
    assert "페이지가 만료됐습니다" not in response.content.decode()


@pytest.mark.parametrize(
    ("email", "shown"),
    [
        ("member@example.com", "me****@example.com"),
        ("abc@x.io", "a**@x.io"),
        ("", ""),
        ("no-at-sign", ""),
    ],
)
def test_masked_email(email: str, shown: str) -> None:
    assert _masked_email(email) == shown
