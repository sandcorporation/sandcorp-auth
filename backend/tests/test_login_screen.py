"""The login screen (#141): the owner form, its wording, the app being signed in to, TOTP
reuse, which messages the screen shows, the logout notice, a `next` that GET cannot open."""

import re

import pytest
from django.contrib.auth.models import User
from django.test import Client

from oauth.models import Client as OAuthClient
from tests.conftest import (
    OWNER_PASSWORD,
    OWNER_USERNAME,
    FakeProviders,
    FrozenClock,
    totp_code,
    use_https,
)
from tests.test_owner_social import member_level_url, members_app  # noqa: F401
from tests.test_social_login import kakao_login, kakao_user

pytestmark = pytest.mark.django_db

OWNER_FORM = re.compile(r'<details[^>]*data-slot="owner-login"[^>]*>')


def login_page(client: Client, next_url: str = "") -> str:
    query = {"next": next_url} if next_url else {}
    return client.get("/login", query).content.decode()


def owner_form_open(html: str) -> bool:
    found = OWNER_FORM.search(html)
    assert found, "the owner form is folded in a <details>"
    return " open" in found.group(0)


def username_autofocus(html: str) -> bool:
    found = re.search(r'<input[^>]*id="username"[^>]*>', html)
    assert found
    return "autofocus" in found.group(0)


# 1. The owner form is open (and focused) unless an app's member login is the screen.


@pytest.mark.parametrize("next_url", ["", "/account", "/"])
def test_owner_form_is_open_and_focused_without_an_app(client: Client, next_url: str) -> None:
    html = login_page(client, next_url)
    assert owner_form_open(html) and username_autofocus(html)


def test_owner_form_stays_folded_for_an_apps_member_login(
    client: Client,
    members_app: OAuthClient,  # noqa: F811
) -> None:
    use_https(client)
    html = login_page(client, member_level_url(members_app))
    assert not owner_form_open(html) and not username_autofocus(html)


def test_owner_form_opens_with_the_enrollment_notice(
    client: Client,
    owner: User,
    members_app: OAuthClient,  # noqa: F811
    fake_providers: FakeProviders,
) -> None:
    from tests.test_owner_social import OWNER_KAKAO_ID, link_owner_kakao

    link_owner_kakao(owner)
    use_https(client)
    response = kakao_login(
        client, fake_providers, member_level_url(members_app), kakao_user(OWNER_KAKAO_ID)
    )
    html = client.get(response["Location"]).content.decode()
    assert "OTP 등록을 먼저 마쳐야 합니다" in html
    assert owner_form_open(html) and username_autofocus(html)


# 2. Wording that reads as the administrator's login, not "my main account".


def test_owner_login_is_called_the_administrator_login(client: Client) -> None:
    html = login_page(client)
    assert "관리자 로그인" in html
    assert "대표 계정으로 로그인" not in html


# 3. The app the login continues to.


def test_login_names_the_app_of_an_authorize_next(
    client: Client,
    members_app: OAuthClient,  # noqa: F811
) -> None:
    use_https(client)
    html = login_page(client, member_level_url(members_app))
    assert 'data-slot="login-app"' in html and members_app.name in html


@pytest.mark.parametrize("case", ["inactive", "unknown", "no_authorize"])
def test_login_names_no_app_for_an_unknown_or_inactive_client(
    client: Client,
    members_app: OAuthClient,  # noqa: F811
    case: str,
) -> None:
    use_https(client)
    next_url = member_level_url(members_app)
    if case == "inactive":
        OAuthClient.objects.filter(pk=members_app.pk).update(active=False)
    elif case == "unknown":
        next_url = member_level_url(members_app, client_id="no-such-client")
    else:
        next_url = "/account"
    html = login_page(client, next_url)
    assert 'data-slot="login-app"' not in html and members_app.name not in html


# 4. A code already used in its time step.


def test_reused_totp_code_says_so(
    logged_in_client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    client = logged_in_client
    client.post("/logout")
    frozen_clock.advance(30)
    client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    code = totp_code(owner)
    assert client.post("/login/totp", {"code": code})["Location"] == "/"
    client.post("/logout")
    client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    replay = client.post("/login/totp", {"code": code})
    assert replay.status_code == 200
    page = replay.content.decode()
    assert "이미 쓴 코드입니다" in page and "다음 코드" in page
    assert client.session.get("_auth_user_id") is None  # still refused
    wrong = f"{(int(code) + 1) % 1_000_000:06d}"
    frozen_clock.advance(2)
    assert "이미 쓴 코드" not in client.post("/login/totp", {"code": wrong}).content.decode()


# 5. The login screen shows only its own messages and leaves the others to their screen.


def test_login_screen_leaves_other_screens_messages(member_client: Client) -> None:
    response = member_client.post("/account/email", {"email": "new@example.com"})
    assert response.status_code == 302
    login = member_client.post("/login", {"username": "x", "password": "y"}).content.decode()
    assert "이메일을 저장했습니다" not in login
    assert 'data-slot="login-notice"' not in login
    account = member_client.get("/account").content.decode()
    assert re.search(r'role="status"[^>]*>이메일을 저장했습니다', account)


# 6. Signing out says so where it lands.


def test_logout_lands_on_a_signed_out_status(logged_in_client: Client) -> None:
    response = logged_in_client.post("/logout")
    html = logged_in_client.get(response["Location"]).content.decode()
    assert re.search(r'role="status"[^>]*>.*로그아웃했습니다', html)
    assert "로그아웃했습니다" not in login_page(logged_in_client)  # shown once


def test_going_back_from_the_code_step_is_not_a_logout(client: Client, owner: User) -> None:
    client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    response = client.post("/logout")
    assert "로그아웃했습니다" not in client.get(response["Location"]).content.decode()


# 7. A `next` that GET cannot open lands on the default page.


@pytest.mark.parametrize(
    ("next_url", "lands"),
    [("/account/email", "/"), ("/logout", "/"), ("/account", "/account")],
)
def test_password_login_next_that_get_cannot_open_lands_home(
    client: Client, owner: User, frozen_clock: FrozenClock, next_url: str, lands: str
) -> None:
    client.post(
        "/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD, "next": next_url}
    )
    response = client.post("/totp/setup", {"code": totp_code(owner)})
    assert response["Location"] == lands
