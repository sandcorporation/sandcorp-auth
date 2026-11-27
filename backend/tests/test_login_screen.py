"""The login screen (#141): the owner form, its wording, the app being signed in to, TOTP
reuse, which messages the screen shows, the logout notice, a `next` that GET cannot open."""

import re

import pytest
from django.contrib import messages
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.test import Client

from oauth.models import Client as OAuthClient
from tests.conftest import (
    OWNER_PASSWORD,
    OWNER_USERNAME,
    FakeProviders,
    FrozenClock,
    make_member,
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
    assert re.search(r'role="status"[^>]*>계정 이메일을 저장했습니다', account)


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


# 8. A logout or a login leaves nothing of the account before (#152).


def _messages_shown(html: str) -> list[str]:
    return re.findall(r'role="status"[^>]*>(?:<span[^>]*>[^<]*</span>)?([^<]*)', html)


def test_logout_drops_the_previous_accounts_messages(member_client: Client, member: User) -> None:
    member_client.post("/account/email", {"email": "left@example.com"})  # never shown
    response = member_client.post("/logout")
    html = member_client.get(response["Location"]).content.decode()
    assert "left@example.com" not in html
    assert _messages_shown(html) == ["로그아웃했습니다."]
    member_client.force_login(make_member("kakao", "1520001", email=""))
    assert "left@example.com" not in member_client.get("/account").content.decode()


def test_admin_logout_drops_messages_and_says_so(logged_in_client: Client) -> None:
    from django.conf import settings
    from django.contrib.messages.storage.cookie import CookieStorage

    request = HttpRequest()
    storage = CookieStorage(request)
    storage.add(messages.SUCCESS, "앞 사람의 알림 left@example.com")
    response_cookie = HttpResponse()
    storage.update(response_cookie)
    logged_in_client.cookies[CookieStorage.cookie_name] = response_cookie.cookies[
        CookieStorage.cookie_name
    ].value
    response = logged_in_client.post("/" + settings.ADMIN_PATH + "logout/")
    assert response.status_code == 302 and response["Location"] == "/login"
    html = logged_in_client.get("/login").content.decode()
    assert "left@example.com" not in html
    assert _messages_shown(html) == ["로그아웃했습니다."]


def test_login_drops_messages_left_by_an_expired_session(
    member_client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    from django.conf import settings

    member_client.post("/account/email", {"email": "left@example.com"})
    del member_client.cookies[settings.SESSION_COOKIE_NAME]  # the session ran out
    member_client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    member_client.post("/totp/setup", {"code": totp_code(owner)})
    assert "left@example.com" not in member_client.get("/account").content.decode()


# 9. After a logout the focus is on the notice, the only autofocus on the screen (#152).


def test_logout_notice_takes_the_focus(logged_in_client: Client) -> None:
    response = logged_in_client.post("/logout")
    html = logged_in_client.get(response["Location"]).content.decode()
    assert html.count("autofocus") == 1
    assert re.search(r'data-slot="login-notice"[^>]*tabindex="-1"[^>]*autofocus', html)
    assert not username_autofocus(html)
    assert username_autofocus(login_page(logged_in_client))  # no notice: the username again


# 10. The folded administrator login opens with a 44px row (#152).


def test_owner_login_summary_is_a_44px_row() -> None:
    from pathlib import Path

    css = (Path(__file__).resolve().parents[1] / "static" / "auth.css").read_text()
    rule = re.search(r"\.auth-details summary \{([^}]*)\}", css)
    assert rule and "min-height: 2.75rem" in rule.group(1)


# 11. One login screen looks its app up once (#152).


def test_login_screen_looks_up_its_client_once(client: Client) -> None:
    from audit.models import AuditEvent
    from services import audit

    use_https(client)
    next_url = "/authorize?client_id=https://ex%C3%A4mple.com/client.json&response_type=code"
    assert client.get("/login", {"next": next_url}).status_code == 200
    assert AuditEvent.objects.filter(kind=audit.CLIENT_CIMD_REJECTED).count() == 1
