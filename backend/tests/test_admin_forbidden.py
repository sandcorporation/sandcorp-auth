"""#95: a member session on the admin gets a 403 page with a re-login button, not a bare 403."""

from django.conf import settings
from django.test import Client

from tests.conftest import MEMBER_EMAIL, make_member

ADMIN_LOGIN = "/" + settings.ADMIN_PATH + "login/"
ADMIN = "/" + settings.ADMIN_PATH
RELOGIN_NEXT = f"/login?next=%2F{settings.ADMIN_PATH.replace('/', '%2F')}"


def test_member_session_gets_relogin_page(client: Client, db: None) -> None:
    client.force_login(make_member())
    response = client.get(ADMIN_LOGIN + "?next=" + ADMIN)
    assert response.status_code == 403
    html = response.content.decode()
    assert "관리자 계정으로 다시 로그인" in html
    assert 'action="/logout"' in html


def test_relogin_button_ends_member_session(client: Client, db: None) -> None:
    client.force_login(make_member())
    response = client.post("/logout", {"next": RELOGIN_NEXT})
    assert response.status_code == 302
    assert response["Location"] == RELOGIN_NEXT
    assert client.get(ADMIN_LOGIN)["Location"].startswith("/login?next=")


def test_anonymous_still_redirects_to_login(client: Client, db: None) -> None:
    assert client.get(ADMIN_LOGIN)["Location"] == RELOGIN_NEXT


def test_owner_reaches_admin(logged_in_client: Client) -> None:
    assert logged_in_client.get(ADMIN).status_code == 200


def test_csrf_failure_shows_retry_page(db: None) -> None:
    strict = Client(enforce_csrf_checks=True)
    response = strict.post("/logout", {"next": "/login"})
    assert response.status_code == 403
    html = response.content.decode()
    assert "페이지가 만료됐습니다" in html
    assert 'href="/logout"' in html


def test_owner_on_member_screen_gets_page_not_bare_403(logged_in_client: Client) -> None:
    response = logged_in_client.get("/account")
    assert response.status_code == 403
    assert "이 화면은 열 수 없습니다" in response.content.decode()


def test_staff_on_admin_login_goes_to_admin(logged_in_client: Client) -> None:
    response = logged_in_client.get(ADMIN_LOGIN)
    assert response.status_code == 302
    assert response["Location"] == ADMIN


def test_csrf_retry_link_never_protocol_relative() -> None:
    from django.test import RequestFactory

    from accounts.views import csrf_failure

    for path in ("//evil.example/x", "/\\evil.example"):
        html = csrf_failure(RequestFactory().post(path)).content.decode()
        assert 'href="/"' in html
    assert 'href="/logout"' in csrf_failure(RequestFactory().post("/logout")).content.decode()


def test_relogin_page_masks_email(client: Client, db: None) -> None:
    client.force_login(make_member())
    html = client.get(ADMIN_LOGIN).content.decode()
    assert MEMBER_EMAIL not in html
    assert MEMBER_EMAIL[:2] + "***@" + MEMBER_EMAIL.split("@")[1] in html
