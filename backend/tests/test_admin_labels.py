"""#145: admin words in Korean, account kind / member status on the user list, and a CSRF
retry on an admin POST-only action that does not land on a 405."""

import re

import pytest
from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client

from accounts.models import Member
from oauth.models import Client as OAuthClient
from tests.conftest import make_member

ADMIN = "/" + settings.ADMIN_PATH
USERS = ADMIN + "auth/user/"


@pytest.mark.parametrize("label", ["accounts", "oauth"])
def test_every_model_has_a_korean_name(label: str) -> None:
    for model in apps.get_app_config(label).get_models():
        for name in (model._meta.verbose_name, model._meta.verbose_name_plural):
            assert re.search("[가-힣]", str(name)), (model.__name__, name)


def test_admin_index_has_no_english_plural(logged_in_client: Client) -> None:
    html = logged_in_client.get(ADMIN).content.decode()
    assert "familys" not in html.lower()
    assert "리프레시 토큰 패밀리" in html


def _row(html: str, text: str) -> str:
    rows = [row for row in html.split("<tr")[1:] if "field-username" in row and text in row]
    assert rows, text
    return rows[0]


def test_user_list_shows_account_kind_and_member_status(logged_in_client: Client) -> None:
    pending = make_member("kakao", "1", agreed=False)
    active = make_member("kakao", "2")
    withdrawn = make_member("kakao", "3")
    Member.objects.filter(user=withdrawn).update(status=Member.Status.WITHDRAWN)

    html = logged_in_client.get(USERS).content.decode()

    assert "계정 종류" in html and "회원 상태" in html
    owner_row = _row(html, User.objects.get(member__isnull=True).username)
    assert "대표" in owner_row
    assert "일반 사용자" in _row(html, pending.username)
    assert "동의 대기" in _row(html, pending.username)
    assert "활성" in _row(html, active.username)
    assert "탈퇴" in _row(html, withdrawn.username)


@pytest.mark.parametrize(
    ("value", "shown", "hidden"),
    [("withdrawn", "m3", "m2"), ("active", "m2", "m3"), ("owner", "owner", "m2")],
)
def test_user_list_filters_by_member_status(
    logged_in_client: Client, value: str, shown: str, hidden: str
) -> None:
    names = {
        "m2": make_member("kakao", "2").username,
        "m3": make_member("kakao", "3").username,
        "owner": User.objects.get(member__isnull=True).username,
    }
    Member.objects.filter(user__username=names["m3"]).update(status=Member.Status.WITHDRAWN)

    html = logged_in_client.get(USERS + "?account_status=" + value).content.decode()

    assert names[shown] in html
    assert names[hidden] not in html


def _retry(html: str) -> str:
    found = re.search(r'href="([^"]*)" data-slot="retry"', html)
    assert found, html
    return found.group(1)


def _strict_owner(logged_in_client: Client) -> Client:
    strict = Client(enforce_csrf_checks=True)
    strict.cookies = logged_in_client.cookies
    return strict


def _rotate_paths(oauth_client: OAuthClient) -> list[str]:
    base = f"{ADMIN}oauth/client/{oauth_client.pk}/"
    return [base + "rotate-secret/", base + "rotate-webhook-secret/"]


def test_csrf_retry_on_admin_post_only_goes_to_referer(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    strict = _strict_owner(logged_in_client)
    change = f"{ADMIN}oauth/client/{dcr_client.pk}/change/"
    for path in [*_rotate_paths(dcr_client), ADMIN + "logout/"]:
        response = strict.post(path, HTTP_REFERER="http://testserver" + change)
        assert response.status_code == 403
        assert _retry(response.content.decode()) == change, path


def test_csrf_retry_on_admin_post_only_without_referer_goes_to_admin(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    strict = _strict_owner(logged_in_client)
    for path in [*_rotate_paths(dcr_client), ADMIN + "logout/"]:
        response = strict.post(path)
        assert _retry(response.content.decode()) == ADMIN, path
        assert logged_in_client.get(_retry(response.content.decode())).status_code == 200


def test_csrf_retry_on_admin_change_form_stays_on_it(
    logged_in_client: Client, dcr_client: OAuthClient
) -> None:
    change = f"{ADMIN}oauth/client/{dcr_client.pk}/change/"
    response = _strict_owner(logged_in_client).post(change)
    assert _retry(response.content.decode()) == change


def test_rotate_views_still_refuse_get(logged_in_client: Client, dcr_client: OAuthClient) -> None:
    for path in _rotate_paths(dcr_client):
        assert logged_in_client.get(path).status_code == 405
