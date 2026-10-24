"""「내 계정」 (#38): sign-in methods, account email, connected apps and their disconnect, and
the member's consent screen wording. Rules for linking are in `test_social_login.py`."""

import pytest
from django.contrib.auth.models import User
from django.test import Client

from accounts.models import Member
from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import Consent, SigningKey
from services import audit
from services.confidential_clients import create_confidential_client
from tests.conftest import authorize_query, make_member, use_https


@pytest.fixture
def members_proxy(db: None, signing_key: SigningKey) -> tuple[OAuthClient, str]:
    """A confidential client that allows members (login info scopes are for those only)."""
    issued = create_confidential_client(
        "Foresight", ["https://news.sandcorp.co.kr/callback"], actor="test"
    )
    OAuthClient.objects.filter(pk=issued.client.pk).update(allows_members=True)
    issued.client.refresh_from_db()
    return issued.client, issued.secret


def page(client: Client) -> str:
    return client.get("/account").content.decode()


def consent_for(member_client: Client, app: OAuthClient) -> str:
    """Run /authorize for a member on `app` and allow; return the code."""
    use_https(member_client)
    url = "/authorize?" + authorize_query(app, scope="openid profile email", resource=None)
    response = member_client.get(url)
    assert response.status_code == 200, response.get("Location")
    response = member_client.post(url, {"decision": "allow"})
    assert response.status_code == 302, response.content
    return response["Location"]


def test_account_page_lists_logins_email_and_no_apps(member_client: Client, member: User) -> None:
    body = page(member_client)
    assert "내 계정" in body and "Google" in body and member.email in body
    assert "연결된 앱이 없습니다" in body
    assert "탈퇴하기" in body and 'href="/account/withdraw"' in body  # #39
    # The old address serves the same page.
    assert member_client.get("/account/identities").status_code == 200


def test_the_owner_has_no_account_page(logged_in_client: Client) -> None:
    assert logged_in_client.get("/account").status_code == 403
    assert logged_in_client.post("/account/email", {"email": "a@b.co"}).status_code == 403


def test_member_sets_an_email_and_it_stays_after_reload(
    member_client: Client, member: User
) -> None:
    response = member_client.post("/account/email", {"email": " New@Example.com "})
    assert response.status_code == 302 and response["Location"] == "/account"
    member.refresh_from_db()
    assert member.email == "New@Example.com"
    assert Member.objects.get(user=member).email_verified is False
    body = page(member_client)
    assert "이메일을 저장했습니다" in body and 'value="New@Example.com"' in body
    assert AuditEvent.objects.filter(kind=audit.MEMBER_EMAIL_CHANGED, actor=member.username)


def test_member_without_an_email_can_add_one(member_client: Client, db: None) -> None:
    nobody = make_member("kakao", "777", email="", name="이메일 없음")
    member_client.force_login(nobody)
    assert "등록된 이메일이 없습니다" in page(member_client)
    member_client.post("/account/email", {"email": "me@example.com"})
    nobody.refresh_from_db()
    assert nobody.email == "me@example.com"


@pytest.mark.parametrize("bad", ["", "not-an-email", "a@", "x" * 250 + "@example.com"])
def test_a_malformed_email_is_refused(member_client: Client, member: User, bad: str) -> None:
    before = member.email
    member_client.post("/account/email", {"email": bad})
    member.refresh_from_db()
    assert member.email == before
    assert "형식이 맞지 않습니다" in page(member_client)


def test_an_email_of_another_member_is_refused(member_client: Client, member: User) -> None:
    other = make_member("kakao", "888", email="Taken@Example.com", name="다른 사람")
    member_client.post("/account/email", {"email": "taken@example.COM"})
    member.refresh_from_db()
    assert member.email != "taken@example.COM"
    assert other.email == "Taken@Example.com"
    assert "이미 다른 계정에서 쓰는 이메일" in page(member_client)


def test_member_consent_screen_says_what_the_app_sees(
    member_client: Client, members_proxy: tuple[OAuthClient, str], signing_key: SigningKey
) -> None:
    app = members_proxy[0]
    use_https(member_client)
    url = "/authorize?" + authorize_query(app, scope="openid profile email", resource=None)
    response = member_client.get(url)
    assert response.status_code == 200, response["Location"]
    assert f"{app.name} 앱이 이메일·이름을 봅니다" in response.content.decode()


def test_connected_app_is_listed_and_disconnect_revokes_consent(
    member_client: Client,
    members_proxy: tuple[OAuthClient, str],
    member: User,
    signing_key: SigningKey,
) -> None:
    app = members_proxy[0]
    consent_for(member_client, app)
    assert Consent.objects.filter(user=member, revoked_at__isnull=True).exists()
    body = page(member_client)
    assert app.name in body and "이메일·이름 제공" in body

    disconnect = f"/account/apps/{app.pk}/disconnect"
    response = member_client.post(disconnect)
    assert response.status_code == 302 and response["Location"] == "/account"
    assert not Consent.objects.filter(user=member, revoked_at__isnull=True).exists()
    event = AuditEvent.objects.get(kind=audit.CONSENT_REVOKED)
    assert event.detail["reason"] == "user_disconnected"
    body = page(member_client)
    assert "앱 연결을 끊었습니다" in body and "연결된 앱이 없습니다" in body
    # A second press changes nothing and says so.
    member_client.post(disconnect)
    assert "이미 연결이 끊어진 앱" in page(member_client)


def test_disconnect_touches_only_the_members_own_consents(
    member_client: Client,
    members_proxy: tuple[OAuthClient, str],
    member: User,
    signing_key: SigningKey,
) -> None:
    app = members_proxy[0]
    other = make_member("kakao", "555", email="o@example.com", name="다른 사람")
    other_client = Client()
    other_client.force_login(other)
    consent_for(other_client, app)
    member_client.post(f"/account/apps/{app.pk}/disconnect")
    assert Consent.objects.filter(user=other, revoked_at__isnull=True).exists()
