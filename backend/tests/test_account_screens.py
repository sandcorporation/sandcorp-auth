"""「내 계정」·약관·TOTP 화면 다듬기 (#143): touch sizes, names in the lists, what the notices
say and where focus goes after an action."""

import re
from pathlib import Path

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from accounts.models import ExternalIdentity, TermsAgreement
from oauth.models import Client as OAuthClient
from oauth.models import SigningKey
from tests.conftest import OWNER_PASSWORD, OWNER_USERNAME, FrozenClock, make_member
from tests.test_account_page import consent_for, members_proxy, page  # noqa: F401 (fixture)

STATIC = Path(settings.BASE_DIR) / "static"


def css_rule(selector: str) -> str:
    """The declarations of the auth.css rule whose selector list holds `selector`."""
    css = (STATIC / "auth.css").read_text()
    for selectors, body in re.findall(r"([^{}]+)\{([^}]*)\}", css):
        if selector in [s.strip() for s in selectors.split(",")]:
            return body
    raise AssertionError(f"no rule for {selector}")


@pytest.mark.parametrize(
    "selector", [".auth-main .sc-btn--sm", ".auth-link-button", ".auth-check"]
)
def test_small_buttons_link_buttons_and_check_rows_are_44px_tall(selector: str) -> None:
    assert re.search(r"min-height:\s*(2\.75rem|44px)", css_rule(selector)), selector


def test_the_qr_graphic_inside_the_named_image_is_hidden(client: Client, owner: User) -> None:
    client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    body = client.get("/totp/setup").content.decode()
    inner = body.split('role="img"', 1)[1]
    assert re.match(r'[^>]*>\s*(<\?xml[^>]*>\s*)?<svg[^>]*aria-hidden="true"', inner)


def test_terms_has_an_agree_to_all_box_that_needs_no_script_for_the_items(
    client: Client, db: None
) -> None:
    member = make_member(agreed=False)
    client.force_login(member)
    body = client.get("/terms").content.decode()
    all_box = re.search(r"<input[^>]*data-agree-all[^>]*>", body)
    assert all_box is not None
    assert "name=" not in all_box.group(0)  # the server never sees it
    # Without the script the box stays hidden and every item is its own required checkbox.
    assert re.search(r"<[^>]*data-slot=\"agree-all\"[^>]*hidden", body)
    assert body.count('name="document"') == 2 and 'name="age_14" required' in body
    assert '<script src="/static/terms.js" defer></script>' in body
    assert "data-agree-all" in (STATIC / "terms.js").read_text()


def test_the_account_page_lists_the_agreed_documents(member_client: Client, member: User) -> None:
    body = page(member_client)
    section = body.split('data-slot="agreements"', 1)[1].split("</section>", 1)[0]
    for agreement in TermsAgreement.objects.filter(user=member).select_related("document"):
        document = agreement.document
        assert document.get_kind_display() in section and document.version in section
        assert f'href="{document.url}"' in section
        assert timezone.localtime(agreement.agreed_at).strftime("%Y-%m-%d") in section


def test_kakao_is_named_in_korean_and_a_login_without_email_shows_when_it_was_linked(
    client: Client, db: None, frozen_clock: FrozenClock
) -> None:
    member = make_member("kakao", "4242", email="")
    client.force_login(member)
    body = page(client)
    section = body.split('data-slot="identities"', 1)[1].split("</section>", 1)[0]
    assert "카카오" in section and "Kakao" not in section
    linked = ExternalIdentity.objects.get(user=member).linked_at
    assert f"연결 {timezone.localtime(linked):%Y-%m-%d}" in section


def notice(body: str) -> str:
    match = re.search(r'<div class="sc-alert[^"]*"[^>]*role="(status|alert)"[^>]*>([^<]*)', body)
    assert match is not None, "no notice"
    assert 'tabindex="-1"' in match.group(0) and "autofocus" in match.group(0)
    return match.group(2)


def test_unlinking_names_the_login_and_focuses_the_notice(
    member_client: Client, member: User
) -> None:
    ExternalIdentity.objects.create(
        user=member, provider="kakao", provider_sub="77", linked_at=timezone.now()
    )
    kakao = ExternalIdentity.objects.get(user=member, provider="kakao")
    member_client.post(f"/account/identities/{kakao.pk}/unlink")
    assert notice(page(member_client)) == "카카오 로그인 수단을 해제했습니다."


def test_disconnecting_names_the_app_and_focuses_the_notice(
    member_client: Client,
    members_proxy: tuple[OAuthClient, str],  # noqa: F811
    signing_key: SigningKey,
) -> None:
    app = members_proxy[0]
    consent_for(member_client, app)
    member_client.post(f"/account/apps/{app.pk}/disconnect")
    assert notice(page(member_client)) == f"{app.name} 연결을 끊었습니다."


def test_saving_the_email_names_it_and_focuses_the_notice(member_client: Client) -> None:
    member_client.post("/account/email", {"email": "new@example.com"})
    assert notice(page(member_client)) == "계정 이메일을 저장했습니다 (new@example.com)."


def test_a_wrong_withdrawal_phrase_focuses_the_input(member_client: Client) -> None:
    body = member_client.post("/account/withdraw", {"confirm": "아니요"}).content.decode()
    field = re.search(r'<input[^>]*id="confirm"[^>]*>', body)
    assert field is not None and "autofocus" in field.group(0)
    first = member_client.get("/account/withdraw").content.decode()
    assert "autofocus" not in re.search(r'<input[^>]*id="confirm"[^>]*>', first).group(0)  # type: ignore[union-attr]
