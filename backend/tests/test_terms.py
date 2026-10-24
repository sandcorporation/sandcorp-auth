"""Terms agreement (#37): versioned documents (이용약관, 개인정보 수집·이용), the required
agreement with the age-14 check that turns a member from 「동의 대기」 to 「활성」, re-agreement
when a new version takes effect, and the three token gates (`/authorize`, `/token`, the token
generator) that refuse a member who has not agreed to the current versions."""

import io
from datetime import date, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.test import Client
from django.utils import timezone

from accounts.models import Member, TermsAgreement, TermsDocument
from adapters.clock import get_clock
from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import Resource, SigningKey
from oauth.tokens import SandcorpTokenGenerator
from services import audit
from services.terms import needs_terms
from tests.conftest import (
    PORTFOLIO,
    FakeProviders,
    FrozenClock,
    authorize_query,
    ensure_terms_documents,
    exchange_code,
    make_member,
    obtain_authorization_code,
    obtain_tokens,
    refresh,
    use_https,
)
from tests.test_social_login import kakao_login, kakao_user

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def documents(db: None) -> None:
    """A first version of each document, as the operator registers before members come."""
    ensure_terms_documents()


@pytest.fixture
def members_app(dcr_client: OAuthClient, signing_key: SigningKey) -> OAuthClient:
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    return dcr_client


@pytest.fixture
def pending(db: None, frozen_clock: FrozenClock) -> User:
    """A member just made by a first social login: no agreement yet."""
    return make_member(agreed=False)


@pytest.fixture
def pending_client(client: Client, pending: User) -> Client:
    client.force_login(pending)
    return client


def today() -> date:
    return timezone.localdate(get_clock().now())


def new_version(kind: str = TermsDocument.Kind.TERMS, *, effective: date | None = None) -> None:
    TermsDocument.objects.create(
        kind=kind,
        version="2026-11",
        effective_date=effective or today(),
        url=f"https://sandcorporation.github.io/privacy-and-terms/account/{kind}/",
        created_at=get_clock().now(),
    )


def authorize_url(app: OAuthClient) -> str:
    return "/authorize?" + authorize_query(app, scope="login")


def terms_redirect(response: "TestResponse") -> str:
    """The `next` of a redirect to the terms screen (fails if it is not one)."""
    assert response.status_code == 302, response.content
    location = urlsplit(response["Location"])
    assert location.path == "/terms", response["Location"]
    return parse_qs(location.query)["next"][0]


def agree(client: Client, next_url: str, **fields: str | list[str]) -> "TestResponse":
    page = client.get("/terms?" + urlencode({"next": next_url}))
    assert page.status_code == 200, page.content
    documents = [str(pk) for pk in page.context["documents"].values_list("pk", flat=True)]
    form: dict[str, str | list[str]] = {"next": next_url, "document": documents, "age_14": "on"}
    form.update(fields)
    return client.post("/terms", {k: v for k, v in form.items() if v != ""})


# --- agreeing ------------------------------------------------------------------------------


def test_pending_member_is_sent_to_the_terms_screen_from_authorize(
    pending_client: Client, members_app: OAuthClient
) -> None:
    use_https(pending_client)
    url = authorize_url(members_app)
    assert terms_redirect(pending_client.get(url)) == url
    assert terms_redirect(pending_client.post(url, {"decision": "allow"})) == url


def test_terms_screen_links_the_current_documents(
    pending_client: Client, members_app: OAuthClient
) -> None:
    response = pending_client.get("/terms?" + urlencode({"next": authorize_url(members_app)}))
    assert response.status_code == 200
    body = response.content.decode()
    for document in TermsDocument.objects.all():
        assert document.url in body
    assert 'name="age_14"' in body


def test_agreeing_activates_the_member_and_returns_to_authorize(
    pending_client: Client, pending: User, members_app: OAuthClient
) -> None:
    url = authorize_url(members_app)
    response = agree(pending_client, url)
    assert response.status_code == 302
    assert response["Location"] == url
    member = Member.objects.get(user=pending)
    assert member.status == Member.Status.ACTIVE
    agreements = TermsAgreement.objects.filter(user=pending)
    assert {a.document.kind for a in agreements} == set(TermsDocument.Kind)
    assert all(a.age_confirmed and a.agreed_at == get_clock().now() for a in agreements)
    assert AuditEvent.objects.filter(kind=audit.TERMS_AGREED, actor=pending.username).exists()
    tokens = obtain_tokens(pending_client, members_app, scope="login")
    assert tokens["access_token"]


def test_missing_age_confirmation_is_refused(
    pending_client: Client, pending: User, members_app: OAuthClient
) -> None:
    response = agree(pending_client, authorize_url(members_app), age_14="")
    assert response.status_code == 400
    assert "만 14세" in response.content.decode()
    assert not TermsAgreement.objects.filter(user=pending).exists()
    assert Member.objects.get(user=pending).status == Member.Status.PENDING_TERMS
    assert needs_terms(pending)


def test_missing_a_document_is_refused(
    pending_client: Client, pending: User, members_app: OAuthClient
) -> None:
    only_terms = TermsDocument.objects.filter(kind=TermsDocument.Kind.TERMS).values_list(
        "pk", flat=True
    )
    response = agree(pending_client, authorize_url(members_app), document=[str(only_terms[0])])
    assert response.status_code == 400
    assert not TermsAgreement.objects.filter(user=pending).exists()
    assert needs_terms(pending)


def test_agreeing_to_an_outdated_version_is_refused(
    pending_client: Client, pending: User, members_app: OAuthClient
) -> None:
    url = authorize_url(members_app)
    page = pending_client.get("/terms?" + urlencode({"next": url}))
    old = [str(pk) for pk in page.context["documents"].values_list("pk", flat=True)]
    new_version()  # takes effect between showing the screen and pressing the button
    response = pending_client.post("/terms", {"next": url, "document": old, "age_14": "on"})
    assert response.status_code == 400
    assert needs_terms(pending)


def test_no_documents_means_no_signup(
    pending_client: Client, pending: User, members_app: OAuthClient
) -> None:
    TermsDocument.objects.all().delete()
    response = pending_client.get("/terms")
    assert response.status_code == 503
    response = pending_client.post("/terms", {"age_14": "on"})
    assert response.status_code == 503
    assert needs_terms(pending)


def test_offsite_next_is_dropped(pending_client: Client) -> None:
    response = agree(pending_client, "https://evil.example/")
    assert response.status_code == 302
    assert response["Location"] == "/"


def test_owner_is_not_asked(logged_in_client: Client, owner: User) -> None:
    assert not needs_terms(owner)
    response = logged_in_client.get("/terms")
    assert response.status_code == 302
    assert response["Location"] == "/"


# --- a new version -------------------------------------------------------------------------


def test_new_version_asks_again_at_authorize(
    member_client: Client, member: User, members_app: OAuthClient
) -> None:
    assert not needs_terms(member)
    use_https(member_client)
    url = authorize_url(members_app)
    new_version()
    assert needs_terms(member)
    assert terms_redirect(member_client.get(url)) == url
    agree(member_client, url)
    assert not needs_terms(member)
    assert obtain_tokens(member_client, members_app, scope="login")["access_token"]


def test_new_version_asks_again_at_login(
    client: Client,
    fake_providers: FakeProviders,
    members_app: OAuthClient,
    frozen_clock: FrozenClock,
) -> None:
    url = authorize_url(members_app)
    first = kakao_login(client, fake_providers, url, kakao_user())
    assert terms_redirect(first) == url  # a new account agrees once
    agree(client, url)
    client.post("/logout")
    new_version(TermsDocument.Kind.PRIVACY)
    again = kakao_login(client, fake_providers, url, kakao_user())
    assert terms_redirect(again) == url


def test_agreed_member_logs_in_straight_through(
    client: Client,
    fake_providers: FakeProviders,
    members_app: OAuthClient,
    frozen_clock: FrozenClock,
) -> None:
    url = authorize_url(members_app)
    kakao_login(client, fake_providers, url, kakao_user())
    agree(client, url)
    client.post("/logout")
    response = kakao_login(client, fake_providers, url, kakao_user())
    assert response.status_code == 302
    assert response["Location"] == url


def test_a_version_not_yet_in_effect_is_not_asked(member: User) -> None:
    new_version(effective=today() + timedelta(days=1))
    assert not needs_terms(member)


# --- the token gates -----------------------------------------------------------------------


def test_token_exchange_refuses_a_member_without_the_current_agreement(
    member_client: Client, members_app: OAuthClient
) -> None:
    code, verifier = obtain_authorization_code(member_client, members_app, scope="login")
    new_version()
    response = exchange_code(member_client, members_app, code, verifier)
    assert response.status_code == 400, response.content
    assert response.json()["error"] == "invalid_grant"


def test_refresh_refuses_a_member_without_the_current_agreement(
    member_client: Client, member: User, members_app: OAuthClient
) -> None:
    tokens = obtain_tokens(member_client, members_app, scope="login")
    new_version()
    response = refresh(member_client, members_app, str(tokens["refresh_token"]))
    assert response.status_code == 400, response.content
    assert response.json()["error"] == "invalid_grant"


def test_refresh_refuses_a_pending_member(
    member_client: Client, member: User, members_app: OAuthClient
) -> None:
    tokens = obtain_tokens(member_client, members_app, scope="login")
    Member.objects.filter(user=member).update(status=Member.Status.PENDING_TERMS)
    response = refresh(member_client, members_app, str(tokens["refresh_token"]))
    assert response.status_code == 400, response.content
    assert response.json()["error"] == "invalid_grant"


def test_token_generator_never_signs_for_a_pending_member(
    pending: User, members_app: OAuthClient
) -> None:
    resource = Resource.objects.get(url=PORTFOLIO)
    with pytest.raises(RuntimeError):
        SandcorpTokenGenerator().generate(
            "authorization_code", members_app, pending, "login", resource=resource
        )


# --- registering versions ------------------------------------------------------------------


def test_terms_command_adds_and_lists(db: None, frozen_clock: FrozenClock) -> None:
    url = "https://sandcorporation.github.io/privacy-and-terms/account/terms/"
    call_command(
        "terms",
        "add",
        "--kind",
        "terms",
        "--doc-version",
        "2026-12",
        "--effective",
        "2026-12-01",
        "--url",
        url,
    )
    document = TermsDocument.objects.get(kind="terms", version="2026-12")
    assert document.effective_date == date(2026, 12, 1)
    assert document.url == url
    assert AuditEvent.objects.filter(kind=audit.TERMS_REGISTERED).exists()
    with pytest.raises(CommandError):
        call_command(
            "terms", "add", "--kind", "terms", "--doc-version", "2026-12",
            "--effective", "2026-12-01", "--url", url,
        )  # fmt: skip
    out = io.StringIO()
    call_command("terms", "list", stdout=out)
    assert "2026-12" in out.getvalue()


def test_admin_registers_a_new_version(logged_in_client: Client) -> None:
    url = f"/{settings.ADMIN_PATH}accounts/termsdocument/add/"
    assert logged_in_client.get(url).status_code == 200
    response = logged_in_client.post(
        url,
        {
            "kind": "privacy",
            "version": "2027-01",
            "effective_date": "2027-01-01",
            "url": "https://sandcorporation.github.io/privacy-and-terms/account/privacy/",
        },
    )
    assert response.status_code == 302, response.content
    assert TermsDocument.objects.filter(kind="privacy", version="2027-01").exists()
    assert AuditEvent.objects.filter(kind=audit.TERMS_REGISTERED).exists()
