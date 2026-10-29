"""Withdrawal (#39, ADR 0004): inactive at once, `user.deleted` webhooks through a retry queue,
personal data purged 30 days later, audit events kept a year."""

import io
import json
import re
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import pytest
from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.test import Client

from accounts.models import ExternalIdentity, Member, TermsAgreement
from adapters.http import FetchError
from audit.models import AuditEvent
from core.models import ThrottleCounter
from oauth.models import Client as OAuthClient
from oauth.models import Consent, RefreshTokenFamily, Resource, SigningKey, WebhookDelivery
from services import audit, throttle
from services.webhooks import MAX_ATTEMPTS, RETRY_DELAYS, deliver_due, set_webhook
from services.withdrawal import CONFIRM_PHRASE, purge_withdrawn, withdraw_member
from tests.conftest import (
    MEMBER_EMAIL,
    PORTFOLIO,
    FakeWebhooks,
    FrozenClock,
    exchange_code,
    make_member,
    obtain_authorization_code,
    refresh,
)
from tests.test_members import members_proxy as members_proxy  # noqa: F401  (fixture)
from tests.test_members import oidc_tokens
from tests.test_oidc import Proxy, userinfo
from tests.test_social_login import google_login, session_user
from tests.test_social_login import next_url as next_url  # noqa: F401  (fixture)

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

DOC = Path(__file__).resolve().parents[2] / "docs" / "resource-server-token-validation.md"
HOOK_URL = "https://news.sandcorp.co.kr/auth/webhook"


class Verifier(Protocol):
    def __call__(
        self, secret: str, body: bytes, signature_header: str, *, now: float | None = None
    ) -> dict[str, object]: ...


def documented_verifier() -> tuple[Verifier, type[Exception]]:
    """`verify_sandcorp_webhook` exactly as section 11 of the validation doc prints it."""
    section = DOC.read_text().split("## 11.", 1)[1]
    found = re.search(r"### Python 예시\n\n```python\n(.*?)```", section, re.DOTALL)
    assert found is not None
    namespace: dict[str, object] = {}
    exec(compile(found.group(1), str(DOC), "exec"), namespace)  # noqa: S102 - our own doc
    verify = namespace["verify_sandcorp_webhook"]
    rejected = namespace["WebhookRejected"]
    assert callable(verify) and isinstance(rejected, type)
    return verify, rejected


@pytest.fixture
def members_app(dcr_client: OAuthClient, signing_key: SigningKey) -> OAuthClient:
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    return dcr_client


@pytest.fixture
def hook_secret(members_app: OAuthClient) -> str:
    secret = set_webhook(members_app, url=HOOK_URL, rotate_secret=False, actor="test")
    assert secret is not None
    return secret


def member_tokens(client: Client, app: OAuthClient) -> dict[str, str]:
    code, verifier = obtain_authorization_code(client, app, scope="login")
    response = exchange_code(client, app, code, verifier)
    assert response.status_code == 200, response.content
    tokens: dict[str, str] = response.json()
    return tokens


def withdraw(client: Client, phrase: str = CONFIRM_PHRASE) -> TestResponse:
    return client.post("/account/withdraw", {"confirm": phrase})


# --- the screens ---------------------------------------------------------------------------


def test_account_page_leads_to_the_withdrawal_screen(member_client: Client) -> None:
    page = member_client.get("/account").content.decode()
    assert 'href="/account/withdraw"' in page
    assert "준비 중" not in page
    confirm = member_client.get("/account/withdraw")
    assert confirm.status_code == 200
    assert f"「{CONFIRM_PHRASE}」" in confirm.content.decode()


def test_a_wrong_phrase_withdraws_nothing(member_client: Client, member: User) -> None:
    response = withdraw(member_client, "탈퇴")
    assert response.status_code == 400
    assert "정확히 입력하세요" in response.content.decode()
    member.refresh_from_db()
    assert member.is_active
    assert Member.objects.get(user=member).status == Member.Status.ACTIVE


def test_the_owner_cannot_withdraw(logged_in_client: Client) -> None:
    assert logged_in_client.get("/account/withdraw").status_code == 403
    assert withdraw(logged_in_client).status_code == 403


def test_withdrawal_needs_a_session(client: Client) -> None:
    response = withdraw(client)
    assert response.status_code == 302 and response["Location"].startswith("/login")


# --- withdrawing ---------------------------------------------------------------------------


def test_withdrawal_signs_out_everywhere_and_refuses_everything(
    member_client: Client, member: User, members_app: OAuthClient, frozen_clock: FrozenClock
) -> None:
    tokens = member_tokens(member_client, members_app)
    unused_code, verifier = obtain_authorization_code(member_client, members_app, scope="login")
    other_device = Client()
    other_device.force_login(member)

    response = withdraw(member_client)

    assert response.status_code == 200
    assert "탈퇴했습니다" in response.content.decode()
    member.refresh_from_db()
    record = Member.objects.get(user=member)
    assert not member.is_active
    assert record.status == Member.Status.WITHDRAWN
    assert record.withdrawn_at == frozen_clock.now()
    # Both sessions are signed out (this one ended, the other no longer authenticates).
    for device in (member_client, other_device):
        assert device.get("/account")["Location"].startswith("/login")
    # Refresh, the unused code, a new /authorize: all refused.
    refused = refresh(member_client, members_app, tokens["refresh_token"])
    assert refused.status_code == 400 and refused.json()["error"] == "invalid_grant"
    late = exchange_code(member_client, members_app, unused_code, verifier)
    assert late.status_code == 400 and late.json()["error"] == "invalid_grant"
    assert not Consent.objects.filter(user=member, revoked_at__isnull=True).exists()
    assert not RefreshTokenFamily.objects.filter(user=member, revoked_at__isnull=True).exists()
    # Its social logins are released at once.
    assert not ExternalIdentity.objects.filter(user=member).exists()
    assert AuditEvent.objects.filter(kind=audit.MEMBER_WITHDRAWN, actor=member.username).exists()


def test_userinfo_is_refused_after_withdrawal(
    member_client: Client, member: User, members_proxy: Proxy, frozen_clock: FrozenClock
) -> None:
    tokens = oidc_tokens(member_client, members_proxy, "openid email")
    assert userinfo(member_client, tokens["access_token"]).status_code == 200
    withdraw_member(member)
    assert userinfo(member_client, tokens["access_token"]).status_code == 401


def test_withdrawing_twice_does_nothing_the_second_time(member: User) -> None:
    assert withdraw_member(member)
    assert not withdraw_member(member)
    assert AuditEvent.objects.filter(kind=audit.MEMBER_WITHDRAWN).count() == 1


def test_withdrawal_erases_the_ip_of_the_members_audit_events(member: User) -> None:
    audit.record(audit.LOGIN_SUCCEEDED, actor=member.username, ip="203.0.113.7")
    audit.record(audit.LOGIN_SUCCEEDED, actor="farrar142", ip="203.0.113.8")
    withdraw_member(member)
    assert set(AuditEvent.objects.filter(actor=member.username).values_list("ip", flat=True)) == {
        ""
    }
    assert AuditEvent.objects.get(actor="farrar142").ip == "203.0.113.8"


def test_the_same_social_login_signs_up_as_a_new_account(
    client: Client, fake_webhooks: FakeWebhooks, next_url: str, fake_providers: object
) -> None:
    from tests.test_social_login import NEW_GOOGLE_SUB

    old = make_member(provider_sub=NEW_GOOGLE_SUB, email="new@example.com")
    withdraw_member(old)

    response = google_login(client, fake_providers, next_url)  # type: ignore[arg-type]

    assert response.status_code == 302
    assert response["Location"] != "/signup/confirm"  # no 「이전 계정」 notice
    user = session_user(client)
    assert user is not None and user != old and user.username != old.username
    assert ExternalIdentity.objects.get(provider_sub=NEW_GOOGLE_SUB).user == user
    assert Member.objects.get(user=user).status == Member.Status.PENDING_TERMS


def test_a_withdrawn_email_is_free_for_another_member(member: User) -> None:
    from services.members import set_member_email

    withdraw_member(member)
    other = make_member(provider_sub="108999999999999999999", email="other@example.com")
    set_member_email(other, MEMBER_EMAIL)
    other.refresh_from_db()
    assert other.email == MEMBER_EMAIL


# --- the webhook ---------------------------------------------------------------------------


def test_withdrawal_queues_user_deleted_for_consented_clients_with_a_webhook(
    member_client: Client,
    member: User,
    members_app: OAuthClient,
    hook_secret: str,
    fake_webhooks: FakeWebhooks,
    frozen_clock: FrozenClock,
) -> None:
    member_tokens(member_client, members_app)
    withdraw(member_client)
    assert fake_webhooks.sent == []  # nothing is sent inside the request

    delivery = WebhookDelivery.objects.get()
    report = deliver_due()

    assert report.delivered == 1
    url, body, headers = fake_webhooks.sent[0]
    assert url == HOOK_URL
    event = json.loads(body)
    assert event == {
        "id": delivery.event_id,
        "type": "user.deleted",
        "sub": member.username,
        "occurred_at": "2026-01-01T00:00:00Z",
    }
    assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", event["id"])
    assert headers["X-Sandcorp-Event"] == "user.deleted"
    assert headers["X-Sandcorp-Delivery"] == delivery.event_id
    verify, rejected = documented_verifier()
    now = frozen_clock.now().timestamp()
    assert verify(hook_secret, body, headers["X-Sandcorp-Signature"], now=now) == event
    with pytest.raises(rejected):
        verify("another-secret", body, headers["X-Sandcorp-Signature"], now=now)
    with pytest.raises(rejected):
        verify(hook_secret, body + b" ", headers["X-Sandcorp-Signature"], now=now)
    with pytest.raises(rejected):
        verify(hook_secret, body, headers["X-Sandcorp-Signature"], now=now + 301)
    delivery.refresh_from_db()
    assert delivery.delivered_at == frozen_clock.now() and delivery.attempts == 1
    assert deliver_due().delivered == 0  # done is done


def test_only_clients_the_member_consented_to_and_that_have_a_webhook_are_told(
    member: User, members_app: OAuthClient, hook_secret: str, cimd_client: OAuthClient
) -> None:
    set_webhook(cimd_client, url="https://elsewhere.example/hook", rotate_secret=False, actor="t")
    withdraw_member(member)  # no consent anywhere
    assert not WebhookDelivery.objects.exists()


def test_a_failed_delivery_is_retried_until_it_succeeds(
    member_client: Client,
    members_app: OAuthClient,
    hook_secret: str,
    fake_webhooks: FakeWebhooks,
    frozen_clock: FrozenClock,
) -> None:
    member_tokens(member_client, members_app)
    withdraw(member_client)
    fake_webhooks.answers = [500, FetchError("timed out")]

    assert deliver_due().retrying == 1
    delivery = WebhookDelivery.objects.get()
    assert delivery.last_error == "status 500"
    assert delivery.next_attempt_at == frozen_clock.now() + RETRY_DELAYS[0]

    frozen_clock.advance(RETRY_DELAYS[0].total_seconds() - 1)
    assert deliver_due() == type(deliver_due())()  # not yet
    frozen_clock.advance(1)
    assert deliver_due().retrying == 1
    delivery.refresh_from_db()
    assert delivery.last_error.startswith("fetch: timed out")
    assert delivery.next_attempt_at == frozen_clock.now() + RETRY_DELAYS[1]

    frozen_clock.advance(RETRY_DELAYS[1].total_seconds())
    assert deliver_due().delivered == 1
    assert len(fake_webhooks.sent) == 3
    bodies = {body for _, body, _ in fake_webhooks.sent}
    assert len(bodies) == 1  # the same event every time (the receiver drops repeats by id)
    delivery.refresh_from_db()
    assert delivery.attempts == 3 and delivery.last_error == ""


def test_a_delivery_is_given_up_after_the_last_attempt(
    member: User,
    members_app: OAuthClient,
    hook_secret: str,
    fake_webhooks: FakeWebhooks,
    frozen_clock: FrozenClock,
) -> None:
    Consent.objects.create(
        user=member,
        client=members_app,
        resource=_portfolio(),
        scopes=["login"],
        granted_at=frozen_clock.now(),
    )
    withdraw_member(member)
    fake_webhooks.answers = [503] * MAX_ATTEMPTS
    for delay in RETRY_DELAYS:
        assert deliver_due().retrying == 1
        frozen_clock.advance(delay.total_seconds())
    assert deliver_due().gave_up == 1
    delivery = WebhookDelivery.objects.get()
    assert delivery.attempts == MAX_ATTEMPTS and delivery.gave_up_at is not None
    assert delivery.next_attempt_at is None
    frozen_clock.advance(timedelta(days=7).total_seconds())
    assert deliver_due().gave_up == 0


def _portfolio() -> Resource:
    return Resource.objects.get(url=PORTFOLIO)


def test_webhooks_command_delivers(
    member: User, members_app: OAuthClient, hook_secret: str, fake_webhooks: FakeWebhooks
) -> None:
    Consent.objects.create(
        user=member,
        client=members_app,
        resource=_portfolio(),
        scopes=["login"],
        granted_at=member.date_joined,
    )
    withdraw_member(member)
    out = io.StringIO()
    call_command("webhooks", "list", stdout=out)
    assert "user.deleted" in out.getvalue()
    out = io.StringIO()
    call_command("webhooks", "deliver", stdout=out)
    assert out.getvalue().strip() == "delivered=1 retrying=0 gave_up=0"


def test_clients_webhook_command(members_app: OAuthClient) -> None:
    out = io.StringIO()
    call_command(
        "clients", "webhook", "--client-id", members_app.client_id, "--url", HOOK_URL, stdout=out
    )
    first = re.search(r"webhook_secret: ([0-9a-f]{64})", out.getvalue())
    assert first is not None
    members_app.refresh_from_db()
    assert members_app.webhook_url == HOOK_URL
    assert first.group(1).encode() not in bytes(members_app.webhook_secret_encrypted or b"")

    out = io.StringIO()
    call_command(
        "clients", "webhook", "--client-id", members_app.client_id, "--rotate-secret", stdout=out
    )
    second = re.search(r"webhook_secret: ([0-9a-f]{64})", out.getvalue())
    assert second is not None and second.group(1) != first.group(1)

    listing = io.StringIO()
    call_command("clients", "list", stdout=listing)
    assert f"webhook={HOOK_URL}" in listing.getvalue()

    with pytest.raises(CommandError):
        call_command(
            "clients",
            "webhook",
            "--client-id",
            members_app.client_id,
            "--url",
            "http://x.example/h",
        )
    call_command("clients", "webhook", "--client-id", members_app.client_id, "--remove")
    members_app.refresh_from_db()
    assert members_app.webhook_url == "" and members_app.webhook_secret_encrypted is None
    assert AuditEvent.objects.filter(kind=audit.CLIENT_WEBHOOK_CHANGED).count() == 3


# --- the purge -----------------------------------------------------------------------------


def test_personal_data_is_purged_30_days_after_withdrawal(
    member: User, members_app: OAuthClient, frozen_clock: FrozenClock
) -> None:
    Consent.objects.create(
        user=member,
        client=members_app,
        resource=_portfolio(),
        scopes=["login"],
        granted_at=frozen_clock.now(),
    )
    sub = member.username
    withdraw_member(member)
    assert TermsAgreement.objects.filter(user=member).exists()

    frozen_clock.advance(timedelta(days=30).total_seconds() - 60)  # 29 days 23:59
    assert purge_withdrawn().members == []
    member.refresh_from_db()
    assert member.email == MEMBER_EMAIL

    frozen_clock.advance(60)  # 30 days
    dry = purge_withdrawn(dry_run=True)
    assert dry.members == [sub]
    member.refresh_from_db()
    assert member.email == MEMBER_EMAIL  # a dry run changes nothing

    assert purge_withdrawn().members == [sub]
    member.refresh_from_db()
    record = Member.objects.get(user=member)
    assert (member.email, member.first_name, member.last_name) == ("", "", "")
    assert not member.is_active and member.username == sub  # the tombstone of the sub
    assert record.status == Member.Status.WITHDRAWN and record.purged_at == frozen_clock.now()
    assert not record.email_verified
    assert not TermsAgreement.objects.filter(user=member).exists()
    assert not Consent.objects.filter(user=member).exists()
    assert not ExternalIdentity.objects.filter(user=member).exists()
    assert AuditEvent.objects.filter(kind=audit.MEMBER_PURGED, actor=sub).exists()
    assert purge_withdrawn().members == []  # once


def test_audit_events_are_kept_one_year(db: None, frozen_clock: FrozenClock) -> None:
    old = audit.record(audit.LOGIN_SUCCEEDED, actor="farrar142", ip="203.0.113.1")
    frozen_clock.advance(timedelta(days=1).total_seconds())
    kept = audit.record(audit.LOGIN_SUCCEEDED, actor="farrar142", ip="203.0.113.1")
    frozen_clock.advance(timedelta(days=365).total_seconds())  # old: 366 days, kept: 365
    report = purge_withdrawn()
    assert report.audit_events == 1
    assert not AuditEvent.objects.filter(pk=old.pk).exists()
    assert AuditEvent.objects.filter(pk=kept.pk).exists()


def test_idle_request_limit_counters_are_deleted(db: None, frozen_clock: FrozenClock) -> None:
    throttle.hit("login", "ip:203.0.113.9")
    frozen_clock.advance(throttle.STALE_AFTER.total_seconds() - 1)
    throttle.hit("login", "ip:203.0.113.10")
    frozen_clock.advance(2)
    assert purge_withdrawn().throttle_counters == 1
    assert list(ThrottleCounter.objects.values_list("key", flat=True)) == ["login:ip:203.0.113.10"]


def test_finished_deliveries_go_30_days_later(
    member: User, members_app: OAuthClient, hook_secret: str, frozen_clock: FrozenClock
) -> None:
    Consent.objects.create(
        user=member,
        client=members_app,
        resource=_portfolio(),
        scopes=["login"],
        granted_at=frozen_clock.now(),
    )
    withdraw_member(member)
    deliver_due()
    frozen_clock.advance(timedelta(days=30).total_seconds())
    assert purge_withdrawn().webhook_deliveries == 1
    assert not WebhookDelivery.objects.exists()


def test_members_purge_command(member: User, frozen_clock: FrozenClock) -> None:
    withdraw_member(member)
    frozen_clock.advance(timedelta(days=30).total_seconds())
    out = io.StringIO()
    call_command("members", "purge", "--dry-run", stdout=out)
    assert "탈퇴 계정 1개 지울 대상" in out.getvalue() and member.username in out.getvalue()
    out = io.StringIO()
    call_command("members", "purge", stdout=out)
    assert "탈퇴 계정 1개 지웠습니다" in out.getvalue()
