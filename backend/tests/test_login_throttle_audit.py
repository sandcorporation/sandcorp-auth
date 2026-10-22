"""Login request limiting (consecutive-failure lock) and the audit log, over HTTP with a frozen
clock: password step, TOTP step, enrollment, per-IP lock, audit rows, read-only admin."""

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, override_settings

from audit.models import AuditEvent
from tests.conftest import OWNER_PASSWORD, OWNER_USERNAME, FrozenClock, totp_code

pytestmark = pytest.mark.django_db

ADMIN = "/" + settings.ADMIN_PATH
LOCKED = "잠시 뒤 다시 시도하세요"
WINDOW = 15 * 60


def post_password(
    client: Client, password: str, username: str = OWNER_USERNAME, ip: str = "10.0.0.1"
) -> tuple[int, str]:
    response = client.post("/login", {"username": username, "password": password}, REMOTE_ADDR=ip)
    return response.status_code, response.content.decode()


def wrong_code(right: str) -> str:
    return f"{(int(right) + 1) % 1_000_000:06d}"


def enroll(client: Client, owner: User, frozen_clock: FrozenClock) -> None:
    """Password + enrollment, then log out: the owner is enrolled, the counters are clean."""
    client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    client.post("/totp/setup", {"code": totp_code(owner)})
    client.post("/logout")
    frozen_clock.advance(30)


def test_password_failures_lock_the_account_until_the_window_passes(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    for _ in range(4):
        status, body = post_password(client, "wrong password!!")
        assert status == 200 and "아이디 또는 비밀번호가 맞지 않습니다" in body
    status, body = post_password(client, "wrong password!!")
    assert LOCKED in body and "약 15분" in body

    # Locked: even the right password is not judged.
    status, body = post_password(client, OWNER_PASSWORD)
    assert status == 200 and LOCKED in body

    frozen_clock.advance(WINDOW + 1)
    status, _ = post_password(client, OWNER_PASSWORD)
    assert status == 302
    client.post("/totp/setup", {"code": totp_code(owner)})
    assert client.get("/").status_code == 200  # logged in: counters reset
    client.post("/logout")

    for _ in range(4):
        status, body = post_password(client, "wrong password!!")
        assert LOCKED not in body
    status, _ = post_password(client, OWNER_PASSWORD)
    assert status == 302


def test_totp_failures_lock_the_second_step(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    enroll(client, owner, frozen_clock)
    post_password(client, OWNER_PASSWORD)
    body = ""
    for _ in range(5):
        body = client.post("/login/totp", {"code": wrong_code(totp_code(owner))}).content.decode()
    assert LOCKED in body

    right = client.post("/login/totp", {"code": totp_code(owner)})
    assert right.status_code == 200 and LOCKED in right.content.decode()
    # The password step is locked for this account too.
    status, body = post_password(client, OWNER_PASSWORD)
    assert LOCKED in body

    frozen_clock.advance(WINDOW + 1)
    post_password(client, OWNER_PASSWORD)
    assert client.post("/login/totp", {"code": totp_code(owner)}).status_code == 302
    assert client.get("/").status_code == 200


def test_enrollment_code_failures_are_limited(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    post_password(client, OWNER_PASSWORD)
    for _ in range(5):
        response = client.post("/totp/setup", {"code": wrong_code(totp_code(owner))})
    assert LOCKED in response.content.decode()
    response = client.post("/totp/setup", {"code": totp_code(owner)})
    assert LOCKED in response.content.decode()
    assert AuditEvent.objects.filter(kind="login.totp_enrolled").count() == 0


def test_failures_from_one_ip_lock_that_ip_across_usernames(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    for name in ["alice", "bob", "carol", "dave", "erin"]:
        post_password(client, "wrong password!!", username=name, ip="10.9.9.9")
    status, body = post_password(client, OWNER_PASSWORD, ip="10.9.9.9")
    assert LOCKED in body
    # Another address is not affected (the owner's account itself had no failures).
    status, _ = post_password(client, OWNER_PASSWORD, ip="10.1.1.1")
    assert status == 302


def test_forwarded_for_is_trusted_only_when_configured(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    with override_settings(TRUST_X_FORWARDED_FOR=True):
        client.post(
            "/login",
            {"username": "nobody", "password": "wrong password!!"},
            REMOTE_ADDR="172.17.0.1",
            HTTP_X_FORWARDED_FOR="203.0.113.7, 172.17.0.1",
        )
    assert AuditEvent.objects.get().ip == "203.0.113.7"


def test_login_events_are_audited_without_secrets(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    post_password(client, "wrong password!!")
    post_password(client, OWNER_PASSWORD)
    first = totp_code(owner)
    client.post("/totp/setup", {"code": wrong_code(first)})
    client.post("/totp/setup", {"code": first})
    client.post("/logout")
    frozen_clock.advance(30)
    post_password(client, OWNER_PASSWORD)
    client.post("/login/totp", {"code": wrong_code(totp_code(owner))})
    for _ in range(5):
        post_password(client, "another wrong one", username="mallory", ip="10.6.6.6")

    kinds = list(AuditEvent.objects.order_by("id").values_list("kind", flat=True))
    assert kinds[:6] == [
        "login.password_failed",
        "login.totp_failed",
        "login.totp_enrolled",
        "login.succeeded",
        "logout",
        "login.totp_failed",
    ]
    assert kinds.count("login.locked") == 2  # the account "mallory" and the address 10.6.6.6
    failed = AuditEvent.objects.filter(kind="login.password_failed").order_by("id").first()
    assert failed is not None and failed.actor == OWNER_USERNAME and failed.ip == "10.0.0.1"
    dump = repr(list(AuditEvent.objects.values()))
    for secret in [OWNER_PASSWORD, "wrong password!!", "another wrong one", first]:
        assert secret not in dump


def test_admin_shows_the_audit_log_read_only(logged_in_client: Client) -> None:
    event = AuditEvent.objects.get(kind="login.succeeded")
    listing = logged_in_client.get(ADMIN + "audit/auditevent/")
    assert listing.status_code == 200 and "login.succeeded" in listing.content.decode()
    assert logged_in_client.get(ADMIN + "audit/auditevent/?q=farrar").status_code == 200
    assert logged_in_client.get(ADMIN + "audit/auditevent/add/").status_code == 403
    change_url = f"{ADMIN}audit/auditevent/{event.pk}/change/"
    page = logged_in_client.get(change_url)
    assert page.status_code == 200 and 'name="_save"' not in page.content.decode()
    assert logged_in_client.post(change_url, {"kind": "edited"}).status_code == 403
    delete_url = f"{ADMIN}audit/auditevent/{event.pk}/delete/"
    assert logged_in_client.post(delete_url, {"post": "yes"}).status_code == 403
    assert AuditEvent.objects.get(pk=event.pk).kind == "login.succeeded"
