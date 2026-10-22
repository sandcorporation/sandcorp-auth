"""Login request limiting and the audit log, over HTTP with a frozen clock: per-IP block
(password step, TOTP step, enrollment), per-account backoff delay, audit rows, read-only admin."""

import re

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, override_settings

from audit.models import AuditEvent
from tests.conftest import OWNER_PASSWORD, OWNER_USERNAME, FrozenClock, totp_code

pytestmark = pytest.mark.django_db

ADMIN = "/" + settings.ADMIN_PATH
LOCKED = "뒤 다시 시도하세요"
WINDOW = 15 * 60
PAST_DELAY = 61  # longer than the largest account delay


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


def test_password_failures_from_one_ip_block_it_until_the_window_passes(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    for _ in range(4):
        status, body = post_password(client, "wrong password!!")
        assert status == 200 and "아이디 또는 비밀번호가 맞지 않습니다" in body
        frozen_clock.advance(PAST_DELAY)
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
        frozen_clock.advance(PAST_DELAY)
        status, body = post_password(client, "wrong password!!")
        assert LOCKED not in body
    frozen_clock.advance(PAST_DELAY)
    status, _ = post_password(client, OWNER_PASSWORD)
    assert status == 302


def test_totp_failures_lock_the_second_step(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    enroll(client, owner, frozen_clock)
    post_password(client, OWNER_PASSWORD)
    body = ""
    for _ in range(5):
        frozen_clock.advance(PAST_DELAY)
        body = client.post("/login/totp", {"code": wrong_code(totp_code(owner))}).content.decode()
    assert LOCKED in body and "약 15분" in body

    right = client.post("/login/totp", {"code": totp_code(owner)})
    assert right.status_code == 200 and LOCKED in right.content.decode()
    # The password step is blocked for this address too.
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
        frozen_clock.advance(PAST_DELAY)
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
    frozen_clock.advance(PAST_DELAY)
    post_password(client, OWNER_PASSWORD)
    first = totp_code(owner)
    client.post("/totp/setup", {"code": wrong_code(first)})
    frozen_clock.advance(PAST_DELAY)
    client.post("/totp/setup", {"code": totp_code(owner)})
    client.post("/logout")
    frozen_clock.advance(30)
    post_password(client, OWNER_PASSWORD)
    client.post("/login/totp", {"code": wrong_code(totp_code(owner))})
    for _ in range(5):
        frozen_clock.advance(PAST_DELAY)
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
    assert kinds.count("login.locked") == 1  # the address 10.6.6.6; accounts are only delayed
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


# --- per-account backoff ---------------------------------------------------------------------


def delay_shown(body: str) -> int:
    """The seconds in 「N초 뒤 다시 시도하세요」, failing when the page shows no delay."""
    match = re.search(r"(\d+)초 뒤 다시 시도하세요", body)
    assert match, body
    return int(match.group(1))


def test_failures_from_many_ips_only_delay_the_owner(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    enroll(client, owner, frozen_clock)
    for i in range(1, 6):
        frozen_clock.advance(PAST_DELAY)
        status, body = post_password(client, "wrong password!!", ip=f"10.0.0.{i}")
        assert "아이디 또는 비밀번호가 맞지 않습니다" in body

    # Right after the fifth failure the owner, from his own address, only meets a delay.
    status, body = post_password(client, OWNER_PASSWORD, ip="10.1.1.1")
    wait = delay_shown(body)
    assert status == 200 and wait == 16
    frozen_clock.advance(wait)
    status, _ = post_password(client, OWNER_PASSWORD, ip="10.1.1.1")
    assert status == 302
    response = client.post("/login/totp", {"code": totp_code(owner)}, REMOTE_ADDR="10.1.1.1")
    assert response.status_code == 302
    assert client.get("/").status_code == 200


def test_account_delay_doubles_up_to_a_minute_and_resets_on_success(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    enroll(client, owner, frozen_clock)
    seen = []
    for i in range(1, 9):  # a fresh address each time, so the per-IP block never applies
        status, body = post_password(client, "wrong password!!", ip=f"10.0.1.{i}")
        assert "아이디 또는 비밀번호가 맞지 않습니다" in body
        status, body = post_password(client, OWNER_PASSWORD, ip=f"10.0.2.{i}")
        seen.append(delay_shown(body))
        frozen_clock.advance(seen[-1])
    assert seen == [1, 2, 4, 8, 16, 32, 60, 60]

    post_password(client, OWNER_PASSWORD, ip="10.1.1.1")
    assert client.post("/login/totp", {"code": totp_code(owner)}).status_code == 302
    client.post("/logout")

    post_password(client, "wrong password!!", ip="10.0.3.1")
    _, body = post_password(client, OWNER_PASSWORD, ip="10.0.3.2")
    assert delay_shown(body) == 1


def test_account_failures_are_forgotten_after_a_quiet_window(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    for i in range(1, 4):
        post_password(client, "wrong password!!", ip=f"10.0.1.{i}")
        frozen_clock.advance(PAST_DELAY)
    frozen_clock.advance(WINDOW)
    post_password(client, "wrong password!!", ip="10.0.1.9")
    _, body = post_password(client, OWNER_PASSWORD, ip="10.0.2.9")
    assert delay_shown(body) == 1


def test_attempts_during_the_delay_are_not_judged_and_are_audited(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    post_password(client, "wrong password!!", ip="10.0.0.1")
    AuditEvent.objects.all().delete()

    status, body = post_password(client, OWNER_PASSWORD, ip="10.1.1.1")
    assert status == 200 and delay_shown(body) == 1
    status, body = post_password(client, "wrong password!!", ip="10.1.1.1")
    assert status == 200 and delay_shown(body) == 1  # same answer: the password is not judged

    events = list(AuditEvent.objects.order_by("id").values_list("kind", "actor", "detail"))
    assert events == [
        ("login.delayed", OWNER_USERNAME, {"wait_seconds": 1}),
        ("login.delayed", OWNER_USERNAME, {"wait_seconds": 1}),
    ]
