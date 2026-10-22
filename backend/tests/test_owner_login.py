"""Owner account and login end to end over HTTP: management command, password step, forced TOTP
enrollment, password + TOTP login, logout, session expiry, admin access (frozen clock)."""

import io

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.test import Client

from services.owner import OwnerExists
from tests.conftest import OWNER_PASSWORD, OWNER_USERNAME, FrozenClock, totp_code

pytestmark = pytest.mark.django_db

ADMIN = "/" + settings.ADMIN_PATH


def login_password(client: Client, password: str = OWNER_PASSWORD, next_url: str = "") -> str:
    data = {"username": OWNER_USERNAME, "password": password}
    if next_url:
        data["next"] = next_url
    response = client.post("/login", data)
    return response["Location"] if response.status_code == 302 else ""


def wrong_code(right: str) -> str:
    return f"{(int(right) + 1) % 1_000_000:06d}"


def test_owner_create_makes_the_one_staff_account_and_names_the_sub() -> None:
    out = io.StringIO()
    call_command("owner", "create", "--password", OWNER_PASSWORD, stdout=out)
    owner = User.objects.get()
    assert owner.username == "farrar142"
    assert owner.is_staff and owner.is_superuser
    assert "sub" in out.getvalue() and "farrar142" in out.getvalue()

    with pytest.raises(CommandError) as refused:
        call_command("owner", "create", "--username", "other", "--password", OWNER_PASSWORD)
    assert refused.value.returncode == 1
    with pytest.raises(OwnerExists):
        User.objects.create_superuser("other", password=OWNER_PASSWORD)
    assert User.objects.count() == 1


def test_owner_create_rejects_a_weak_password() -> None:
    with pytest.raises(CommandError):
        call_command("owner", "create", "--password", "short")
    assert not User.objects.exists()


def test_full_login_lifecycle(client: Client, owner: User, frozen_clock: FrozenClock) -> None:
    # Not logged in: admin sends us to this service's login, not Django's.
    response = client.get(ADMIN)
    assert response.status_code == 302
    admin_login = client.get(response["Location"])
    assert admin_login["Location"] == f"/login?next=%2F{settings.ADMIN_PATH.replace('/', '%2F')}"
    assert client.get("/")["Location"].startswith("/login")

    # Wrong password.
    response = client.post("/login", {"username": OWNER_USERNAME, "password": "nope-nope-nope"})
    assert response.status_code == 200
    assert "맞지 않습니다" in response.content.decode()

    # Right password, TOTP not enrolled: only the setup screen is reachable.
    assert login_password(client, next_url=ADMIN) == "/totp/setup"
    for path in (ADMIN, "/", "/login/totp"):
        assert client.get(path)["Location"] == "/totp/setup", path
    setup = client.get("/totp/setup")
    assert setup.status_code == 200
    assert "<svg" in setup.content.decode()
    assert not client.session.get("_auth_user_id")

    # Wrong code refused; a code from the frozen clock enrolls and finishes the login.
    code = totp_code(owner)
    response = client.post("/totp/setup", {"code": wrong_code(code)})
    assert response.status_code == 200 and "맞지 않습니다" in response.content.decode()
    response = client.post("/totp/setup", {"code": code})
    assert response["Location"] == ADMIN
    assert client.get(ADMIN).status_code == 200

    # Logout (POST only).
    assert client.get("/logout").status_code == 405
    client.post("/logout")
    assert client.get(ADMIN).status_code == 302

    # Re-login needs password + TOTP; wrong and replayed codes are refused.
    frozen_clock.advance(30)
    assert login_password(client, next_url="/") == "/login/totp"
    assert client.get(ADMIN).status_code == 302  # half-authenticated is not logged in
    code = totp_code(owner)
    assert client.post("/login/totp", {"code": wrong_code(code)}).status_code == 200
    assert client.post("/login/totp", {"code": code})["Location"] == "/"
    client.post("/logout")
    login_password(client)
    replay = client.post("/login/totp", {"code": code})
    assert replay.status_code == 200 and "맞지 않습니다" in replay.content.decode()
    frozen_clock.advance(30)
    assert client.post("/login/totp", {"code": totp_code(owner)})["Location"] == "/"
    assert client.get(ADMIN).status_code == 200

    # The session ends after SESSION_COOKIE_AGE.
    frozen_clock.advance(settings.SESSION_COOKIE_AGE + 1)
    response = client.get(ADMIN)
    assert response.status_code == 302 and "login" in response["Location"]


def test_reset_totp_forces_enrollment_again(
    logged_in_client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    assert logged_in_client.get(ADMIN).status_code == 200
    call_command("owner", "reset-totp", stdout=io.StringIO())

    # The open session ends; the next login must enroll a new device.
    assert logged_in_client.get(ADMIN).status_code == 302
    assert login_password(logged_in_client) == "/totp/setup"
    assert logged_in_client.get(ADMIN)["Location"] == "/totp/setup"
    frozen_clock.advance(30)
    response = logged_in_client.post("/totp/setup", {"code": totp_code(owner)})
    assert response["Location"] == "/"
    assert logged_in_client.get(ADMIN).status_code == 200


def test_set_password_ends_sessions_and_changes_the_password(logged_in_client: Client) -> None:
    new_password = "another long passphrase"
    call_command("owner", "set-password", "--password", new_password, stdout=io.StringIO())
    assert logged_in_client.get(ADMIN).status_code == 302
    assert login_password(logged_in_client) == ""
    assert login_password(logged_in_client, password=new_password) == "/login/totp"


@pytest.mark.parametrize(
    "next_url", ["https://evil.example/", "//evil.example/", "javascript:alert(1)"]
)
def test_next_must_be_a_relative_path(
    client: Client, owner: User, frozen_clock: FrozenClock, next_url: str
) -> None:
    login_password(client, next_url=next_url)
    assert client.post("/totp/setup", {"code": totp_code(owner)})["Location"] == "/"
