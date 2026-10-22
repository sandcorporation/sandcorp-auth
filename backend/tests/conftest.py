"""Shared fixtures for backend HTTP-boundary tests.

Fake adapters get registered here as they appear: `frozen_clock`, `recording_randomness`.
`signing_key` gives a test an active token signing key.
`owner` is the owner account (before TOTP enrollment); `logged_in_client` is a test client that
finished password + TOTP (Django `login()` done), with `frozen_clock` running.
"""

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from adapters.clock import set_clock
from adapters.randomness import set_randomness
from oauth.models import SigningKey
from services.owner import create_owner
from services.signing import create_signing_key
from services.totp import current_code, enrollment_device

OWNER_USERNAME = "farrar142"
OWNER_PASSWORD = "correct horse battery staple"


class FrozenClock:
    """A clock that only moves when the test says so."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[FrozenClock]:
    """Freeze `get_clock().now()` at 2026-01-01T00:00:00Z; `advance(seconds)` moves it.

    Django's own `timezone.now()` (session expiry, last_login) follows the same clock.
    """
    clock = FrozenClock(datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(timezone, "now", clock.now)
    previous = set_clock(clock)
    yield clock
    set_clock(previous)


class RecordingRandomness:
    """Deterministic, distinct bytes per call; remembers everything it handed out."""

    def __init__(self) -> None:
        self.issued: list[bytes] = []

    def token_bytes(self, n: int) -> bytes:
        block = hashlib.sha256(len(self.issued).to_bytes(4, "big")).digest()
        out = (block * (n // len(block) + 1))[:n]
        self.issued.append(out)
        return out


@pytest.fixture
def recording_randomness() -> Iterator[RecordingRandomness]:
    """Install a deterministic randomness source whose outputs the test can inspect."""
    randomness = RecordingRandomness()
    previous = set_randomness(randomness)
    yield randomness
    set_randomness(previous)


@pytest.fixture
def signing_key(db: None) -> SigningKey:
    """An active signing key (same as `manage.py signing_keys create`)."""
    return create_signing_key()


@pytest.fixture
def owner(db: None) -> User:
    """The owner account, as `manage.py owner create` makes it (TOTP not enrolled yet)."""
    return create_owner(OWNER_USERNAME, OWNER_PASSWORD)


def totp_code(user: User) -> str:
    """The code the owner's authenticator shows at `get_clock().now()`."""
    return current_code(enrollment_device(user))


@pytest.fixture
def logged_in_client(client: Client, owner: User, frozen_clock: FrozenClock) -> Client:
    """A client logged in with password + TOTP (enrolled on the way). The code's time step is
    used up: advance the clock 30 s before asking for another code."""
    client.post("/login", {"username": OWNER_USERNAME, "password": OWNER_PASSWORD})
    client.post("/totp/setup", {"code": totp_code(owner)})
    return client
